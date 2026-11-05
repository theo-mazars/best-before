<script lang="ts">
	import { resolve } from '$app/paths';
	import ArrowDownIcon from '@lucide/svelte/icons/arrow-down';
	import ArrowUpIcon from '@lucide/svelte/icons/arrow-up';
	import ChevronsUpDownIcon from '@lucide/svelte/icons/chevrons-up-down';
	import ListFilterIcon from '@lucide/svelte/icons/list-filter';
	import RotateCcwIcon from '@lucide/svelte/icons/rotate-ccw';
	import TriangleAlertIcon from '@lucide/svelte/icons/triangle-alert';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.js';
	import * as Table from '#lib/components/ui/table/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import Hint from '#lib/components/hint.svelte';
	import SeverityStrip from '#lib/components/severity-strip.svelte';
	import StatusBadge from '#lib/components/status-badge.svelte';
	import TimeAgo from '#lib/components/time-ago.svelte';
	import type { ServerSummary } from '#lib/api.js';
	import { statuses, statusLook, statusRank, statusRule, worstIssue } from '#lib/status.js';

	let { servers }: { servers: ServerSummary[] } = $props();

	type SortKey = 'status' | 'hostname' | 'vulns' | 'lastReport';
	const pageSize = 20;

	let search = $state('');
	let shownStatuses = $state<string[]>([]);
	let sort = $state<{ key: SortKey; desc: boolean }>({ key: 'status', desc: false });
	let pageIndex = $state(0);

	// vulnRank orders by what needs fixing first: emergencies, known
	// exploited, then critical, high and medium.
	function vulnRank(s: ServerSummary) {
		return [s.emergencies, s.knownExploited, s.critical, s.high, s.medium];
	}

	function compare(a: ServerSummary, b: ServerSummary, key: SortKey): number {
		switch (key) {
			case 'status':
				return statusRank(a.status) - statusRank(b.status);
			case 'hostname':
				return a.hostname.localeCompare(b.hostname);
			case 'lastReport':
				return (Date.parse(a.lastReportAt ?? '') || 0) - (Date.parse(b.lastReportAt ?? '') || 0);
			case 'vulns': {
				const x = vulnRank(a);
				const y = vulnRank(b);
				const i = x.findIndex((v, i) => v !== y[i]);
				return i < 0 ? 0 : y[i] - x[i];
			}
		}
	}

	const statusCounts = $derived(
		statuses
			.map((s) => ({ status: s, count: servers.filter((x) => x.status === s).length }))
			.filter((s) => s.count > 0)
	);

	const rows = $derived.by(() => {
		const q = search.trim().toLowerCase();
		const list = servers.filter(
			(s) =>
				(!q || s.hostname.toLowerCase().includes(q)) &&
				(shownStatuses.length === 0 || shownStatuses.includes(s.status))
		);
		const dir = sort.desc ? -1 : 1;
		return list.sort(
			(a, b) => dir * compare(a, b, sort.key) || a.hostname.localeCompare(b.hostname)
		);
	});
	const pageCount = $derived(Math.max(1, Math.ceil(rows.length / pageSize)));
	const pageRows = $derived(rows.slice(pageIndex * pageSize, (pageIndex + 1) * pageSize));
	const filtered = $derived(search !== '' || shownStatuses.length > 0);

	$effect(() => {
		if (pageIndex >= pageCount) pageIndex = pageCount - 1;
	});

	function sortBy(key: SortKey) {
		sort = sort.key === key ? { key, desc: !sort.desc } : { key, desc: false };
	}

	function toggleStatus(status: string, on: boolean) {
		shownStatuses = on ? [...shownStatuses, status] : shownStatuses.filter((s) => s !== status);
		pageIndex = 0;
	}

	function reset() {
		search = '';
		shownStatuses = [];
		pageIndex = 0;
	}
</script>

{#snippet sortable(key: SortKey, label: string)}
	<Button variant="ghost" size="sm" class="-ml-2 h-8" onclick={() => sortBy(key)}>
		{label}
		{#if sort.key !== key}
			<ChevronsUpDownIcon class="text-muted-foreground" />
		{:else if sort.desc}
			<ArrowDownIcon />
		{:else}
			<ArrowUpIcon />
		{/if}
	</Button>
{/snippet}

<div class="flex flex-col gap-3">
	<div class="flex flex-wrap items-center gap-2">
		<Input
			class="h-8 w-full sm:w-64"
			placeholder="Search servers"
			aria-label="Search servers"
			bind:value={search}
			oninput={() => (pageIndex = 0)}
		/>
		<DropdownMenu.Root>
			<DropdownMenu.Trigger>
				{#snippet child({ props })}
					<Button {...props} variant="outline" size="sm" class="h-8">
						<ListFilterIcon />
						Status
						{#if shownStatuses.length}
							<span class="rounded-sm bg-muted px-1 text-xs tabular-nums"
								>{shownStatuses.length}</span
							>
						{/if}
					</Button>
				{/snippet}
			</DropdownMenu.Trigger>
			<DropdownMenu.Content align="start" class="w-48">
				{#each statusCounts as { status, count } (status)}
					<DropdownMenu.CheckboxItem
						checked={shownStatuses.includes(status)}
						onCheckedChange={(on) => toggleStatus(status, on)}
						closeOnSelect={false}
					>
						{statusLook(status).label}
						<span class="ml-auto text-xs text-muted-foreground tabular-nums">{count}</span>
					</DropdownMenu.CheckboxItem>
				{/each}
			</DropdownMenu.Content>
		</DropdownMenu.Root>
		{#if filtered}
			<Button variant="ghost" size="sm" class="h-8" onclick={reset}>
				<RotateCcwIcon />
				Reset
			</Button>
		{/if}
	</div>

	<div class="overflow-x-auto rounded-md border">
		<Table.Root>
			<Table.Header>
				<Table.Row>
					<Table.Head>
						<span class="flex items-center gap-1">
							{@render sortable('status', 'Status')}
							<Hint text={statusRule} />
						</span>
					</Table.Head>
					<Table.Head>{@render sortable('hostname', 'Server')}</Table.Head>
					<Table.Head>Issue</Table.Head>
					<Table.Head>
						<span class="flex items-center gap-1">
							{@render sortable('vulns', 'Vulnerabilities')}
							<Hint
								text="Coloured counts have a fix, are at or above your threshold and are not accepted. Grey counts are the others (no fix, below threshold, accepted): they never change the status. Kernels installed but not running are left out."
							/>
						</span>
					</Table.Head>
					<Table.Head>Updates</Table.Head>
					<Table.Head>Reboot</Table.Head>
					<Table.Head>{@render sortable('lastReport', 'Last report')}</Table.Head>
				</Table.Row>
			</Table.Header>
			<Table.Body>
				{#each pageRows as s (s.id)}
					<Table.Row class={s.problems.length ? 'border-b-0' : undefined}>
						<Table.Cell><StatusBadge status={s.status} /></Table.Cell>
						<Table.Cell class="font-medium">
							<a href={resolve('/(app)/servers/[id]', { id: s.id })} class="hover:underline"
								>{s.hostname}</a
							>
						</Table.Cell>
						<Table.Cell class="text-muted-foreground">{worstIssue(s)}</Table.Cell>
						<Table.Cell><SeverityStrip counts={s.severities} /></Table.Cell>
						<Table.Cell class="tabular-nums">
							{#if s.updates}
								<span class={s.securityUpdates ? 'font-medium' : 'text-muted-foreground'}>
									{s.securityUpdates}
								</span>
								<span class="text-muted-foreground">/ {s.updates}</span>
							{:else}
								<span class="text-muted-foreground">—</span>
							{/if}
						</Table.Cell>
						<Table.Cell>
							{#if s.rebootRequired}
								<span class="text-amber-700 dark:text-amber-400">Required</span>
							{:else}
								<span class="text-muted-foreground">—</span>
							{/if}
						</Table.Cell>
						<Table.Cell class="text-muted-foreground"><TimeAgo time={s.lastReportAt} /></Table.Cell>
					</Table.Row>
					{#if s.problems.length}
						<Table.Row class="hover:bg-transparent">
							<Table.Cell colspan={7} class="pt-0">
								{#each s.problems as problem, i (i)}
									<p
										class="flex items-center gap-1.5 text-xs whitespace-normal text-amber-700 dark:text-amber-400"
									>
										<TriangleAlertIcon class="size-3.5 shrink-0" />
										{problem}
									</p>
								{/each}
							</Table.Cell>
						</Table.Row>
					{/if}
				{:else}
					<Table.Row>
						<Table.Cell colspan={7} class="h-24 text-center text-muted-foreground">
							No server matches.
						</Table.Cell>
					</Table.Row>
				{/each}
			</Table.Body>
		</Table.Root>
	</div>

	{#if pageCount > 1}
		<div class="flex items-center justify-end gap-2">
			<span class="text-sm text-muted-foreground tabular-nums"
				>Page {pageIndex + 1} of {pageCount}</span
			>
			<Button variant="outline" size="sm" disabled={pageIndex === 0} onclick={() => pageIndex--}>
				Previous
			</Button>
			<Button
				variant="outline"
				size="sm"
				disabled={pageIndex >= pageCount - 1}
				onclick={() => pageIndex++}
			>
				Next
			</Button>
		</div>
	{/if}
</div>
