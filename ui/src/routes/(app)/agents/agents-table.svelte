<script lang="ts">
	import type { Snippet } from 'svelte';
	import { resolve } from '$app/paths';
	import ArrowDownIcon from '@lucide/svelte/icons/arrow-down';
	import ArrowUpIcon from '@lucide/svelte/icons/arrow-up';
	import ChevronsUpDownIcon from '@lucide/svelte/icons/chevrons-up-down';
	import EllipsisIcon from '@lucide/svelte/icons/ellipsis';
	import ListFilterIcon from '@lucide/svelte/icons/list-filter';
	import RotateCcwIcon from '@lucide/svelte/icons/rotate-ccw';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.js';
	import * as Table from '#lib/components/ui/table/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import StatusBadge from '#lib/components/status-badge.svelte';
	import TimeAgo from '#lib/components/time-ago.svelte';
	import type { Agent } from '#lib/api.js';
	import { agentLook, agentRank, agentStatuses } from '#lib/status.js';
	import { cn } from '#lib/utils.js';

	let {
		agents,
		onrevoke,
		add
	}: { agents: Agent[]; onrevoke: (a: Agent) => void; add: Snippet<[boolean]> } = $props();

	type SortKey = 'status' | 'hostname' | 'lastReport' | 'enrolled';
	const pageSize = 20;
	// Revoked agents are kept for the record, out of the way.
	const defaultStatuses = agentStatuses.filter((s) => s !== 'revoked');

	let search = $state('');
	let shownStatuses = $state<string[]>([...defaultStatuses]);
	let shownVersions = $state<string[]>([]);
	let sort = $state<{ key: SortKey; desc: boolean }>({ key: 'status', desc: false });
	let pageIndex = $state(0);

	const time = (iso: string | null) => Date.parse(iso ?? '') || 0;

	function compare(a: Agent, b: Agent, key: SortKey): number {
		switch (key) {
			case 'status':
				return agentRank(a.status) - agentRank(b.status);
			case 'hostname':
				return a.hostname.localeCompare(b.hostname);
			case 'lastReport':
				return time(a.lastReportAt) - time(b.lastReportAt);
			case 'enrolled':
				return time(a.enrolledAt) - time(b.enrolledAt);
		}
	}

	const statusShown = (a: Agent) => shownStatuses.includes(a.status);
	const versionShown = (a: Agent) =>
		shownVersions.length === 0 || shownVersions.includes(a.agentVersion);

	// Each menu counts what the other filter shows, so its numbers match the table.
	const statusCounts = $derived(
		agentStatuses.map((s) => ({
			status: s,
			count: agents.filter((a) => a.status === s && versionShown(a)).length
		}))
	);

	// Newest version first; agents that never said theirs come last.
	const versionCounts = $derived(
		[...new Set(agents.map((a) => a.agentVersion))]
			.sort((a, b) => (!a ? 1 : !b ? -1 : b.localeCompare(a, undefined, { numeric: true })))
			.map((v) => ({
				version: v,
				count: agents.filter((a) => a.agentVersion === v && statusShown(a)).length
			}))
	);

	// A search looks through every agent, revoked ones included: the filters
	// wait until it is cleared.
	const searching = $derived(search.trim() !== '');

	function matches(a: Agent, q: string) {
		const compact = q.replaceAll(' ', '');
		return (
			a.hostname.toLowerCase().includes(q) ||
			(compact !== '' && a.fingerprint.replaceAll(' ', '').includes(compact))
		);
	}

	const rows = $derived.by(() => {
		const q = search.trim().toLowerCase();
		const list = agents.filter((a) =>
			searching ? matches(a, q) : statusShown(a) && versionShown(a)
		);
		const dir = sort.desc ? -1 : 1;
		const revoked = (a: Agent) => (a.revokedAt ? 1 : 0);
		return list.sort(
			(a, b) =>
				revoked(a) - revoked(b) ||
				dir * compare(a, b, sort.key) ||
				a.hostname.localeCompare(b.hostname)
		);
	});
	const pageCount = $derived(Math.max(1, Math.ceil(rows.length / pageSize)));
	const pageRows = $derived(rows.slice(pageIndex * pageSize, (pageIndex + 1) * pageSize));
	const changedStatuses = $derived(
		shownStatuses.length !== defaultStatuses.length ||
			defaultStatuses.some((s) => !shownStatuses.includes(s))
	);
	const filtered = $derived(search !== '' || changedStatuses || shownVersions.length > 0);
	const anyActive = $derived(agents.some((a) => !a.revokedAt));

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

	function toggleVersion(version: string, on: boolean) {
		shownVersions = on ? [...shownVersions, version] : shownVersions.filter((v) => v !== version);
		pageIndex = 0;
	}

	function reset() {
		search = '';
		shownStatuses = [...defaultStatuses];
		shownVersions = [];
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

{#snippet filterMenu(
	label: string,
	items: { value: string; label: string; count: number }[],
	shown: string[],
	changed: boolean,
	toggle: (value: string, on: boolean) => void
)}
	<DropdownMenu.Root>
		<DropdownMenu.Trigger disabled={searching}>
			{#snippet child({ props })}
				<Button {...props} variant="outline" size="sm" class="h-8">
					<ListFilterIcon />
					{label}
					{#if changed && !searching}
						<span class="rounded-sm bg-muted px-1 text-xs tabular-nums">{shown.length}</span>
					{/if}
				</Button>
			{/snippet}
		</DropdownMenu.Trigger>
		<DropdownMenu.Content align="start" class="w-48">
			{#each items as item (item.value)}
				<DropdownMenu.CheckboxItem
					checked={shown.includes(item.value)}
					onCheckedChange={(on) => toggle(item.value, on)}
					closeOnSelect={false}
				>
					{item.label}
					<span class="ml-auto text-xs text-muted-foreground tabular-nums">{item.count}</span>
				</DropdownMenu.CheckboxItem>
			{/each}
		</DropdownMenu.Content>
	</DropdownMenu.Root>
{/snippet}

<div class="flex flex-col gap-3">
	<div class="flex flex-wrap items-center gap-2">
		<Input
			class="h-8 w-full sm:w-64"
			placeholder="Search name or fingerprint"
			aria-label="Search name or fingerprint"
			bind:value={search}
			oninput={() => (pageIndex = 0)}
		/>
		{@render filterMenu(
			'Status',
			statusCounts.map(({ status, count }) => ({
				value: status,
				label: agentLook(status).label,
				count
			})),
			shownStatuses,
			changedStatuses,
			toggleStatus
		)}
		{@render filterMenu(
			'Version',
			versionCounts.map(({ version, count }) => ({
				value: version,
				label: version || 'Unknown',
				count
			})),
			shownVersions,
			shownVersions.length > 0,
			toggleVersion
		)}
		{#if filtered}
			<Button variant="ghost" size="sm" class="h-8" onclick={reset}>
				<RotateCcwIcon />
				Reset
			</Button>
		{/if}
		<div class="ml-auto">{@render add(false)}</div>
	</div>

	<div class="overflow-x-auto rounded-md border">
		<Table.Root>
			<Table.Header>
				<Table.Row>
					<Table.Head>{@render sortable('hostname', 'Server')}</Table.Head>
					<Table.Head>{@render sortable('status', 'Status')}</Table.Head>
					<Table.Head>{@render sortable('lastReport', 'Last report')}</Table.Head>
					<Table.Head>Fingerprint</Table.Head>
					<Table.Head>Version</Table.Head>
					<Table.Head>{@render sortable('enrolled', 'Enrolled')}</Table.Head>
					<Table.Head class="w-10"><span class="sr-only">Actions</span></Table.Head>
				</Table.Row>
			</Table.Header>
			<Table.Body>
				{#each pageRows as a (a.id)}
					<Table.Row class={cn(a.revokedAt && 'text-muted-foreground')}>
						<Table.Cell class="font-medium">
							{#if a.revokedAt}
								{a.hostname}
							{:else}
								<a href={resolve('/(app)/servers/[id]', { id: a.id })} class="hover:underline"
									>{a.hostname}</a
								>
							{/if}
						</Table.Cell>
						<Table.Cell><StatusBadge status={a.status} look={agentLook(a.status)} /></Table.Cell>
						<Table.Cell class="text-muted-foreground">
							{#if a.lastReportAt}<TimeAgo time={a.lastReportAt} />{:else}Never{/if}
						</Table.Cell>
						<Table.Cell class="font-mono text-xs">{a.fingerprint}</Table.Cell>
						<Table.Cell>{a.agentVersion || '—'}</Table.Cell>
						<Table.Cell class="text-muted-foreground">
							<TimeAgo time={a.enrolledAt} detail={a.enrolledFrom && `from ${a.enrolledFrom}`} />
						</Table.Cell>
						<Table.Cell>
							{#if !a.revokedAt}
								<DropdownMenu.Root>
									<DropdownMenu.Trigger>
										{#snippet child({ props })}
											<Button
												{...props}
												variant="ghost"
												size="icon-sm"
												aria-label="Actions for {a.hostname}"
											>
												<EllipsisIcon />
											</Button>
										{/snippet}
									</DropdownMenu.Trigger>
									<DropdownMenu.Content align="end">
										<DropdownMenu.Item variant="destructive" onSelect={() => onrevoke(a)}>
											Revoke
										</DropdownMenu.Item>
									</DropdownMenu.Content>
								</DropdownMenu.Root>
							{/if}
						</Table.Cell>
					</Table.Row>
				{:else}
					<Table.Row>
						<Table.Cell colspan={7} class="h-24 text-center text-muted-foreground">
							{#if anyActive || filtered}
								No agent matches.
							{:else}
								No server enrolled yet · {@render add(true)}
							{/if}
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
