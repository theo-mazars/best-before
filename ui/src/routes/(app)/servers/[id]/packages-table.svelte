<script lang="ts">
	import { SvelteMap, SvelteSet } from 'svelte/reactivity';
	import ChevronLeftIcon from '@lucide/svelte/icons/chevron-left';
	import ChevronRightIcon from '@lucide/svelte/icons/chevron-right';
	import ExternalLinkIcon from '@lucide/svelte/icons/external-link';
	import ListFilterIcon from '@lucide/svelte/icons/list-filter';
	import RotateCcwIcon from '@lucide/svelte/icons/rotate-ccw';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.js';
	import * as Table from '#lib/components/ui/table/index.js';
	import * as Tooltip from '#lib/components/ui/tooltip/index.js';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import SeverityStrip from '#lib/components/severity-strip.svelte';
	import TimeAgo from '#lib/components/time-ago.svelte';
	import { stripSeverities, type Cve, type PackageRow } from '#lib/api.js';
	import { formatUTC } from '#lib/date.js';
	import {
		filterPackages,
		noFilter,
		severityLook,
		stateLooks,
		wheres,
		type PackageFilter
	} from '#lib/packages.js';
	import { cn } from '#lib/utils.js';
	import ExploitedBadge from './exploited-badge.svelte';
	import FixNowBadge from './fix-now-badge.svelte';
	import WhereLabel from './where-label.svelte';

	let {
		packages,
		filter = $bindable(),
		onaccept,
		onwithdraw
	}: {
		packages: PackageRow[];
		filter: PackageFilter;
		onaccept: (p: PackageRow, c: Cve) => void;
		onwithdraw: (p: PackageRow, c: Cve) => void;
	} = $props();

	const pageSize = 20;
	const severityNames: Record<string, string> = {
		critical: 'Critical',
		high: 'High',
		medium: 'Medium',
		low: 'Low',
		unknown: 'Unknown or negligible'
	};

	let pageIndex = $state(0);
	const expanded = new SvelteSet<string>();
	const cvePageSize = 10;
	const cvePages = new SvelteMap<string, number>();

	// cvePage is the page of an expanded package's vulnerabilities, kept
	// within range when a refresh shortens the list.
	function cvePage(p: PackageRow) {
		const last = Math.max(0, Math.ceil(p.cves.length / cvePageSize) - 1);
		return Math.min(cvePages.get(key(p)) ?? 0, last);
	}

	const places = $derived(wheres(packages));
	const mutedCount = $derived(packages.filter((p) => p.muted).length);
	const rows = $derived(filterPackages(packages, filter));
	const pageCount = $derived(Math.max(1, Math.ceil(rows.length / pageSize)));
	const pageRows = $derived(rows.slice(pageIndex * pageSize, (pageIndex + 1) * pageSize));
	const filtered = $derived(
		filter.search !== '' ||
			filter.where !== '' ||
			filter.severities.length > 0 ||
			filter.fixNow ||
			filter.knownExploited ||
			filter.showMuted
	);

	$effect(() => {
		if (pageIndex >= pageCount) pageIndex = pageCount - 1;
	});

	const key = (p: PackageRow) => `${p.target}\0${p.package}\0${p.version}`;

	function toggle(p: PackageRow) {
		const k = key(p);
		if (expanded.has(k)) expanded.delete(k);
		else expanded.add(k);
	}

	function set(f: Partial<PackageFilter>) {
		filter = { ...filter, ...f };
		pageIndex = 0;
	}
</script>

<div class="flex flex-col gap-3">
	<div class="flex flex-wrap items-center gap-2">
		<Input
			class="h-8 w-full sm:w-64"
			placeholder="Search packages"
			aria-label="Search packages"
			value={filter.search}
			oninput={(e) => set({ search: e.currentTarget.value })}
		/>
		{#if places.length > 1}
			<DropdownMenu.Root>
				<DropdownMenu.Trigger>
					{#snippet child({ props })}
						<Button {...props} variant="outline" size="sm" class="h-8 max-w-64">
							<ListFilterIcon />
							{#if filter.where}
								<WhereLabel where={filter.where} class="max-w-48" />
							{:else}
								Where
							{/if}
						</Button>
					{/snippet}
				</DropdownMenu.Trigger>
				<DropdownMenu.Content align="start" class="w-64">
					<DropdownMenu.RadioGroup
						value={filter.where}
						onValueChange={(v) => set({ where: v ?? '' })}
					>
						<DropdownMenu.RadioItem value="">Everywhere</DropdownMenu.RadioItem>
						{#each places as w (w)}
							<DropdownMenu.RadioItem value={w}>
								<WhereLabel where={w} class="max-w-52" />
							</DropdownMenu.RadioItem>
						{/each}
					</DropdownMenu.RadioGroup>
				</DropdownMenu.Content>
			</DropdownMenu.Root>
		{/if}
		<DropdownMenu.Root>
			<DropdownMenu.Trigger>
				{#snippet child({ props })}
					<Button {...props} variant="outline" size="sm" class="h-8">
						<ListFilterIcon />
						Severity
						{#if filter.severities.length}
							<span class="rounded-sm bg-muted px-1 text-xs tabular-nums"
								>{filter.severities.length}</span
							>
						{/if}
					</Button>
				{/snippet}
			</DropdownMenu.Trigger>
			<DropdownMenu.Content align="start" class="w-56">
				{#each stripSeverities as sev (sev)}
					<DropdownMenu.CheckboxItem
						checked={filter.severities.includes(sev)}
						onCheckedChange={(on) =>
							set({
								severities: on
									? [...filter.severities, sev]
									: filter.severities.filter((s) => s !== sev)
							})}
						closeOnSelect={false}
					>
						{severityNames[sev]}
					</DropdownMenu.CheckboxItem>
				{/each}
			</DropdownMenu.Content>
		</DropdownMenu.Root>
		<Button
			variant={filter.fixNow ? 'secondary' : 'outline'}
			size="sm"
			class="h-8"
			aria-pressed={filter.fixNow}
			onclick={() => set({ fixNow: !filter.fixNow })}
		>
			To fix now
		</Button>
		<Button
			variant={filter.knownExploited ? 'secondary' : 'outline'}
			size="sm"
			class="h-8"
			aria-pressed={filter.knownExploited}
			onclick={() => set({ knownExploited: !filter.knownExploited })}
		>
			Known exploited
		</Button>
		{#if mutedCount}
			<Button
				variant={filter.showMuted ? 'secondary' : 'outline'}
				size="sm"
				class="h-8"
				aria-pressed={filter.showMuted}
				onclick={() => set({ showMuted: !filter.showMuted })}
			>
				Muted
				<span class="rounded-sm bg-muted px-1 text-xs tabular-nums">{mutedCount}</span>
			</Button>
		{/if}
		{#if filtered}
			<Button variant="ghost" size="sm" class="h-8" onclick={() => set(noFilter)}>
				<RotateCcwIcon />
				Reset
			</Button>
		{/if}
	</div>

	<div class="overflow-x-auto rounded-md border">
		<Table.Root>
			<Table.Header>
				<Table.Row>
					<Table.Head class="w-8"></Table.Head>
					<Table.Head>Where</Table.Head>
					<Table.Head>Package</Table.Head>
					<Table.Head>Vulnerabilities</Table.Head>
					<Table.Head>CVSS</Table.Head>
					<Table.Head>Update to</Table.Head>
				</Table.Row>
			</Table.Header>
			<Table.Body>
				{#each pageRows as p (key(p))}
					{@const open = expanded.has(key(p))}
					<Table.Row
						class={cn('cursor-pointer', p.muted && 'text-muted-foreground', open && 'border-b-0')}
						onclick={() => toggle(p)}
					>
						<Table.Cell>
							<Button
								variant="ghost"
								size="icon"
								class="size-6"
								aria-label={open ? 'Hide vulnerabilities' : 'Show vulnerabilities'}
								aria-expanded={open}
							>
								<ChevronRightIcon class={cn('transition-transform', open && 'rotate-90')} />
							</Button>
						</Table.Cell>
						<Table.Cell class="max-w-56"><WhereLabel where={p.where} /></Table.Cell>
						<Table.Cell>
							<span class="font-medium">{p.package}</span>
							<span class="ml-1 text-xs text-muted-foreground">{p.version}</span>
							{#if p.kind === 'software'}
								<Tooltip.Root>
									<Tooltip.Trigger class="ml-1 text-xs text-muted-foreground"
										>by version</Tooltip.Trigger
									>
									<Tooltip.Content>Matched from the image's version variable</Tooltip.Content>
								</Tooltip.Root>
							{/if}
						</Table.Cell>
						<Table.Cell>
							<span class="flex items-center gap-2">
								<SeverityStrip counts={p.severities} />
								{#if p.emergency}<FixNowBadge />{/if}
								{#if p.knownExploited}<ExploitedBadge />{/if}
							</span>
						</Table.Cell>
						<Table.Cell class="tabular-nums">{p.maxCvss ? p.maxCvss.toFixed(1) : '—'}</Table.Cell>
						<Table.Cell class="font-mono text-xs">
							{#if p.reboot}
								<Tooltip.Root>
									<Tooltip.Trigger class="font-sans font-medium text-amber-700 dark:text-amber-400"
										>Reboot</Tooltip.Trigger
									>
									<Tooltip.Content>Kernel {p.reboot} is installed: reboot to run it</Tooltip.Content
									>
								</Tooltip.Root>
							{:else}
								{p.updateTo || '—'}
							{/if}
						</Table.Cell>
					</Table.Row>
					{#if open}
						<Table.Row class="bg-muted/30 hover:bg-muted/30">
							<Table.Cell></Table.Cell>
							<Table.Cell colspan={5} class="pt-0 pb-2">
								{@render cves(p)}
							</Table.Cell>
						</Table.Row>
					{/if}
				{:else}
					<Table.Row>
						<Table.Cell colspan={6} class="h-24 text-center text-muted-foreground">
							{packages.length ? 'No package matches.' : 'No vulnerabilities found.'}
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

{#snippet cves(p: PackageRow)}
	{@const cvePageIndex = cvePage(p)}
	{@const first = cvePageIndex * cvePageSize}
	<Table.Root class="text-xs">
		<Table.Header>
			<Table.Row class="hover:bg-transparent">
				<Table.Head class="h-8">Vulnerability</Table.Head>
				<Table.Head class="h-8">Severity</Table.Head>
				<Table.Head class="h-8">CVSS</Table.Head>
				<Table.Head class="h-8">Fixed in</Table.Head>
				<Table.Head class="h-8">First seen</Table.Head>
				<Table.Head class="h-8">State</Table.Head>
				<Table.Head class="h-8"></Table.Head>
			</Table.Row>
		</Table.Header>
		<Table.Body>
			{#each p.cves.slice(first, first + cvePageSize) as c (c.id)}
				{@const sev = severityLook(c.severity)}
				{@const state = stateLooks[c.state]}
				<Table.Row class="hover:bg-transparent">
					<Table.Cell class="py-1">
						<span class="flex items-center gap-1.5">
							{#if c.url}
								<!-- eslint-disable svelte/no-navigation-without-resolve -- external advisory -->
								<a
									href={c.url}
									target="_blank"
									rel="noreferrer"
									class="inline-flex items-center gap-1 font-medium text-primary underline decoration-muted-foreground/40 underline-offset-4 hover:decoration-foreground"
									aria-label="{c.id} (opens in a new tab)"
									>{c.id}<ExternalLinkIcon class="size-3 text-muted-foreground" /></a
								>
								<!-- eslint-enable svelte/no-navigation-without-resolve -->
							{:else}
								<span class="font-medium">{c.id}</span>
							{/if}
							{#if c.emergency}<FixNowBadge />{/if}
							{#if c.knownExploited}<ExploitedBadge />{/if}
						</span>
					</Table.Cell>
					<Table.Cell class="py-1">
						<Badge class={cn('rounded-sm', sev.class)}>{sev.label}</Badge>
					</Table.Cell>
					<Table.Cell class="py-1 tabular-nums">{c.cvss ? c.cvss.toFixed(1) : '—'}</Table.Cell>
					<Table.Cell class="max-w-48 truncate py-1 font-mono">
						{c.fixVersions.length ? c.fixVersions.join(', ') : '—'}
					</Table.Cell>
					<Table.Cell class="py-1 text-muted-foreground"
						><TimeAgo time={c.firstSeenAt} /></Table.Cell
					>
					<Table.Cell class="py-1">
						{#if c.risk}
							<Tooltip.Root>
								<Tooltip.Trigger>
									<Badge variant="outline" class={state.class}>
										Accepted until {c.risk.expiresAt.slice(0, 10)}
									</Badge>
								</Tooltip.Trigger>
								<Tooltip.Content class="max-w-80 whitespace-pre-line">
									{c.risk.reason}
									<span class="block pt-1 opacity-70">
										{c.risk.acceptedBy || 'Deleted user'} · {formatUTC(c.risk.acceptedAt)}
									</span>
								</Tooltip.Content>
							</Tooltip.Root>
						{:else}
							<Badge variant="outline" class={state.class}>{state.label}</Badge>
						{/if}
					</Table.Cell>
					<Table.Cell class="py-1 text-right">
						{#if c.risk}
							<Button variant="ghost" size="sm" class="h-7" onclick={() => onaccept(p, c)}>
								Change
							</Button>
							<Button variant="ghost" size="sm" class="h-7" onclick={() => onwithdraw(p, c)}>
								Withdraw
							</Button>
						{:else if c.state !== 'oldKernel'}
							<Button variant="outline" size="sm" class="h-7" onclick={() => onaccept(p, c)}>
								Accept
							</Button>
						{/if}
					</Table.Cell>
				</Table.Row>
			{/each}
		</Table.Body>
	</Table.Root>
	{#if p.cves.length > cvePageSize}
		<div class="flex items-center justify-end gap-1 pt-1">
			<span class="mr-1 text-xs text-muted-foreground tabular-nums">
				{first + 1}–{Math.min(first + cvePageSize, p.cves.length)} of {p.cves.length}
			</span>
			<Button
				variant="ghost"
				size="icon"
				class="size-7"
				aria-label="Previous vulnerabilities"
				disabled={cvePageIndex === 0}
				onclick={() => cvePages.set(key(p), cvePageIndex - 1)}
			>
				<ChevronLeftIcon />
			</Button>
			<Button
				variant="ghost"
				size="icon"
				class="size-7"
				aria-label="Next vulnerabilities"
				disabled={first + cvePageSize >= p.cves.length}
				onclick={() => cvePages.set(key(p), cvePageIndex + 1)}
			>
				<ChevronRightIcon />
			</Button>
		</div>
	{/if}
{/snippet}
