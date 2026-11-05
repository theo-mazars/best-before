<script lang="ts">
	import { invalidate, replaceState } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';
	import CpuIcon from '@lucide/svelte/icons/cpu';
	import DatabaseIcon from '@lucide/svelte/icons/database';
	import HourglassIcon from '@lucide/svelte/icons/hourglass';
	import ServerOffIcon from '@lucide/svelte/icons/server-off';
	import TriangleAlertIcon from '@lucide/svelte/icons/triangle-alert';
	import * as Alert from '#lib/components/ui/alert/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import * as Tabs from '#lib/components/ui/tabs/index.js';
	import * as Tooltip from '#lib/components/ui/tooltip/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import Hint from '#lib/components/hint.svelte';
	import PageHeader from '#lib/components/page-header.svelte';
	import StatusBadge from '#lib/components/status-badge.svelte';
	import TimeAgo from '#lib/components/time-ago.svelte';
	import type { Cve, PackageRow } from '#lib/api.js';
	import { clock } from '#lib/clock.svelte.js';
	import { formatUptime, formatUTC, timeAgo } from '#lib/date.js';
	import { noFilter, type PackageFilter } from '#lib/packages.js';
	import { statusRule } from '#lib/status.js';
	import AcceptRiskDialog from './accept-risk-dialog.svelte';
	import ImagesList from './images-list.svelte';
	import PackagesTable from './packages-table.svelte';
	import UpdatesTable from './updates-table.svelte';
	import WithdrawRiskDialog from './withdraw-risk-dialog.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const v = $derived(data.server);
	const overview = resolve('/(app)');

	const tabs = ['vulnerabilities', 'updates', 'images'] as const;
	type Tab = (typeof tabs)[number];
	const fromURL = page.url.searchParams.get('tab') as Tab;
	let tab = $state<Tab>(tabs.includes(fromURL) ? fromURL : 'vulnerabilities');

	function show(t: Tab) {
		tab = t;
		const path = resolve('/(app)/servers/[id]', { id: page.params.id ?? '' });
		// eslint-disable-next-line svelte/no-navigation-without-resolve -- the same page, with its query
		replaceState(t === 'vulnerabilities' ? path : `${path}?tab=${t}`, page.state);
	}

	let filter = $state<PackageFilter>({ ...noFilter });
	let accepting = $state<{ pkg: PackageRow; cve: Cve } | null>(null);
	let withdrawing = $state<{ pkg: PackageRow; cve: Cve } | null>(null);

	const refresh = () => invalidate('app:server');

	// Kernels installed but not running: newer ones wait for a reboot, older
	// ones can be removed.
	const kernelNotes = $derived.by(() => {
		const list = (newer: boolean) =>
			(v?.oldKernels ?? [])
				.filter((k) => k.newer === newer)
				.map(
					(k) =>
						`${k.abi} (${k.vulnerabilities} ${k.vulnerabilities === 1 ? 'vulnerability' : 'vulnerabilities'})`
				)
				.join(', ');
		const notes = [];
		const newer = list(true);
		if (newer)
			notes.push({
				title: 'Newer kernel installed, waiting for a reboot',
				list: newer,
				hint: 'Not running yet, so not counted: the running kernel counts until the server reboots.'
			});
		const older = list(false);
		if (older)
			notes.push({
				title: 'Old kernel installed',
				list: older,
				hint: 'Not running, so not counted. Removing old kernels (apt autoremove) clears the list.'
			});
		return notes;
	});
	// The latest report waits for matching: what is shown is older.
	const pending = $derived(v?.report ? !v.report.matched : false);

	// covering lists the packages a risk decision applies to: every one with
	// the vulnerability on the same host or image.
	function covering(d: { pkg: PackageRow; cve: Cve }) {
		return (v?.packages ?? []).filter(
			(p) => p.target === d.pkg.target && p.cves.some((c) => c.id === d.cve.id)
		);
	}
	// Vulnerabilities count once per host or image, as on the overview.
	const cveCount = $derived(
		v ? Object.values(v.server.severities).reduce((n, c) => n + c.open + c.muted, 0) : 0
	);

	const stats = $derived(
		v
			? [
					{ label: 'To fix now', value: v.server.emergencies },
					{ label: 'Known exploited', value: v.server.knownExploited },
					{ label: 'Critical', value: v.server.critical },
					{ label: 'Security updates', value: v.server.securityUpdates }
				]
			: []
	);
</script>

<PageHeader
	title={v?.server.hostname ?? 'Server'}
	parent={{ href: overview, label: 'Overview' }}
	{refresh}
>
	{#snippet actions()}
		{#if v?.report?.matched}
			<Tooltip.Root>
				<Tooltip.Trigger class="p-2 text-muted-foreground" aria-label="Last check">
					<DatabaseIcon class="size-4" />
				</Tooltip.Trigger>
				<Tooltip.Content>
					Checked {timeAgo(v.report.matchedAt, clock.now)} against the database built {formatUTC(
						v.report.dbBuilt
					)}
				</Tooltip.Content>
			</Tooltip.Root>
		{/if}
	{/snippet}
</PageHeader>

<div class="flex flex-col gap-4 p-4">
	{#if !v}
		<Empty.Root class="border">
			<Empty.Header>
				<Empty.Media variant="icon"><ServerOffIcon /></Empty.Media>
				<Empty.Title>No such server</Empty.Title>
			</Empty.Header>
			<Empty.Content>
				<Button href={overview}>Back to the overview</Button>
			</Empty.Content>
		</Empty.Root>
	{:else}
		{#if v.db.lastError}
			<Alert.Root variant="destructive">
				<TriangleAlertIcon />
				<Alert.Title>Vulnerability database update failed</Alert.Title>
				<Alert.Description>{v.db.lastError}</Alert.Description>
			</Alert.Root>
		{:else if !v.db.ready}
			<Alert.Root>
				<DatabaseIcon />
				<Alert.Title>Vulnerability database not downloaded yet</Alert.Title>
			</Alert.Root>
		{/if}

		{#if v.server.problems.length}
			<Alert.Root class="text-amber-800 dark:text-amber-400">
				<TriangleAlertIcon />
				<Alert.Title>Report incomplete</Alert.Title>
				<Alert.Description class="text-amber-800/90 dark:text-amber-400/90">
					<ul>
						{#each v.server.problems as problem, i (i)}<li>{problem}</li>{/each}
					</ul>
				</Alert.Description>
			</Alert.Root>
		{/if}

		{#if !v.host}
			<Empty.Root class="border">
				<Empty.Header>
					<Empty.Media variant="icon"><HourglassIcon /></Empty.Media>
					<Empty.Title>Waiting for the first report</Empty.Title>
				</Empty.Header>
			</Empty.Root>
		{:else}
			<div class="grid gap-4 lg:grid-cols-[1fr_22rem]">
				<div class="grid grid-cols-2 gap-4 md:grid-cols-3">
					<Card.Root size="sm">
						<Card.Header>
							<Card.Description class="flex items-center gap-1">
								Status <Hint text={statusRule} />
							</Card.Description>
							<Card.Title><StatusBadge status={v.server.status} /></Card.Title>
						</Card.Header>
					</Card.Root>
					{#each stats as stat (stat.label)}
						<Card.Root size="sm">
							<Card.Header>
								<Card.Description>{stat.label}</Card.Description>
								<Card.Title class="text-2xl tabular-nums">{stat.value}</Card.Title>
							</Card.Header>
						</Card.Root>
					{/each}
					<Card.Root size="sm">
						<Card.Header>
							<Card.Description>Last report</Card.Description>
							<Card.Title class="text-base font-medium">
								<TimeAgo time={v.server.lastReportAt} />
							</Card.Title>
						</Card.Header>
					</Card.Root>
				</div>
				<Card.Root size="sm">
					<Card.Content>
						<dl class="grid grid-cols-[6rem_1fr] gap-x-3 gap-y-1.5 text-sm">
							<dt class="text-muted-foreground">System</dt>
							<dd>{v.host.os || '—'}</dd>
							<dt class="text-muted-foreground">Kernel</dt>
							<dd class="font-mono text-xs leading-5">{v.host.kernel || '—'}</dd>
							<dt class="text-muted-foreground">Uptime</dt>
							<dd>{formatUptime(v.host.uptimeSeconds)}</dd>
							<dt class="text-muted-foreground">Reboot</dt>
							<dd>
								{#if v.host.rebootRequired}
									<span class="text-amber-700 dark:text-amber-400">Required</span>
									{#if v.host.rebootPackages.length}
										<Hint text={'Asked for by ' + v.host.rebootPackages.join(', ')} />
									{/if}
								{:else}
									<span class="text-muted-foreground">Not required</span>
								{/if}
							</dd>
							<dt class="text-muted-foreground">Agent</dt>
							<dd>{v.host.agentVersion || '—'}</dd>
						</dl>
					</Card.Content>
				</Card.Root>
			</div>

			{#each kernelNotes as note (note.title)}
				<Alert.Root class="text-muted-foreground">
					<CpuIcon />
					<Alert.Title class="flex items-center gap-1.5">
						{note.title}: {note.list}
						<Hint text={note.hint} />
					</Alert.Title>
				</Alert.Root>
			{/each}

			{#if pending}
				<Alert.Root
					class="border-amber-500/50 bg-amber-500/10 text-amber-800 dark:border-amber-500/40 dark:text-amber-400"
				>
					<HourglassIcon />
					<Alert.Title>
						{#if v.report?.matchedAt}
							Showing the vulnerabilities found {timeAgo(v.report.matchedAt, clock.now)}: the latest
							report, received {timeAgo(v.report.receivedAt, clock.now)}, isn't checked yet.
						{:else}
							The report isn't checked against the vulnerability database yet.
						{/if}
					</Alert.Title>
				</Alert.Root>
			{/if}

			<Tabs.Root value={tab} onValueChange={(t) => show(t as Tab)}>
				<Tabs.List>
					<Tabs.Trigger value="vulnerabilities">
						Vulnerabilities
						<span class="text-xs text-muted-foreground tabular-nums">{cveCount}</span>
					</Tabs.Trigger>
					<Tabs.Trigger value="updates">
						Updates
						<span class="text-xs text-muted-foreground tabular-nums">{v.upgradable.length}</span>
					</Tabs.Trigger>
					<Tabs.Trigger value="images">
						Images
						<span class="text-xs text-muted-foreground tabular-nums">{v.images.length}</span>
					</Tabs.Trigger>
				</Tabs.List>
				<Tabs.Content value="vulnerabilities" class={pending ? 'pt-2 opacity-60' : 'pt-2'}>
					<PackagesTable
						packages={v.packages}
						bind:filter
						onaccept={(pkg, cve) => (accepting = { pkg, cve })}
						onwithdraw={(pkg, cve) => (withdrawing = { pkg, cve })}
					/>
				</Tabs.Content>
				<Tabs.Content value="updates" class="pt-2">
					<UpdatesTable updates={v.upgradable} listsPublishedAt={v.host.listsPublishedAt} />
				</Tabs.Content>
				<Tabs.Content value="images" class={pending ? 'pt-2 opacity-60' : 'pt-2'}>
					<ImagesList
						images={v.images}
						onshow={(where) => {
							filter = { ...noFilter, where, showMuted: true };
							show('vulnerabilities');
						}}
					/>
				</Tabs.Content>
			</Tabs.Root>
		{/if}

		{#if accepting}
			<AcceptRiskDialog
				serverId={v.server.id}
				pkg={accepting.pkg}
				covered={covering(accepting)}
				cve={accepting.cve}
				limits={v.risk}
				onclose={() => (accepting = null)}
				ondone={refresh}
			/>
		{/if}
		{#if withdrawing}
			<WithdrawRiskDialog
				serverId={v.server.id}
				pkg={withdrawing.pkg}
				covered={covering(withdrawing)}
				cve={withdrawing.cve}
				onclose={() => (withdrawing = null)}
				ondone={refresh}
			/>
		{/if}
	{/if}
</div>
