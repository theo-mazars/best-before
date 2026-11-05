<script lang="ts">
	import { invalidate } from '$app/navigation';
	import DatabaseIcon from '@lucide/svelte/icons/database';
	import RefrigeratorIcon from '@lucide/svelte/icons/refrigerator';
	import TriangleAlertIcon from '@lucide/svelte/icons/triangle-alert';
	import * as Alert from '#lib/components/ui/alert/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import * as Tooltip from '#lib/components/ui/tooltip/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import PageHeader from '#lib/components/page-header.svelte';
	import { clock } from '#lib/clock.svelte.js';
	import { formatUTC, timeAgo } from '#lib/date.js';
	import ServersTable from './servers-table.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const db = $derived(data.overview.db);
	const servers = $derived(data.overview.servers);

	const sum = (f: (s: (typeof servers)[number]) => number) => servers.reduce((n, s) => n + f(s), 0);
	const stats = $derived([
		{
			label: 'Needing action',
			value: sum((s) => (s.status === 'OK' ? 0 : 1)),
			of: servers.length
		},
		{ label: 'To fix now', value: sum((s) => s.emergencies) },
		{ label: 'Known exploited', value: sum((s) => s.knownExploited) },
		{ label: 'Security updates', value: sum((s) => s.securityUpdates) },
		{ label: 'Reboots pending', value: sum((s) => (s.rebootRequired ? 1 : 0)) }
	]);
</script>

<PageHeader title="Overview" refresh={() => invalidate('app:overview')}>
	{#snippet actions()}
		{#if db.ready}
			<Tooltip.Root>
				<Tooltip.Trigger class="p-2 text-muted-foreground" aria-label="Vulnerability database">
					<DatabaseIcon class="size-4" />
				</Tooltip.Trigger>
				<Tooltip.Content
					>Vulnerability database built {timeAgo(db.built, clock.now)} · {formatUTC(
						db.built
					)}</Tooltip.Content
				>
			</Tooltip.Root>
		{/if}
	{/snippet}
</PageHeader>

<div class="flex flex-col gap-4 p-4">
	{#if db.lastError}
		<Alert.Root variant="destructive">
			<TriangleAlertIcon />
			<Alert.Title>Vulnerability database update failed</Alert.Title>
			<Alert.Description>{db.lastError}</Alert.Description>
		</Alert.Root>
	{:else if !db.ready}
		<Alert.Root>
			<DatabaseIcon />
			<Alert.Title>Vulnerability database not downloaded yet</Alert.Title>
		</Alert.Root>
	{/if}

	{#if servers.length === 0}
		<Empty.Root class="border">
			<Empty.Header>
				<Empty.Media variant="icon"><RefrigeratorIcon /></Empty.Media>
				<Empty.Title>The fridge is empty</Empty.Title>
			</Empty.Header>
			<Empty.Content>
				<Button href="/agents" data-sveltekit-reload>Add a server</Button>
			</Empty.Content>
		</Empty.Root>
	{:else}
		<div class="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-5">
			{#each stats as stat (stat.label)}
				<Card.Root size="sm">
					<Card.Header>
						<Card.Description>{stat.label}</Card.Description>
						<Card.Title class="text-2xl tabular-nums">
							{stat.value}
							{#if stat.of !== undefined}
								<span class="text-sm font-normal text-muted-foreground">of {stat.of}</span>
							{/if}
						</Card.Title>
					</Card.Header>
				</Card.Root>
			{/each}
		</div>
		<ServersTable {servers} />
	{/if}
</div>
