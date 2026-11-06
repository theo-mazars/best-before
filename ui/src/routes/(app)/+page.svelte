<script lang="ts">
	import { invalidate } from '$app/navigation';
	import { resolve } from '$app/paths';
	import DatabaseIcon from '@lucide/svelte/icons/database';
	import ServerIcon from '@lucide/svelte/icons/server';
	import TriangleAlertIcon from '@lucide/svelte/icons/triangle-alert';
	import * as Alert from '#lib/components/ui/alert/index.js';
	import * as Card from '#lib/components/ui/card/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import * as Tooltip from '#lib/components/ui/tooltip/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import PageHeader from '#lib/components/page-header.svelte';
	import { clock } from '#lib/clock.svelte.js';
	import { formatUTC, timeAgo } from '#lib/date.js';
	import { focuses, type Focus } from '#lib/status.js';
	import { cn } from '#lib/utils.js';
	import ServersTable from './servers-table.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const db = $derived(data.overview.db);
	const servers = $derived(data.overview.servers);

	const sum = (f: (s: (typeof servers)[number]) => number) => servers.reduce((n, s) => n + f(s), 0);
	let focus = $state<Focus | null>(null);
	const stats = $derived<{ focus: Focus; value: number; of?: number }[]>([
		{ focus: 'action', value: sum((s) => (s.status === 'OK' ? 0 : 1)), of: servers.length },
		{ focus: 'fixNow', value: sum((s) => s.emergencies) },
		{ focus: 'exploited', value: sum((s) => s.knownExploited) },
		{ focus: 'updates', value: sum((s) => s.securityUpdates) },
		{ focus: 'reboot', value: sum((s) => (s.rebootRequired ? 1 : 0)) }
	]);
</script>

<PageHeader title="Servers" refresh={() => invalidate('app:overview')}>
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
				<Empty.Media variant="icon"><ServerIcon /></Empty.Media>
				<Empty.Title>No server enrolled yet</Empty.Title>
			</Empty.Header>
			<Empty.Content>
				<Button href={resolve('/(app)/agents')}>Add an agent</Button>
			</Empty.Content>
		</Empty.Root>
	{:else}
		<div class="grid grid-cols-2 gap-4 md:grid-cols-3 xl:grid-cols-5">
			{#each stats as stat (stat.focus)}
				<button
					type="button"
					class={cn(
						'cursor-pointer rounded-xl text-left transition-shadow outline-none hover:ring-2 hover:ring-ring/30 focus-visible:ring-2 focus-visible:ring-ring/50',
						focus === stat.focus && 'ring-2 ring-ring/60 hover:ring-ring/60'
					)}
					aria-pressed={focus === stat.focus}
					onclick={() => (focus = focus === stat.focus ? null : stat.focus)}
				>
					<Card.Root size="sm" class="h-full">
						<Card.Header>
							<Card.Description>{focuses[stat.focus].label}</Card.Description>
							<Card.Title class="text-2xl tabular-nums">
								{stat.value}
								{#if stat.of !== undefined}
									<span class="text-sm font-normal text-muted-foreground">of {stat.of}</span>
								{/if}
							</Card.Title>
						</Card.Header>
					</Card.Root>
				</button>
			{/each}
		</div>
		<ServersTable {servers} bind:focus />
	{/if}
</div>
