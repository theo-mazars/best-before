<script lang="ts">
	import { invalidate, replaceState } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { page } from '$app/state';
	import * as Tabs from '#lib/components/ui/tabs/index.js';
	import PageHeader from '#lib/components/page-header.svelte';
	import AlertsTab from './alerts-tab.svelte';
	import ChannelsTab from './channels-tab.svelte';
	import DigestTab from './digest-tab.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const s = $derived(data.settings);

	const tabs = ['channels', 'alerts', 'digest'] as const;
	type Tab = (typeof tabs)[number];
	const fromURL = page.url.searchParams.get('tab') as Tab;
	let tab = $state<Tab>(tabs.includes(fromURL) ? fromURL : 'channels');

	function show(t: Tab) {
		tab = t;
		const path = resolve('/(app)/settings');
		// eslint-disable-next-line svelte/no-navigation-without-resolve -- the same page, with its query
		replaceState(t === 'channels' ? path : `${path}?tab=${t}`, page.state);
	}

	const refresh = () => invalidate('app:settings');
</script>

<PageHeader title="Settings" {refresh} />

<div class="flex flex-col gap-4 p-4">
	<Tabs.Root value={tab} onValueChange={(t) => show(t as Tab)}>
		<Tabs.List>
			<Tabs.Trigger value="channels">
				Channels
				<span class="text-xs text-muted-foreground tabular-nums">{s.channels.length}</span>
			</Tabs.Trigger>
			<Tabs.Trigger value="alerts">Alerts</Tabs.Trigger>
			<Tabs.Trigger value="digest">Digest</Tabs.Trigger>
		</Tabs.List>
		<Tabs.Content value="channels" class="pt-2">
			<ChannelsTab settings={s} {refresh} />
		</Tabs.Content>
		<Tabs.Content value="alerts" class="pt-2">
			{#key s.alerts}
				<AlertsTab settings={s} {refresh} />
			{/key}
		</Tabs.Content>
		<Tabs.Content value="digest" class="pt-2">
			{#key s.alerts}
				<DigestTab settings={s} {refresh} />
			{/key}
		</Tabs.Content>
	</Tabs.Root>
</div>
