<script lang="ts">
	import type { Snippet } from 'svelte';
	import RefreshCwIcon from '@lucide/svelte/icons/refresh-cw';
	import * as Breadcrumb from '#lib/components/ui/breadcrumb/index.js';
	import * as Sidebar from '#lib/components/ui/sidebar/index.js';
	import * as Tooltip from '#lib/components/ui/tooltip/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Separator } from '#lib/components/ui/separator/index.js';
	import { cn } from '#lib/utils.js';
	import ServerTime from './server-time.svelte';

	let {
		title,
		refresh,
		actions
	}: { title: string; refresh?: () => Promise<unknown>; actions?: Snippet } = $props();

	let loading = $state(false);

	async function reload() {
		if (!refresh || loading) return;
		loading = true;
		try {
			await refresh();
		} finally {
			loading = false;
		}
	}
</script>

<svelte:head><title>{title} · Best Before</title></svelte:head>

<header class="flex h-12 shrink-0 items-center gap-2 border-b px-4">
	<Sidebar.Trigger class="-ml-1" />
	<Separator orientation="vertical" class="mr-2 data-[orientation=vertical]:h-4" />
	<Breadcrumb.Root>
		<Breadcrumb.List>
			<Breadcrumb.Item>
				<Breadcrumb.Page>{title}</Breadcrumb.Page>
			</Breadcrumb.Item>
		</Breadcrumb.List>
	</Breadcrumb.Root>
	<div class="ml-auto flex items-center gap-1">
		<ServerTime />
		{@render actions?.()}
		{#if refresh}
			<Tooltip.Root>
				<Tooltip.Trigger>
					{#snippet child({ props })}
						<Button {...props} variant="ghost" size="icon" aria-label="Refresh" onclick={reload}>
							<RefreshCwIcon class={cn(loading && 'animate-spin')} />
						</Button>
					{/snippet}
				</Tooltip.Trigger>
				<Tooltip.Content>Refresh</Tooltip.Content>
			</Tooltip.Root>
		{/if}
	</div>
</header>
