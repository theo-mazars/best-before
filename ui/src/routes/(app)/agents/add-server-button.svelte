<script lang="ts">
	import PlusIcon from '@lucide/svelte/icons/plus';
	import * as Tooltip from '#lib/components/ui/tooltip/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { cn } from '#lib/utils.js';

	let {
		canEnrol,
		busy,
		onclick,
		link = false
	}: { canEnrol: boolean; busy: boolean; onclick: () => void; link?: boolean } = $props();

	const variant = $derived(link ? 'link' : 'default');
	const label = $derived(link ? 'Add a server' : 'Add server');
</script>

{#if canEnrol}
	<Button {variant} size="sm" class={cn(link ? 'h-auto p-0' : 'h-8')} disabled={busy} {onclick}>
		{#if !link}<PlusIcon />{/if}{label}
	</Button>
{:else}
	<Tooltip.Root>
		<Tooltip.Trigger>
			{#snippet child({ props })}
				<Button
					{...props}
					{variant}
					size="sm"
					aria-disabled="true"
					class={cn('cursor-not-allowed opacity-50', link ? 'h-auto p-0' : 'h-8')}
				>
					{#if !link}<PlusIcon />{/if}{label}
				</Button>
			{/snippet}
		</Tooltip.Trigger>
		<Tooltip.Content>Set public_url in the dashboard configuration first</Tooltip.Content>
	</Tooltip.Root>
{/if}
