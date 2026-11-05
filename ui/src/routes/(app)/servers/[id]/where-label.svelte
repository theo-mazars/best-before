<script lang="ts">
	import ContainerIcon from '@lucide/svelte/icons/container';
	import ServerIcon from '@lucide/svelte/icons/server';
	import { cn } from '#lib/utils.js';

	let { where, class: className }: { where: string; class?: string } = $props();
	const host = $derived(where === 'host');
</script>

<span
	class={cn(
		'inline-flex max-w-full items-center gap-1 rounded-sm border px-1.5 py-0.5 text-xs font-medium',
		host
			? 'border-transparent bg-muted text-foreground'
			: 'border-sky-500/30 bg-sky-500/5 text-sky-800 dark:text-sky-300',
		className
	)}
	title={host ? 'Host' : `Image ${where}`}
>
	{#if host}
		<ServerIcon class="size-3 shrink-0" />
		Host
	{:else}
		<ContainerIcon class="size-3 shrink-0" />
		<span class="truncate">{where}</span>
	{/if}
</span>
