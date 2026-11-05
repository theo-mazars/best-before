<script lang="ts">
	import * as Tooltip from '#lib/components/ui/tooltip/index.js';
	import { clock } from '#lib/clock.svelte.js';
	import { formatUTC, timeAgo } from '#lib/date.js';

	let { time }: { time: string | null | undefined } = $props();
</script>

{#if time}
	<Tooltip.Root>
		<Tooltip.Trigger class="cursor-default">{timeAgo(time, clock.now)}</Tooltip.Trigger>
		<Tooltip.Content class="tabular-nums">{formatUTC(time)}</Tooltip.Content>
	</Tooltip.Root>
{:else}
	—
{/if}
