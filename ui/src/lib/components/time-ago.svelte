<script lang="ts">
	import * as Tooltip from '#lib/components/ui/tooltip/index.js';
	import { clock } from '#lib/clock.svelte.js';
	import { formatUTC, timeAgo } from '#lib/date.js';

	let { time, detail }: { time: string | null | undefined; detail?: string } = $props();
</script>

{#if time}
	<Tooltip.Root>
		<Tooltip.Trigger class="cursor-default">{timeAgo(time, clock.now)}</Tooltip.Trigger>
		<Tooltip.Content class="tabular-nums"
			>{formatUTC(time)}{#if detail}&nbsp;· {detail}{/if}</Tooltip.Content
		>
	</Tooltip.Root>
{:else}
	—
{/if}
