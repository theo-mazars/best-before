<script lang="ts">
	import * as Tooltip from '#lib/components/ui/tooltip/index.js';
	import { stripSeverities, type SeverityCount, type StripSeverity } from '#lib/api.js';
	import { cn } from '#lib/utils.js';

	let { counts }: { counts: Record<StripSeverity, SeverityCount> } = $props();

	const boxes: Record<StripSeverity, { letter: string; name: string; class: string }> = {
		critical: { letter: 'C', name: 'Critical', class: 'bg-red-700 text-white' },
		high: { letter: 'H', name: 'High', class: 'bg-orange-600 text-white' },
		medium: { letter: 'M', name: 'Medium', class: 'bg-amber-400 text-amber-950' },
		low: { letter: 'L', name: 'Low', class: 'bg-yellow-200 text-yellow-950' },
		unknown: { letter: 'U', name: 'Unknown or negligible', class: 'bg-neutral-400 text-white' }
	};
</script>

<div class="flex w-fit gap-px overflow-hidden rounded-md">
	{#each stripSeverities as sev (sev)}
		{@const c = counts[sev]}
		{@const box = boxes[sev]}
		<Tooltip.Root>
			<Tooltip.Trigger
				class={cn(
					'flex h-6 min-w-9 items-center justify-center gap-0.5 px-1.5 text-xs font-medium tabular-nums',
					c.open ? box.class : 'bg-muted text-muted-foreground',
					!c.open && !c.muted && 'text-muted-foreground/50'
				)}
				aria-label="{box.name}: {c.open} open, {c.muted} muted"
			>
				<span>{c.open || c.muted}</span><span class="opacity-70">{box.letter}</span>
			</Tooltip.Trigger>
			<Tooltip.Content>
				{box.name}: {c.open} open · {c.muted} no fix, accepted or below threshold
			</Tooltip.Content>
		</Tooltip.Root>
	{/each}
</div>
