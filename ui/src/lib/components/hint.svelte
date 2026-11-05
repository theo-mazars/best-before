<script lang="ts">
	import InfoIcon from '@lucide/svelte/icons/info';
	import * as Tooltip from '#lib/components/ui/tooltip/index.js';

	let { text }: { text: string } = $props();
</script>

<Tooltip.Root>
	<Tooltip.Trigger class="text-muted-foreground" aria-label={text}>
		<InfoIcon class="size-3.5" />
	</Tooltip.Trigger>
	<Tooltip.Content class="max-w-64">{text}</Tooltip.Content>
</Tooltip.Root>
