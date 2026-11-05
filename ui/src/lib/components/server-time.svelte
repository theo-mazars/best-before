<script lang="ts">
	import { clock } from '#lib/clock.svelte.js';
	import { formatOffset } from '#lib/date.js';

	const time = $derived(new Date(clock.now + clock.offset * 60_000).toISOString().slice(11, 19));
</script>

<span
	class="hidden h-7 items-center gap-1.5 rounded-md border px-2 text-xs text-muted-foreground tabular-nums md:flex"
>
	Server time
	<span class="font-medium text-foreground">{time} {clock.zone}</span>
	<span class="text-border">|</span>
	{formatOffset(clock.offset)}
</span>
