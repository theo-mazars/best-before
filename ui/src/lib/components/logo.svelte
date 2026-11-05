<script lang="ts">
	import { cn } from '#lib/utils.js';
	import LogoMark from './logo-mark.svelte';

	let { class: className = '' }: { class?: string } = $props();
</script>

<span class={cn('flex items-center gap-2 font-semibold', className)}>
	<LogoMark class="size-6" />
	Best Before
</span>
