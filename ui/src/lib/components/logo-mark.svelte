<script lang="ts">
	let { class: className = '' }: { class?: string } = $props();
</script>

<svg
	viewBox="0 0 24 24"
	fill="none"
	stroke="currentColor"
	stroke-width="2"
	stroke-linecap="round"
	stroke-linejoin="round"
	class={className}
	aria-hidden="true"
>
	<rect x="3" y="4.5" width="18" height="17" rx="3" />
	<path d="M8 2.5v4M16 2.5v4M3 10h18M9 15.5l2 2 4-4" />
</svg>
