<script lang="ts">
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { statusLook } from '#lib/status.js';

	let { status, look }: { status: string; look?: { label: string; class: string } } = $props();
	const shown = $derived(look ?? statusLook(status));
</script>

<Badge variant="outline" class={shown.class}>{shown.label}</Badge>
