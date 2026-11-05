<script lang="ts">
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { statusLook } from '#lib/status.js';

	let { status }: { status: string } = $props();
	const look = $derived(statusLook(status));
</script>

<Badge variant="outline" class={look.class}>{look.label}</Badge>
