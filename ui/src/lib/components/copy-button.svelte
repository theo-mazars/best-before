<script lang="ts">
	import CopyIcon from '@lucide/svelte/icons/copy';
	import CheckIcon from '@lucide/svelte/icons/check';
	import { Button } from '#lib/components/ui/button/index.js';

	let { text }: { text: string } = $props();
	let copied = $state(false);

	async function copy() {
		await navigator.clipboard.writeText(text);
		copied = true;
		setTimeout(() => (copied = false), 1500);
	}
</script>

<Button type="button" variant="ghost" size="icon-sm" aria-label="Copy" onclick={copy}>
	{#if copied}<CheckIcon />{:else}<CopyIcon />{/if}
</Button>
