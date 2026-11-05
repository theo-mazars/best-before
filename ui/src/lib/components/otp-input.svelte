<script lang="ts">
	import * as InputOTP from '#lib/components/ui/input-otp/index.js';
	import { cn } from '#lib/utils.js';

	let {
		value = $bindable(''),
		id,
		large = false,
		oncomplete
	}: {
		value?: string;
		id?: string;
		large?: boolean;
		oncomplete?: (value: string) => void;
	} = $props();

	const slot = $derived(cn(large && 'size-12 text-xl'));
</script>

<InputOTP.Root
	{id}
	maxlength={6}
	bind:value
	pattern="^\d*$"
	autocomplete="one-time-code"
	onComplete={oncomplete}
	class="justify-center"
>
	{#snippet children({ cells })}
		<InputOTP.Group>
			{#each cells.slice(0, 3) as cell (cell)}
				<InputOTP.Slot {cell} class={slot} />
			{/each}
		</InputOTP.Group>
		<InputOTP.Separator />
		<InputOTP.Group>
			{#each cells.slice(3) as cell (cell)}
				<InputOTP.Slot {cell} class={slot} />
			{/each}
		</InputOTP.Group>
	{/snippet}
</InputOTP.Root>
