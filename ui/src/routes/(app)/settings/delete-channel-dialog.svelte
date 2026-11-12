<script lang="ts">
	import { toast } from 'svelte-sonner';
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.js';
	import { api, ApiError, type ChannelView } from '#lib/api.js';

	let {
		channel,
		onclose,
		ondone
	}: { channel: ChannelView; onclose: () => void; ondone: () => Promise<unknown> } = $props();

	let deleting = $state(false);

	const receives = $derived(
		[channel.emergencies && 'emergencies', channel.digest && 'the digest']
			.filter(Boolean)
			.join(' and ') || 'nothing'
	);

	async function remove(e: MouseEvent) {
		e.preventDefault();
		if (deleting) return;
		deleting = true;
		try {
			await api('DELETE', `/settings/channels/${channel.id}`);
			toast.success(`${channel.name} deleted`);
			await ondone();
			onclose();
		} catch (err) {
			toast.error(err instanceof ApiError ? err.message : 'Something went wrong.');
		} finally {
			deleting = false;
		}
	}
</script>

<AlertDialog.Root open onOpenChange={(open) => !open && onclose()}>
	<AlertDialog.Content>
		<AlertDialog.Header>
			<AlertDialog.Title>Delete {channel.name}?</AlertDialog.Title>
			<AlertDialog.Description>
				{channel.typeLabel} · it receives {receives}.
			</AlertDialog.Description>
		</AlertDialog.Header>
		<AlertDialog.Footer>
			<AlertDialog.Cancel>Cancel</AlertDialog.Cancel>
			<AlertDialog.Action variant="destructive" disabled={deleting} onclick={remove}
				>Delete</AlertDialog.Action
			>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
