<script lang="ts">
	import { toast } from 'svelte-sonner';
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import { api, ApiError, type Agent } from '#lib/api.js';

	let {
		agent,
		onclose,
		ondone
	}: { agent: Agent; onclose: () => void; ondone: () => Promise<unknown> } = $props();

	let typed = $state('');
	let saving = $state(false);
	const confirmed = $derived(typed.trim() === agent.hostname);

	async function revoke(e: Event) {
		e.preventDefault();
		if (saving || !confirmed) return;
		saving = true;
		try {
			await api('POST', `/agents/${agent.id}/revoke`);
			toast.success(`${agent.hostname} revoked`);
			await ondone();
			onclose();
		} catch (err) {
			toast.error(err instanceof ApiError ? err.message : 'Something went wrong.');
		} finally {
			saving = false;
		}
	}
</script>

<AlertDialog.Root open onOpenChange={(open) => !open && onclose()}>
	<AlertDialog.Content>
		<form class="contents" onsubmit={revoke}>
			<AlertDialog.Header>
				<AlertDialog.Title>Revoke {agent.hostname}?</AlertDialog.Title>
				<AlertDialog.Description>
					Key <span class="font-mono">{agent.fingerprint}</span> · its reports are refused from now on.
				</AlertDialog.Description>
			</AlertDialog.Header>
			<Input
				bind:value={typed}
				placeholder={agent.hostname}
				aria-label="Type the server name to confirm"
				autocomplete="off"
				spellcheck={false}
			/>
			<AlertDialog.Footer>
				<AlertDialog.Cancel type="button">Cancel</AlertDialog.Cancel>
				<AlertDialog.Action
					type="submit"
					variant="destructive"
					disabled={!confirmed || saving}
					onclick={revoke}>Revoke</AlertDialog.Action
				>
			</AlertDialog.Footer>
		</form>
	</AlertDialog.Content>
</AlertDialog.Root>
