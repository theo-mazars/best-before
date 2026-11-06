<script lang="ts">
	import { invalidate } from '$app/navigation';
	import { toast } from 'svelte-sonner';
	import PageHeader from '#lib/components/page-header.svelte';
	import { api, ApiError, type Agent, type EnrolmentCode } from '#lib/api.js';
	import ActiveCodes from './active-codes.svelte';
	import AddServerButton from './add-server-button.svelte';
	import AddServerDialog from './add-server-dialog.svelte';
	import AgentsTable from './agents-table.svelte';
	import RevokeAgentDialog from './revoke-agent-dialog.svelte';
	import type { PageProps } from './$types';

	let { data }: PageProps = $props();
	const agents = $derived(data.agents.agents);
	const canEnrol = $derived(data.agents.canEnrol);

	let creating = $state(false);
	let code = $state<EnrolmentCode | null>(null);
	let revoking = $state<Agent | null>(null);

	const refresh = () => Promise.all([invalidate('app:agents'), invalidate('app:overview')]);

	async function addServer() {
		if (creating) return;
		creating = true;
		try {
			code = await api<EnrolmentCode>('POST', '/agents/codes');
		} catch (err) {
			toast.error(err instanceof ApiError ? err.message : 'Something went wrong.');
		} finally {
			creating = false;
		}
	}

	function closeCode() {
		code = null;
		refresh();
	}
</script>

<PageHeader title="Agents" refresh={() => invalidate('app:agents')} />

<div class="flex flex-col gap-4 p-4">
	<ActiveCodes codes={data.agents.codes} ondone={() => invalidate('app:agents')} />
	<AgentsTable {agents} onrevoke={(a) => (revoking = a)}>
		{#snippet add(link)}
			<AddServerButton {canEnrol} busy={creating} onclick={addServer} {link} />
		{/snippet}
	</AgentsTable>
</div>

{#if code}
	<AddServerDialog {code} onclose={closeCode} />
{/if}
{#if revoking}
	<RevokeAgentDialog agent={revoking} onclose={() => (revoking = null)} ondone={refresh} />
{/if}
