<script lang="ts">
	import { toast } from 'svelte-sonner';
	import * as AlertDialog from '#lib/components/ui/alert-dialog/index.js';
	import { api, ApiError, type Cve, type PackageRow } from '#lib/api.js';
	import WhereLabel from './where-label.svelte';

	let {
		serverId,
		pkg,
		covered,
		cve,
		onclose,
		ondone
	}: {
		serverId: string;
		pkg: PackageRow;
		// covered are the packages the decision applies to, pkg included.
		covered: PackageRow[];
		cve: Cve;
		onclose: () => void;
		ondone: () => Promise<unknown>;
	} = $props();

	let saving = $state(false);

	async function withdraw(e: MouseEvent) {
		e.preventDefault();
		if (saving) return;
		saving = true;
		try {
			await api('DELETE', `/servers/${serverId}/risk`, {
				target: pkg.target,
				vulnerability: cve.id
			});
			toast.success('Acceptance withdrawn');
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
		<AlertDialog.Header>
			<AlertDialog.Title>Withdraw the acceptance of {cve.id}?</AlertDialog.Title>
			<AlertDialog.Description>
				<span class="flex flex-wrap items-center gap-2">
					<WhereLabel where={pkg.where} />
					<span
						>{covered.map((p) => `${p.package} ${p.version}`).join(', ')} · it counts again at once.</span
					>
				</span>
			</AlertDialog.Description>
		</AlertDialog.Header>
		<AlertDialog.Footer>
			<AlertDialog.Cancel>Cancel</AlertDialog.Cancel>
			<AlertDialog.Action disabled={saving} onclick={withdraw}>Withdraw</AlertDialog.Action>
		</AlertDialog.Footer>
	</AlertDialog.Content>
</AlertDialog.Root>
