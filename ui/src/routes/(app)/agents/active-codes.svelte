<script lang="ts">
	import { toast } from 'svelte-sonner';
	import TicketIcon from '@lucide/svelte/icons/ticket';
	import { Button } from '#lib/components/ui/button/index.js';
	import TimeAgo from '#lib/components/time-ago.svelte';
	import { api, ApiError, type ActiveCode } from '#lib/api.js';
	import { clock } from '#lib/clock.svelte.js';

	let { codes, ondone }: { codes: ActiveCode[]; ondone: () => Promise<unknown> } = $props();

	// Codes run out while the page is open: hide them without a refresh.
	const active = $derived(codes.filter((c) => Date.parse(c.expiresAt) > clock.now));
	let revoking = $state<string | null>(null);

	async function revoke(c: ActiveCode) {
		if (revoking) return;
		revoking = c.id;
		try {
			await api('DELETE', `/agents/codes/${c.id}`);
			toast.success('Enrolment code revoked');
			await ondone();
		} catch (err) {
			toast.error(err instanceof ApiError ? err.message : 'Something went wrong.');
		} finally {
			revoking = null;
		}
	}
</script>

{#if active.length}
	<section class="rounded-md border text-sm" aria-label="Active enrolment codes">
		<h2 class="flex items-center gap-2 border-b px-3 py-2 font-medium">
			<TicketIcon class="size-4 text-muted-foreground" />
			Active enrolment codes
			<span class="text-xs text-muted-foreground tabular-nums">{active.length}</span>
		</h2>
		<ul class="divide-y">
			{#each active as c (c.id)}
				<li class="flex flex-wrap items-center gap-x-3 gap-y-1 px-3 py-1.5">
					<span class="inline-flex flex-wrap items-center gap-1 text-muted-foreground">
						<span>Created</span>
						<TimeAgo time={c.createdAt} />
						{#if c.createdBy}
							<span>by</span>
							<span class="text-foreground">{c.createdBy}</span>
						{/if}
						<span>· expires</span>
						<TimeAgo time={c.expiresAt} />
					</span>
					<Button
						variant="destructive"
						size="sm"
						class="ml-auto h-7"
						disabled={revoking === c.id}
						onclick={() => revoke(c)}>Revoke</Button
					>
				</li>
			{/each}
		</ul>
	</section>
{/if}
