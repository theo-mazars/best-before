<script lang="ts">
	import * as Table from '#lib/components/ui/table/index.js';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import TimeAgo from '#lib/components/time-ago.svelte';
	import type { ServerPage } from '#lib/api.js';

	let {
		updates,
		listsPublishedAt
	}: { updates: ServerPage['upgradable']; listsPublishedAt: string | null } = $props();

	let search = $state('');
	const rows = $derived.by(() => {
		const q = search.trim().toLowerCase();
		return q ? updates.filter((u) => u.name.toLowerCase().includes(q)) : updates;
	});
</script>

<div class="flex flex-col gap-3">
	<div class="flex flex-wrap items-center gap-2">
		<Input
			class="h-8 w-full sm:w-64"
			placeholder="Search packages"
			aria-label="Search packages"
			bind:value={search}
		/>
		<span class="ml-auto text-xs text-muted-foreground">
			Package lists published <TimeAgo time={listsPublishedAt} />
		</span>
	</div>
	<div class="overflow-x-auto rounded-md border">
		<Table.Root>
			<Table.Header>
				<Table.Row>
					<Table.Head>Package</Table.Head>
					<Table.Head>Installed</Table.Head>
					<Table.Head>Available</Table.Head>
					<Table.Head></Table.Head>
				</Table.Row>
			</Table.Header>
			<Table.Body>
				{#each rows as u (u.name)}
					<Table.Row>
						<Table.Cell class="font-medium">{u.name}</Table.Cell>
						<Table.Cell class="font-mono text-xs text-muted-foreground">{u.current}</Table.Cell>
						<Table.Cell class="font-mono text-xs">{u.candidate}</Table.Cell>
						<Table.Cell>
							{#if u.security}
								<Badge
									variant="outline"
									class="border-amber-500/40 text-amber-800 dark:text-amber-400">Security</Badge
								>
							{/if}
						</Table.Cell>
					</Table.Row>
				{:else}
					<Table.Row>
						<Table.Cell colspan={4} class="h-24 text-center text-muted-foreground">
							{updates.length ? 'No package matches.' : 'Nothing to update.'}
						</Table.Cell>
					</Table.Row>
				{/each}
			</Table.Body>
		</Table.Root>
	</div>
</div>
