<script lang="ts">
	import { toast } from 'svelte-sonner';
	import CheckIcon from '@lucide/svelte/icons/check';
	import EllipsisIcon from '@lucide/svelte/icons/ellipsis';
	import PlusIcon from '@lucide/svelte/icons/plus';
	import TriangleAlertIcon from '@lucide/svelte/icons/triangle-alert';
	import TimeAgo from '#lib/components/time-ago.svelte';
	import * as Alert from '#lib/components/ui/alert/index.js';
	import { Badge } from '#lib/components/ui/badge/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.js';
	import * as Table from '#lib/components/ui/table/index.js';
	import * as Tooltip from '#lib/components/ui/tooltip/index.js';
	import {
		api,
		ApiError,
		type ChannelType,
		type ChannelView,
		type SettingsPage
	} from '#lib/api.js';
	import ChannelSheet from './channel-sheet.svelte';
	import DeleteChannelDialog from './delete-channel-dialog.svelte';

	let { settings, refresh }: { settings: SettingsPage; refresh: () => Promise<unknown> } = $props();

	const channels = $derived([...settings.channels].sort((a, b) => a.name.localeCompare(b.name)));
	const noEmergencies = $derived(!settings.channels.some((c) => c.emergencies));

	let editing = $state<{ type: ChannelType; channel: ChannelView | null } | null>(null);
	let deleting = $state<ChannelView | null>(null);
	let testing = $state('');

	function edit(c: ChannelView) {
		const type = settings.types.find((t) => t.name === c.type);
		if (type) editing = { type, channel: c };
		else toast.error(c.problem ?? 'Unknown kind of channel.');
	}

	async function test(c: ChannelView) {
		if (testing) return;
		testing = c.id;
		try {
			await api('POST', `/settings/channels/${c.id}/test`);
			toast.success(`Test sent to ${c.name}`);
		} catch (err) {
			toast.error(err instanceof ApiError ? err.message : 'Something went wrong.');
		} finally {
			testing = '';
		}
	}
</script>

{#snippet addMenu(link: boolean)}
	<DropdownMenu.Root>
		<DropdownMenu.Trigger>
			{#snippet child({ props })}
				{#if link}
					<Button {...props} variant="link" size="sm" class="h-auto p-0">Add a channel</Button>
				{:else}
					<Button {...props} size="sm" class="h-8"><PlusIcon />Add channel</Button>
				{/if}
			{/snippet}
		</DropdownMenu.Trigger>
		<DropdownMenu.Content align={link ? 'center' : 'end'}>
			{#each settings.types as t (t.name)}
				<DropdownMenu.Item onSelect={() => (editing = { type: t, channel: null })}>
					{t.label}
				</DropdownMenu.Item>
			{/each}
		</DropdownMenu.Content>
	</DropdownMenu.Root>
{/snippet}

{#snippet yes(on: boolean)}
	{#if on}<CheckIcon class="size-4" aria-label="Yes" />{:else}<span class="text-muted-foreground"
			>–</span
		>{/if}
{/snippet}

<div class="flex flex-col gap-3">
	{#if noEmergencies}
		<Alert.Root class="text-amber-800 dark:text-amber-400">
			<TriangleAlertIcon />
			<Alert.Title>No channel receives emergencies</Alert.Title>
		</Alert.Root>
	{/if}
	{#if settings.publicUrlMissing}
		<Alert.Root class="text-amber-800 dark:text-amber-400">
			<TriangleAlertIcon />
			<Alert.Title>Set public_url so notifications link to the dashboard</Alert.Title>
		</Alert.Root>
	{/if}
	<div class="flex items-center">
		<div class="ml-auto">{@render addMenu(false)}</div>
	</div>
	<div class="overflow-x-auto rounded-md border">
		<Table.Root>
			<Table.Header>
				<Table.Row>
					<Table.Head>Name</Table.Head>
					<Table.Head>Kind</Table.Head>
					<Table.Head>Emergencies</Table.Head>
					<Table.Head>Digest</Table.Head>
					<Table.Head>Updated</Table.Head>
					<Table.Head class="w-10"><span class="sr-only">Actions</span></Table.Head>
				</Table.Row>
			</Table.Header>
			<Table.Body>
				{#each channels as c (c.id)}
					<Table.Row>
						<Table.Cell class="font-medium">
							<div class="flex items-center gap-2">
								<button type="button" class="hover:underline" onclick={() => edit(c)}
									>{c.name}</button
								>
								{#if c.problem}
									<Tooltip.Root>
										<Tooltip.Trigger>
											<Badge variant="destructive">Cannot send</Badge>
										</Tooltip.Trigger>
										<Tooltip.Content class="max-w-64">{c.problem}</Tooltip.Content>
									</Tooltip.Root>
								{/if}
							</div>
						</Table.Cell>
						<Table.Cell>{c.typeLabel}</Table.Cell>
						<Table.Cell>{@render yes(c.emergencies)}</Table.Cell>
						<Table.Cell>{@render yes(c.digest)}</Table.Cell>
						<Table.Cell class="text-muted-foreground"><TimeAgo time={c.updatedAt} /></Table.Cell>
						<Table.Cell>
							<DropdownMenu.Root>
								<DropdownMenu.Trigger>
									{#snippet child({ props })}
										<Button
											{...props}
											variant="ghost"
											size="icon-sm"
											aria-label="Actions for {c.name}"
										>
											<EllipsisIcon />
										</Button>
									{/snippet}
								</DropdownMenu.Trigger>
								<DropdownMenu.Content align="end">
									<DropdownMenu.Item disabled={!!testing} onSelect={() => test(c)}>
										Send test
									</DropdownMenu.Item>
									<DropdownMenu.Item onSelect={() => edit(c)}>Edit</DropdownMenu.Item>
									<DropdownMenu.Separator />
									<DropdownMenu.Item variant="destructive" onSelect={() => (deleting = c)}>
										Delete
									</DropdownMenu.Item>
								</DropdownMenu.Content>
							</DropdownMenu.Root>
						</Table.Cell>
					</Table.Row>
				{:else}
					<Table.Row>
						<Table.Cell colspan={6} class="h-24 text-center text-muted-foreground">
							No channel yet · {@render addMenu(true)}
						</Table.Cell>
					</Table.Row>
				{/each}
			</Table.Body>
		</Table.Root>
	</div>
</div>

{#if editing}
	<ChannelSheet
		type={editing.type}
		channel={editing.channel}
		onclose={() => (editing = null)}
		ondone={refresh}
	/>
{/if}
{#if deleting}
	<DeleteChannelDialog channel={deleting} onclose={() => (deleting = null)} ondone={refresh} />
{/if}
