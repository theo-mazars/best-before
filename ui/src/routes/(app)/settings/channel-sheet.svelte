<script lang="ts">
	import { untrack } from 'svelte';
	import { toast } from 'svelte-sonner';
	import Hint from '#lib/components/hint.svelte';
	import * as Alert from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import * as Sheet from '#lib/components/ui/sheet/index.js';
	import { Switch } from '#lib/components/ui/switch/index.js';
	import {
		api,
		ApiError,
		type ChannelField,
		type ChannelForm,
		type ChannelType,
		type ChannelView
	} from '#lib/api.js';

	let {
		type,
		channel,
		onclose,
		ondone
	}: {
		type: ChannelType;
		// channel is null for a new one.
		channel: ChannelView | null;
		onclose: () => void;
		ondone: () => Promise<unknown>;
	} = $props();

	const start = untrack(() => ({ type, channel }));
	const optionDefault = (f: ChannelField) => f.default || f.options?.[0] || '';

	let name = $state(start.channel?.name ?? '');
	let emergencies = $state(start.channel?.emergencies ?? true);
	let digest = $state(start.channel?.digest ?? start.type.digest);
	let values = $state<Record<string, string>>(
		Object.fromEntries(
			start.type.fields
				.filter((f) => !f.secret)
				.map((f) => [f.name, start.channel?.values[f.name] || (f.options ? optionDefault(f) : '')])
		)
	);
	// Secrets: what was typed, which saved ones get replaced, which removed.
	let secrets = $state<Record<string, string>>({});
	let replacing = $state<string[]>([]);
	let removing = $state<string[]>([]);

	let error = $state('');
	let field = $state('');
	let saving = $state(false);

	const isSaved = (f: ChannelField) => start.channel?.saved.includes(f.name) ?? false;
	const editable = (f: ChannelField) => !isSaved(f) || replacing.includes(f.name);

	function body(): ChannelForm {
		const v: Record<string, string> = { ...values };
		for (const f of start.type.fields) {
			if (f.secret && editable(f) && secrets[f.name]) v[f.name] = secrets[f.name];
		}
		return {
			...(start.channel ? {} : { type: start.type.name }),
			name,
			emergencies,
			digest: start.type.digest && digest,
			values: v,
			remove: removing
		};
	}
	const initial = JSON.stringify(untrack(body));
	const changed = $derived(!start.channel || JSON.stringify(body()) !== initial);

	const toggle = (list: string[], item: string, on: boolean) =>
		on ? [...list, item] : list.filter((x) => x !== item);

	function replace(f: ChannelField, on: boolean) {
		replacing = toggle(replacing, f.name, on);
		if (!on) delete secrets[f.name];
	}

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		if (saving || !changed) return;
		saving = true;
		error = field = '';
		try {
			if (start.channel) {
				await api('PUT', `/settings/channels/${start.channel.id}`, body());
			} else {
				await api('POST', '/settings/channels', body());
			}
			toast.success(`${name.trim()} saved`);
			await ondone();
			onclose();
		} catch (err) {
			error = err instanceof ApiError ? err.message : 'Something went wrong.';
			field = err instanceof ApiError ? (err.field ?? '') : '';
		} finally {
			saving = false;
		}
	}

	const title = start.channel ? start.channel.name : `New ${start.type.label} channel`;
</script>

{#snippet star()}
	<span class="-ml-1.5 text-destructive" aria-hidden="true">*</span>
{/snippet}

<Sheet.Root open onOpenChange={(open) => !open && onclose()}>
	<Sheet.Content class="w-full gap-0 sm:max-w-md">
		<form class="flex min-h-0 flex-1 flex-col" onsubmit={submit}>
			<Sheet.Header>
				<Sheet.Title class="flex items-center gap-1.5 pr-8">
					<span class="truncate">{title}</span>
					<Hint text={start.type.help} />
				</Sheet.Title>
				<Sheet.Description>{start.type.label}</Sheet.Description>
			</Sheet.Header>
			<div class="flex-1 overflow-y-auto px-4 pb-4">
				<Field.Group>
					{#if error && field !== 'name'}
						<Alert.Root variant="destructive">
							<Alert.Description>{error}</Alert.Description>
						</Alert.Root>
					{/if}
					<Field.Field data-invalid={field === 'name' || undefined}>
						<Field.Label for="channel-name">Name{@render star()}</Field.Label>
						<Input
							id="channel-name"
							maxlength={100}
							required
							placeholder="Ops team"
							aria-invalid={field === 'name' || undefined}
							bind:value={name}
						/>
						{#if field === 'name'}<Field.Error>{error}</Field.Error>{/if}
					</Field.Field>
					{#each start.type.fields as f (f.name)}
						{@const id = `channel-${f.name}`}
						<Field.Field>
							<Field.Label for={id}>
								{f.label}{#if f.required}{@render star()}{/if}{#if f.help}<Hint
										text={f.help}
									/>{/if}
							</Field.Label>
							{#if f.options}
								<Select.Root type="single" bind:value={values[f.name]}>
									<Select.Trigger {id} class="w-full">{values[f.name]}</Select.Trigger>
									<Select.Content>
										{#each f.options as o (o)}
											<Select.Item value={o} label={o}>{o}</Select.Item>
										{/each}
									</Select.Content>
								</Select.Root>
							{:else if !f.secret}
								<Input
									{id}
									autocomplete="off"
									placeholder={f.default || f.label}
									required={f.required}
									bind:value={values[f.name]}
								/>
							{:else if editable(f)}
								<div class="flex gap-2">
									<Input
										{id}
										type="password"
										autocomplete="off"
										placeholder={f.label}
										required={f.required}
										bind:value={secrets[f.name]}
									/>
									{#if isSaved(f)}
										<Button variant="ghost" size="sm" class="h-9" onclick={() => replace(f, false)}
											>Cancel</Button
										>
									{/if}
								</div>
							{:else}
								{@const removed = removing.includes(f.name)}
								<div class="flex gap-2">
									<Input
										{id}
										disabled
										class={removed ? 'line-through' : ''}
										placeholder={removed ? 'Removed' : '•••••• Saved'}
									/>
									{#if removed}
										<Button
											variant="ghost"
											size="sm"
											class="h-9"
											onclick={() => (removing = toggle(removing, f.name, false))}>Undo</Button
										>
									{:else}
										<Button variant="outline" size="sm" class="h-9" onclick={() => replace(f, true)}
											>Replace</Button
										>
										{#if !f.required}
											<Button
												variant="ghost"
												size="sm"
												class="h-9"
												onclick={() => (removing = toggle(removing, f.name, true))}>Remove</Button
											>
										{/if}
									{/if}
								</div>
							{/if}
						</Field.Field>
					{/each}
					<Field.Separator />
					<Field.Field orientation="horizontal">
						<Switch id="channel-emergencies" bind:checked={emergencies} />
						<Field.Label for="channel-emergencies" class="font-normal">
							Emergencies and stale servers
						</Field.Label>
					</Field.Field>
					{#if start.type.digest}
						<Field.Field orientation="horizontal">
							<Switch id="channel-digest" bind:checked={digest} />
							<Field.Label for="channel-digest" class="font-normal">Weekly digest</Field.Label>
						</Field.Field>
					{/if}
				</Field.Group>
			</div>
			<Sheet.Footer class="flex-row justify-end border-t">
				<Button variant="ghost" size="sm" onclick={onclose}>Cancel</Button>
				<Button type="submit" size="sm" disabled={!changed || saving}>Save</Button>
			</Sheet.Footer>
		</form>
	</Sheet.Content>
</Sheet.Root>
