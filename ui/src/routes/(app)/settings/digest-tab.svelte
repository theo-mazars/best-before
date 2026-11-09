<script lang="ts">
	import { untrack } from 'svelte';
	import { toast } from 'svelte-sonner';
	import SendIcon from '@lucide/svelte/icons/send';
	import Hint from '#lib/components/hint.svelte';
	import TimeAgo from '#lib/components/time-ago.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Checkbox } from '#lib/components/ui/checkbox/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import * as Select from '#lib/components/ui/select/index.js';
	import * as Tooltip from '#lib/components/ui/tooltip/index.js';
	import { api, ApiError, type SettingsPage } from '#lib/api.js';
	import { sameAlerts, saveAlerts, severityChoices } from './alerts.js';

	let { settings, refresh }: { settings: SettingsPage; refresh: () => Promise<unknown> } = $props();

	// The page rebuilds this tab when the saved settings change.
	const saved = untrack(() => settings.alerts);
	let form = $state(structuredClone(saved));
	let problem = $state<{ field: string; message: string } | null>(null);
	let saving = $state(false);
	let sending = $state(false);
	const changed = $derived(!sameAlerts(form, saved));
	const digestChannels = $derived(settings.channels.filter((c) => c.digest).length);

	const days = [
		{ value: 'off', label: 'Never' },
		...['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'].map(
			(label, i) => ({ value: String((i + 1) % 7), label })
		)
	];
	const newChoices = [{ value: '', label: 'Leave out' }, ...severityChoices];
	const zones = Intl.supportedValuesOf('timeZone');

	type Section =
		'digestEmergencies' | 'digestStale' | 'digestUpdates' | 'digestAccepted' | 'digestAllClear';
	const sections: { key: Section; label: string }[] = [
		{ key: 'digestEmergencies', label: 'Emergencies still open' },
		{ key: 'digestStale', label: 'Stale servers' },
		{ key: 'digestUpdates', label: 'Security updates waiting' },
		{ key: 'digestAccepted', label: 'Accepted risks expired or expiring within a week' },
		{ key: 'digestAllClear', label: 'Send even when all is clear' }
	];

	const labelOf = (list: { value: string; label: string }[], v: string) =>
		list.find((o) => o.value === v)?.label ?? '';

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		if (saving || !changed) return;
		saving = true;
		// Only this tab's fields: the emergency rules stay as saved.
		problem = await saveAlerts(
			{
				...form,
				emergencyKnownExploited: saved.emergencyKnownExploited,
				emergencyMinCvss: saved.emergencyMinCvss,
				reminderDays: saved.reminderDays
			},
			refresh
		);
		saving = false;
	}

	async function sendNow() {
		if (sending) return;
		sending = true;
		try {
			await api('POST', '/settings/digest');
			toast.success('Digest sent');
			await refresh();
		} catch (err) {
			toast.error(err instanceof ApiError ? err.message : 'Something went wrong.');
		} finally {
			sending = false;
		}
	}

	const invalid = (name: string) => problem?.field === name || undefined;
	const cannotSend = $derived(
		digestChannels === 0 ? 'No channel receives the digest' : changed ? 'Save first' : ''
	);
</script>

<form class="flex max-w-xl flex-col gap-4" onsubmit={submit}>
	<div class="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm">
		<span>
			<span class="text-muted-foreground">Next:</span>
			{#if settings.nextDigestAt}<TimeAgo time={settings.nextDigestAt} />{:else}Never{/if}
		</span>
		<span>
			<span class="text-muted-foreground">Last:</span>
			{#if settings.lastDigestAt}<TimeAgo time={settings.lastDigestAt} />{:else}Never{/if}
		</span>
		<Tooltip.Root disabled={!cannotSend}>
			<Tooltip.Trigger>
				{#snippet child({ props })}
					<Button
						{...props}
						variant="outline"
						size="sm"
						class="ml-auto h-8"
						aria-disabled={!!cannotSend || sending || undefined}
						onclick={() => !cannotSend && sendNow()}
					>
						<SendIcon />Send now
					</Button>
				{/snippet}
			</Tooltip.Trigger>
			<Tooltip.Content>{cannotSend}</Tooltip.Content>
		</Tooltip.Root>
	</div>

	<Field.Set>
		<Field.Legend>Schedule</Field.Legend>
		<div class="flex flex-wrap items-start gap-3">
			<Field.Field data-invalid={invalid('digestWeekday')} class="w-40">
				<Field.Label for="day">Day</Field.Label>
				<Select.Root
					type="single"
					bind:value={
						() => (form.digestWeekday === null ? 'off' : String(form.digestWeekday)),
						(v) => (form.digestWeekday = v === 'off' ? null : Number(v))
					}
				>
					<Select.Trigger id="day" class="w-full">
						{labelOf(days, form.digestWeekday === null ? 'off' : String(form.digestWeekday))}
					</Select.Trigger>
					<Select.Content>
						{#each days as d (d.value)}
							<Select.Item value={d.value} label={d.label}>{d.label}</Select.Item>
						{/each}
					</Select.Content>
				</Select.Root>
				{#if invalid('digestWeekday')}<Field.Error>{problem?.message}</Field.Error>{/if}
			</Field.Field>
			<Field.Field data-invalid={invalid('digestTime')} class="w-32">
				<Field.Label for="time">Time</Field.Label>
				<Input
					id="time"
					type="time"
					required
					aria-invalid={invalid('digestTime')}
					bind:value={form.digestTime}
				/>
				{#if invalid('digestTime')}<Field.Error>{problem?.message}</Field.Error>{/if}
			</Field.Field>
			<Field.Field data-invalid={invalid('digestTimezone')} class="w-56">
				<Field.Label for="zone">Time zone</Field.Label>
				<Input
					id="zone"
					list="zones"
					autocomplete="off"
					placeholder="Europe/London"
					required
					aria-invalid={invalid('digestTimezone')}
					bind:value={form.digestTimezone}
				/>
				<datalist id="zones">
					{#each zones as z (z)}<option value={z}></option>{/each}
				</datalist>
				{#if invalid('digestTimezone')}<Field.Error>{problem?.message}</Field.Error>{/if}
			</Field.Field>
		</div>
	</Field.Set>

	<Field.Set>
		<Field.Legend class="flex items-center gap-1.5">
			Contents
			<Hint text="Vulnerabilities without a fix and accepted risks are never listed" />
		</Field.Legend>
		<Field.Group>
			{#each sections as s (s.key)}
				<Field.Field orientation="horizontal">
					<Checkbox id={s.key} bind:checked={() => form[s.key], (v) => (form[s.key] = v)} />
					<Field.Label for={s.key} class="font-normal">{s.label}</Field.Label>
				</Field.Field>
			{/each}
			<Field.Field data-invalid={invalid('digestNewMinSeverity')} class="w-56">
				<Field.Label for="new">
					New vulnerabilities <Hint text="With a fix, found since the last digest" />
				</Field.Label>
				<Select.Root type="single" bind:value={form.digestNewMinSeverity}>
					<Select.Trigger id="new" class="w-full">
						{labelOf(newChoices, form.digestNewMinSeverity)}
					</Select.Trigger>
					<Select.Content>
						{#each newChoices as c (c.value)}
							<Select.Item value={c.value} label={c.label}>{c.label}</Select.Item>
						{/each}
					</Select.Content>
				</Select.Root>
				{#if invalid('digestNewMinSeverity')}<Field.Error>{problem?.message}</Field.Error>{/if}
			</Field.Field>
		</Field.Group>
	</Field.Set>
	<div>
		<Button type="submit" size="sm" disabled={!changed || saving}>Save</Button>
	</div>
</form>
