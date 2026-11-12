<script lang="ts">
	import { untrack } from 'svelte';
	import Hint from '#lib/components/hint.svelte';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Checkbox } from '#lib/components/ui/checkbox/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';
	import type { SettingsPage } from '#lib/api.js';
	import { sameAlerts, saveAlerts } from './alerts.js';

	let { settings, refresh }: { settings: SettingsPage; refresh: () => Promise<unknown> } = $props();

	// The page rebuilds this tab when the saved settings change.
	const saved = untrack(() => settings.alerts);
	let form = $state(structuredClone(saved));
	let problem = $state<{ field: string; message: string } | null>(null);
	let saving = $state(false);
	const changed = $derived(!sameAlerts(form, saved));

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		if (saving || !changed) return;
		saving = true;
		// Only this tab's fields: the digest's stay as saved.
		problem = await saveAlerts(
			{
				...saved,
				emergencyKnownExploited: form.emergencyKnownExploited,
				emergencyMinCvss: form.emergencyMinCvss,
				reminderDays: form.reminderDays
			},
			refresh
		);
		saving = false;
	}

	const invalid = (name: string) => problem?.field === name || undefined;
</script>

<form class="flex max-w-xl flex-col gap-4" onsubmit={submit}>
	<p class="text-sm">
		<span class="text-muted-foreground">Emergencies now:</span>
		{settings.emergencyRule ? `vulnerabilities with a fix, ${settings.emergencyRule}` : 'none'}
	</p>
	<Field.Set>
		<Field.Legend class="flex items-center gap-1.5">
			Emergencies
			<Hint
				text="A vulnerability with a fix is an emergency when a rule below matches. It is sent at once, once per server, then again as a reminder while it stays open. Vulnerabilities without a fix and accepted risks are never sent. A server that stops reporting is also sent at once."
			/>
		</Field.Legend>
		<Field.Group>
			<Field.Field orientation="horizontal">
				<Checkbox id="known-exploited" bind:checked={form.emergencyKnownExploited} />
				<Field.Label for="known-exploited" class="font-normal">
					Known exploited <Hint text="Listed by CISA KEV, whatever its score" />
				</Field.Label>
			</Field.Field>
			<Field.Field data-invalid={invalid('emergencyMinCvss')}>
				<Field.Label for="cvss">CVSS at least</Field.Label>
				<Input
					id="cvss"
					type="number"
					min="0.1"
					max="10"
					step="0.1"
					placeholder="None"
					class="w-32"
					aria-invalid={invalid('emergencyMinCvss')}
					bind:value={form.emergencyMinCvss}
				/>
				{#if invalid('emergencyMinCvss')}<Field.Error>{problem?.message}</Field.Error>{/if}
			</Field.Field>
			<Field.Field data-invalid={invalid('reminderDays')}>
				<Field.Label for="reminder">
					Remind every (days) <Hint text="While an emergency stays open" />
				</Field.Label>
				<Input
					id="reminder"
					type="number"
					min="1"
					max="365"
					required
					placeholder="7"
					class="w-32"
					aria-invalid={invalid('reminderDays')}
					bind:value={form.reminderDays}
				/>
				{#if invalid('reminderDays')}<Field.Error>{problem?.message}</Field.Error>{/if}
			</Field.Field>
		</Field.Group>
	</Field.Set>
	<div>
		<Button type="submit" size="sm" disabled={!changed || saving}>Save</Button>
	</div>
</form>
