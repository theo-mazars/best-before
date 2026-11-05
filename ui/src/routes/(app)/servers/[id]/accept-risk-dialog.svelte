<script lang="ts">
	import { untrack } from 'svelte';
	import { parseDate, type DateValue } from '@internationalized/date';
	import { toast } from 'svelte-sonner';
	import CalendarIcon from '@lucide/svelte/icons/calendar';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import * as Popover from '#lib/components/ui/popover/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import { Calendar } from '#lib/components/ui/calendar/index.js';
	import { Textarea } from '#lib/components/ui/textarea/index.js';
	import { api, ApiError, type Cve, type PackageRow, type ServerPage } from '#lib/api.js';
	import { expiryPresets, presetDate } from '#lib/packages.js';
	import WhereLabel from './where-label.svelte';

	let {
		serverId,
		pkg,
		cve,
		limits,
		onclose,
		ondone
	}: {
		serverId: string;
		pkg: PackageRow;
		cve: Cve;
		limits: ServerPage['risk'];
		onclose: () => void;
		ondone: () => Promise<unknown>;
	} = $props();

	const maxReason = 1000;
	// The dialog is created for one vulnerability: its props never change.
	const risk = untrack(() => cve.risk);
	let reason = $state(risk?.reason ?? '');
	let preset = $state<number | 'custom'>(risk ? 'custom' : 90);
	let custom = $state<DateValue | undefined>(
		risk ? parseDate(risk.expiresAt.slice(0, 10)) : undefined
	);
	let calendarOpen = $state(false);
	let errors = $state<{ reason?: string; expires?: string; form?: string }>({});
	let saving = $state(false);

	const expires = $derived(
		preset === 'custom' ? (custom?.toString() ?? '') : presetDate(limits.min, limits.max, preset)
	);

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		if (saving) return;
		saving = true;
		errors = {};
		try {
			await api('PUT', `/servers/${serverId}/risk`, {
				target: pkg.target,
				vulnerability: cve.id,
				reason,
				expires
			});
			toast.success('Risk accepted');
			await ondone();
			onclose();
		} catch (err) {
			const message = err instanceof ApiError ? err.message : 'Something went wrong.';
			const field = err instanceof ApiError ? err.field : undefined;
			errors = field === 'reason' || field === 'expires' ? { [field]: message } : { form: message };
		} finally {
			saving = false;
		}
	}
</script>

<Dialog.Root open onOpenChange={(open) => !open && onclose()}>
	<Dialog.Content class="sm:max-w-lg">
		<Dialog.Header>
			<Dialog.Title>Accept {cve.id}</Dialog.Title>
			<Dialog.Description class="flex flex-wrap items-center gap-2">
				<WhereLabel where={pkg.where} />
				<span>{pkg.package} {pkg.version}</span>
			</Dialog.Description>
		</Dialog.Header>
		<form onsubmit={submit}>
			<Field.Group>
				<Field.Field data-invalid={errors.reason ? true : undefined}>
					<Field.Label for="reason">Reason</Field.Label>
					<Textarea
						id="reason"
						bind:value={reason}
						placeholder="Not reachable from outside: the service only listens on localhost"
						maxlength={maxReason}
						aria-invalid={errors.reason ? true : undefined}
						class="max-h-48"
						required
					/>
					{#if reason.length > maxReason - 100}
						<p class="text-right text-xs text-muted-foreground tabular-nums">
							{reason.length} / {maxReason}
						</p>
					{/if}
					{#if errors.reason}<Field.Error>{errors.reason}</Field.Error>{/if}
				</Field.Field>
				<Field.Field data-invalid={errors.expires ? true : undefined}>
					<Field.Label>Until</Field.Label>
					<div class="flex flex-wrap items-center gap-1">
						{#each expiryPresets as days (days)}
							<Button
								type="button"
								size="sm"
								variant={preset === days ? 'secondary' : 'outline'}
								aria-pressed={preset === days}
								onclick={() => (preset = days)}
							>
								{days === 365 ? '1 year' : `${days} days`}
							</Button>
						{/each}
						<Popover.Root bind:open={calendarOpen}>
							<Popover.Trigger>
								{#snippet child({ props })}
									<Button
										{...props}
										type="button"
										size="sm"
										variant={preset === 'custom' ? 'secondary' : 'outline'}
										aria-pressed={preset === 'custom'}
									>
										<CalendarIcon />
										{preset === 'custom' && custom ? custom.toString() : 'Date'}
									</Button>
								{/snippet}
							</Popover.Trigger>
							<Popover.Content class="w-auto p-0" align="start">
								<Calendar
									type="single"
									bind:value={custom}
									minValue={parseDate(limits.min)}
									maxValue={parseDate(limits.max)}
									captionLayout="dropdown"
									onValueChange={(v) => {
										if (v) {
											preset = 'custom';
											calendarOpen = false;
										}
									}}
								/>
							</Popover.Content>
						</Popover.Root>
					</div>
					{#if expires}
						<p class="text-xs text-muted-foreground tabular-nums">{expires}, 00:00 UTC</p>
					{/if}
					{#if errors.expires}<Field.Error>{errors.expires}</Field.Error>{/if}
				</Field.Field>
				{#if errors.form}<Field.Error>{errors.form}</Field.Error>{/if}
			</Field.Group>
			<Dialog.Footer class="mt-4">
				<Button type="button" variant="outline" onclick={onclose}>Cancel</Button>
				<Button type="submit" disabled={saving || !reason.trim() || !expires}>Accept</Button>
			</Dialog.Footer>
		</form>
	</Dialog.Content>
</Dialog.Root>
