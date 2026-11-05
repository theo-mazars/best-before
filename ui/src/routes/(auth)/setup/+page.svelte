<script lang="ts">
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import { toast } from 'svelte-sonner';
	import { api, ApiError } from '#lib/api.js';
	import CopyButton from '#lib/components/copy-button.svelte';
	import Hint from '#lib/components/hint.svelte';
	import OtpInput from '#lib/components/otp-input.svelte';
	import * as Alert from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';

	type Totp = { secret: string; key: string; qrSize: number; qrPath: string };

	let totp = $state<Totp>();
	let setupCode = $state('');
	let email = $state('');
	let password = $state('');
	let passwordAgain = $state('');
	let code = $state('');
	let error = $state('');
	let field = $state('');
	let busy = $state(false);

	onMount(async () => {
		try {
			totp = await api<Totp>('GET', '/setup');
		} catch {
			goto(resolve('/(auth)/login'), { replaceState: true });
		}
	});

	async function submit(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		error = field = '';
		try {
			await api('POST', '/setup', {
				secret: totp!.secret,
				setupCode,
				email,
				password,
				passwordAgain,
				code
			});
			toast.success('Admin created');
			goto(resolve('/(auth)/login'), { replaceState: true });
		} catch (err) {
			error = err instanceof ApiError ? err.message : 'Something went wrong.';
			field = err instanceof ApiError ? (err.field ?? '') : '';
			code = '';
			busy = false;
		}
	}
</script>

<form class="w-full max-w-md" onsubmit={submit}>
	{#if totp}
		<Field.Group>
			<h1 class="text-center text-2xl font-bold">Create the first admin</h1>
			{#if error}
				<Alert.Root variant="destructive">
					<Alert.Description>{error}</Alert.Description>
				</Alert.Root>
			{/if}
			<Field.Field data-invalid={field === 'setupCode' || undefined}>
				<Field.Label for="setup-code">
					Setup code <Hint text="Printed in the dashboard's log, e.g. docker logs" />
				</Field.Label>
				<Input
					id="setup-code"
					autocomplete="off"
					placeholder="XXXX-XXXX-XXXX-XXXX"
					required
					bind:value={setupCode}
				/>
			</Field.Field>
			<Field.Field data-invalid={field === 'email' || undefined}>
				<Field.Label for="email">Email</Field.Label>
				<Input
					id="email"
					type="email"
					autocomplete="username"
					placeholder="you@example.org"
					required
					bind:value={email}
				/>
			</Field.Field>
			<div class="grid grid-cols-2 gap-4">
				<Field.Field data-invalid={field === 'password' || undefined}>
					<Field.Label for="password">
						Password <Hint text="At least 12 characters" />
					</Field.Label>
					<Input
						id="password"
						placeholder="12+ characters"
						type="password"
						autocomplete="new-password"
						required
						minlength={12}
						bind:value={password}
					/>
				</Field.Field>
				<Field.Field data-invalid={field === 'passwordAgain' || undefined}>
					<Field.Label for="password-again">Confirm</Field.Label>
					<Input
						id="password-again"
						placeholder="Same again"
						type="password"
						autocomplete="new-password"
						required
						minlength={12}
						bind:value={passwordAgain}
					/>
				</Field.Field>
			</div>
			<Field.Separator>Authenticator</Field.Separator>
			<div class="flex items-center gap-4">
				<svg
					viewBox="-4 -4 {totp.qrSize} {totp.qrSize}"
					class="size-32 shrink-0 rounded-md border"
					role="img"
					aria-label="QR code for your authenticator app"
				>
					<rect x="-4" y="-4" width="100%" height="100%" fill="#fff" />
					<path d={totp.qrPath} fill="#000" />
				</svg>
				<div class="flex min-w-0 flex-col gap-3">
					<div class="flex items-start gap-1">
						<code class="font-mono text-xs leading-5 tracking-wide break-all">{totp.key}</code>
						<CopyButton text={totp.secret} />
					</div>
					<Field.Field data-invalid={field === 'code' || undefined}>
						<Field.Label for="code">Code</Field.Label>
						<OtpInput id="code" bind:value={code} />
					</Field.Field>
				</div>
			</div>
			<Button type="submit" disabled={busy || code.length !== 6}>Create admin</Button>
		</Field.Group>
	{/if}
</form>
