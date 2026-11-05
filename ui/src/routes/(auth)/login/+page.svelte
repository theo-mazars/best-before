<script lang="ts">
	import { onMount, tick } from 'svelte';
	import { goto } from '$app/navigation';
	import { resolve } from '$app/paths';
	import ArrowLeftIcon from '@lucide/svelte/icons/arrow-left';
	import LoaderIcon from '@lucide/svelte/icons/loader-circle';
	import { api, ApiError, type Session } from '#lib/api.js';
	import OtpInput from '#lib/components/otp-input.svelte';
	import * as Alert from '#lib/components/ui/alert/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as Field from '#lib/components/ui/field/index.js';
	import { Input } from '#lib/components/ui/input/index.js';

	let step = $state<'password' | 'code' | 'loading'>('password');
	let email = $state('');
	let password = $state('');
	let code = $state('');
	let error = $state('');
	let busy = $state(false);

	onMount(async () => {
		try {
			const s = await api<Session>('GET', '/session');
			if (s.setup) goto(resolve('/(auth)/setup'), { replaceState: true });
			else location.replace('/');
		} catch {
			// not logged in
		}
	});

	function message(err: unknown) {
		return err instanceof ApiError ? err.message : 'Something went wrong.';
	}

	async function submitPassword(e: SubmitEvent) {
		e.preventDefault();
		busy = true;
		error = '';
		try {
			await api('POST', '/login', { email, password });
			password = '';
			step = 'code';
			await tick();
			document.getElementById('code')?.focus();
		} catch (err) {
			error = message(err);
		}
		busy = false;
	}

	async function submitCode() {
		if (busy || code.length !== 6) return;
		busy = true;
		error = '';
		try {
			await api('POST', '/login/code', { code });
			step = 'loading';
			location.assign('/');
			return;
		} catch (err) {
			error = message(err);
			code = '';
			if (err instanceof ApiError && err.field === 'expired') step = 'password';
		}
		busy = false;
	}

	function back() {
		step = 'password';
		code = error = '';
	}
</script>

<div class="flex w-full max-w-md flex-col gap-6">
	{#if step === 'password'}
		<form onsubmit={submitPassword}>
			<Field.Group>
				<h1 class="text-center text-2xl font-bold">Log in</h1>
				{#if error}
					<Alert.Root variant="destructive">
						<Alert.Description>{error}</Alert.Description>
					</Alert.Root>
				{/if}
				<Field.Field>
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
				<Field.Field>
					<Field.Label for="password">Password</Field.Label>
					<Input
						id="password"
						type="password"
						autocomplete="current-password"
						placeholder="Your password"
						required
						bind:value={password}
					/>
				</Field.Field>
				<Button type="submit" disabled={busy}>Continue</Button>
			</Field.Group>
		</form>
	{:else if step === 'code'}
		<form
			onsubmit={(e) => {
				e.preventDefault();
				submitCode();
			}}
		>
			<Field.Group>
				<div class="flex flex-col items-center gap-1 text-center">
					<h1 class="text-2xl font-bold">Authenticator code</h1>
					<p class="text-sm text-muted-foreground">{email}</p>
				</div>
				{#if error}
					<Alert.Root variant="destructive">
						<Alert.Description>{error}</Alert.Description>
					</Alert.Root>
				{/if}
				<Field.Field class="items-center">
					<Field.Label for="code" class="sr-only">Authenticator code</Field.Label>
					<OtpInput id="code" large bind:value={code} oncomplete={submitCode} />
				</Field.Field>
				<Button type="button" variant="ghost" onclick={back}>
					<ArrowLeftIcon />
					Back
				</Button>
			</Field.Group>
		</form>
	{:else}
		<div class="flex flex-col items-center gap-3 text-muted-foreground" role="status">
			<LoaderIcon class="size-8 animate-spin" />
			<p class="text-sm">Loading the dashboard…</p>
		</div>
	{/if}
</div>
