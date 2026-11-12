<script lang="ts">
	import { page } from '$app/state';
	import { resolve } from '$app/paths';
	import { Button } from '#lib/components/ui/button/index.js';
	import Logo from '#lib/components/logo.svelte';

	const notFound = $derived(page.status === 404);
</script>

<svelte:head>
	<title>{notFound ? 'Page not found' : 'Error'} · Best Before</title>
</svelte:head>

<main class="flex min-h-svh flex-col items-center justify-center gap-4 p-6 text-center">
	<Logo />
	<h1 class="text-xl font-semibold">{notFound ? 'Page not found' : 'Something went wrong'}</h1>
	{#if !notFound && page.error?.message}
		<p class="text-sm text-muted-foreground">{page.error.message}</p>
	{/if}
	<Button href={resolve('/(app)')}>Back to servers</Button>
</main>
