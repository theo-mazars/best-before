<script lang="ts">
	import Logo from '#lib/components/logo.svelte';
	import LogoMark from '#lib/components/logo-mark.svelte';
	import ThemeToggle from '#lib/components/theme-toggle.svelte';
	import type { LayoutProps } from './$types';

	let { children }: LayoutProps = $props();
</script>

<div class="grid min-h-svh lg:grid-cols-2">
	<div class="flex flex-col gap-4 p-6 md:p-10">
		<div class="flex items-center justify-between">
			<Logo />
			<ThemeToggle />
		</div>
		<div class="flex flex-1 items-center justify-center">
			{@render children()}
		</div>
	</div>
	<div class="relative hidden flex-col items-center justify-center gap-6 bg-muted lg:flex">
		<LogoMark class="size-24 text-foreground/80" />
		<p class="text-lg font-medium text-muted-foreground">Know what's gone off on your servers.</p>
	</div>
</div>
