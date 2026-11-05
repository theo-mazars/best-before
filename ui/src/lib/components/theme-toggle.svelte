<script lang="ts">
	import { setMode, userPrefersMode } from 'mode-watcher';
	import SunIcon from '@lucide/svelte/icons/sun';
	import MoonIcon from '@lucide/svelte/icons/moon';
	import { Button } from '#lib/components/ui/button/index.js';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.js';
</script>

<DropdownMenu.Root>
	<DropdownMenu.Trigger>
		{#snippet child({ props })}
			<Button {...props} variant="ghost" size="icon" aria-label="Theme">
				<SunIcon class="scale-100 dark:scale-0" />
				<MoonIcon class="absolute scale-0 dark:scale-100" />
			</Button>
		{/snippet}
	</DropdownMenu.Trigger>
	<DropdownMenu.Content align="end">
		<DropdownMenu.RadioGroup
			value={userPrefersMode.current}
			onValueChange={(v) => setMode(v as 'light' | 'dark' | 'system')}
		>
			<DropdownMenu.RadioItem value="light">Light</DropdownMenu.RadioItem>
			<DropdownMenu.RadioItem value="dark">Dark</DropdownMenu.RadioItem>
			<DropdownMenu.RadioItem value="system">System</DropdownMenu.RadioItem>
		</DropdownMenu.RadioGroup>
	</DropdownMenu.Content>
</DropdownMenu.Root>
