<script lang="ts">
	import { page } from '$app/state';
	import { resolve } from '$app/paths';
	import { setMode, userPrefersMode } from 'mode-watcher';
	import LayoutDashboardIcon from '@lucide/svelte/icons/layout-dashboard';
	import ServerIcon from '@lucide/svelte/icons/server';
	import SettingsIcon from '@lucide/svelte/icons/settings';
	import ChevronsUpDownIcon from '@lucide/svelte/icons/chevrons-up-down';
	import LogOutIcon from '@lucide/svelte/icons/log-out';
	import * as Sidebar from '#lib/components/ui/sidebar/index.js';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.js';
	import { api, type Session } from '#lib/api.js';
	import Logo from './logo.svelte';

	let { session }: { session: Session } = $props();

	// Agents and settings are still server pages: they need a full load.
	const nav = [
		{ href: '/', label: 'Overview', icon: LayoutDashboardIcon, spa: true },
		{ href: '/agents', label: 'Agents', icon: ServerIcon, spa: false },
		{ href: '/settings', label: 'Settings', icon: SettingsIcon, spa: false }
	];

	async function logout() {
		await api('POST', '/logout').catch(() => {});
		location.assign('/login');
	}
</script>

<Sidebar.Root collapsible="icon">
	<Sidebar.Header>
		<Sidebar.Menu>
			<Sidebar.MenuItem>
				<Sidebar.MenuButton size="lg">
					{#snippet child({ props })}
						<a href={resolve('/(app)')} {...props}><Logo /></a>
					{/snippet}
				</Sidebar.MenuButton>
			</Sidebar.MenuItem>
		</Sidebar.Menu>
	</Sidebar.Header>
	<Sidebar.Content>
		<Sidebar.Group>
			<Sidebar.Menu>
				{#each nav as item (item.href)}
					<Sidebar.MenuItem>
						<Sidebar.MenuButton
							isActive={page.url.pathname === item.href ||
								(item.href === '/' && page.url.pathname.startsWith('/servers/'))}
							tooltipContent={item.label}
						>
							{#snippet child({ props })}
								<!-- eslint-disable-next-line svelte/no-navigation-without-resolve -- server pages until migrated -->
								<a href={item.href} data-sveltekit-reload={item.spa ? undefined : true} {...props}>
									<item.icon />
									<span>{item.label}</span>
								</a>
							{/snippet}
						</Sidebar.MenuButton>
					</Sidebar.MenuItem>
				{/each}
			</Sidebar.Menu>
		</Sidebar.Group>
	</Sidebar.Content>
	<Sidebar.Footer>
		<Sidebar.Menu>
			<Sidebar.MenuItem>
				<DropdownMenu.Root>
					<DropdownMenu.Trigger>
						{#snippet child({ props })}
							<Sidebar.MenuButton {...props} size="lg" tooltipContent={session.email}>
								<span
									class="flex size-8 shrink-0 items-center justify-center rounded-md bg-sidebar-accent text-xs font-medium uppercase"
								>
									{session.email.slice(0, 1)}
								</span>
								<span class="truncate">{session.email}</span>
								<ChevronsUpDownIcon class="ml-auto" />
							</Sidebar.MenuButton>
						{/snippet}
					</DropdownMenu.Trigger>
					<DropdownMenu.Content
						side="top"
						align="start"
						class="w-(--bits-dropdown-menu-anchor-width) min-w-48"
					>
						<DropdownMenu.Label class="truncate">{session.email}</DropdownMenu.Label>
						<DropdownMenu.Separator />
						<DropdownMenu.Label class="text-xs text-muted-foreground">Theme</DropdownMenu.Label>
						<DropdownMenu.RadioGroup
							value={userPrefersMode.current}
							onValueChange={(v) => setMode(v as 'light' | 'dark' | 'system')}
						>
							<DropdownMenu.RadioItem value="light">Light</DropdownMenu.RadioItem>
							<DropdownMenu.RadioItem value="dark">Dark</DropdownMenu.RadioItem>
							<DropdownMenu.RadioItem value="system">System</DropdownMenu.RadioItem>
						</DropdownMenu.RadioGroup>
						<DropdownMenu.Separator />
						<DropdownMenu.Item onSelect={logout}>
							<LogOutIcon />
							Log out
						</DropdownMenu.Item>
					</DropdownMenu.Content>
				</DropdownMenu.Root>
			</Sidebar.MenuItem>
		</Sidebar.Menu>
	</Sidebar.Footer>
	<Sidebar.Rail />
</Sidebar.Root>
