<script lang="ts">
	import { page } from '$app/state';
	import { resolve } from '$app/paths';
	import { setMode, userPrefersMode } from 'mode-watcher';
	import ChevronRightIcon from '@lucide/svelte/icons/chevron-right';
	import KeyRoundIcon from '@lucide/svelte/icons/key-round';
	import ServerIcon from '@lucide/svelte/icons/server';
	import SettingsIcon from '@lucide/svelte/icons/settings';
	import ChevronsUpDownIcon from '@lucide/svelte/icons/chevrons-up-down';
	import LogOutIcon from '@lucide/svelte/icons/log-out';
	import * as Sidebar from '#lib/components/ui/sidebar/index.js';
	import * as Collapsible from '#lib/components/ui/collapsible/index.js';
	import * as DropdownMenu from '#lib/components/ui/dropdown-menu/index.js';
	import { api, type ServerSummary, type Session } from '#lib/api.js';
	import { statusLook } from '#lib/status.js';
	import { cn } from '#lib/utils.js';
	import Logo from './logo.svelte';

	let { session, servers }: { session: Session; servers: ServerSummary[] } = $props();

	// Agents and settings are still server pages: they need a full load.
	const nav = [
		{ href: '/agents', label: 'Agents', icon: KeyRoundIcon },
		{ href: '/settings', label: 'Settings', icon: SettingsIcon }
	];

	// The first servers, worst first as the API sorts them, for quick access.
	const quick = 8;
	const dots: Record<string, string> = {
		critical: 'bg-red-600',
		stale: 'bg-orange-500',
		attention: 'bg-amber-500',
		OK: 'bg-emerald-600'
	};
	let open = $state(true);

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
				<Collapsible.Root bind:open>
					<Sidebar.MenuItem>
						<Sidebar.MenuButton isActive={page.url.pathname === '/'} tooltipContent="Servers">
							{#snippet child({ props })}
								<a href={resolve('/(app)')} {...props}>
									<ServerIcon />
									<span>Servers</span>
								</a>
							{/snippet}
						</Sidebar.MenuButton>
						{#if servers.length}
							<Collapsible.Trigger>
								{#snippet child({ props })}
									<Sidebar.MenuAction
										{...props}
										aria-label={open ? 'Hide servers' : 'Show servers'}
									>
										<ChevronRightIcon class={cn('transition-transform', open && 'rotate-90')} />
									</Sidebar.MenuAction>
								{/snippet}
							</Collapsible.Trigger>
							<Collapsible.Content>
								<Sidebar.MenuSub>
									{#each servers.slice(0, quick) as s (s.id)}
										{@const href = resolve('/(app)/servers/[id]', { id: s.id })}
										<Sidebar.MenuSubItem>
											<Sidebar.MenuSubButton isActive={page.url.pathname === href}>
												{#snippet child({ props })}
													<a {href} {...props} title="{s.hostname} · {statusLook(s.status).label}">
														<span
															class={cn(
																'size-2 shrink-0 rounded-full',
																dots[s.status] ?? 'bg-muted-foreground/40'
															)}
														></span>
														<span class="truncate">{s.hostname}</span>
													</a>
												{/snippet}
											</Sidebar.MenuSubButton>
										</Sidebar.MenuSubItem>
									{/each}
									{#if servers.length > quick}
										<Sidebar.MenuSubItem>
											<Sidebar.MenuSubButton>
												{#snippet child({ props })}
													<a href={resolve('/(app)')} {...props} class="text-muted-foreground">
														<span>All {servers.length} servers</span>
													</a>
												{/snippet}
											</Sidebar.MenuSubButton>
										</Sidebar.MenuSubItem>
									{/if}
								</Sidebar.MenuSub>
							</Collapsible.Content>
						{/if}
					</Sidebar.MenuItem>
				</Collapsible.Root>
				{#each nav as item (item.href)}
					<Sidebar.MenuItem>
						<Sidebar.MenuButton
							isActive={page.url.pathname === item.href}
							tooltipContent={item.label}
						>
							{#snippet child({ props })}
								<!-- eslint-disable-next-line svelte/no-navigation-without-resolve -- server pages until migrated -->
								<a href={item.href} data-sveltekit-reload {...props}>
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
