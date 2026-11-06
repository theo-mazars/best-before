<script lang="ts">
	import ContainerIcon from '@lucide/svelte/icons/container';
	import * as Accordion from '#lib/components/ui/accordion/index.js';
	import * as Empty from '#lib/components/ui/empty/index.js';
	import { Button } from '#lib/components/ui/button/index.js';
	import SeverityStrip from '#lib/components/severity-strip.svelte';
	import type { ImageInfo } from '#lib/api.js';
	import WhereLabel from './where-label.svelte';

	let { images, onshow }: { images: ImageInfo[]; onshow: (where: string) => void } = $props();

	const vulns = (i: ImageInfo) =>
		Object.values(i.severities).reduce((n, c) => n + c.open + c.muted, 0);
</script>

{#if images.length === 0}
	<Empty.Root class="border">
		<Empty.Header>
			<Empty.Media variant="icon"><ContainerIcon /></Empty.Media>
			<Empty.Title>No running containers</Empty.Title>
		</Empty.Header>
	</Empty.Root>
{:else}
	<Accordion.Root type="multiple" class="overflow-hidden rounded-md border">
		{#each images as img (img.id)}
			<Accordion.Item value={img.id}>
				<Accordion.Trigger
					class="cursor-pointer items-center rounded-none px-4 py-3 hover:bg-muted/50 hover:no-underline"
				>
					<span class="flex min-w-0 flex-1 flex-wrap items-center gap-x-3 gap-y-1">
						<WhereLabel where={img.where} class="text-sm" />
						<span class="text-xs font-normal text-muted-foreground">
							{img.containers.length}
							{img.containers.length === 1 ? 'container' : 'containers'}
						</span>
						{#if img.notChecked}
							<span class="text-xs font-normal text-amber-700 dark:text-amber-400">Not checked</span
							>
						{:else if img.nothingChecked}
							<span class="text-xs font-normal text-muted-foreground">Nothing to check</span>
						{/if}
					</span>
					<span class="mr-2"><SeverityStrip counts={img.severities} /></span>
				</Accordion.Trigger>
				<Accordion.Content class="px-4 pt-1">
					<dl class="grid grid-cols-[8rem_1fr] gap-x-4 gap-y-1 text-sm">
						<dt class="text-muted-foreground">Containers</dt>
						<dd>{img.containers.join(', ') || '—'}</dd>
						{#if img.references.length > 1}
							<dt class="text-muted-foreground">Also used as</dt>
							<dd>{img.references.slice(1).join(', ')}</dd>
						{/if}
						<dt class="text-muted-foreground">Image ID</dt>
						<dd class="font-mono text-xs break-all">{img.id}</dd>
						{#if img.os}
							<dt class="text-muted-foreground">System</dt>
							<dd>{img.os}</dd>
						{/if}
						<dt class="text-muted-foreground">Checked</dt>
						<dd>
							{#if img.checked.length}
								{img.checked.join('; ')}
							{:else if img.nothingChecked}
								Nothing: no package records and no known runtime
							{:else}
								Nothing
							{/if}
						</dd>
						{#if img.notChecked}
							<dt class="text-muted-foreground">Not checked</dt>
							<dd class="text-amber-700 dark:text-amber-400">{img.notChecked}</dd>
						{/if}
						{#if img.imprecise.length}
							<dt class="text-muted-foreground">Version too vague</dt>
							<dd>{img.imprecise.join(', ')}</dd>
						{/if}
					</dl>
					{#if vulns(img)}
						<Button variant="outline" size="sm" class="mt-3" onclick={() => onshow(img.where)}>
							Show vulnerabilities
						</Button>
					{/if}
				</Accordion.Content>
			</Accordion.Item>
		{/each}
	</Accordion.Root>
{/if}
