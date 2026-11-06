<script lang="ts">
	import TriangleAlertIcon from '@lucide/svelte/icons/triangle-alert';
	import * as Dialog from '#lib/components/ui/dialog/index.js';
	import * as Tooltip from '#lib/components/ui/tooltip/index.js';
	import CopyButton from '#lib/components/copy-button.svelte';
	import TimeAgo from '#lib/components/time-ago.svelte';
	import type { EnrolmentCode } from '#lib/api.js';

	let { code, onclose }: { code: EnrolmentCode; onclose: () => void } = $props();
</script>

<Dialog.Root open onOpenChange={(open) => !open && onclose()}>
	<Dialog.Content class="sm:max-w-2xl">
		<Dialog.Header>
			<Dialog.Title>Add a server</Dialog.Title>
			<Dialog.Description class="flex items-center gap-1.5">
				Run as root on the server · expires <TimeAgo time={code.expiresAt} />
				<Tooltip.Root>
					<Tooltip.Trigger
						class="text-amber-700 dark:text-amber-400"
						aria-label="Works once. Treat it as a password until used."
					>
						<TriangleAlertIcon class="size-3.5" />
					</Tooltip.Trigger>
					<Tooltip.Content class="max-w-64"
						>Works once. Treat it as a password until used.</Tooltip.Content
					>
				</Tooltip.Root>
			</Dialog.Description>
		</Dialog.Header>
		<div class="flex items-start gap-1 rounded-md border bg-muted/50 p-2">
			<pre
				class="min-w-0 flex-1 py-1 pl-1 font-mono text-xs break-all whitespace-pre-wrap">{code.command}</pre>
			<CopyButton text={code.command} />
		</div>
	</Dialog.Content>
</Dialog.Root>
