<script lang="ts">
	import * as Tooltip from '#lib/components/ui/tooltip/index.js';
	import { Badge } from '#lib/components/ui/badge/index.js';
</script>

<Tooltip.Root>
	<Tooltip.Trigger>
		<Badge class="rounded-sm bg-red-700 text-white dark:bg-red-600">Fix now</Badge>
	</Tooltip.Trigger>
	<Tooltip.Content>Worth an emergency alert (Settings › What is worth sending)</Tooltip.Content>
</Tooltip.Root>
