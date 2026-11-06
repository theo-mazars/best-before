import type { ServerSummary } from './api.js';

export const statuses = [
	'critical',
	'stale',
	'not checked yet',
	'waiting for first report',
	'attention',
	'OK'
] as const;

const looks: Record<string, { label: string; class: string }> = {
	critical: {
		label: 'Critical',
		class: 'bg-red-600/10 text-red-700 dark:bg-red-500/20 dark:text-red-400'
	},
	stale: {
		label: 'Stale',
		class: 'bg-orange-500/10 text-orange-700 dark:bg-orange-500/20 dark:text-orange-400'
	},
	'not checked yet': { label: 'Not checked', class: 'bg-muted text-muted-foreground' },
	'waiting for first report': {
		label: 'Waiting',
		class: 'border-border text-muted-foreground'
	},
	attention: {
		label: 'Needs attention',
		class: 'bg-amber-500/15 text-amber-800 dark:bg-amber-500/20 dark:text-amber-400'
	},
	OK: {
		label: 'OK',
		class: 'bg-emerald-600/10 text-emerald-700 dark:bg-emerald-500/20 dark:text-emerald-400'
	}
};

export const statusRule =
	'Critical: a vulnerability worth an emergency alert (Settings › What is worth sending). Needs attention: security updates to install, a reboot, or gaps in the report. OK: nothing to do now.';

export function statusLook(status: string) {
	return looks[status] ?? { label: status, class: 'border-border text-muted-foreground' };
}

export function statusRank(status: string): number {
	const i = (statuses as readonly string[]).indexOf(status);
	return i < 0 ? statuses.length : i;
}

function plural(n: number, one: string, many = one + 's') {
	return `${n} ${n === 1 ? one : many}`;
}

// worstIssue sums up what most needs doing on a server, in a few words.
export function worstIssue(s: ServerSummary): string {
	if (s.status === 'waiting for first report') return 'Waiting for first report';
	if (s.status === 'stale') return 'Stopped reporting';
	if (s.emergencies) return `${s.emergencies} to fix now`;
	if (s.status === 'not checked yet') return 'Not checked yet';
	if (s.securityUpdates) return plural(s.securityUpdates, 'security update');
	if (s.rebootRequired) return 'Reboot required';
	if (s.notChecked) return plural(s.notChecked, 'image') + ' not checked';
	if (s.problems.length) return 'Report incomplete';
	return '—';
}

// focuses are the overview's cards: each one shows the servers it counts.
export const focuses = {
	action: { label: 'Needing action', test: (s: ServerSummary) => s.status !== 'OK' },
	fixNow: { label: 'To fix now', test: (s: ServerSummary) => s.emergencies > 0 },
	exploited: { label: 'Known exploited', test: (s: ServerSummary) => s.knownExploited > 0 },
	updates: { label: 'Security updates', test: (s: ServerSummary) => s.securityUpdates > 0 },
	reboot: { label: 'Reboots pending', test: (s: ServerSummary) => s.rebootRequired }
} as const;
export type Focus = keyof typeof focuses;
