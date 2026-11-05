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
	if (s.knownExploited) return `${s.knownExploited} known exploited`;
	if (s.critical) return `${s.critical} critical`;
	if (s.status === 'not checked yet') return 'Not checked yet';
	if (s.high) return `${s.high} high`;
	if (s.securityUpdates) return plural(s.securityUpdates, 'security update');
	if (s.rebootRequired) return 'Reboot required';
	if (s.medium) return `${s.medium} medium`;
	if (s.notChecked) return plural(s.notChecked, 'image') + ' not checked';
	if (s.problems.length) return 'Report incomplete';
	return '—';
}
