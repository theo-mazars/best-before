import { parseDate } from '@internationalized/date';
import type { CveState, PackageRow, StripSeverity } from './api.js';

export const stateLooks: Record<CveState, { label: string; class: string }> = {
	open: { label: 'Open', class: 'border-border' },
	noFix: { label: 'No fix yet', class: 'bg-muted text-muted-foreground' },
	below: { label: 'Below threshold', class: 'bg-muted text-muted-foreground' },
	accepted: { label: 'Accepted', class: 'bg-sky-500/10 text-sky-700 dark:text-sky-400' },
	oldKernel: { label: 'Old kernel', class: 'bg-muted text-muted-foreground' }
};

export const severityLooks: Record<string, { label: string; class: string }> = {
	critical: { label: 'Critical', class: 'bg-red-700 text-white' },
	high: { label: 'High', class: 'bg-orange-600 text-white' },
	medium: { label: 'Medium', class: 'bg-amber-400 text-amber-950' },
	low: { label: 'Low', class: 'bg-yellow-200 text-yellow-950' },
	negligible: { label: 'Negligible', class: 'bg-neutral-400 text-white' }
};

export function severityLook(severity: string) {
	return severityLooks[severity] ?? { label: 'Unknown', class: 'bg-neutral-400 text-white' };
}

export type PackageFilter = {
	search: string;
	where: string;
	severities: StripSeverity[];
	knownExploited: boolean;
	showMuted: boolean;
};

export const noFilter: PackageFilter = {
	search: '',
	where: '',
	severities: [],
	knownExploited: false,
	showMuted: false
};

export function filterPackages(rows: PackageRow[], f: PackageFilter): PackageRow[] {
	const q = f.search.trim().toLowerCase();
	return rows.filter(
		(p) =>
			(f.showMuted || !p.muted) &&
			(!q || p.package.toLowerCase().includes(q)) &&
			(!f.where || p.where === f.where) &&
			(!f.knownExploited || p.knownExploited) &&
			(f.severities.length === 0 ||
				f.severities.some((s) => p.severities[s].open + p.severities[s].muted > 0))
	);
}

// wheres lists the places packages are in: the host first, then images.
export function wheres(rows: PackageRow[]): string[] {
	const set = [...new Set(rows.map((p) => p.where))];
	return set.sort((a, b) => (a === 'host' ? -1 : b === 'host' ? 1 : a.localeCompare(b)));
}

export const expiryPresets = [30, 90, 180, 365] as const;

// presetDate is the date `days` from now, given min, which is tomorrow,
// and kept within max.
export function presetDate(min: string, max: string, days: number): string {
	const d = parseDate(min).add({ days: days - 1 });
	return d.compare(parseDate(max)) > 0 ? max : d.toString();
}
