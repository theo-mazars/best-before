import { describe, expect, it } from 'vitest';
import type { PackageRow } from './api.js';
import { filterPackages, noFilter, presetDate, severityLook, wheres } from './packages.js';

const counts = (o: Partial<Record<string, [number, number]>>) =>
	Object.fromEntries(
		['critical', 'high', 'medium', 'low', 'unknown'].map((k) => {
			const [open, muted] = o[k] ?? [0, 0];
			return [k, { open, muted }];
		})
	) as PackageRow['severities'];

const row = (p: Partial<PackageRow>): PackageRow => ({
	where: 'host',
	target: 'host',
	package: 'x',
	version: '1',
	kind: 'package',
	severities: counts({}),
	knownExploited: false,
	maxCvss: 0,
	updateTo: '',
	reboot: '',
	emergency: false,
	muted: false,
	cves: [],
	...p
});

describe('filterPackages', () => {
	const rows = [
		row({
			package: 'openssl',
			severities: counts({ critical: [1, 0] }),
			knownExploited: true,
			emergency: true
		}),
		row({ package: 'curl', where: 'node:22', severities: counts({ high: [0, 1] }) }),
		row({ package: 'bash', muted: true, severities: counts({ low: [0, 1] }) })
	];
	const names = (f = {}) => filterPackages(rows, { ...noFilter, ...f }).map((p) => p.package);

	it('hides muted rows unless asked', () => {
		expect(names()).toEqual(['openssl', 'curl']);
		expect(names({ showMuted: true })).toEqual(['openssl', 'curl', 'bash']);
	});
	it('filters by search, where, severity and known exploited', () => {
		expect(names({ search: 'CUR' })).toEqual(['curl']);
		expect(names({ where: 'node:22' })).toEqual(['curl']);
		expect(names({ severities: ['high'] })).toEqual(['curl']);
		expect(names({ knownExploited: true })).toEqual(['openssl']);
		expect(names({ fixNow: true })).toEqual(['openssl']);
	});
	it('lists the host first', () => {
		expect(wheres([row({ where: 'b' }), row({ where: 'a' }), row({})])).toEqual(['host', 'a', 'b']);
	});
});

describe('presetDate', () => {
	it('counts from today and stays within the limit', () => {
		expect(presetDate('2026-11-06', '2027-11-06', 1)).toBe('2026-11-06');
		expect(presetDate('2026-11-06', '2027-11-06', 90)).toBe('2027-02-03');
		expect(presetDate('2026-11-06', '2027-11-06', 400)).toBe('2027-11-06');
	});
});

describe('severityLook', () => {
	it('labels unknown severities', () => {
		expect(severityLook('high').label).toBe('High');
		expect(severityLook('unknown').label).toBe('Unknown');
	});
});
