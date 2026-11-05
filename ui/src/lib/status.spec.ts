import { describe, expect, it } from 'vitest';
import type { ServerSummary } from './api.js';
import { statusLook, statusRank, worstIssue } from './status.js';

const none = { open: 0, muted: 0 };
const base: ServerSummary = {
	id: 'a',
	hostname: 'web-01',
	status: 'OK',
	lastReportAt: null,
	critical: 0,
	high: 0,
	medium: 0,
	knownExploited: 0,
	noFixYet: 0,
	accepted: 0,
	securityUpdates: 0,
	updates: 0,
	rebootRequired: false,
	images: 0,
	notChecked: 0,
	severities: { critical: none, high: none, medium: none, low: none, unknown: none },
	problems: []
};

describe('status', () => {
	it('maps API statuses to labels', () => {
		expect(statusLook('attention').label).toBe('Needs attention');
		expect(statusLook('waiting for first report').label).toBe('Waiting');
		expect(statusLook('new thing').label).toBe('new thing');
	});

	it('ranks worst first', () => {
		expect(statusRank('critical')).toBeLessThan(statusRank('OK'));
		expect(statusRank('new thing')).toBeGreaterThan(statusRank('OK'));
	});

	it('sums up the worst issue', () => {
		expect(worstIssue(base)).toBe('—');
		expect(worstIssue({ ...base, status: 'stale', critical: 3 })).toBe('Stopped reporting');
		expect(worstIssue({ ...base, critical: 2, knownExploited: 1 })).toBe('1 known exploited');
		expect(worstIssue({ ...base, high: 1, securityUpdates: 4 })).toBe('1 high');
		expect(worstIssue({ ...base, securityUpdates: 1 })).toBe('1 security update');
		expect(worstIssue({ ...base, rebootRequired: true, medium: 2 })).toBe('Reboot required');
		expect(worstIssue({ ...base, notChecked: 2 })).toBe('2 images not checked');
		expect(worstIssue({ ...base, problems: ['Docker: down'] })).toBe('Report incomplete');
	});
});
