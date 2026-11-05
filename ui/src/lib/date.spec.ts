import { describe, expect, it } from 'vitest';
import { formatOffset, formatUptime, formatUTC, offsetMinutes, timeAgo } from './date.js';

const now = Date.parse('2026-11-05T13:00:00Z');

describe('dates', () => {
	it('says how long ago', () => {
		expect(timeAgo('2026-11-05T12:59:30Z', now)).toBe('just now');
		expect(timeAgo('2026-11-05T12:55:00Z', now)).toBe('5 min ago');
		expect(timeAgo('2026-11-05T12:00:00Z', now)).toBe('1 h ago');
		expect(timeAgo('2026-11-03T13:00:00Z', now)).toBe('2 days ago');
		expect(timeAgo('2026-11-17T13:00:00Z', now)).toBe('in 12 days');
		expect(timeAgo('2025-10-01T13:00:00Z', now)).toBe('1 year ago');
		expect(timeAgo(null, now)).toBe('—');
	});

	it('shows the exact time in UTC', () => {
		expect(formatUTC('2026-11-05T14:35:42+01:00')).toBe('2026-11-05 13:35:42 UTC');
		expect(formatUTC('nope')).toBe('—');
	});

	it('reads and writes offsets', () => {
		expect(offsetMinutes('2026-11-05T14:35:42+01:00')).toBe(60);
		expect(offsetMinutes('2026-11-05T09:35:42-04:30')).toBe(-270);
		expect(offsetMinutes('2026-11-05T13:35:42Z')).toBe(0);
		expect(formatOffset(0)).toBe('UTC+00:00');
		expect(formatOffset(-270)).toBe('UTC-04:30');
	});
	it('shows an uptime', () => {
		expect(formatUptime(3 * 3_600)).toBe('3 h');
		expect(formatUptime(86_400 + 7_200)).toBe('1 day 2 h');
		expect(formatUptime(12 * 86_400)).toBe('12 days 0 h');
	});
});
