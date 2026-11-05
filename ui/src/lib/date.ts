// offsetMinutes reads the UTC offset of an RFC 3339 time.
export function offsetMinutes(iso: string): number {
	const m = /([+-])(\d{2}):(\d{2})$/.exec(iso);
	return m ? (m[1] === '-' ? -1 : 1) * (Number(m[2]) * 60 + Number(m[3])) : 0;
}

export function formatOffset(minutes: number): string {
	const a = Math.abs(minutes);
	const pad = (n: number) => String(n).padStart(2, '0');
	return `UTC${minutes < 0 ? '-' : '+'}${pad(Math.floor(a / 60))}:${pad(a % 60)}`;
}

function parse(iso: string | null | undefined): number | undefined {
	const t = iso ? Date.parse(iso) : NaN;
	return isNaN(t) ? undefined : t;
}

export function formatUTC(iso: string | null | undefined): string {
	const t = parse(iso);
	return t === undefined ? '—' : new Date(t).toISOString().slice(0, 19).replace('T', ' ') + ' UTC';
}

const units: [number, string, string][] = [
	[365 * 86_400_000, 'year', 'years'],
	[30 * 86_400_000, 'month', 'months'],
	[86_400_000, 'day', 'days'],
	[3_600_000, 'h', 'h'],
	[60_000, 'min', 'min']
];

// timeAgo says how long ago, or in how long, a time is from now.
export function timeAgo(iso: string | null | undefined, now: number): string {
	const t = parse(iso);
	if (t === undefined) return '—';
	const diff = now - t;
	if (Math.abs(diff) < 60_000) return 'just now';
	for (const [ms, one, many] of units) {
		const n = Math.floor(Math.abs(diff) / ms);
		if (n >= 1) {
			const text = `${n} ${n === 1 ? one : many}`;
			return diff > 0 ? `${text} ago` : `in ${text}`;
		}
	}
	return 'just now';
}
