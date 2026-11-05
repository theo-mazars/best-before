export class ApiError extends Error {
	constructor(
		readonly status: number,
		message: string,
		readonly field?: string
	) {
		super(message);
	}
}

export async function api<T = void>(method: string, path: string, body?: unknown): Promise<T> {
	const res = await fetch('/api/ui' + path, {
		method,
		headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
		body: body === undefined ? undefined : JSON.stringify(body)
	});
	const data = await res.json().catch(() => undefined);
	if (!res.ok) {
		throw new ApiError(res.status, data?.error ?? 'Something went wrong.', data?.field);
	}
	return data as T;
}

export type Session = {
	email: string;
	role: string;
	minSeverity: string;
	now: string;
	zone: string;
	setup?: boolean;
};

export type SeverityCount = { open: number; muted: number };

export const stripSeverities = ['critical', 'high', 'medium', 'low', 'unknown'] as const;
export type StripSeverity = (typeof stripSeverities)[number];

export type ServerSummary = {
	id: string;
	hostname: string;
	status: string;
	lastReportAt: string | null;
	critical: number;
	high: number;
	medium: number;
	knownExploited: number;
	noFixYet: number;
	accepted: number;
	securityUpdates: number;
	updates: number;
	rebootRequired: boolean;
	images: number;
	notChecked: number;
	severities: Record<StripSeverity, SeverityCount>;
	problems: string[];
};

export type Overview = {
	db: { ready: boolean; built?: string; lastError?: string };
	servers: ServerSummary[];
};
