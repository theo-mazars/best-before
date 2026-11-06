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
	emergencies: number;
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

export type CveState = 'open' | 'noFix' | 'below' | 'accepted' | 'oldKernel';

export type Cve = {
	id: string;
	url: string;
	severity: string;
	cvss: number;
	knownExploited: boolean;
	fixVersions: string[];
	firstSeenAt: string;
	state: CveState;
	emergency: boolean;
	risk: { reason: string; acceptedBy: string; acceptedAt: string; expiresAt: string } | null;
};

export type PackageRow = {
	where: string;
	target: string;
	package: string;
	version: string;
	kind: string;
	severities: Record<StripSeverity, SeverityCount>;
	knownExploited: boolean;
	maxCvss: number;
	updateTo: string;
	reboot: string;
	emergency: boolean;
	muted: boolean;
	cves: Cve[];
};

export type ImageInfo = {
	id: string;
	references: string[];
	containers: string[];
	os: string;
	notChecked: string;
	checked: string[];
	imprecise: string[];
	nothingChecked: boolean;
	where: string;
	severities: Record<StripSeverity, SeverityCount>;
};

export type ServerPage = {
	server: ServerSummary;
	db: Overview['db'];
	report: {
		receivedAt: string;
		matched: boolean;
		matchedAt: string | null;
		dbBuilt: string | null;
	} | null;
	host: {
		os: string;
		kernel: string;
		uptimeSeconds: number;
		rebootRequired: boolean;
		rebootPackages: string[];
		listsPublishedAt: string | null;
		agentVersion: string;
	} | null;
	oldKernels: { abi: string; packages: string[]; vulnerabilities: number; newer: boolean }[];
	upgradable: { name: string; current: string; candidate: string; security: boolean }[];
	packages: PackageRow[];
	images: ImageInfo[];
	risk: { min: string; max: string; default: string };
};
