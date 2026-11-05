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
