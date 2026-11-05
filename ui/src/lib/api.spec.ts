import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, ApiError } from './api';

afterEach(() => vi.unstubAllGlobals());

describe('api', () => {
	it('sends JSON and returns the reply', async () => {
		const fetch = vi.fn().mockResolvedValue(new Response('{"ok":true}', { status: 200 }));
		vi.stubGlobal('fetch', fetch);
		expect(await api('POST', '/login', { a: 1 })).toEqual({ ok: true });
		expect(fetch).toHaveBeenCalledWith('/api/ui/login', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: '{"a":1}'
		});
	});

	it('throws the server error with its field', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn().mockResolvedValue(new Response('{"error":"Bad","field":"email"}', { status: 400 }))
		);
		await expect(api('POST', '/setup', {})).rejects.toEqual(new ApiError(400, 'Bad', 'email'));
	});

	it('accepts an empty reply', async () => {
		vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 204 })));
		expect(await api('POST', '/logout')).toBeUndefined();
	});
});
