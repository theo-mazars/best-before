import { redirect } from '@sveltejs/kit';
import { ApiError } from './api.js';

// guard sends the browser to the login page when the session is gone.
export async function guard<T>(p: Promise<T>): Promise<T> {
	try {
		return await p;
	} catch (e) {
		if (e instanceof ApiError && e.status === 401) redirect(307, '/login');
		throw e;
	}
}
