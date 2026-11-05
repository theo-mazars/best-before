import { redirect } from '@sveltejs/kit';
import { api, type Session } from '#lib/api.js';
import { guard } from '#lib/load.js';
import { clock } from '#lib/clock.svelte.js';
import type { LayoutLoad } from './$types';

export const load: LayoutLoad = async () => {
	const session = await guard(api<Session>('GET', '/session'));
	if (session.setup) redirect(307, '/setup');
	clock.sync(session.now, session.zone);
	return { session };
};
