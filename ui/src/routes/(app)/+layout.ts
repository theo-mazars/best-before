import { redirect } from '@sveltejs/kit';
import { api, type Overview, type Session } from '#lib/api.js';
import { guard } from '#lib/load.js';
import { clock } from '#lib/clock.svelte.js';
import type { LayoutLoad } from './$types';

// The servers are loaded here for the sidebar, and used by the servers page.
export const load: LayoutLoad = async ({ depends }) => {
	depends('app:overview');
	const session = await guard(api<Session>('GET', '/session'));
	if (session.setup) redirect(307, '/setup');
	clock.sync(session.now, session.zone);
	return { session, overview: await guard(api<Overview>('GET', '/overview')) };
};
