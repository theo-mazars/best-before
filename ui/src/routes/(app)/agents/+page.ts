import { api, type AgentsPage } from '#lib/api.js';
import { guard } from '#lib/load.js';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ depends }) => {
	depends('app:agents');
	return { agents: await guard(api<AgentsPage>('GET', '/agents')) };
};
