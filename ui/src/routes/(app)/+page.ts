import { api, type Overview } from '#lib/api.js';
import { guard } from '#lib/load.js';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ depends }) => {
	depends('app:overview');
	return { overview: await guard(api<Overview>('GET', '/overview')) };
};
