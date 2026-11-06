import { ApiError, api, type ServerPage } from '#lib/api.js';
import { guard } from '#lib/load.js';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ params, depends }) => {
	depends('app:server');
	try {
		return { server: await guard(api<ServerPage>('GET', '/servers/' + params.id)) };
	} catch (e) {
		if (e instanceof ApiError && e.status === 404) return { server: null };
		throw e;
	}
};
