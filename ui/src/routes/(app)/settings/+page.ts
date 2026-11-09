import { api, type SettingsPage } from '#lib/api.js';
import { guard } from '#lib/load.js';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ depends }) => {
	depends('app:settings');
	return { settings: await guard(api<SettingsPage>('GET', '/settings')) };
};
