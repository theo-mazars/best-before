import { toast } from 'svelte-sonner';
import { api, ApiError, type AlertsForm } from '#lib/api.js';

// The severities a digest or a page can start from, worst first.
export const severityChoices = [
	{ value: 'critical', label: 'Critical' },
	{ value: 'high', label: 'High or worse' },
	{ value: 'medium', label: 'Medium or worse' },
	{ value: 'low', label: 'Low or worse' }
];

// sameAlerts tells whether a form still holds what was saved.
export function sameAlerts(a: AlertsForm, b: AlertsForm): boolean {
	return JSON.stringify(normal(a)) === JSON.stringify(normal(b));
}

// normal puts the keys in one order and turns an empty score into none.
export function normal(f: AlertsForm): AlertsForm {
	const score = f.emergencyMinCvss as number | null | undefined | '';
	return {
		emergencyKnownExploited: f.emergencyKnownExploited,
		emergencyMinCvss: score === '' || score == null || Number.isNaN(score) ? null : Number(score),
		reminderDays: Number(f.reminderDays),
		digestWeekday: f.digestWeekday,
		digestTime: f.digestTime,
		digestTimezone: f.digestTimezone.trim(),
		digestEmergencies: f.digestEmergencies,
		digestStale: f.digestStale,
		digestUpdates: f.digestUpdates,
		digestNewMinSeverity: f.digestNewMinSeverity,
		digestAccepted: f.digestAccepted,
		digestAllClear: f.digestAllClear
	};
}

// saveAlerts stores the settings, and returns the field to fix, if any.
export async function saveAlerts(
	f: AlertsForm,
	refresh: () => Promise<unknown>
): Promise<{ field: string; message: string } | null> {
	try {
		await api('PUT', '/settings/alerts', normal(f));
	} catch (err) {
		const message = err instanceof ApiError ? err.message : 'Something went wrong.';
		const field = err instanceof ApiError ? (err.field ?? '') : '';
		if (!field) toast.error(message);
		return { field, message };
	}
	toast.success('Saved');
	await refresh();
	return null;
}
