import { offsetMinutes } from './date.js';

// clock is the dashboard's time, so time-ago labels and the server time do
// not depend on the browser's clock. It ticks every second.
let timer: ReturnType<typeof setInterval> | undefined;

class Clock {
	#skew = 0;
	#tick = $state(Date.now());
	offset = $state(0);
	zone = $state('');

	get now() {
		return this.#tick + this.#skew;
	}

	sync(serverNow: string, zone: string) {
		this.#skew = Date.parse(serverNow) - Date.now();
		this.offset = offsetMinutes(serverNow);
		this.zone = zone;
		this.#tick = Date.now();
		timer ??= setInterval(() => (this.#tick = Date.now()), 1000);
	}
}

export const clock = new Clock();
