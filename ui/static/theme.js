// Sets the theme before the first paint, as the CSP forbids inline scripts.
const mode = localStorage.getItem('mode-watcher-mode');
const dark = mode === 'dark' || (mode !== 'light' && matchMedia('(prefers-color-scheme: dark)').matches);
document.documentElement.classList.toggle('dark', dark);
document.documentElement.style.colorScheme = dark ? 'dark' : 'light';
