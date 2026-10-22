#!/usr/bin/env node
// Checks every link in the built site (dist/) and fails on a broken one.
//
// Run after `npm run build`: `npm run check-links`. Checked:
// - Links under the site base (/docs/llm-proxy/...): the page or file must
//   exist in dist/, and a #fragment must name an id on that page.
// - Other root-relative links (/foo): reported, because the site is served
//   under its base path, so they point outside the docs.
// - Links to this repository on GitHub (blob/ or tree/ on main): the path must
//   exist in the checkout, so a renamed example or source file is caught here
//   rather than by a reader.
// Other external links are not fetched; the check stays offline.
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const siteDir = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const dist = join(siteDir, 'dist');
const repoRoot = resolve(siteDir, '..', '..');
const BASE = '/docs/llm-proxy';
const REPO_PREFIX = /^https:\/\/github\.com\/ergonlabs-io\/llm-proxy\/(?:blob|tree)\/main\/([^#?]*)/;

if (!existsSync(dist)) {
	console.error('dist/ does not exist. Run `npm run build` first.');
	process.exit(2);
}

function htmlFiles(dir) {
	const out = [];
	for (const name of readdirSync(dir)) {
		const path = join(dir, name);
		if (statSync(path).isDirectory()) out.push(...htmlFiles(path));
		else if (name.endsWith('.html')) out.push(path);
	}
	return out;
}

const idCache = new Map();
function idsOf(file) {
	if (!idCache.has(file)) {
		const html = readFileSync(file, 'utf8');
		idCache.set(file, new Set([...html.matchAll(/\sid="([^"]*)"/g)].map((m) => m[1])));
	}
	return idCache.get(file);
}

// Maps a path under BASE to the file Astro wrote for it, or null.
function targetFile(path) {
	const rel = decodeURIComponent(path.slice(BASE.length)).replace(/^\//, '');
	const candidates = [join(dist, rel), join(dist, rel, 'index.html'), join(dist, `${rel}.html`)];
	return candidates.find((c) => existsSync(c) && statSync(c).isFile()) ?? null;
}

const errors = [];
let checked = 0;
for (const file of htmlFiles(dist)) {
	const page = '/' + relative(dist, file);
	const html = readFileSync(file, 'utf8');
	for (const [, raw] of html.matchAll(/\shref="([^"]*)"/g)) {
		const href = raw.replaceAll('&amp;', '&');
		checked++;
		const repo = href.match(REPO_PREFIX);
		if (repo) {
			if (!existsSync(join(repoRoot, decodeURIComponent(repo[1])))) {
				errors.push(`${page}: ${href} (no such path in the repository)`);
			}
			continue;
		}
		if (/^[a-z][a-z0-9+.-]*:/i.test(href) || href.startsWith('//')) continue;
		const [pathAndQuery, fragment] = href.split('#');
		const path = pathAndQuery.split('?')[0];
		let target;
		if (path === '') {
			target = file;
		} else if (path.startsWith(BASE + '/') || path === BASE) {
			target = targetFile(path);
		} else if (path.startsWith('/')) {
			errors.push(`${page}: ${href} (outside the site base ${BASE})`);
			continue;
		} else {
			const abs = resolve('/' + dirname(relative(dist, file)), path);
			target = targetFile(BASE + abs);
		}
		if (!target) {
			errors.push(`${page}: ${href} (no such page)`);
		} else if (fragment && target.endsWith('.html') && !idsOf(target).has(decodeURIComponent(fragment))) {
			errors.push(`${page}: ${href} (no id "${fragment}" on the target page)`);
		}
	}
}

if (errors.length > 0) {
	console.error(`${errors.length} broken link(s):`);
	for (const e of errors) console.error(`  ${e}`);
	process.exit(1);
}
console.log(`${checked} links checked, none broken.`);
