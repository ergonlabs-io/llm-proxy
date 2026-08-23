// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLlmsTxt from 'starlight-llms-txt';

// https://astro.build/config
export default defineConfig({
	// `starlight-llms-txt` needs an absolute `site` to build the URLs it lists
	// in llms.txt/llms-full.txt (Astro also uses it for the sitemap).
	// The docs are served from the ergonlabs marketing site, one path segment
	// per product, so `base` has to match where the built `dist/` is copied to.
	site: 'https://ergonlabs.io',
	base: '/docs/llm-proxy',
	integrations: [
		starlight({
			title: 'llm-proxy',
			description: 'A high-performance proxy for LLM inference APIs.',
			// No `social` entry: `git remote -v` in this repo has no configured
			// remote to link to. Add one here once the repo has a GitHub home.
			plugins: [
				// Generates /llms.txt and /llms-full.txt at build time -- the
				// reason this project uses Starlight instead of a Rust-native
				// doc generator. See docs/site/README.md.
				starlightLlmsTxt(),
			],
			// The sidebar spine is specified (WP doc-scaffold) as nine groups.
			// A sidebar entry that points at a page that doesn't exist fails the
			// build, so a group (or an item within it) stays commented out until
			// its page lands. Uncomment an item (and add its page under
			// src/content/docs/<slug>/) as content arrives; keep the group order
			// and item labels as specified.
			sidebar: [
				{
					label: 'Getting started',
					items: [
						{ label: 'Introduction', slug: 'getting-started/introduction' },
						{ label: 'Quickstart', slug: 'getting-started/quickstart' },
						// {
						// 	label: 'Choosing a config front-end',
						// 	slug: 'getting-started/choosing-a-config-front-end',
						// },
					],
				},
				{
					label: 'Configuration',
					items: [
						{ label: 'Configuration file', slug: 'configuration/configuration-file' },
						// { label: 'Strict config mode', slug: 'configuration/strict-config-mode' },
					],
				},
				// {
				// 	label: 'Providers and routing',
				// 	items: [
				// 		{ label: 'Providers and clusters', slug: 'providers-and-routing/providers-and-clusters' },
				// 		{ label: 'Failover and aggregates', slug: 'providers-and-routing/failover-and-aggregates' },
				// 		{ label: 'Load balancing', slug: 'providers-and-routing/load-balancing' },
				// 		{ label: 'Timeouts and retries', slug: 'providers-and-routing/timeouts-and-retries' },
				// 	],
				// },
				// {
				// 	label: 'API compatibility',
				// 	items: [
				// 		{ label: 'OpenAI Chat Completions', slug: 'api-compatibility/openai-chat-completions' },
				// 		{ label: 'OpenAI Responses', slug: 'api-compatibility/openai-responses' },
				// 		{ label: 'Anthropic Messages', slug: 'api-compatibility/anthropic-messages' },
				// 	],
				// },
				// {
				// 	label: 'Authentication',
				// 	items: [
				// 		{ label: 'Virtual keys', slug: 'authentication/virtual-keys' },
				// 		{ label: 'Managing secrets', slug: 'authentication/managing-secrets' },
				// 	],
				// },
				// {
				// 	label: 'Limits and budgets',
				// 	items: [
				// 		{ label: 'Token rate limiting', slug: 'limits-and-budgets/token-rate-limiting' },
				// 		{ label: 'Tenants', slug: 'limits-and-budgets/tenants' },
				// 	],
				// },
				{
					label: 'Observability',
					items: [
						{ label: 'Access logs', slug: 'observability/access-logs' },
						{ label: 'Metrics and /stats', slug: 'observability/metrics-and-stats' },
						// { label: 'Admin endpoints', slug: 'observability/admin-endpoints' },
					],
				},
				{
					label: 'Operations',
					items: [
						// { label: 'Running in production', slug: 'operations/running-in-production' },
						{ label: 'Config reload', slug: 'operations/config-reload' },
						{ label: 'Draining and shutdown', slug: 'operations/draining-and-shutdown' },
						// { label: 'TLS', slug: 'operations/tls' },
					],
				},
				{
					label: 'Reference',
					items: [
						{ label: 'CLI', slug: 'reference/cli' },
						// { label: 'Config schema', slug: 'reference/config-schema' },
						// { label: 'Response flags', slug: 'reference/response-flags' },
					],
				},
			],
		}),
	],
});
