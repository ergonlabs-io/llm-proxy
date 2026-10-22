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
	// Slugs that moved in the docs restructure (DOCS_STRUCTURE.md, "moved"),
	// so inbound links keep working. Sources are relative to `base`; destinations
	// include it.
	redirects: {
		'/providers-and-routing/providers-and-clusters': '/docs/llm-proxy/providers/overview/',
		'/providers-and-routing/websocket-and-upgrades': '/docs/llm-proxy/api-compatibility/realtime/',
		'/observability/admin-endpoints': '/docs/llm-proxy/administration/admin-api/',
		'/authentication/external-authorization': '/docs/llm-proxy/help/limitations/',
		'/operations/xds-conformance': '/docs/llm-proxy/help/limitations/',
	},
	integrations: [
		starlight({
			title: 'llm-proxy',
			description: 'A high-performance proxy for LLM inference APIs.',
			// Overrides Starlight's theme tokens only (accent, greys, fonts) so
			// these docs match ergonlabs.io, which serves them.
			customCss: ['./src/styles/custom.css'],
			// Adds the frontmatter `related` list to every page footer.
			components: { Footer: './src/components/Footer.astro' },
			// No `social` entry: `git remote -v` in this repo has no configured
			// remote to link to. Add one here once the repo has a GitHub home.
			plugins: [
				// Generates /llms.txt and /llms-full.txt at build time -- the
				// reason this project uses Starlight instead of a Rust-native
				// doc generator. See docs/site/README.md.
				starlightLlmsTxt(),
			],
			// The sidebar follows docs/site/DOCS_STRUCTURE.md, group for group.
			// A sidebar entry that points at a page that doesn't exist fails the
			// build. Change DOCS_STRUCTURE.md in the same commit as this list.
			sidebar: [
				// Way back to the site that serves these docs. External links are
				// left untouched by `base`, so this one is written in full.
				{ label: '← ergonlabs.io', link: 'https://ergonlabs.io/' },
				{
					label: 'Getting started',
					items: [
						{ label: 'Introduction', slug: 'getting-started/introduction' },
						{ label: 'Quickstart', slug: 'getting-started/quickstart' },
						{ label: 'Install llm-proxy', slug: 'getting-started/installation' },
						{ label: 'Core concepts', slug: 'getting-started/core-concepts' },
						{ label: 'Connect your application', slug: 'getting-started/connect-your-application' },
						{ label: 'Coming from LiteLLM or OpenRouter', slug: 'getting-started/coming-from-litellm-or-openrouter' },
					],
				},
				{
					label: 'Providers',
					items: [
						{ label: 'Overview', slug: 'providers/overview' },
						{ label: 'OpenAI', slug: 'providers/openai' },
						{ label: 'Anthropic', slug: 'providers/anthropic' },
						{ label: 'OpenRouter', slug: 'providers/openrouter' },
						{ label: 'Azure OpenAI', slug: 'providers/azure-openai' },
						{ label: 'Vertex AI', slug: 'providers/vertex-ai' },
						{ label: 'Amazon Bedrock', slug: 'providers/amazon-bedrock' },
						{ label: 'OpenAI-compatible servers', slug: 'providers/openai-compatible' },
					],
				},
				{
					label: 'API compatibility',
					items: [
						{ label: 'Overview', slug: 'api-compatibility/overview' },
						{ label: 'OpenAI Chat Completions', slug: 'api-compatibility/openai-chat-completions' },
						{ label: 'OpenAI Responses', slug: 'api-compatibility/openai-responses' },
						{ label: 'Anthropic Messages', slug: 'api-compatibility/anthropic-messages' },
						{ label: 'Realtime sessions', slug: 'api-compatibility/realtime' },
						{ label: 'Errors', slug: 'api-compatibility/errors' },
					],
				},
				{
					label: 'Configuration',
					items: [
						{ label: 'Configuration file', slug: 'configuration/configuration-file' },
						{ label: 'Models and routes', slug: 'configuration/models-and-routes' },
						{ label: 'Strict config mode', slug: 'configuration/strict-config-mode' },
					],
				},
				{
					label: 'Routing and reliability',
					items: [
						{ label: 'Failover and aggregates', slug: 'providers-and-routing/failover-and-aggregates' },
						{ label: 'Load balancing', slug: 'providers-and-routing/load-balancing' },
						{ label: 'The auto model', slug: 'providers-and-routing/auto-model' },
						{ label: 'Timeouts and retries', slug: 'providers-and-routing/timeouts-and-retries' },
					],
				},
				{
					label: 'Access control',
					items: [
						{ label: 'Virtual keys', slug: 'authentication/virtual-keys' },
						{ label: 'Manage configured virtual keys', slug: 'authentication/managing-secrets' },
						{ label: 'Tenant provider credentials', slug: 'authentication/tenant-provider-credentials' },
						{ label: 'Request guardrails', slug: 'authentication/guardrails' },
					],
				},
				{
					label: 'Limits and spend',
					items: [
						{ label: 'Configure rate limits', slug: 'limits-and-budgets/token-rate-limiting' },
						{ label: 'Pricing and cost tracking', slug: 'limits-and-budgets/pricing-and-cost-tracking' },
						{ label: 'Spend policies', slug: 'limits-and-budgets/spend-policies' },
						{ label: 'Read current usage', slug: 'limits-and-budgets/current-usage' },
						{ label: 'Billing ledger', slug: 'limits-and-budgets/billing-ledger' },
						{ label: 'Chargeback tags', slug: 'limits-and-budgets/chargeback-tags' },
					],
				},
				{
					label: 'Observability',
					items: [
						{ label: 'Observability overview', slug: 'observability/overview' },
						{ label: 'Access logs', slug: 'observability/access-logs' },
						{ label: 'Metrics and /stats', slug: 'observability/metrics-and-stats' },
						{ label: 'Tracing', slug: 'observability/tracing' },
						{ label: 'Request records', slug: 'observability/request-capture' },
						{ label: 'Request and response body export', slug: 'observability/trace-export' },
					],
				},
				{
					label: 'Administration',
					items: [
						{ label: 'Admin API', slug: 'administration/admin-api' },
						{ label: 'Admin UI', slug: 'administration/admin-ui' },
					],
				},
				{
					label: 'Operations',
					items: [
						{ label: 'Deployment', slug: 'operations/deployment' },
						{ label: 'Share state across replicas', slug: 'operations/running-in-production' },
						{ label: 'TLS', slug: 'operations/tls' },
						{ label: 'Reload configuration', slug: 'operations/config-reload' },
						{ label: 'Draining and shutdown', slug: 'operations/draining-and-shutdown' },
					],
				},
				{
					label: 'Reference',
					items: [
						{ label: 'CLI', slug: 'reference/cli' },
						{ label: 'Configuration fields', slug: 'configuration/reference' },
						{ label: 'Response flags', slug: 'reference/response-flags' },
						{ label: 'Metrics', slug: 'reference/metrics' },
						{ label: 'Environment variables', slug: 'reference/environment-variables' },
						{ label: 'Glossary', slug: 'reference/glossary' },
					],
				},
				{
					label: 'Help',
					items: [
						{ label: 'Troubleshooting', slug: 'help/troubleshooting' },
						{ label: 'FAQ', slug: 'help/faq' },
						{ label: 'Limitations', slug: 'help/limitations' },
					],
				},
			],
		}),
	],
});
