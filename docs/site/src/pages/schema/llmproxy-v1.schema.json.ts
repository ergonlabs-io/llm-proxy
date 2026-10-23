// Serves the normative --config schema at the URL in its `$id`:
// https://ergonlabs.io/docs/llm-proxy/schema/llmproxy-v1.schema.json
// Editors (yaml-language-server) fetch it from there. The build copies the
// repository's schema/ file byte for byte, so there is no second copy to drift.
import type { APIRoute } from 'astro';
import schema from '../../../../../schema/llmproxy-v1.schema.json?raw';

export const GET: APIRoute = () =>
	new Response(schema, { headers: { 'Content-Type': 'application/schema+json' } });
