import { defineCollection, z } from 'astro:content';
import { docsLoader } from '@astrojs/starlight/loaders';
import { docsSchema } from '@astrojs/starlight/schema';

// Page metadata contract. Starlight renders `description` into the HTML
// <meta name="description"> and llms.txt, and `lastUpdated` in the footer.
// `summary` is a longer abstract for agents reading the Markdown source; it is
// not rendered. `related` lists docs slugs (for example
// `authentication/virtual-keys`); src/components/Footer.astro renders them
// and fails the build on a slug that names no page.
export const collections = {
	docs: defineCollection({
		loader: docsLoader(),
		schema: docsSchema({
			extend: z.object({
				description: z.string().max(200),
				summary: z.string().optional(),
				related: z.array(z.string()).optional(),
			}),
		}),
	}),
};
