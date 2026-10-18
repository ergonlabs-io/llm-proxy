# llm-proxy docs site

Astro + Starlight. User documentation lives under `src/content/docs/`.
The configuration field reference is generated from the normative dialect
schema with `make config-reference`; edit the schema rather than its generated
page. Hand-written guides should be checked against the implementation and
schema when behavior changes.

## Commands

From the repo root:

```
make docs-dev      # dev server at localhost:4321
make docs-build    # production build to docs/site/dist/
```

Or from this directory directly:

| Command           | Action                                       |
| :----------------- | :-------------------------------------------- |
| `npm install`      | Install dependencies                          |
| `npm run dev`       | Start local dev server                        |
| `npm run build`     | Build the production site to `./dist/`        |
| `npm run preview`   | Preview a build locally                       |

## Notable configuration

- **`starlight-llms-txt`** is installed and enabled in `astro.config.mjs`. It
  generates `dist/llms.txt` and `dist/llms-full.txt` on every build — this is
  why the site uses Astro/Starlight rather than a Rust-native doc generator.
- **Pagefind** search is Starlight's default and needs no extra setup; it
  indexes at build time into `dist/pagefind/`.
- Active sidebar sections and page slugs live in `astro.config.mjs`. Add a
  page there when it should appear in navigation. Commented entries describe
  pages that have not been added yet.

Check out [Starlight's docs](https://starlight.astro.build/) or
[the Astro documentation](https://docs.astro.build) for more.
