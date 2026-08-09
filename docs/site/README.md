# llm-proxy docs site

Astro + Starlight, generated from the `starlight` template. This directory is
infrastructure only; content pages live under `src/content/docs/` and are
maintained separately (see `docs/user/` for the source material that will
eventually populate it).

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
- The sidebar spine (nine sections) is specified but commented out in
  `astro.config.mjs` until each section has at least one real page — an
  uncommented group pointing at a page that doesn't exist fails the build.

Check out [Starlight's docs](https://starlight.astro.build/) or
[the Astro documentation](https://docs.astro.build) for more.
