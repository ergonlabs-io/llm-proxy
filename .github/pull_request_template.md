## What this changes

<!-- One or two sentences: the behaviour before, the behaviour after, and why. -->

## How it is tested

<!-- Name the test that proves the behaviour. Code that only compiles is not done. -->

## Checklist

- [ ] `make ci` passes.
- [ ] User-visible behaviour is documented in `docs/site`, and `CHANGELOG.md` is updated.
- [ ] A new configuration field maps to the IR or fails with its full dotted path.
- [ ] No per-provider value (credential, host rewrite) is attached to a route.
- [ ] No secrets in the diff, the tests, or the commit message.
