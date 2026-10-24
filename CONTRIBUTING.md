# Contributing to llm-proxy

Thank you for your interest in llm-proxy. This file tells you how to report a
problem, propose a change, and get a pull request merged.

llm-proxy has one maintainer. The 1.x releases follow the
[stability policy](https://ergonlabs.io/docs/llm-proxy/reference/stability/), so a change
that removes or renames a stable surface waits for a major release. Reviews
are a best effort, so a small, focused pull request is merged sooner than a
large one.

## Report a problem

- **Security vulnerability:** do not open a public issue. Follow
  [SECURITY.md](SECURITY.md).
- **Bug:** open an issue with the bug report template. Include the version
  (`llm-proxy --version`), the configuration (with secrets removed), the
  request you sent, and what you expected.
- **Feature request:** open an issue with the feature request template. Tell
  us the problem first, then the solution you have in mind.

Before you open an issue, read
[Limitations](docs/site/src/content/docs/help/limitations.md). Many gaps are
known and documented.

## Propose a change

For a change larger than a bug fix, open an issue first. Agree on the design
before you write the code. This applies especially to the configuration
surface, the IR in `crates/proxy-config/src/ir.rs`, and the filter traits,
which other crates depend on.

## Set up

You need [rustup](https://rustup.rs), a C toolchain, and `protoc`.
`rust-toolchain.toml` pins the Rust version, so `rustup` installs it on the
first build.

```sh
xcode-select --install; brew install protobuf        # macOS
sudo apt install build-essential protobuf-compiler   # Debian and Ubuntu
cargo build -p proxy
```

The Go QA suite in `testing/qa` needs Go. The docs site in `docs/site` needs
Node.js 22 or later.

## Rules for code

[AGENTS.md](AGENTS.md) holds the full set of conventions. These are the rules
that reviews check most often:

- **Strict configuration.** Every configuration field maps to the IR or fails
  with its full dotted path. A field that is silently ignored is a bug.
- **Per-provider values belong on the cluster, not the route.** Credentials
  and host rewrites that sit on a route follow the routing decision and can
  reach the wrong provider on failover.
- **No `unsafe`.** It is denied in the whole workspace.
- **No `unwrap()` outside tests.** Use `?`, `if let`, or `let ... else`. Where a
  panic is correct, use `expect("...")` and state the invariant.
- **Comments explain why.** Do not cite issue numbers or plans in comments; git
  history records where a change came from.
- **Envoy semantics.** The proxy follows Envoy v1.38 behaviour. A deliberate
  departure needs a test that pins it and a note in the pull request.

## Test your change

Every change includes a test that proves the behaviour. Use the `make`
targets, not bare `cargo test`:

```sh
make tq-changed   # tests for the crates you changed
make tq           # the full workspace
make ci           # format, lint, tests, doctests, and QA: what CI runs
```

For a documentation change, build the site and check its links:

```sh
cd docs/site && npm ci && cd ../..
make docs-check
```

## Pull requests

- Keep one logical change in each pull request.
- Write the commit message in the imperative mood ("Add ...", "Fix ...") and
  say why the change is necessary.
- Update the documentation in `docs/site` when you change behaviour that users
  can see. Update `CHANGELOG.md` for a user-visible change.
- Make sure that `make ci` passes.

## Licence

llm-proxy is licensed under Apache-2.0. Unless you state otherwise, any
contribution that you submit for inclusion is licensed under Apache-2.0, as
section 5 of the [licence](LICENSE) says, with no additional terms.

## Code of conduct

All participants must follow the [code of conduct](CODE_OF_CONDUCT.md).
