# Capacity report — 2026-08-23

The v0.2.0 gate asks for a published capacity report from a run that is **not
harness-bound**. This is that run. The headline number is real and
reproducible; read the "What is not saturated" section before quoting it as
the proxy's capacity, because it is a ceiling we impose on ourselves, not one
the hardware imposes.

- Commit: `74727414de95`
- Machine: MacBookPro18,3, 8 cores, 16 GB, macOS 26.5.2
- Command: `make sweep` (`scripts/capacity-sweep.sh`, defaults)
- Raw report: [`2026-08-23-chat-http2-128tok.json`](2026-08-23-chat-http2-128tok.json)

## Method

Open-loop, coordinated-omission-aware driver (`testing/loadgen`) against
`testing/mockupstream`, HTTP/2 on both hops, 128-token chat completions with
250 ms TTFT and 25 ms inter-token pacing — an intrinsic stream time of
3450 ms. Ramp-hold-bisect, 30 s hold per level after a 3 s warmup. SLO gate:
p99 ≤ 6900 ms and TTFT p99 ≤ 1000 ms.

80,507 requests served across 20 driven levels. `upstream_rq_total` and
`downstream_cx_total` agree exactly at 80,507.

## Result

**Max sustainable concurrency within SLO: 808.** First failing level: 809.

| concurrency | throughput (rps) | p50 ms | p99 ms | TTFT p99 ms | errors | peak RSS | mean CPU |
|---|---|---|---|---|---|---|---|
| 1 | 0.3 | 3727 | 3815 | 352 | 0 | 31.5 MB | 0% |
| 64 | 19.0 | 3711 | 3795 | 337 | 0 | 35.3 MB | 4% |
| 256 | 75.9 | 3709 | 3779 | 349 | 0 | 45.4 MB | 12% |
| 512 | 146.4 | 3719 | 3793 | 375 | 0 | 57.7 MB | 18% |
| 768 | 227.6 | 3715 | 3770 | 361 | 0 | 84.4 MB | 22% |
| **808** | **237.0** | **3705** | **3793** | **397** | **0** | **84.4 MB** | **22%** |
| 809 | 237.0 | 3721 | 7213 | 3777 | 0 | 84.4 MB | 21% |
| 1024 | 237.0 | 3744 | 7402 | 3977 | 0 | 84.4 MB | 22% |

Cost model, least-squares across all 20 levels:

- RSS ≈ 31.5 MB baseline + **63.8 KB per concurrent stream** (R² = 0.981)
- CPU ≈ 544 ms baseline + **0.871 ms per request** (R² = 0.973)

**Error rate was 0.00 at every level, including every failing one.** Levels
fail the SLO on latency, never on correctness — nothing is dropped or
truncated, requests just queue.

## Not harness-bound

`harness_bound: null` in the report, and `loadgen` exited 0. The rig
self-estimates ~16383 sustainable concurrent streams from the ephemeral port
range and fd limit, and a separate ~546 connects/sec churn ceiling — both far
above anything this run reached. The 808 ceiling is the proxy's, not the
harness's.

This matters because the harness has been wrong in this direction before: the
sweep only became trustworthy after two honesty bugs were fixed in `c029d44`
(all-failure levels rendering `Duration::MAX` as a plausible-looking latency,
and a guard that budgeted concurrency while ignoring connect churn).

## What is not saturated

Nothing. At the 808 ceiling the proxy sits at **22% CPU and 84 MB RSS** with a
zero error rate, and throughput has been pinned at exactly 237 rps since
concurrency 768. At 809 the TTFT p99 jumps from 397 ms to 3777 ms — almost
exactly one intrinsic stream time (3450 ms).

That combination — flat throughput, idle CPU, and a TTFT step of exactly one
stream duration — is the signature of a **fixed-slot queue**, not exhaustion.
It is the same signature that identified the previous 202-stream ceiling
(hyper's h2 server default `max_concurrent_streams: 200` against a pool that
held one connection per key), which WP-15 slice C fixed by holding a bounded
set of connections instead.

**The mechanism behind 808 is not diagnosed.** The obvious candidate does not
add up: `MAX_CONNECTIONS_PER_KEY = 4` and `SOFT_STREAMS_PER_CONNECTION = 100`
give 400 streams per worker, and the cache is per worker across 8 workers,
which does not produce 808. The number reproduces slice C's independently
measured 808 exactly, so it is stable and not noise. Finding the real cause is
the next piece of WP-15 work, and it should follow the same method that found
the last one: per-level evidence, not aggregates.

Read 808 as "the current ceiling, imposed by us, cause unknown" — not as a
hardware or design limit.

## Caveats

- The sweep warns that `--hold-secs 30` is under ten stream times, so
  percentiles at the lowest concurrency levels come from a handful of samples.
  This affects the low rows, not the ceiling.
- One upstream cluster, one route, no TLS on either hop, access logs off.
- The upstream is a mock with deterministic pacing. Real provider latency
  variance is not represented.
- macOS only. The Linux `/proc` sampler path remains unverified.
