# Performance and bundle measurements

Measurements belong to a named runtime and machine. They are observations, not guarantees. The
in-process benchmark measures valid proof verification with an in-memory replay store; it excludes
Supabase token authentication, network access, Next.js handler overhead, database cache misses, and
proof creation.

## Reproduce verifier latency

```sh
pnpm benchmark:verify
```

The script builds `@tether/core`, signs unique proofs before timing, warms the verifier, then reports
mean, p50, p95, p99, and maximum latency. Set `TETHER_BENCH_SAMPLES` to use at least 100 samples.

## Reproduce the browser client bundle size

Build the core package, bundle the public client entry for a browser, and gzip the minified result:

```sh
pnpm --filter @tether/core build
pnpm dlx esbuild@0.28.2 packages/client/src/index.ts --bundle --minify --format=esm --platform=browser --target=es2022 --outfile=packages/client/dist/client.measure.min.js
node -e "const fs=require('node:fs');const zlib=require('node:zlib');const p='packages/client/dist/client.measure.min.js';const b=fs.readFileSync(p);console.log(JSON.stringify({rawBytes:b.length,gzipBytes:zlib.gzipSync(b).length}))"
```

This measures the complete exported `@tether/client` entry and its tree-shaken dependencies, not the
larger Next.js example route or React/Supabase runtime.

## Current result

Measured in this workspace on Node.js 24.18.0, Windows x64, AMD Ryzen 9 8940HX:

| Measurement | Result | Target |
| --- | ---: | ---: |
| Core verifier mean | 0.197 ms | — |
| Core verifier p50 | 0.177 ms | — |
| Core verifier p95 | 0.311 ms | — |
| Core verifier p99 | 0.395 ms | under 1 ms |
| Core verifier maximum | 1.883 ms | — |
| `@tether/client` minified output | 8,189 bytes | — |
| `@tether/client` gzip output | 3,182 bytes | under 10 KB |

The verifier run used 300 warm-up proofs and 5,000 unique timed proofs. Bundle size used esbuild
0.28.2 and includes the complete client package entry. These local results meet the listed size and
in-process p99 targets on this machine; they do not measure network or Next.js request latency.
