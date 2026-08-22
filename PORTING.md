# Porting notes: an nginx zstd filter module

This repository starts from the test infrastructure and the shared
header layer of a reworked `ngx_brotli`, with the filter module itself
deliberately left unwritten. Everything below is either a constraint
that cost measurement to establish, or a decision already taken so it
does not need retaking.

Read this before changing anything. It replaces the usual `CLAUDE.md`
and carries the same weight.

---

## 1. Hard constraints

**Per-request memory outranks compression ratio.** This is the binding
constraint, not a preference. Measure peak per-request memory before
proposing any encoder tuning that buys ratio. The Brotli module this
derives from defaults to a 64 KB window (`lg_win` 16) for exactly this
reason, not because larger windows were untested.

**`ZSTD_c_nbWorkers` stays at 0.** zstd's built-in multithreading is a
tempting knob and it is the wrong one here. nginx already parallelises
across worker processes, one per core, so under load every core is
compressing something already — a per-worker thread pool only
oversubscribes. Intra-request parallelism helps only at low
concurrency, which is when nobody is waiting.

**`ngx_config.h` must be included first**, before `<zstd.h>` and before
the local headers. On Linux it reaches `ngx_linux_config.h`, which
defines `_GNU_SOURCE` and `_FILE_OFFSET_BITS`; those are not on the
compiler command line. Put a libc-touching header first and glibc's
feature set latches without `_GNU_SOURCE`, `struct in6_pktinfo` stays
hidden, and `ngx_event_udp.h` fails with `field 'pkt6' has incomplete
type`. Darwin declares that struct unconditionally and **cannot show
the failure**, so this breaks only in CI.

**`-Werror` is on.** Two consequences learned the hard way: a build
that fails leaves the previous binary in place, so a test suite can
"pass" against stale code — always check the build's exit status
before believing a green run. And removing the last use of a local is
an error, not a warning, which can turn a one-line experiment into a
compile failure that looks unrelated.

**Style**: 70-column limit, nginx declare-at-top locals (declare at the
top of the function, assign below), `.clang-format` is authoritative
and CI enforces it. `deps/` is vendored — never reformat it.

**`const` only where it constrains a pointee.** `const T *p` is
information: it crosses function boundaries and cannot be verified by
reading the function alone. `T *const p` on a local is a restatement of
what a reader can already see, changes no generated code, and fights
`AlignConsecutiveDeclarations`. nginx uses the second form for a local
exactly zero times across 260 `.c` files. `static const` on string
constants *is* load-bearing: it places them in read-only data and lets
the compiler fold them; dropping it costs about 5 instructions at
`-O2` and moves them into writable memory.

---

## 2. The reference: zstd's streaming example

From `facebook/zstd/examples/streaming_compression.c`:

```c
size_t const buffInSize  = ZSTD_CStreamInSize();
size_t const buffOutSize = ZSTD_CStreamOutSize();
ZSTD_CCtx* const cctx = ZSTD_createCCtx();
ZSTD_CCtx_setParameter(cctx, ZSTD_c_compressionLevel, cLevel);
ZSTD_CCtx_setParameter(cctx, ZSTD_c_checksumFlag, 1);

for (;;) {
    size_t read = fread_orDie(buffIn, toRead, fin);
    int const lastChunk = (read < toRead);
    ZSTD_EndDirective const mode = lastChunk ? ZSTD_e_end
                                             : ZSTD_e_continue;
    ZSTD_inBuffer input = { buffIn, read, 0 };
    int finished;
    do {
        ZSTD_outBuffer output = { buffOut, buffOutSize, 0 };
        size_t const remaining =
            ZSTD_compressStream2(cctx, &output, &input, mode);
        CHECK_ZSTD(remaining);
        fwrite_orDie(buffOut, output.pos, fout);
        finished = lastChunk ? (remaining == 0)
                             : (input.pos == input.size);
    } while (!finished);
    if (lastChunk) break;
}
ZSTD_freeCCtx(cctx);
```

### Why it cannot be used as written

`fwrite_orDie` blocks until the bytes are gone.
`ngx_http_next_body_filter` does not — it may return `NGX_AGAIN`,
meaning downstream took some or none of the buffer and you must come
back later. So the inner `do { } while (!finished)` **cannot be a
loop**: the filter has to suspend between producing output and having
it accepted, then resume on a later call with a different input chain.

Everything else in this document follows from that one fact.

---

## 3. Architecture

### Context

```c
typedef struct {
    ZSTD_CCtx   *cctx;
    ngx_chain_t *in;            /* unconsumed input, ours to free */
    ngx_chain_t *out_chain;     /* single link wrapping out_buf */
    ngx_buf_t   *out_buf;       /* WE own this memory now */
    u_char      *out_start;
    size_t       out_size;      /* see the open question in §7 */

    off_t        content_length;
    unsigned     accepted_for_compression : 1;
    unsigned     initialized : 1;
    unsigned     closed : 1;
    unsigned     end_of_input : 1;   /* last_buf seen, e_end issued */
    unsigned     frame_closed : 1;   /* remaining == 0 at e_end */
    unsigned     caller_wants_output : 1;
    ngx_http_zstd_output_e output;   /* IDLE | READY | BUSY */
    ngx_http_request_t *request;
} ngx_http_zstd_ctx_t;
```

The one structural departure from the Brotli module: `out_buf` points
at memory **we allocated**. Brotli's `BrotliEncoderTakeOutput` handed
back a borrowed pointer into encoder-owned memory, so the filter never
allocated an output buffer. zstd has no equivalent — verified, there is
no `TakeOutput` in `zstd.h` — so you supply a `ZSTD_outBuffer` and own
it for the life of the request.

### The loop

`take_output` and `feed_encoder` **merge**: `ZSTD_compressStream2`
moves input and output in one call, so the Brotli module's three-phase
loop becomes two.

```c
for (;;) {
    if (ctx->output != NGX_HTTP_ZSTD_OUTPUT_IDLE) {
        step = zstd_send_output(ctx);   /* may yield STEP_AGAIN */
    } else {
        step = zstd_compress(ctx);
    }

    switch (step) {
        case STEP_CONTINUE: break;
        case STEP_DONE:     return NGX_OK;
        case STEP_AGAIN:    return NGX_AGAIN;
        default:            zstd_close(ctx); return NGX_ERROR;
    }
}
```

### The step that does the work

```c
static ngx_int_t
zstd_compress(ngx_http_zstd_ctx_t *ctx)
{
    ZSTD_inBuffer     in;
    ZSTD_outBuffer    out;
    ZSTD_EndDirective mode;
    size_t            remaining;
    ngx_buf_t        *b;

    if (ctx->in == NULL) {
        if (ctx->frame_closed) {
            return STEP_DONE;
        }
        if (!ctx->end_of_input && !ctx->caller_wants_output) {
            return STEP_DONE;               /* wait for more input */
        }
        mode = ctx->end_of_input ? ZSTD_e_end : ZSTD_e_flush;
        in.src = NULL; in.size = 0; in.pos = 0;
    } else {
        b = ctx->in->buf;
        mode = b->last_buf ? ZSTD_e_end
             : b->flush    ? ZSTD_e_flush
                           : ZSTD_e_continue;
        in.src  = b->pos;
        in.size = ngx_buf_size(b);
        in.pos  = 0;
    }

    out.dst  = ctx->out_start;
    out.size = ctx->out_size;
    out.pos  = 0;

    remaining = ZSTD_compressStream2(ctx->cctx, &out, &in, mode);
    if (ZSTD_isError(remaining)) {
        return STEP_FAILED;
    }

    /* Record progress in the chain itself. The example keeps it in
       input.pos, which does not survive returning to nginx. */
    if (ctx->in) {
        ctx->in->buf->pos += in.pos;
        if (ngx_buf_size(ctx->in->buf) == 0) {
            ngx_chain_t *link = ctx->in;
            if (link->buf->last_buf) {
                ctx->end_of_input = 1;
            }
            ctx->in = link->next;
            ngx_free_chain(ctx->request->pool, link);
        }
    }

    if (mode == ZSTD_e_end && remaining == 0) {
        ctx->frame_closed = 1;              /* the example's `finished` */
    }

    if (out.pos == 0) {
        return ctx->frame_closed ? STEP_DONE : STEP_CONTINUE;
    }

    ctx->out_buf->pos      = ctx->out_start;
    ctx->out_buf->last     = ctx->out_start + out.pos;
    ctx->out_buf->flush    = (mode == ZSTD_e_flush);
    ctx->out_buf->last_buf = ctx->frame_closed;
    ctx->output = NGX_HTTP_ZSTD_OUTPUT_READY;
    return STEP_CONTINUE;
}
```

### How the example's invariants map

| example | here |
| --- | --- |
| `lastChunk = (read < toRead)` | `b->last_buf` — nginx tells you |
| `finished = (remaining == 0)` | `ctx->frame_closed`, sticky |
| `finished = (input.pos == input.size)` | buffer drained, free the link |
| `do { } while (!finished)` | outer loop plus `STEP_CONTINUE` |
| `fwrite_orDie` | `send_output()`, may yield `STEP_AGAIN` |

---

## 4. API mapping from the Brotli module

| Brotli | zstd |
| --- | --- |
| `BROTLI_OPERATION_PROCESS` | `ZSTD_e_continue` |
| `BROTLI_OPERATION_FLUSH` | `ZSTD_e_flush` |
| `BROTLI_OPERATION_FINISH` | `ZSTD_e_end` |
| `BrotliEncoderIsFinished` | `compressStream2` returning 0 at `e_end` |
| `BrotliEncoderHasMoreOutput` / `TakeOutput` | *(no equivalent — you own the buffer)* |
| `BROTLI_PARAM_QUALITY` (0–11) | `ZSTD_c_compressionLevel` (1–22, negatives allowed) |
| `BROTLI_PARAM_LGWIN` | `ZSTD_c_windowLog` |
| known `content_length` → window tuning | `ZSTD_CCtx_setPledgedSrcSize` |
| `BROTLI_BOOL ok` | `ZSTD_isError(rc)` |
| custom allocator in `CreateInstance` | `ZSTD_createCCtx_advanced(ZSTD_customMem)` — **experimental API**, see §7 |

Deliberate departures from the example:

- **No `ZSTD_c_checksumFlag`.** The example sets it; over HTTP it is
  four wasted bytes beneath TLS and TCP integrity.
- **No input buffer.** The example reads into `buffIn`. Point
  `ZSTD_inBuffer` at `buf->pos` directly and let the chain own the
  bytes.
- **`ZSTD_CCtx_setPledgedSrcSize`** when the length is known: it writes
  the size into the frame header, helping the decoder allocate.

---

## 5. What is in this repository

| path | state |
| --- | --- |
| `module/common/ngx_http_zstd_headers.h` | adapted and compiles under `-Wall -Werror`; token is `"zstd"` (4 chars), `Content-Encoding: zstd` |
| `module/filter/ngx_http_zstd_filter_module.c` | **implemented** — the architecture in §3, built and passing the full suite below |
| `module/static/ngx_http_zstd_static_module.c` | **implemented** — mechanical port, no encoder involved |
| `config`, `module/filter/config`, `module/static/config` | **implemented** — builds against the vendored `deps/zstd` submodule, statically |
| `deps/zstd` | **submodule, pinned at `v1.5.7`** — see §7 for why it's vendored rather than taken from the system |
| `script/build.sh` | **implemented** — was referenced by `run-tests.sh` and CI but missing from the initial commit; now builds `deps/zstd` before nginx |
| `script/test.conf`, `script/test_h2.conf` | **implemented** — also missing from the initial commit; `run-tests.sh` needs both |
| `script/test_stream.py`, `script/test_stream.conf` | **adapted** — directives, tokens, log lines, `.zst` extension; 44/44 passing against a `--with-debug` build |
| `script/run-tests.sh` | **adapted** — 18/18 passing over HTTP/1.1 and HTTP/2 |
| `script/prepare-tests.sh` | verbatim copy (encoding-agnostic) |
| `script/bench_corpus.py` | **adapted** — used to measure the §7 defaults below |
| `script/corpus/` | verbatim, with `PROVENANCE.md` — real-world HTML/CSS/JS/prose |
| `script/fuzz/` | **adapted**: harness, seed corpus and dictionary now target the `zstd` token; 7M+ exec fuzzed clean |
| `.github/workflows/ci.yml` | **adapted** — builds `deps/zstd` from source in place of the Brotli build it replaces |
| `.clang-format` | verbatim; `clang-format --dry-run --Werror` passes on every `.c`/`.h` file above |
| `.gitignore` | **adapted** — `tmp/` was missing (see §8); `deps/zstd/out/` replaces the old blanket `deps/` entry |

Built and run locally against nginx `stable-1.30` (the CI ref) with
`--with-debug --with-http_v2_module`, both `script/test_stream.py`
and `script/run-tests.sh` green, and the fuzz target replayed and
run for 7M+ executions with no crash.

---

## 6. Adapting the copied harness

Do this **before** writing encoder code, against a stub filter that
passes bytes through unchanged. A green suite before the first real
line means every later change is measured.

1. **`script/test_stream.py`** — rename `brotli`→`zstd` throughout;
   point decoder discovery at the `zstd` CLI (`locate_decoder`,
   `locate_encoder`); change the `Accept-Encoding` value and the
   expected `content-encoding` to `zstd`; `.br` fixtures become `.zst`.
   The `Upstream` class, the abort and encoder-lifetime tests, the
   `/vary/` cases and the chain-cleanup checks are encoding-agnostic
   and should not need touching.
2. **`script/test_stream.conf`** — `brotli*` directives become
   `zstd*`. Keep the `/vary/` location and its `gzip_vary off`: that
   line is the *only* reason `check_vary`'s loop is reachable, and
   without it those seven tests silently cover nothing.
3. **`script/fuzz/`** — the target only exercises the shared
   `Accept-Encoding` parser. Change the include and the seed corpus
   tokens; the ASan-visible heap allocation sized exactly to the input
   is the whole point of the harness and must stay.
4. **`.github/workflows/ci.yml`** — swap the Brotli submodule build for
   a zstd one (`deps/zstd`, see below); the shape of the step barely
   changes. Keep the `format` job pinned to a distribution with
   clang-format 19+ — `.clang-format` sets `AlignFunctionDeclarations`,
   and an older clang-format rejects the whole file rather than that
   one key.
5. **`script/run-tests.sh`** — swap the decompressor to `zstd -d`.

---

## 7. Decisions, and what settled them

**zstd is vendored at `deps/zstd`, not taken from the system.** A
later decision than the rest of this section, and it supersedes §6
item 4's original "no vendored dependency is needed": some
distributions ship a zstd old enough to be missing API this module
uses, and pinning the submodule (currently `v1.5.7`) keeps the build
on the same version everywhere rather than whatever `apt`/`brew`
happen to have. Mirrors the Brotli module's own `deps/brotli` exactly
— `git submodule add https://github.com/facebook/zstd deps/zstd`,
checked out at the pinned tag — down to `module/filter/config`'s
error message when the submodule hasn't been checked out.
`script/build.sh` builds it via `cmake -S deps/zstd/build/cmake -B
deps/zstd/out`, static only (`ZSTD_BUILD_SHARED=OFF`) so the test
runs stay free of `LD_LIBRARY_PATH` handling, and with
`ZSTD_MULTITHREAD_SUPPORT=OFF` and `ZSTD_LEGACY_SUPPORT=OFF` - the
first because `ZSTD_c_nbWorkers` never leaves 0 (§1) so the pthread
dependency it pulls in buys nothing, the second because decoding
pre-1.0 zstd frames is not something an encoder-only module ever
does. The `zstd` target also builds the CLI at
`deps/zstd/out/programs/zstd`, which `run-tests.sh` and
`test_stream.py` fall back to when there is no `zstd` on `PATH`,
exactly as the Brotli scripts fall back to `deps/brotli/out/brotli`.

One gotcha worth recording: on a Mac with both an Apple Silicon and
an Intel Homebrew prefix, whichever `cmake` resolves first on `PATH`
governs what architecture it builds for when run under Rosetta - it
is not guaranteed to match `uname -m` on the host. The symptom is
nginx's own build succeeding (its own `./configure`/`make` picks the
native arch correctly) while linking fails with "symbol(s) not found
for architecture arm64" against a `libzstd.a` that turns out to be
x86_64 (`lipo -info` on the archive shows this immediately). Not a
concern in CI, which runs single-arch, but worth knowing before
chasing it as a code problem.

The three measurements below were originally taken against the
system's dynamically-linked `libzstd` and re-run after vendoring to
check whether static linking, `ZSTD_MULTITHREAD_SUPPORT=OFF` or
`ZSTD_LEGACY_SUPPORT=OFF` had moved anything. They hadn't: every
compressed size came back byte-identical and every timing landed
within measurement noise of the original run. Worth having checked
rather than assumed - none of those three flags touch the code path
a single-threaded compression call actually runs, but "obviously
shouldn't matter" is exactly the kind of claim this document
otherwise insists on measuring rather than taking on faith.

**Output buffer size: 16 KB, still a first pass.** `NGX_HTTP_ZSTD_OUT_SIZE`
in the filter. `ZSTD_CStreamOutSize()` is the recommended size and
guarantees at least one complete block flushes, but it is around
128 KB and now lives per request for the whole response — straight
into the §1 constraint. 16 KB is well clear of that and the full
suite passes at that size, including the TTFB test, but it has not
been swept the way the level and window below were. A smaller buffer
is legal either way — you simply round-trip through `send_output`
more often.

**Custom allocator: used, and cheaper than it looked.** The filter
defines `ZSTD_STATIC_LINKING_ONLY` and calls
`ZSTD_createCCtx_advanced(ZSTD_customMem)` to route encoder
allocations through `ngx_alloc`/`ngx_free` and trace them in the
debug log, exactly as the Brotli module does — this is what
`test_alloc_balance_static`, `test_alloc_balance_stream` and
`test_alloc_soak` need to mean anything. The doc comment on
`ZSTD_createCCtx_advanced` calls it `ZSTDLIB_STATIC_API` and warns it
needs "static linking", which reads like it forces the build off
system `libzstd`. Checked directly rather than taken on the doc
comment's word, back when the module still linked the system library
dynamically: `nm -gU libzstd.dylib` listed `_ZSTD_createCCtx_advanced`
with default visibility, exported exactly like the stable API.
"Static linking only" is a promise about API *stability* across
releases — the symbols can move or disappear in a future version
without a SONAME bump — not a linker restriction, so this was never
actually a reason to vendor zstd by itself. Now that the library is
vendored and pinned anyway (see above), the point is moot either way:
a version bump is a deliberate submodule update this API can be
re-checked against, not something that changes silently under an
`apt upgrade`.

**Input deferral threshold: 64 KB, tied to `zstd_window`'s default
rather than to encoder internals.** The Brotli module holds back up
to 64 KB while waiting to learn the response size, chosen to match
Brotli's internal block size so the deferral was not observable.
zstd's block structure differs and isn't a single fixed number the
way Brotli's is, so that reasoning doesn't transfer — but there's a
simpler bound available: deferring longer than the window the encoder
would use anyway cannot change the window choice any further, so
`NGX_HTTP_ZSTD_DEFER_INPUT` just matches the compiled-in
`zstd_window` default (also 64 KB). The two happen to be the same
number for a different reason, not the same reason.

**Compression level default: 3, measured rather than assumed.**
`script/bench_corpus.py` (adapted, see §5) against `script/corpus/`
with a `--with-debug` build: level 3 (zstd's own documented default)
compresses the corpus to 241,626 bytes at 0.65 ms of encoder time per
request; level 6 gets to 220,262 bytes (8.8% smaller) for roughly 3x
the CPU; past level 9 the curve goes flat — level 19 buys another 4%
over level 12 for more than 5x the time. Level 3 is not simply "the
default nobody questioned": level 1 gives up 6% ratio to save little
time (256,640 bytes / 0.58 ms), so 3 is the actual elbow of the
curve, matching the "CPU over ratio" reasoning that set Brotli's
quality-4 default without inheriting Brotli's specific number.

**Window default: 64 KB, and confirmed to cost memory here unlike
Brotli.** Brotli's own window/memory curve was flat — quality had no
effect on peak encoder memory, only `lg_win` did, and even then only
up to where the hasher changed at 64 KB. zstd's does not stay flat:
measured against a 1.5 MB response, peak live encoder bytes were
333 KB at a 16 KB window, 1.25 MB at 64 KB, 1.83 MB at 256 KB and
2.61 MB at 1 MB — climbing steadily rather than plateauing. That
makes staying at the small end of the range a real, checked decision
here rather than an assumption carried over from a module where it
happened not to matter.

**Compressed-response minimum length: 256, re-derived rather than
copied.** zstd's per-frame overhead is a handful of bytes against
Brotli's roughly 560 KB encoder-instance cost, so Brotli's crossover
reasoning doesn't transfer as-is. Measured directly instead: small
JSON-shaped text compressed at level 3 starts coming out smaller
than the original somewhere around 90-106 bytes. 256 clears that
with room to spare, landing on the same number as the Brotli module
for an independently re-checked reason.

---

## 8. Working practices that earned their place

**A test that has never failed proves nothing.** Before trusting new
coverage, reintroduce the bug it targets and watch it fail. The Vary
tests in the source project were validated exactly this way, against
two bugs that code had actually had.

**Check the build's exit status before reading test results.** With
`-Werror`, a failed build leaves the old binary in place and the suite
will happily pass against it.

**A green suite does not mean the code was reached.** `check_vary`
lived for several commits with both suites green because no fixture
produced the configuration that reaches it — during which an inverted
comparison shipped that would have dropped the `Vary` header entirely.

**Measure, do not assume, when the claim is about generated code.**
Compare object files at `-O0` through `-Os`; `-O0` is the one that
exposes a semantic difference the optimiser would otherwise erase.

**A zero-size buffer must not claim to be in memory.** `ngx_buf_special()`
is false for anything `ngx_buf_in_memory()` accepts, and
`ngx_http_write_filter` does not merely complain about a zero-size
non-special buffer - it logs "zero size buf in writer" and returns
`NGX_ERROR`, killing the response. The filter commits one reusable
`out_buf` per round and originally set `temporary = 1` once at
initialization, so had a round ever committed zero bytes while
carrying `last_buf`, the response would have died. It now sets
`temporary`/`sync` per round from `out.pos`, so an empty marker
buffer is genuinely special.

The path is not reachable today, which is the interesting part.
`ZSTD_e_end` returning 0 (frame complete) while writing 0 bytes would
be required, and a standalone harness driving `ZSTD_compressStream2`
across 3360 combinations of output capacity, input length, level and
chunk size produced that outcome zero times - consistent with zstd's
documented contract, where a nonzero return means data genuinely
remains. The full suite at a 64-byte output buffer never reached the
branch either. It was fixed anyway, because the branch exists, the
comment above it asserted nginx would accept such a buffer, and that
assertion was simply false.

Both halves were verified by forcing `out.pos = 0` on the final
round. Before the fix: `[alert] zero size buf in writer t:1` and a
dead connection - `http=000`, zero bytes. After: `http=200`, the
buffer logged as `t:0`, no alert. That is the §8 rule about a test
that has never failed, applied to a branch that has never run.

**A green suite is not a memory audit; sanitizers and a hostile
buffer size are.** The whole suite passes at the shipped 16 KB output
buffer without ever exercising a partial send - one round produces
everything most responses need. Rebuilt under AddressSanitizer with
`NGX_HTTP_ZSTD_OUT_SIZE` cut to 64 bytes, the same 44 tests hammer
the multi-round paths instead: `send_output` resending a partly
consumed buffer, `ZSTD_e_end` draining across many calls,
`draining_flush` looping. Clean - no ASan findings, no alerts. Worth
repeating after any change to the output path, and worth doing with a
deliberate overflow first to confirm the sanitizer is actually armed
(a four-byte allocation overrun by three bytes sits inside the
allocator's granule and is *not* reported, which reads exactly like a
clean run).

**A test's docstring can catch a bug before the test runs.** Adapting
`test_stream.py`'s `wait_for_encoder_release` docstring to zstd
surfaced that the filter's happy path never freed the `ZSTD_CCtx`
early — only the pool cleanup handler would, at request teardown.
The docstring explained *why* Brotli frees where it does (`out_buf`
points into encoder-owned memory, so it can't be released sooner);
writing the zstd-accurate version of that sentence forced the
question of where *this* filter actually frees, and the honest answer
was "nowhere, yet". Fixed by closing in `zstd_compress` itself, once
`ctx->output` is back to `IDLE` and a fresh call finds
`ctx->frame_closed` already set — mirroring Brotli's timing for a
different reason, since here it's `out_chain` still needing to reach
the filters below intact, not encoder-owned memory. Left as recommended in
§1, this would have held the encoder's memory for the rest of the
request's life on every keep-alive connection, silently violating the
"per-request memory outranks ratio" constraint the whole module is
built around. The bug was never exercised by a failing test — it was
caught by writing an accurate sentence about what the code does.

**Files a script assumes exist are not necessarily there.**
`run-tests.sh` referenced `script/build.sh`, `script/test.conf` and
`script/test_h2.conf`; none were in the initial commit, and the
"what is in this repository" table in §5 didn't mention them either.
Discovered by tracing what the copied scripts actually needed rather
than trusting the table — worth re-checking any time a script fails
with "no such file" before assuming the script itself is broken.

**A `.gitignore` inherited from another project can be missing a line
that project needed for a reason no longer visible.** `tmp/` — where
`run-tests.sh` writes response bodies and their decompressed copies —
was untracked in the Brotli source this repository started from
because its own `.gitignore` had a `tmp/` entry; that entry did not
get copied into this repository's `.gitignore` even though the
script that populates the directory did. Running the suite once and
then running `git status` is what surfaces this kind of gap; reading
the ignore file alone would not have.
