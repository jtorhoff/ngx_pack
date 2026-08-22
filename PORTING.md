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
| `module/common/ngx_http_zstd_headers.h` | **adapted and compiles** under `-Wall -Werror`; token is `"zstd"` (4 chars), `Content-Encoding: zstd` |
| `script/test_stream.py` | **verbatim copy**, still Brotli-facing — see §6 |
| `script/test_stream.conf` | verbatim copy |
| `script/run-tests.sh`, `prepare-tests.sh` | verbatim copies |
| `script/bench_corpus.py` | verbatim copy |
| `script/corpus/` | verbatim, with `PROVENANCE.md` — real-world HTML/CSS/JS/prose |
| `script/fuzz/` | verbatim: harness, seeds, dictionary |
| `.github/workflows/ci.yml` | verbatim: build, sanitizers, fuzz, format jobs |
| `.clang-format` | verbatim |
| `module/filter/`, `module/static/` | **empty — this is the work** |

The copies are deliberately unmodified. A mechanical rename across
1,500 lines of test code that cannot yet be run would be unverifiable
churn, and half-ported files are worse than obviously unported ones.
§6 lists exactly what to change, and every change is checkable the
moment a stub filter exists.

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
4. **`.github/workflows/ci.yml`** — drop the Brotli submodule build;
   zstd is a system package (`libzstd-dev`), so no vendored dependency
   is needed. Keep the `format` job pinned to a distribution with
   clang-format 19+ — `.clang-format` sets `AlignFunctionDeclarations`,
   and an older clang-format rejects the whole file rather than that
   one key.
5. **`script/run-tests.sh`** — swap the decompressor to `zstd -d`.

---

## 7. Open decisions

**Output buffer size.** `ZSTD_CStreamOutSize()` is the recommended
size and guarantees at least one complete block flushes, but it is
around 128 KB and now lives per request for the whole response. That
runs straight into §1. A smaller buffer is legal — you simply
round-trip through `send_output` more often. Measure before choosing.

**Custom allocator.** `ZSTD_createCCtx_advanced(ZSTD_customMem)` is
`ZSTDLIB_STATIC_API`: it needs `ZSTD_STATIC_LINKING_ONLY` and static
linking. The Brotli module used the equivalent hook to route encoder
allocations through `ngx_alloc` and to assert allocation balance in
the debug build. Either accept the experimental dependency or drop
custom allocation and lose that assertion.

**Input deferral threshold.** The Brotli module holds back up to 64 KB
while waiting to learn the response size, chosen to match Brotli's
internal block size so the deferral was not observable. zstd's block
structure differs; the number must be re-derived, not copied.

**Compression level default.** Brotli's default here is quality 4 after
measurement against the real corpus. zstd's scale is different; pick it
with `bench_corpus.py` against `script/corpus/`, never against
synthetic text — synthetic fixtures overstated a ratio change roughly
fourfold in the original measurements.

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
