# Test corpus

Real-world files, vendored deliberately. The suite used to compress
`make_text()` output - random words drawn from a small list - and that misleads
badly about compression: measured against these files, a synthetic corpus
overstated a ratio change roughly fourfold, because repeated vocabulary at long
range is the easiest thing in the world to compress and nothing on the web
looks like it.

They are checked in rather than downloaded so the suite is deterministic and
runs offline. Sizes are kept modest; where a source was larger it was trimmed
at a clean boundary (a paragraph break, a CSS rule) rather than mid-token.

| file | what it is | source | licence |
|------|------------|--------|---------|
| `wiki.html` | rendered encyclopedia article, MediaWiki markup | [Wikipedia, "HTTP compression"](https://en.wikipedia.org/wiki/HTTP_compression) | CC BY-SA 4.0 |
| `site.css` | utility-class stylesheet, first ~200 KB | [Tailwind CSS 2.2.19](https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css) | MIT |
| `app.js` | unminified UMD library build | [React 18.3.1 development build](https://unpkg.com/react@18.3.1/umd/react.development.js) | MIT |
| `app.min.js` | minified UMD library build | [React DOM 18.3.1 production build](https://unpkg.com/react-dom@18.3.1/umd/react-dom.production.min.js) | MIT |
| `prose.txt` | English prose, first ~256 KB | Tolstoy, *War and Peace* (Maude translation), via Project Gutenberg ebook 2600 | public domain (US) |
| `api.json` | JSON API response, first 280 records | [USGS earthquake feed, all earthquakes past month](https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/all_month.geojson) | public domain (US) |
| `feed.pb` | serialized protobuf API response, first 181 records | [HSL GTFS-realtime trip updates](https://realtime.hsl.fi/realtime/trip-updates/v2/hsl) | CC BY 4.0 |

`wiki.html`, `site.css`, `app.js`, `app.min.js` and `prose.txt` retrieved
2026-08-19; `api.json` and `feed.pb` 2026-09-05.

## Notes on `api.json`

Kept as the wire form: minified, UTF-8 rather than `\u` escapes, exactly as
USGS serves it. Pretty-printed JSON is largely indentation and compresses
spectacularly, which would flatter every codec and measure nothing anyone
serves.

Trimmed to the first 280 features - a whole-record boundary, the JSON
equivalent of the paragraph break above, and the same slice a `limit`ed query
would return. `metadata.count` and `bbox` were recomputed for the records that
remain, so the envelope still describes its own contents rather than the 11,291
it was cut from; nothing else was altered.

The USGS is a US federal agency, so its authored data carries no copyright in
the US (17 U.S.C. 105) and USGS publishes it as public domain. Like `feed.pb`
below it is not `text/*`, which is why `test_stream.conf` names
`application/json` in its `types` block as well as in `pack_*_types`.

## Notes on `feed.pb`

A GTFS-realtime feed: one `FeedHeader` followed by repeated `FeedEntity`
records, served as `application/x-protobuf`. Binary protobuf wire format -
varints, one-to-two byte field tags, length-delimited strings - which is a
different shape from anything else here, all of which is characters.

Trimmed to the first 181 entities. `FeedHeader` carries no entity count, so a
prefix of the entities is a valid `FeedMessage` as it stands and nothing needed
recomputing; the trim was made by walking top-level fields and cutting on a
field boundary, so no record is truncated mid-varint.

**Attribution, required by CC BY 4.0:** © Digitransit / HSL, GTFS-realtime trip
updates, retrieved 2026-09-05.

CC BY is attribution-only, not share-alike, so unlike `wiki.html` it puts no
condition on this repository beyond the credit above. Note that Digitransit's
terms place their *routing, geocoding and map* APIs under ODbL because those
carry OpenStreetMap data; this is the GTFS-realtime feed, which is HSL's own
transit data under CC BY, and none of the OSM-derived APIs are used here.

## Notes on `prose.txt` and `wiki.html`

`prose.txt` had the Project Gutenberg header and footer stripped, so what
remains is the public-domain text alone with no Project Gutenberg branding,
licence text or trademark. That is the arrangement Project Gutenberg's own
licence describes for works already in the US public domain. The same ebook is
what `prepare-tests.sh` downloads for the shell suite, so the choice is not new
here - only the vendoring is.

`wiki.html` is **CC BY-SA 4.0**, which is a share-alike licence and the only
file here that is not permissive. Attribution: text by Wikipedia contributors,
available under CC BY-SA 4.0 at the URL above. If carrying a share-alike file
in this repository is unwanted, replace it with rendered HTML from a
permissively licensed source and re-baseline `bench_corpus.py`; nothing in the
suite depends on this particular article, only on it being real-world HTML.
