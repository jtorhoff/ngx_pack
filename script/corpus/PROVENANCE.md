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

Retrieved 2026-08-19.

## Notes on the two that are not MIT

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
