# LDAP Hex Dump Decoder

Paste the decrypted plaintext hex dump section from the output of Java's
`-Djavax.net.debug=ssl,record,plaintext` (the block following
`Plaintext before ENCRYPTION (` / `Plaintext after DECRYPTION (`), and it
decodes it as an LDAP message using
[pyasn1_ldap](https://github.com/hokuda/pyasn1_ldap), displaying it in a
human-readable format (`prettyPrint()` tree view).

All processing runs entirely in the browser via
[Pyodide](https://pyodide.org/) (CPython running on WebAssembly). There is
no server-side processing at all, so it works with static hosting such as
GitHub Pages.

## Usage

1. Copy just the hex dump section (the lines with offset, hex bytes, and
   ASCII sidebar) from the Java-side log. It's fine if the surrounding
   `Plaintext before ENCRYPTION (` / `)` lines are included too.
2. Paste it into the text area and click the "Decode" button.
3. If a single paste contains multiple concatenated LDAPMessages, each one
   is displayed separately as "Message 1", "Message 2", etc.

## Verifying it works locally

Opening `index.html` directly via `file://` will cause `fetch()` /
`loadPyodide()` to fail, so serve it via a simple HTTP server instead.

```sh
python3 -m http.server 8000
```

Open `http://localhost:8000/` in a browser. The status display should
progress through "Loading Python runtime…" → "Loading micropip…" →
"Installing pyasn1_ldap from PyPI…" → "Ready.", after which the Decode
button becomes enabled.

## Deploying to GitHub Pages

This repository consists only of static files that require no build step.

1. Push to the `main` branch.
2. In the repository's Settings → Pages → Source, set
   "Deploy from a branch" / Branch: `main` / `(root)`.
3. Confirm the page opens at the published URL.

## Limitations

- `pyasn1_ldap` is a small package published as a single release (0.1.0)
  on PyPI. Since it's fetched directly from PyPI at runtime, it won't work
  in environments where access to PyPI is blocked (e.g. behind a corporate
  proxy).
- The initial load takes a few to several tens of seconds, since it
  downloads Pyodide itself along with its dependent packages.
