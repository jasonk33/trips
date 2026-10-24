# Personal GitHub Pages

- This public repository is `jasonk33/trips`; publish from `main` at the root. The entry point is `https://jasonk33.github.io/trips/`.
- Keep existing report filenames and URLs stable. No folders, framework or backend are needed for ordinary additions.
- `index.html` contains an AES-GCM-encrypted catalog of every root HTML report. Its password envelope wraps the existing library key; preserve both it and the key when updating the catalog.
- Never put a password, library key, full private sharing link or decrypted private report into this repository or commit history. Private reports must remain encrypted wrappers.
- For every new page, copy only the approved public HTML or encrypted wrapper into the root, then update the library before committing. A private page needs its full sharing-link file; public publication must be intentional.
- Use `scripts/update-library.mjs`, not manual ciphertext editing. It checks the complete inventory, decrypts private report links to validate them, rejects exposed keys, and preserves password access. It requires only Node's standard library.

```sh
# Run from a checkout of this repository. LINK_FILE is a private local file.
node scripts/update-library.mjs --library-link-file "$LINK_FILE" \
  --page example.html --title "Example report" \
  --description "A short, useful description" --collection "Travel" --public

# For a private wrapper, replace --public with:
# --report-link-file /absolute/path/to/its/private-share-link.txt

# An existing page keeps its metadata and access unless explicitly updated:
node scripts/update-library.mjs --library-link-file "$LINK_FILE" --page existing.html
node scripts/update-library.mjs --library-link-file "$LINK_FILE" --check
node --test scripts/update-library.test.mjs

# Retire pages: delete them, or replace them with a note that carries
# <meta name="library" content="unlisted">, then drop their entries in one run:
node scripts/update-library.mjs --library-link-file "$LINK_FILE" --remove old.html --remove other.html
```

- If the library bookmark file is unavailable, `--password-stdin` can replace `--library-link-file`. Supply it privately through standard input, never as an argument, committed file or public log.
- Commit the report and updated `index.html` together; stage only intended files. Refresh from `origin/main` before publishing. After concurrent changes, rerun the updater against the latest catalog; do not overwrite the remote index with a stale copy.
- Verify the deployed report and its library entry. For privacy/encryption changes, also check password login, an existing key bookmark, and missing/wrong credentials headlessly. Routine content edits need only targeted checks.
