# pi-anon-export

[![npm version](https://img.shields.io/npm/v/pi-anon-export?color=7c3aed)](https://www.npmjs.com/package/pi-anon-export)
[![npm downloads](https://img.shields.io/npm/dm/pi-anon-export)](https://www.npmjs.com/package/pi-anon-export)
[![license](https://img.shields.io/badge/license-MIT%20%2B%20Apache--2.0-blue)](LICENSE)
[![pi extension](https://img.shields.io/badge/pi-extension-7c3aed)](https://pi.dev/packages/pi-anon-export)

English | [简体中文](https://github.com/tychenjiajun/pi-anon-export/blob/main/docs/README.zh-CN.md)

**A [pi](https://pi.dev) extension that exports your agent sessions as anonymized JSONL or HTML** — locally, with nothing ever leaving your machine. Use it when you want to share a session transcript (for a bug report, a colleague, or a public gist) without leaking API keys, tokens, cookies, emails, or embedded screenshots.

![pi-anon-export: a session file before and after redaction](https://raw.githubusercontent.com/tychenjiajun/pi-anon-export/main/assets/preview.png)

## Install

```bash
pi install npm:pi-anon-export
```

Or try it for one invocation without installing:

```bash
pi -e npm:pi-anon-export
```

## Usage

```
/anon-export [path]     export the CURRENT session, anonymized — like /export:
                        `.jsonl` writes JSONL, anything else writes HTML
/anon-export zip        export ALL sessions of the current working directory's
                        session folder, redacted and packed into one zip
```

![demo: session file → redact → after → verify](https://raw.githubusercontent.com/tychenjiajun/pi-anon-export/main/assets/demo.gif)

### Flags (both modes)

Arguments are shell-like and values are validated: an empty value is an error for every flag (`--out ""` cannot silently mean "the current directory"), and a quoted value may start with dashes (`--secret "--abc123x"`) while `--out --no-images` is still rejected as a missing value.

| Flag | Effect |
|---|---|
| `--no-images` | Strip embedded image data blocks (replaced with `[IMAGE_REMOVED]`). Without it, images are **kept byte-exact** and counted for manual review. |
| `--level fast\|full` | Redaction depth. Default: `full`. |
| `--pii conservative\|aggressive` | `aggressive` adds the upstream personal-name and street-address patterns. Needs `--level full` (they over-redact prose and code, so they are opt-in); `--level fast` together with `--pii aggressive` is rejected instead of silently doing nothing. |
| `--out <dir>` | Write one anonymized JSONL file per session into `<dir>` instead of following `/export`'s exact-path semantics. Default in zip mode: the current directory. |
| `--secret <lit\|file>` | Add an extra literal secret. If the value is a readable file path, it is read as one secret per line. Repeatable. |
| `--env-file <path>` | Env file to scan **instead of** the default shell rc files. Repeatable. |

Arguments are shell-like: quotes group values (`--secret "value with spaces"`), and `--flag=value` works for values that themselves start with `--`. A missing value is an error, so `--out --no-images` can never create a directory named `--no-images`.

### Output paths

With no `--out`, the command follows `/export` exactly:

- `/anon-export` → `<APP_NAME>-session-<session-file>.html` in the current directory (pi's HTML export; `APP_NAME` is normally `pi`).
- `/anon-export report.jsonl` → anonymized JSONL at that exact path (parent directories are created, like `/export`).
- `/anon-export report.html` (or any other non-`.jsonl` path) → anonymized HTML at that exact path.

HTML is generated from already-redacted JSONL through pi's own exporter (the system prompt and active-tool metadata are redacted with the same pipeline), so it keeps the same layout and theme as `/export` while containing none of the original secrets. The current-branch selection is also the same: JSONL contains the live session branch, not every branch in the file.

The legacy/batch forms remain available:

- `/anon-export --out <dir>` → `<dir>/<session-file>.jsonl`
- `/anon-export zip` → `./pi-anon-export-<timestamp>.zip` (or `<--out>/pi-anon-export-<timestamp>.zip`) — one timestamp for the whole run. Sessions are fed to the zip compressor as they are redacted (the archive is written to a per-run `<name>.<pid>-<random>.part` file, then renamed), so a project's whole redacted set is never buffered in memory and two runs in the same millisecond cannot interleave. Duplicate entry names are rejected, and an unparseable/empty session is reported instead of shipping as a 0-byte file.

Output is created with private permissions (`0700` directory, `0600` files, `0600` archive, enforced even when a stale file or `.part` already exists). If a session still contains a known secret after redaction, its output is **quarantined** instead of written under the normal name: `<target>.UNSAFE`, `<session-file>.jsonl.UNSAFE` for `--out`, or `pi-anon-export-<timestamp>-UNSAFE.zip`, and an unattended run exits non-zero. An output path that resolves to the source session — including through a symlink or hard link — is refused instead of overwriting the live transcript, and an empty or unparseable session is reported as skipped rather than shipped as a 0-byte file. Zip mode writes into the current directory by default — if that directory is a git working tree, the report says so; keep the archive out of commits. A killed run can leave its `<name>.<pid>-<random>.part` file behind (already-redacted bytes, no cleanup sweep); delete those by hand.

The command reports the number of exported sessions, the output path, the redaction counts (secrets replaced, images removed/flagged, dropped lines, and anonymizer categories), any notes about ignored inputs, and the result of the post-redaction verification pass. When there is no TUI (print/JSON mode) the report goes to **stderr**, so machine-readable stdout stays clean.

### Examples

```bash
/anon-export                                  # HTML, named like /export
/anon-export report.jsonl                     # anonymized JSONL at that path
/anon-export report.html                      # anonymized HTML at that path
/anon-export zip --no-images
/anon-export --level fast --out /tmp/shareable --secret "my-personal-token"
/anon-export --env-file ./.env --env-file ~/.zshrc
```

## Redaction levels

Every export runs the same base pipeline, per JSONL line:

1. **Parse or drop (fail-safe).** Lines that are not valid JSON, or are not JSON objects, are **discarded and counted** (`dropped_lines`) — broken lines are never passed through verbatim.
2. **Media handling.** A string longer than 256 characters is treated as an embedded image/audio/video payload only when the bytes or the surrounding object say so: a media carrier key (`b64_json`, `imageData`, `image_data`, `audioData`, `videoData`, `fileData`, `contentBytes`), a `data`/`base64`/`blob` value whose parent declares a media `type`/`mimeType`/`mediaType`, a `data:image/…` URL under any key, or a recognisable container magic (`iVBOR`, `/9j/`, `R0lGOD`, `UklGR`, `GkXf`, `ftyp`). A declared MIME type only covers the payload-ish key it sits next to, and text-based media types (`image/svg+xml`, `text/*`, `*json`) are always redacted as text, because their bytes are prose. With `--no-images` such a payload becomes `[IMAGE_REMOVED]`; otherwise it is kept **byte-exact** and counted (`images_flagged`). Kept payloads are never rewritten — not even by the anonymizer — because any edit corrupts the image. Plain text under a `data` key (`{"type":"tool-result","data":"csv,…"}`) is **not** a payload: it goes through normal redaction instead of being exempted (and `--no-images` no longer deletes it).
3. **Literal secret replacement, in one pass.** Every occurrence of a discovered secret becomes `[REDACTED_<NAME>]`. Secrets come from:
   - `export NAME=...` / `declare -x NAME=...` lines in your shell rc files (`~/.zshenv`, `~/.zprofile`, `~/.zshrc`, `~/.zlogin`, `~/.bash_profile`, `~/.bashrc`, `~/.profile`) — or the files you pass with `--env-file`. Files are scanned in the order a shell sources them, so the value you actually get wins, and a variable defined twice with different values produces a name-only warning (never a value). The variable name must contain `KEY`, `TOKEN`, `SECRET`, `PASS`, `PWD`, `COOKIE`, or `CREDENTIAL`;
   - every `--secret` you pass (literals or files, one secret per line; BOM/CRLF tolerated).
   Values are read the way a POSIX shell reads them, so a secret is never silently truncated: quoted segments run to their matching closing quote and concatenate with unquoted runs (a `#` inside quotes is part of the value, `\"` is unescaped), an unquoted value ends at shell whitespace (`#` is kept when it starts a word: `pa#ss123`), `\`-continued lines are joined first, indented lines inside an `if` block are scanned, `NAME+=value` registers both the appended text and the resulting full value, and an unterminated quote keeps the remainder.
   Values shorter than 5 characters are refused; values that could match *inside* a `[REDACTED_…]` marker (e.g. `REDACT`) are refused too. Both cases produce a value-free note naming the actual reason — a long secret that merely *contains* `[REDACTED_` is redacted normally. Each value is matched in its NFC and NFD spellings as well, so a composed rc-file secret is still found in a decomposed session. Replacement is a single longest-first pass, so overlapping secrets are fully covered and inserted markers are never re-scanned.

Then, depending on the level:

- **`fast`** — stops here. Only structural drops, image policy, and literal secrets. Paths, usernames, emails, and timestamps are **not** touched.
- **`full`** (default) — additionally runs every remaining leaf value through an **anonymizer** (emails → `redacted-<hash8>@example.com`, home-path usernames, code-host URLs, API keys, JWTs, bearer tokens, credential URLs, query-string secrets, private-key blocks, SSN/phone/IP) with a stateful, consistent mapping across the whole export run, so the same input always maps to the same output within one export. `--pii aggressive` adds personal-name and street-address patterns. There is **no size cutoff**: a megabyte-sized tool output gets the same passes, with guards that stay linear per match (a 1 MiB git log full of addresses takes ~0.1 s).

Every export then runs a **verification pass** per file, before the file gets its shareable name: it re-scans for every known secret literal (raw *and* JSON-escaped) and reports `Verified: no known secret literal remains` — or a loud `✖ VERIFICATION FAILED`. Anything that fails is written as `*.UNSAFE` / `-UNSAFE.zip` and the run exits non-zero in print/JSON mode, so a script cannot mistake a leaky export for a clean one.

The zip mode adds a `manifest.json` with, per file: the source name, the sha256 of the redacted content (computed from the exact bytes written into the archive), and its **per-file** redaction counts. It also carries `verification.residualSecrets` (must be `0`) and `verification.secretSet`, a **salted** fingerprint of the secret set that was applied — no values, and a fresh salt per run, so two exports are not linkable to each other. The fingerprint is a consistency check (it is not a secrecy guarantee; the salt travels in the manifest). Skipped-file entries in the manifest are **sanitized**: only the basename is kept (pi's session directory names embed the local username and project path) and fs error messages are rewritten so they cannot reintroduce an absolute path.

## ⚠️ Disclaimer: anonymization is best-effort

**Anonymization is a best-effort heuristic, not a guarantee.** Review every export manually before publishing or sharing it. Secrets that don't match the naming heuristics, novel identifiers, or PII patterns the anonymizer doesn't know about can survive redaction. The author assumes no liability for information that remains in an exported file.

Known by-design behaviors (all documented in `extensions/lib/anonymize.ts`):

- Text segments containing `/` are treated as paths and their `user@host`-shaped parts are **kept** (matches the upstream Teich guards); URL userinfo (`https://user@host/…`) is also kept.
- Public git remotes, reserved example domains, systemd units (`x@y.service`), and package versions (`lodash@4.17.21`) are preserved.
- Backslash-separated strings like `dir\name@foo.com` are **over-redacted** (the email-shaped tail is replaced): false positives are preferred over leaks.
- Usernames in code-host URLs (`git:github.com/<user>/…`, `git@github.com:<user>/…`, `https://github.com/<user>`) are rewritten only after that username has been seen in a home path or as an email local part.
- Images are kept by default and flagged for manual review; use `--no-images` to strip them. Screenshots are not OCR'd or redacted, so a known secret that appears inside a kept image payload cannot be replaced — the verification pass catches it and quarantines the export as `*.UNSAFE`.
- **Media payloads are recognised by evidence**, not by key name alone: a >256-character value under a media carrier, with a declared media `type`/`mimeType`, a `data:` URL, or a known container magic. Anything else is treated as text (redacted, kept, never deleted), so an unrecognised payload can survive `--no-images` — but it is never exempted from redaction.
- The anonymizer's own base64-media replacement (`redactBase64Media`) is only reachable when the anonymizer is used standalone. `/anon-export` owns the image policy, so that branch never rewrites an exported image.
- Secret discovery is deliberately narrow: only `export NAME=value` lines in the shell rc files above (or `--env-file` files). `NAME=value` without `export`, a project `.env`, `~/.aws/credentials`, `~/.npmrc`, `~/.netrc` and Windows PowerShell profiles are **not** read unless you pass them with `--env-file`; pass values you care about with `--secret` as well.
- Personal names and street addresses are only redacted with `--pii aggressive`; SSN, phone and IP are always redacted at the `full` level.
- The anonymizer is heuristic: it knows common credential shapes, not your employer's internal ID format.
- Verification can only check the secrets it was given: when the secret set is empty the report says so explicitly instead of claiming success.
- Code comparisons (`password == "x"`, `=>`) are never treated as assignments — the source mangled them — so a literal on the right-hand side of a comparison is not redacted.
- Email addresses with a non-ASCII domain (IDN) or a leading dot in the local part are not recognised, and an address glued to a preceding word character (`...alice@x.io`) is left alone. Addresses with `_` in the domain, `+tags`, ports and surrounding punctuation are recognised. The local part is bounded to the RFC limit (64 chars), which is also what keeps the guard linear on address-dense text.
- A credential URL whose password was inserted **without escaping** (`postgres://user:pa/ss#x@host`) is covered for the common database/mail schemes; on other schemes the password stops at the URL authority, so the unescaped tail can survive. Conversely, a URL with no credentials (`https://host:8080/path?a=b@c.io`) is never mistaken for one.
- Code comparisons (`password == "secret"`, `api_secret=>x`) are not assignments, so the right-hand literal is not redacted; YAML/INI comment values (`password: # TODO`) are left intact.
- A backslash-continued line is joined the way a shell joins it (never inside a comment or single quotes); `declare -x`/`export` are supported, `typeset` is not.

## FAQ

### Does anything leave my machine?

No. The extension performs **no network I/O at all** — no telemetry, no uploads, no model calls. It reads session and env files, writes the export, and stops.

### How is this different from copying the JSONL out of the session directory?

`~/.pi/sessions/--<path>--/*.jsonl` contains everything your agent ever saw: shell rc secrets, employee emails, home paths, base64 screenshots. `/anon-export` re-writes it leaf by leaf (secrets → `[REDACTED_<NAME>]`, emails → `redacted-<hash8>@example.com`, home paths → `user_<hash8>`), drops unparseable lines, and then re-scans the result for every known secret before it hands you a shareable name.

### What happens if redaction fails?

The file is not written under its normal name: it becomes `<session>.jsonl.UNSAFE` (or `pi-anon-export-<timestamp>-UNSAFE.zip`) and an unattended run exits non-zero. A script cannot mistake a leaky export for a clean one.

### Which secrets does it find?

Literal values of `export NAME=value` lines whose name contains `KEY`, `TOKEN`, `SECRET`, `PASS`, `PWD`, `COOKIE` or `CREDENTIAL`, from `~/.zshenv`, `~/.zprofile`, `~/.zshrc`, `~/.zlogin`, `~/.bash_profile`, `~/.bashrc`, `~/.profile` — or from files you pass with `--env-file`. On top of that the `full` level recognises common credential shapes (API keys, JWTs, bearer tokens, credential URLs, private-key blocks) and PII (emails, SSN/phone/IP, home paths); `--pii aggressive` adds personal names and street addresses. Project `.env` files, `~/.aws/credentials`, `~/.npmrc` and `~/.netrc` are **not** read unless you point `--env-file` at them.

### Does it work with screenshots and images?

Images are kept **byte-exact** by default and counted for review, because any rewrite corrupts them. Pass `--no-images` to replace every recognised media payload with `[IMAGE_REMOVED]`. Text-based media types (`image/svg+xml`, `text/*`, `*json`) are always treated as text and redacted.

### Can I share the zip safely?

The zip carries a `manifest.json` with a sha256 per file, the per-file redaction counts, and `verification.residualSecrets` (must be `0`). Skipped-file entries are sanitized to basenames, so the manifest does not reintroduce your home directory or project path. Still read the export before publishing it — anonymization is best-effort, not a guarantee.

### Why does the export directory warn me about git?

Zip mode writes into the current directory by default. If that directory is a git working tree the report says so, because committing a transcript is one `git add -A` away; add the archive (or the export directory) to `.gitignore`.

### Does it support very large sessions?

Yes. There is **no size cutoff**: a megabyte-sized tool output gets the same passes, and the guards stay linear per match (a 1 MiB git log full of addresses takes ~0.1 s). Zip mode streams each session into the archive as it is redacted instead of buffering the whole redacted set.

## Privacy: fully local

This extension performs **no network I/O at all**. It reads your session files and env files, writes results under the output directory, and does nothing else. No telemetry, no uploads, no model calls. The only runtime dependency is [`fflate`](https://github.com/101arrowz/fflate) (pure-JS zip), used locally in zip mode.

## Session location

Exported sessions are located the same way pi itself locates them:

- `ctx.sessionManager.getSessionDir()` / `getSessionFile()` inside a running session (these already honor `--session-dir`, `PI_CODING_AGENT_SESSION_DIR`, and the `sessionDir` setting);
- otherwise the pi agent dir from `getAgentDir()` (which honors `PI_CODING_AGENT_DIR`) plus `sessions/--<path>--/`, where `<path>` is the cwd with the leading slash stripped and `/`, `\`, `:` replaced by `-`.

Relative session dirs are resolved against the session cwd, never against `process.cwd()`.

## For developers: the anonymizer contract

`extensions/lib/anonymize.ts` exposes the extension point used by the `full` level:

```ts
export interface Anonymizer {
  anonymizeValue(value: unknown): unknown; // stateful, consistent within one instance
  readonly counts: Record<string, number>;
}
export function createAnonymizer(options?: { aggressivePii?: boolean }): Anonymizer;
```

One `Anonymizer` instance is created per export run and shared across all files, so mappings stay consistent. `counts` accumulates lifetime counts on the instance; `redactSessionJsonl` snapshots them per call and reports **deltas**, so per-file counts in the manifest are genuinely per file.

`extensions/lib/secrets.ts` offers `createSecretMatcher()` (single-pass, longest-first literal replacement) and `computeSecretFingerprint()` (salted, length-prefixed, order-independent).

## Development

```bash
pnpm install
pnpm run check   # tsc --noEmit
pnpm run smoke   # offline smoke tests: pipeline, secrets, args, zip, end-to-end handler,
                 # plus scripts/hypothesis-smoke.ts (adversarial regression cases)
pnpm test        # check + smoke
```

The smoke tests are hermetic: `--env-file` points at `fixtures/`, and every export goes to a temp directory, so your real `~/.zshrc` and sessions are never read.

## Links

- Package page: <https://pi.dev/packages/pi-anon-export>
- 中文说明 (Chinese README): <https://github.com/tychenjiajun/pi-anon-export/blob/main/docs/README.zh-CN.md>
- pi packages documentation: <https://pi.dev/docs/latest/packages>
- Issues and bug reports: <https://github.com/tychenjiajun/pi-anon-export/issues>
- The upstream anonymizer this ports: <https://github.com/TeichAI/teich>

## License

Dual-licensed, because this package embeds a port of an Apache-2.0 project:

- **MIT** — everything original in this package (see `LICENSE`).
- **Apache-2.0** — `extensions/lib/anonymize.ts`, a modified TypeScript port of
  [`TeichAI/teich`](https://github.com/TeichAI/teich) `src/teich/anonymize.py`
  (see `LICENSE-APACHE`; the file header lists every deviation as required by
  Apache-2.0 §4(b)).

`extensions/lib/secrets.ts` is an independent implementation: only the
publicly documented *approach* of [`badlogic/pi-share-hf`](https://github.com/badlogic/pi-share-hf)
(env-file literal-secret redaction) was reused — that project ships **no
license**, so no code was taken from it.

The [pi](https://github.com/earendil-works/pi) API types are consumed at
runtime as a `peerDependency`; pi is MIT and no pi source is bundled here.
