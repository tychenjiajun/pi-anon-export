# pi-anon-export

A [pi](https://pi.dev) extension that exports your agent sessions as **anonymized JSONL** — locally, with nothing ever leaving your machine. Use it when you want to share a session transcript (for a bug report, a colleague, or a public gist) without leaking API keys, tokens, cookies, emails, or embedded screenshots.

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
/anon-export            export the CURRENT session, anonymized, as JSONL
/anon-export zip        export ALL sessions of the current working directory's
                        session folder, redacted and packed into one zip
```

### Flags (both modes)

| Flag | Effect |
|---|---|
| `--no-images` | Strip embedded image data blocks (replaced with `[IMAGE_REMOVED]`). Without it, images are **kept byte-exact** and counted for manual review. |
| `--level fast\|full` | Redaction depth. Default: `full`. |
| `--out <dir>` | Output directory. Default: `./pi-anon-export-<timestamp>/` for the current session, the current directory for zip mode. |
| `--secret <lit\|file>` | Add an extra literal secret. If the value is a readable file path, it is read as one secret per line. Repeatable. |
| `--env-file <path>` | Env file to scan **instead of** the default shell rc files. Repeatable. |

Arguments are shell-like: quotes group values (`--secret "value with spaces"`), and `--flag=value` works for values that themselves start with `--`. A missing value is an error, so `--out --no-images` can never create a directory named `--no-images`.

### Output paths

- `/anon-export` → `./pi-anon-export-<timestamp>/<session-file>.jsonl` (or `<--out>/<session-file>.jsonl`)
- `/anon-export zip` → `./pi-anon-export-<timestamp>.zip` (or `<--out>/pi-anon-export-<timestamp>.zip`) — one timestamp for the whole run, and the archive is streamed straight to disk (written as `.part`, then renamed), so a big project's session folder is never held in memory twice.

The command reports the number of exported sessions, the output path, the redaction counts (secrets replaced, images removed/flagged, dropped lines, and anonymizer categories), any notes about ignored inputs, and the result of the post-redaction verification pass. When there is no TUI (print/JSON mode) the report goes to **stderr**, so machine-readable stdout stays clean.

### Examples

```bash
/anon-export
/anon-export zip --no-images
/anon-export --level fast --out /tmp/shareable --secret "my-personal-token"
/anon-export --env-file ./.env --env-file ~/.zshrc
```

## Redaction levels

Every export runs the same base pipeline, per JSONL line:

1. **Parse or drop (fail-safe).** Lines that are not valid JSON, or are not JSON objects, are **discarded and counted** (`dropped_lines`) — broken lines are never passed through verbatim.
2. **Image handling.** A `data` (or `base64`) string longer than 256 characters is treated as an embedded image payload. With `--no-images` it becomes `[IMAGE_REMOVED]`; otherwise it is kept **byte-exact** and counted (`images_flagged`) so you know to review it. Kept payloads are never rewritten — not even by the anonymizer — because any edit corrupts the image.
3. **Literal secret replacement, in one pass.** Every occurrence of a discovered secret becomes `[REDACTED_<NAME>]`. Secrets come from:
   - `export NAME=...` lines in your shell rc files (`~/.zshrc`, `~/.zshenv`, `~/.bashrc`, `~/.bash_profile`, `~/.profile`) — or the files you pass with `--env-file` — where the variable name contains `KEY`, `TOKEN`, `SECRET`, `PASS`, `PWD`, `COOKIE`, or `CREDENTIAL`;
   - every `--secret` you pass (literals or files, one secret per line).
   Values shorter than 5 characters, and values that would match inside a `[REDACTED_…]` marker, are **refused** (with a value-free note): a one-character "secret" would rewrite half the file, and a marker-shaped one would corrupt the output. Replacement is a single longest-first pass, so overlapping secrets are fully covered and inserted markers are never re-scanned.

Then, depending on the level:

- **`fast`** — stops here. Only structural drops, image policy, and literal secrets. Paths, usernames, emails, and timestamps are **not** touched.
- **`full`** (default) — additionally runs every remaining leaf value through an **anonymizer** (emails → `redacted-<hash8>@example.com`, home-path usernames, code-host URLs, API keys, JWTs, bearer tokens, credential URLs, query-string secrets, private-key blocks, SSN/phone/IP) with a stateful, consistent mapping across the whole export run, so the same input always maps to the same output within one export.

Every export then runs a **verification pass** over the emitted content: it re-scans for every known secret literal (raw *and* JSON-escaped) and reports `Verified: no known secret literal remains` — or a loud `✖ VERIFICATION FAILED` that tells you not to share the file.

The zip mode adds a `manifest.json` with, per file: the source name, the sha256 of the redacted content (computed from the exact bytes written into the archive), and its **per-file** redaction counts. It also carries `verification.residualSecrets` (must be `0`) and `verification.secretSet`, a **salted** fingerprint of the secret set that was applied — no values, and a fresh salt per run, so two exports are not linkable to each other. The fingerprint is a consistency check (it is not a secrecy guarantee; the salt travels in the manifest).

## ⚠️ Disclaimer: anonymization is best-effort

**Anonymization is a best-effort heuristic, not a guarantee.** Review every export manually before publishing or sharing it. Secrets that don't match the naming heuristics, novel identifiers, or PII patterns the anonymizer doesn't know about can survive redaction. The author assumes no liability for information that remains in an exported file.

Known by-design behaviors (all documented in `extensions/lib/anonymize.ts`):

- Text segments containing `/` are treated as paths and their `user@host`-shaped parts are **kept** (matches the upstream Teich guards); URL userinfo (`https://user@host/…`) is also kept.
- Public git remotes, reserved example domains, systemd units (`x@y.service`), and package versions (`lodash@4.17.21`) are preserved.
- Backslash-separated strings like `dir\name@foo.com` are **over-redacted** (the email-shaped tail is replaced): false positives are preferred over leaks.
- Usernames in code-host URLs (`git:github.com/<user>/…`, `git@github.com:<user>/…`, `https://github.com/<user>`) are rewritten only after that username has been seen in a home path or as an email local part.
- Images are kept by default and flagged for manual review; use `--no-images` to strip them. Screenshots are not OCR'd or redacted.
- **Screenshot/binary payloads are only recognised under the `data` / `base64` keys with a >256-character string value.** Payloads stored under other keys are treated as text.
- The anonymizer's own base64-media replacement (`redactBase64Media`) is only reachable when the anonymizer is used standalone. `/anon-export` owns the image policy, so that branch never rewrites an exported image.

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
export function createAnonymizer(): Anonymizer;
```

One `Anonymizer` instance is created per export run and shared across all files, so mappings stay consistent. `counts` accumulates lifetime counts on the instance; `redactSessionJsonl` snapshots them per call and reports **deltas**, so per-file counts in the manifest are genuinely per file.

`extensions/lib/secrets.ts` offers `createSecretMatcher()` (single-pass, longest-first literal replacement) and `computeSecretFingerprint()` (salted, length-prefixed, order-independent).

## Development

```bash
pnpm install
pnpm run check   # tsc --noEmit
pnpm run smoke   # offline smoke tests: pipeline, secrets, args, zip, end-to-end handler
pnpm test        # check + smoke
```

The smoke tests are hermetic: `--env-file` points at `fixtures/`, and every export goes to a temp directory, so your real `~/.zshrc` and sessions are never read.

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
