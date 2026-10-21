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
| `--no-images` | Strip embedded image data blocks (replaced with `[IMAGE_REMOVED]`). Without it, images are **kept** and counted for manual review. |
| `--level fast\|full` | Redaction depth. Default: `full`. |
| `--out <dir>` | Output directory. Default: `./pi-anon-export-<timestamp>/` in the current working directory. |
| `--secret <lit\|file>` | Add an extra literal secret. If the value is a readable file path, it is read as one secret per line. Repeatable. |

The command reports the number of exported sessions, the output path, and the redaction counts (secrets replaced, images removed/flagged, dropped lines, and anonymizer categories).

### Examples

```bash
/anon-export
/anon-export zip --no-images
/anon-export --level fast --out /tmp/shareable --secret "my-personal-token"
```

## Redaction levels

Every export runs the same base pipeline, per JSONL line:

1. **Parse or drop (fail-safe).** Lines that are not valid JSON are **discarded and counted** (`dropped_lines`) — broken lines are never passed through verbatim.
2. **Image handling.** A `data` string longer than 256 characters inside a content block is treated as an embedded image. With `--no-images` it becomes `[IMAGE_REMOVED]`; otherwise it is kept but counted (`images_flagged`) so you know to review it.
3. **Literal secret replacement.** Every occurrence of a discovered secret becomes `[REDACTED_<NAME>]`. Secrets come from:
   - `export NAME=...` lines in `~/.zshrc` where the variable name contains `KEY`, `TOKEN`, `SECRET`, `PASSWORD`, `PWD`, or `COOKIE` and the value is longer than 4 characters;
   - every `--secret` you pass (literals or files, one secret per line).
   Longer values are replaced first so partial overlaps are fully covered.

Then, depending on the level:

- **`fast`** — stops here. Only structural drops, image policy, and literal secrets.
- `full` (default) — additionally runs every leaf value through an **anonymizer** (emails → `redacted-<hash8>@example.com`, plus other identity patterns) with a stateful, consistent mapping across the whole export run, so the same input always maps to the same output within one export.

The zip mode adds a `manifest.json` listing each source file, the sha256 of its redacted content, and its redaction counts — so recipients can verify exactly what was applied.

## ⚠️ Disclaimer: anonymization is best-effort

**Anonymization is a best-effort heuristic, not a guarantee.** Review every export manually before publishing or sharing it. Secrets that don't match the naming heuristics, novel identifiers, or PII patterns the anonymizer doesn't know about can survive redaction. The author assumes no liability for information that remains in an exported file.

Known by-design behaviors (all documented in `extensions/lib/anonymize.ts`):

- Text segments containing `/` are treated as paths and their `user@host`-shaped parts are **kept** (matches the upstream Teich guards); URL userinfo (`https://user@host/…`) is also kept.
- Public git remotes, reserved example domains, systemd units (`x@y.service`), and package versions (`lodash@4.17.21`) are preserved.
- Backslash-separated strings like `dir\name@foo.com` are **over-redacted** (the email-shaped tail is replaced): false positives are preferred over leaks.
- Usernames in code-host URLs (`git:github.com/<user>/…`, `git@github.com:<user>/…`, `https://github.com/<user>`) are rewritten only after that username has been seen in a home path or as an email local part.
- Images are kept by default and flagged for manual review; use `--no-images` to strip them.

## Privacy: fully local

This extension performs **no network I/O at all**. It reads your session files and `~/.zshrc`, writes results under the output directory, and does nothing else. No telemetry, no uploads, no model calls. The only runtime dependency is [`fflate`](https://github.com/101arrowz/fflate) (pure-JS zip), used locally in zip mode.

## Session location

Exported sessions are located the same way pi itself locates them:

- `ctx.sessionManager.getSessionDir()` / `getSessionFile()` inside a running session (these already honor `--session-dir`, `PI_CODING_AGENT_SESSION_DIR`, and the `sessionDir` setting);
- otherwise `~/.pi/agent/sessions/--<path>--/`, where `<path>` is the cwd with the leading slash stripped and `/`, `\`, `:` replaced by `-`.

## For developers: the anonymizer contract

`extensions/lib/anonymize.ts` exposes the extension point used by the `full` level:

```ts
export interface Anonymizer {
  anonymizeValue(value: unknown): unknown; // stateful, consistent within one instance
  readonly counts: Record<string, number>;
}
export function createAnonymizer(): Anonymizer;
```

One `Anonymizer` instance is created per export run and shared across all files, so mappings stay consistent. `counts` accumulates rewritten-value counts per category and is merged into the redaction report and the zip manifest.

## Development

```bash
npm install
npm run check   # tsc --noEmit
npm run smoke   # offline smoke test against fixtures/
```

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
