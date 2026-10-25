// Literal secret discovery, matching and fingerprinting.
//
// Independent implementation — not copied from any upstream source. The
// *approach* (scan shell env files for `export NAME=value` lines with
// credential-looking variable names, merge user-supplied literals, replace
// exact occurrences longest-first with [REDACTED_<NAME>]) is publicly
// documented in several tools, including badlogic/pi-share-hf — which ships
// no license at all, so no code was taken from it; only the documented
// behavior is reimplemented here, with an unrelated line-based parser.
//
// Behavior:
// - env files (default: the user's shell rc files): `export NAME=value` lines
//   (optionally indented), valid shell identifier names, value read the way a
//   POSIX shell reads it: a quoted value runs to its matching closing quote
//   (so `#` inside quotes is part of the secret), an unquoted value ends at
//   the first whitespace (a `#` that starts a word is a comment, but
//   `plain#not-a-comment` keeps its `#`)
// - a variable counts as secret when its name contains KEY / TOKEN / SECRET /
//   PASS / PWD / COOKIE / CREDENTIAL (case-insensitive) and the value is at
//   least MIN_SECRET_LENGTH characters
// - user --secret inputs: a literal, or a file of one secret per line
// - values shorter than MIN_SECRET_LENGTH are refused: a 1-character "secret"
//   would replace every occurrence of that character and destroy the export
// - output sorted longest-value-first so overlapping secrets redact fully

import { createHash, randomBytes } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { basename, join } from "node:path";

import { resolveUserPath } from "./paths.ts";

/**
 * Names containing any of these substrings are treated as credentials.
 * "PASS" covers PASS / PASSWD / PASSWORD; "KEY" covers API_KEY, STRIPE_KEY…
 */
const SENSITIVE_NAME_PARTS = ["KEY", "TOKEN", "SECRET", "PASS", "PWD", "COOKIE", "CREDENTIAL"] as const;

/**
 * Values shorter than this are refused (both env-file and --secret inputs).
 * Short values match too much text: replacing "a" would rewrite half the file.
 */
export const MIN_SECRET_LENGTH = 5;

/** Marker prefix used for replacements; secrets matching inside it are refused. */
const PLACEHOLDER_PREFIX = "[REDACTED_";

export interface SecretEntry {
	/** Variable name (env var name, or SECRET_n for user-provided inputs). */
	name: string;
	/** The literal value to redact. */
	value: string;
	/** Replacement text, always `[REDACTED_<NAME>]`. */
	replacement: string;
}

/** True when a variable name suggests a credential. */
export function looksSensitiveName(name: string): boolean {
	const upper = name.toUpperCase();
	return SENSITIVE_NAME_PARTS.some((part) => upper.includes(part));
}

/**
 * Shell rc files scanned when the user passes no --env-file, in the order a
 * shell would source them: a later file overrides an earlier one, so the value
 * the user actually gets in an interactive shell wins (`.zshenv` → `.zprofile`
 * → `.zshrc` → `.zlogin`, then the bash files). Missing files are skipped.
 */
export function defaultEnvFiles(home: string = homedir()): string[] {
	return [
		".zshenv",
		".zprofile",
		".zshrc",
		".zlogin",
		".bash_profile",
		".bashrc",
		".profile",
	].map((name) => join(home, name));
}

const EXPORT_LINE_RE = /^\s*(?:export|declare\s+-x)\s+/;
const IDENTIFIER_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const WHITESPACE_RE = /[ \t\r\n\f\v]/;

/** Strip a UTF-8 BOM and split on CRLF, CR and LF. */
function splitEnvLines(content: string): string[] {
	return content.replace(/^\uFEFF/, "").split(/\r\n|\r|\n/);
}

/**
 * Read the value part of an assignment the way a POSIX shell would.
 *
 * Quoted segments run to their matching closing quote and concatenate with
 * unquoted runs (`"$HOME/bin"` + `:x`), so a `#` inside quotes stays part of
 * the value. Truncating at the first `#` used to turn `"Tr0ub4dor#2024!x"`
 * into `"Tr0ub4dor"`: only the prefix was redacted, the tail leaked, and the
 * residual-secret verification could not see it (it only knew the truncated
 * needle). An unquoted run ends at whitespace (so ` # comment` is skipped),
 * and an unterminated quote keeps the remainder rather than dropping a real
 * secret.
 */
function readShellValue(raw: string): string {
	let out = "";
	let index = 0;
	while (index < raw.length) {
		const char = raw.charAt(index);
		if (char === '"' || char === "'") {
			const rest = raw.slice(index);
			const closing = findClosingQuote(rest, char);
			if (closing < 0) return out + rest.slice(1).replace(/\s+$/, "");
			out += unescapeQuotedValue(rest.slice(1, closing), char);
			index += closing + 1;
			continue;
		}
		if (char === "\\" && index + 1 < raw.length) {
			// Unquoted `\ ` / `\#` / `\"` keep the escaped character: bash sets
			// `API_KEY=abc123\ def456` to `abc123 def456`, and stopping at the
			// space produced the truncated needle `abc123\`.
			out += raw.charAt(index + 1);
			index += 2;
			continue;
		}
		if (WHITESPACE_RE.test(char)) break;
		out += char;
		index += 1;
	}
	return out;
}

/** Index of the quote that closes an opening quote at index 0, or -1. */
function findClosingQuote(text: string, quote: string): number {
	for (let index = 1; index < text.length; index++) {
		const char = text.charAt(index);
		if (quote === '"' && char === "\\") {
			index += 1; // skip the escaped character
			continue;
		}
		if (char === quote) return index;
	}
	return -1;
}

/** Inside double quotes a shell resolves `\"`, `\\`, `\$` and `` \` ``. */
function unescapeQuotedValue(text: string, quote: string): string {
	if (quote === "'") return text;
	return text.replace(/\\(["\\$`])/g, "$1");
}

/**
 * Parse `export NAME=...` lines out of env file content.
 *
 * Implemented line-by-line, and indentation is allowed: an `export TOKEN=…`
 * indented inside an `if` block in a shell rc file is just as real as an
 * unindented one. A line with nothing after `=` yields no entry; a value that
 * reads as empty still yields one (the caller's length filter decides).
 *
 * Physical lines ending in `\` are joined first: a continuation inside a
 * quoted value (`export API_KEY="abc1\` + newline + `def456"`) would
 * otherwise become the truncated needle `abc1\` and leak the rest.
 */
export interface EnvSecretLine {
	name: string;
	value: string;
	/** True for `NAME+=value` (an append, not a definition). */
	append?: boolean;
}

export function parseEnvFileSecrets(content: string): EnvSecretLine[] {
	const found: EnvSecretLine[] = [];
	for (const rawLine of joinContinuations(splitEnvLines(content))) {
		const keyword = EXPORT_LINE_RE.exec(rawLine);
		if (keyword === null) continue;

		const afterKeyword = rawLine.slice(keyword[0].length);
		const eqIndex = findAssignmentIndex(afterKeyword);
		if (eqIndex <= 0) continue;
		// `A+=x` appends to A; the appended text must be redacted too, so the
		// trailing `+` is dropped from the name and the value read as usual.
		const rawName = afterKeyword.slice(0, eqIndex).trim();
		const append = rawName.endsWith("+");
		const name = append ? rawName.slice(0, -1).trim() : rawName;
		if (!IDENTIFIER_RE.test(name)) continue;

		const raw = afterKeyword.slice(eqIndex + 1);
		if (raw.length === 0) continue; // `export A=` — nothing to redact
		const entry: EnvSecretLine = { name, value: readShellValue(raw) };
		if (append) entry.append = true;
		found.push(entry);
	}
	return found;
}

/**
 * Join `\`-continued physical lines into logical ones.
 *
 * Shell rules that matter for secret discovery: a COMMENT line is never
 * continued (so `# note \` must not swallow the `export` on the next line, as
 * it would leave the real key unscanned), and a backslash inside single quotes
 * is a literal character, not a continuation.
 */
function joinContinuations(lines: readonly string[]): string[] {
	const joined: string[] = [];
	let pending: string | null = null;
	let inSingleQuote = false;
	for (const line of lines) {
		if (pending === null && line.trimStart().startsWith("#")) {
			joined.push(line);
			continue;
		}
		inSingleQuote = advanceSingleQuoteState(line, inSingleQuote);
		const combined: string = pending === null ? line : `${pending}${line}`;
		if (!inSingleQuote && /\\$/.test(combined)) {
			pending = combined.slice(0, -1);
			continue;
		}
		joined.push(combined);
		pending = null;
	}
	if (pending !== null) joined.push(pending);
	return joined;
}

/** Track single-quote state across a physical line (outside quotes `\` escapes). */
function advanceSingleQuoteState(line: string, inSingleQuote: boolean): boolean {
	for (let index = 0; index < line.length; index++) {
		const char = line.charAt(index);
		if (inSingleQuote) {
			if (char === "'") inSingleQuote = false;
			continue;
		}
		if (char === "\\") {
			index += 1;
			continue;
		}
		if (char === "'") inSingleQuote = true;
	}
	return inSingleQuote;
}

/**
 * Index of the `=` that assigns. In an `export`/`declare -x` line the first
 * `=` always starts the value: bash sets `export A==x` to `=x`, so skipping
 * `==` (as if it were a comparison) silently dropped the value.
 * `A+=x` is an append; the caller folds the `+` into the name.
 */
function findAssignmentIndex(text: string): number {
	return text.indexOf("=");
}

export interface BuildSecretsOptions {
	/** Env files to scan. Defaults to defaultEnvFiles(). Missing files are ignored. */
	envFiles?: readonly string[];
	/** User-provided --secret inputs: a literal value, or a path to a file of one secret per line. */
	secretInputs?: readonly string[];
	/** Base directory for relative env-file / secret-file paths (default: process.cwd()). */
	cwd?: string;
	/** Home directory used for `~` expansion in paths (default: os.homedir()). */
	home?: string;
	/** Warn when an env file does not exist (set for user-supplied --env-file paths). */
	warnMissingEnvFiles?: boolean;
}

export interface BuildSecretsResult {
	/** Deduplicated, length-descending list of literal secrets. */
	secrets: SecretEntry[];
	/**
	 * Human-readable notes about inputs that were ignored. Never contains a
	 * secret value — notes are safe to show and to write into a report.
	 */
	warnings: string[];
}

/** Why a candidate value must not become a secret. */
type Rejection = "too-short" | "placeholder";

function rejectionFor(value: string): Rejection | null {
	if (value.length < MIN_SECRET_LENGTH) return "too-short";
	// Only a value that could sit INSIDE a generated marker is refused: replacing
	// it would corrupt the marker we just wrote (and the value would forever
	// count as a residual secret). A long secret that merely CONTAINS
	// `[REDACTED_` is perfectly safe to replace — the matcher never rescans
	// inserted text — and refusing it used to drop a real secret silently.
	if (PLACEHOLDER_PREFIX.includes(value)) return "placeholder";
	return null;
}

export interface RejectionCounts {
	tooShort: number;
	placeholder: number;
}

function describeRejections(counts: RejectionCounts, source: string): string[] {
	const notes: string[] = [];
	if (counts.tooShort > 0) {
		notes.push(
			`Ignored ${counts.tooShort} ${source} shorter than ${MIN_SECRET_LENGTH} characters ` +
				"(they would match unrelated text and destroy the export)",
		);
	}
	if (counts.placeholder > 0) {
		notes.push(
			`Ignored ${counts.placeholder} ${source} that match part of the ` +
				`${PLACEHOLDER_PREFIX}…] marker (they would corrupt the output)`,
		);
	}
	return notes;
}

/**
 * Build the deduplicated, length-descending list of literal secrets.
 * User-provided secrets win over env-file entries with the same name.
 */
export function buildLiteralSecrets(options: BuildSecretsOptions = {}): BuildSecretsResult {
	const cwd = options.cwd ?? process.cwd();
	const home = options.home ?? homedir();
	const warnings: string[] = [];
	const byName = new Map<string, string>(); // name -> value

	const envFiles = options.envFiles ?? defaultEnvFiles(home);
	const envRejections: RejectionCounts = { tooShort: 0, placeholder: 0 };
	const overridden = new Map<string, string>(); // name -> last file it was seen in
	// `NAME+=x` is an append: the effective value is previous+x, and the previous
	// value is still a substring worth redacting, so both are registered.
	const appended: Array<{ name: string; value: string }> = [];
	// Values as written, BEFORE the length/marker filters: `export API_KEY=sk`
	// is rejected as too short, but `API_KEY+=live-1234` still means
	// `sklive-1234`, and reconstructing it from the accepted values alone lost
	// the `sk` half of the secret.
	const rawValues = new Map<string, string>();
	const previousLabels = new Set<string>();
	const previousLabel = (name: string): string => {
		let label = `${name}_PREVIOUS`;
		let counter = 2;
		while (previousLabels.has(label) || byName.has(label)) {
			label = `${name}_PREVIOUS_${counter++}`;
		}
		previousLabels.add(label);
		return label;
	};
	for (const rawPath of envFiles) {
		const path = resolveUserPath(rawPath, cwd, home);
		if (!existsSync(path)) {
			if (options.warnMissingEnvFiles) warnings.push(`Env file not found: ${path}`);
			continue;
		}
		let content: string;
		try {
			content = readFileSync(path, "utf-8");
		} catch {
			warnings.push(`Ignored unreadable env file: ${path}`);
			continue;
		}
		for (const { name, value, append } of parseEnvFileSecrets(content)) {
			if (!looksSensitiveName(name)) continue;
			const previousRaw = rawValues.get(name);
			const effective = append ? `${previousRaw ?? ""}${value}` : value;
			rawValues.set(name, effective);

			const rejection = rejectionFor(effective);
			if (rejection === "too-short") {
				envRejections.tooShort += 1;
				continue;
			}
			if (rejection === "placeholder") {
				envRejections.placeholder += 1;
				continue;
			}
			if (append) {
				// The base value is still a substring of whatever gets exported.
				if (previousRaw !== undefined && previousRaw.length > 0 && rejectionFor(previousRaw) === null) {
					appended.push({ name: previousLabel(name), value: previousRaw });
				}
				byName.set(name, effective);
				continue;
			}
			// Later files win (source order), but a variable defined twice with
			// different values means one of them is stale: say so instead of
			// silently redacting the wrong needle.
			if (previousRaw !== undefined && previousRaw !== value) {
				overridden.set(name, basename(path));
			}
			byName.set(name, value);
		}
	}
	warnings.push(...describeRejections(envRejections, "env value(s)"));
	if (overridden.size > 0) {
		warnings.push(
			`${overridden.size} variable(s) are defined more than once across the scanned env files ` +
				`(last one wins, per shell source order): ${[...overridden.keys()].join(", ")}`,
		);
	}

	const inputRejections: RejectionCounts = { tooShort: 0, placeholder: 0 };
	let secretIndex = 1;
	let fileInputs = 0;
	let fileLines = 0;
	// `SECRET_<n>` is a plausible real variable name, so never let a generated
	// name clobber an env-file entry (that used to drop the env secret silently).
	const nextSecretName = (): string => {
		let name = `SECRET_${secretIndex++}`;
		while (byName.has(name)) name = `SECRET_${secretIndex++}`;
		return name;
	};
	for (const input of options.secretInputs ?? []) {
		const asPath = resolveUserPath(input, cwd, home);
		let isFile = false;
		try {
			isFile = existsSync(asPath) && statSync(asPath).isFile();
		} catch {
			isFile = false;
		}

		if (isFile) {
			fileInputs += 1;
			let lines: string[];
			try {
				// BOM-stripped and CRLF/CR aware, like the env files.
				lines = splitEnvLines(readFileSync(asPath, "utf-8"));
			} catch {
				warnings.push(`Ignored unreadable secret file: ${asPath}`);
				continue;
			}
			for (const line of lines) {
				const value = line.trim();
				if (value.length === 0) continue;
				const rejection = rejectionFor(value);
				if (rejection !== null) {
					inputRejections[rejection === "too-short" ? "tooShort" : "placeholder"] += 1;
					continue;
				}
				byName.set(nextSecretName(), value);
				fileLines += 1;
			}
			continue;
		}

		if (input.length === 0) continue;
		const rejection = rejectionFor(input);
		if (rejection !== null) {
			inputRejections[rejection === "too-short" ? "tooShort" : "placeholder"] += 1;
			continue;
		}
		byName.set(nextSecretName(), input);
	}
	warnings.push(...describeRejections(inputRejections, "secret value(s)"));
	if (fileInputs > 0) {
		warnings.push(`Read ${fileLines} secret(s) from ${fileInputs} file(s)`);
	}

	const secrets: SecretEntry[] = [];
	const values = new Set<string>();
	for (const [name, value] of [...byName, ...appended.map((entry) => [entry.name, entry.value] as const)]) {
		if (values.has(value)) continue; // one marker per distinct value
		values.add(value);
		secrets.push({ name, value, replacement: `[REDACTED_${name}]` });
	}
	// Longest value first: when one secret contains another as a substring,
	// the longer replacement wins and nothing survives inside it.
	secrets.sort((a, b) => b.value.length - a.value.length);
	return { secrets, warnings };
}

function escapeRegExp(literal: string): string {
	return literal.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** The value plus its NFC/NFD forms (normalization must not hide a secret). */
function valueVariants(value: string): string[] {
	const forms = new Set<string>([value]);
	forms.add(value.normalize("NFC"));
	forms.add(value.normalize("NFD"));
	return [...forms];
}

export interface SecretMatcher {
	/**
	 * Replace every occurrence in one pass. Because the matcher is a single
	 * alternation, replacement markers are never rescanned — a short secret can
	 * never rewrite a marker that a previous secret just inserted.
	 */
	replace(text: string, onReplace?: (entry: SecretEntry) => void): string;
}

/**
 * Build the single-pass literal matcher, or null when there is nothing to replace.
 *
 * Each value is registered in its NFC and NFD forms: a secret typed as `café`
 * (NFC) would otherwise be invisible in a session that stored the same text
 * decomposed (NFD) — both the redaction and the residual check would pass.
 */
export function createSecretMatcher(secrets: readonly SecretEntry[]): SecretMatcher | null {
	const usable = secrets.filter((entry) => entry.value.length > 0 && rejectionFor(entry.value) === null);
	if (usable.length === 0) return null;

	const byValue = new Map<string, SecretEntry>();
	for (const entry of usable) {
		for (const variant of valueVariants(entry.value)) {
			if (rejectionFor(variant) !== null) continue;
			if (!byValue.has(variant)) byValue.set(variant, entry);
		}
	}
	if (byValue.size === 0) return null;

	const alternatives = [...byValue.keys()]
		.sort((a, b) => b.length - a.length)
		.map(escapeRegExp)
		.join("|");
	const pattern = new RegExp(alternatives, "g");

	return {
		replace(text, onReplace) {
			if (!text) return text;
			return text.replace(pattern, (match: string): string => {
				const entry = byValue.get(match);
				if (!entry) return match;
				onReplace?.(entry);
				return entry.replacement;
			});
		},
	};
}

export interface SecretFingerprint {
	/** Hash algorithm. */
	algorithm: "sha256";
	/** Random per-run salt (hex). Makes identical secret sets unlinkable across runs. */
	salt: string;
	/** Hex digest of the salted, length-prefixed, order-independent secret value set. */
	digest: string;
}

const FINGERPRINT_VERSION = "pi-anon-export/secret-set/v1";

/**
 * Salted fingerprint of the secret set, suitable for reports and manifests.
 *
 * - The salt is random per export so two exports with the same secret set are
 *   not linkable, and a shared manifest cannot be used as an offline oracle
 *   for guessing a low-entropy secret (the salt is in the manifest, so treat
 *   this as a consistency check, not as a secrecy guarantee).
 * - Each value is length-prefixed before hashing, so ["ab","c"] and ["a","bc"]
 *   do not collide.
 */
export function computeSecretFingerprint(
	secrets: readonly SecretEntry[],
	salt: string = randomBytes(8).toString("hex"),
): SecretFingerprint {
	const digest = createHash("sha256");
	digest.update(FINGERPRINT_VERSION).update("\0");
	digest.update(salt).update("\0");
	// Deduplicated: the fingerprint describes the secret VALUE SET, so the same
	// value listed under two names must not change the digest.
	const values = new Set(secrets.map((entry) => entry.value));
	for (const value of [...values].sort()) {
		const bytes = Buffer.from(value, "utf8");
		digest.update(`${bytes.length}:`).update(bytes).update("\n");
	}
	return { algorithm: "sha256", salt, digest: digest.digest("hex") };
}
