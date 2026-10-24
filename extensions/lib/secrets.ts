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
// - env files (default: the user's shell rc files): lines starting with
//   `export`, valid shell identifier names, value = text after the first `=`
//   (one optional opening quote), truncated at the first `"`, `'`, or `#`,
//   then trimmed
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
import { join } from "node:path";

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

/** Shell rc files scanned when the user passes no --env-file. Missing files are skipped. */
export function defaultEnvFiles(home: string = homedir()): string[] {
	return [".zshrc", ".zshenv", ".bashrc", ".bash_profile", ".profile"].map((name) => join(home, name));
}

const EXPORT_PREFIX = "export";
const IDENTIFIER_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const VALUE_STOP_RE = /["'#]/;

/**
 * Parse `export NAME=...` lines out of env file content.
 *
 * Implemented line-by-line: after an exact `export` prefix and whitespace,
 * the value starts at the first `=`, drops one optional opening quote, and
 * ends at the first quote or `#` (inline comment). A line with nothing at
 * all after `=` yields no entry; a value that trims to empty still yields
 * one (the caller's length filter decides).
 */
export function parseEnvFileSecrets(content: string): Array<{ name: string; value: string }> {
	const found: Array<{ name: string; value: string }> = [];
	for (const line of content.split("\n")) {
		if (!line.startsWith(EXPORT_PREFIX)) continue;
		const afterKeyword = line.slice(EXPORT_PREFIX.length);
		if (afterKeyword.length === 0 || !/^\s/.test(afterKeyword)) continue;

		const eqIndex = afterKeyword.indexOf("=");
		if (eqIndex <= 0) continue;
		const name = afterKeyword.slice(0, eqIndex).trim();
		if (!IDENTIFIER_RE.test(name)) continue;

		let value = afterKeyword.slice(eqIndex + 1);
		if (value.length === 0) continue; // `export A=` — nothing to redact
		if (value.startsWith('"') || value.startsWith("'")) value = value.slice(1);
		const stop = value.search(VALUE_STOP_RE);
		if (stop >= 0) value = value.slice(0, stop);
		found.push({ name, value: value.trim() });
	}
	return found;
}

export interface BuildSecretsOptions {
	/** Env files to scan. Defaults to defaultEnvFiles(). Missing files are ignored. */
	envFiles?: readonly string[];
	/** Single env file (legacy shorthand for envFiles: [envFile]). */
	envFile?: string;
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
	// A value that appears inside the replacement marker would corrupt the
	// marker itself (and would forever show up as a "residual secret").
	if (value.includes(PLACEHOLDER_PREFIX) || PLACEHOLDER_PREFIX.includes(value)) return "placeholder";
	return null;
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

	const envFiles = options.envFiles ?? (options.envFile ? [options.envFile] : defaultEnvFiles(home));
	let tooShortEnv = 0;
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
		for (const { name, value } of parseEnvFileSecrets(content)) {
			if (!looksSensitiveName(name)) continue;
			const rejection = rejectionFor(value);
			if (rejection === "too-short") {
				tooShortEnv += 1;
				continue;
			}
			if (rejection === "placeholder") continue;
			byName.set(name, value);
		}
	}
	if (tooShortEnv > 0) {
		warnings.push(`Ignored ${tooShortEnv} env value(s) shorter than ${MIN_SECRET_LENGTH} characters`);
	}

	let secretIndex = 1;
	let tooShortInputs = 0;
	let fileInputs = 0;
	let fileLines = 0;
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
				lines = readFileSync(asPath, "utf-8").split("\n");
			} catch {
				warnings.push(`Ignored unreadable secret file: ${asPath}`);
				continue;
			}
			for (const line of lines) {
				const value = line.trim();
				if (value.length === 0) continue;
				if (rejectionFor(value) !== null) {
					tooShortInputs += 1;
					continue;
				}
				byName.set(`SECRET_${secretIndex++}`, value);
				fileLines += 1;
			}
			continue;
		}

		if (input.length === 0) continue;
		if (rejectionFor(input) !== null) {
			tooShortInputs += 1;
			continue;
		}
		byName.set(`SECRET_${secretIndex++}`, input);
	}
	if (tooShortInputs > 0) {
		warnings.push(
			`Ignored ${tooShortInputs} secret value(s) shorter than ${MIN_SECRET_LENGTH} characters ` +
				"(they would match unrelated text and destroy the export)",
		);
	}
	if (fileInputs > 0) {
		warnings.push(`Read ${fileLines} secret(s) from ${fileInputs} file(s)`);
	}

	const secrets: SecretEntry[] = [];
	for (const [name, value] of byName) {
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

export interface SecretMatcher {
	/**
	 * Replace every occurrence in one pass. Because the matcher is a single
	 * alternation, replacement markers are never rescanned — a short secret can
	 * never rewrite a marker that a previous secret just inserted.
	 */
	replace(text: string, onReplace?: (entry: SecretEntry) => void): string;
}

/** Build the single-pass literal matcher, or null when there is nothing to replace. */
export function createSecretMatcher(secrets: readonly SecretEntry[]): SecretMatcher | null {
	const usable = secrets.filter((entry) => entry.value.length > 0 && rejectionFor(entry.value) === null);
	if (usable.length === 0) return null;

	const byValue = new Map<string, SecretEntry>();
	for (const entry of usable) {
		if (!byValue.has(entry.value)) byValue.set(entry.value, entry);
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

/** Count non-overlapping occurrences of a literal in a text. */
export function countOccurrences(text: string, value: string): number {
	if (!value) return 0;
	let count = 0;
	let from = 0;
	for (;;) {
		const at = text.indexOf(value, from);
		if (at < 0) return count;
		count += 1;
		from = at + value.length;
	}
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
	for (const value of secrets.map((entry) => entry.value).sort()) {
		const bytes = Buffer.from(value, "utf8");
		digest.update(`${bytes.length}:`).update(bytes).update("\n");
	}
	return { algorithm: "sha256", salt, digest: digest.digest("hex") };
}
