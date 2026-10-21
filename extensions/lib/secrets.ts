// Literal secret discovery and hashing.
//
// Independent implementation — not copied from any upstream source. The
// *approach* (scan a shell env file for `export NAME=value` lines with
// credential-looking variable names, merge user-supplied literals, replace
// exact occurrences longest-first with [REDACTED_<NAME>]) is publicly
// documented in several tools, including badlogic/pi-share-hf — which ships
// no license at all, so no code was taken from it; only the documented
// behavior is reimplemented here, with an unrelated line-based parser.
//
// Behavior:
// - env file (default ~/.zshrc): lines starting with `export`, valid shell
//   identifier names, value = text after the first `=` (one optional opening
//   quote), truncated at the first `"`, `'`, or `#`, then trimmed
// - a variable counts as secret when its name contains KEY / TOKEN / SECRET /
//   PASSWORD / PWD / COOKIE (case-insensitive) and the value is > 4 chars
// - user --secret inputs: a literal, or a file of one secret per line
// - output sorted longest-value-first so overlapping secrets redact fully

import { createHash } from "node:crypto";
import { existsSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

const SENSITIVE_NAME_PARTS = ["KEY", "TOKEN", "SECRET", "PASSWORD", "PWD", "COOKIE"] as const;
const MIN_SECRET_LENGTH = 5; // value must be longer than 4 characters

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

/** Default env file scanned for `export NAME=...` secret lines. */
export function defaultEnvFile(): string {
	return join(homedir(), ".zshrc");
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
		if (/^\s*$/.test(afterKeyword)) continue; // `export` alone, value on… nowhere

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
	/** Env file to scan. Defaults to ~/.zshrc. Missing file is ignored. */
	envFile?: string;
	/** User-provided --secret inputs: a literal value, or a path to a file of one secret per line. */
	secretInputs?: readonly string[];
}

/**
 * Build the deduplicated, length-descending list of literal secrets.
 * User-provided secrets win over env-file entries with the same value.
 */
export function buildLiteralSecrets(options: BuildSecretsOptions = {}): SecretEntry[] {
	const secrets = new Map<string, string>(); // name -> value

	const envFile = options.envFile ?? defaultEnvFile();
	if (envFile && existsSync(envFile)) {
		try {
			const content = readFileSync(envFile, "utf-8");
			for (const { name, value } of parseEnvFileSecrets(content)) {
				if (looksSensitiveName(name) && value.length >= MIN_SECRET_LENGTH) {
					secrets.set(name, value);
				}
			}
		} catch {
			// Unreadable env file: skip rather than fail the export.
		}
	}

	let secretIndex = 1;
	for (const input of options.secretInputs ?? []) {
		const asPath = resolve(input);
		let isFile = false;
		try {
			isFile = existsSync(asPath) && statSync(asPath).isFile();
		} catch {
			isFile = false;
		}

		if (isFile) {
			const lines = readFileSync(asPath, "utf-8").split("\n");
			for (const line of lines) {
				const value = line.trim();
				if (value.length > 0) {
					secrets.set(`SECRET_${secretIndex++}`, value);
				}
			}
			continue;
		}

		if (input.length > 0) {
			secrets.set(`SECRET_${secretIndex++}`, input);
		}
	}

	const entries: SecretEntry[] = [];
	for (const [name, value] of secrets) {
		entries.push({ name, value, replacement: `[REDACTED_${name}]` });
	}
	// Longest value first: when one secret contains another as a substring,
	// the longer replacement wins and nothing survives inside it.
	entries.sort((a, b) => b.value.length - a.value.length);
	return entries;
}

/** Count non-overlapping occurrences of a secret value in a text. */
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

/**
 * Stable fingerprint of the secret set (independent of names/order), usable in
 * reports and manifests to prove which secret set was applied without leaking it.
 */
export function computeSecretHash(secrets: readonly SecretEntry[]): string {
	const digest = createHash("sha256");
	const values = secrets.map((entry) => entry.value).sort();
	for (const value of values) {
		digest.update(value).update("\n");
	}
	return `sha256:${digest.digest("hex")}`;
}
