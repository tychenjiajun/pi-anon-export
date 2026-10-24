// Argument parsing for /anon-export.
//
// The command receives one raw string from the pi prompt, so this module
// implements a tiny shell-like tokenizer: single and double quotes are
// honored (so `--secret "value with spaces"` works) and `\"` / `\\` escape
// inside double quotes. `--flag=value` is accepted as an escape hatch for
// values that themselves start with `--`.
//
// A missing value is an error rather than "the next flag becomes the value":
// `--out --no-images` must never create a directory called "--no-images".

import { type RedactionLevel } from "./redact.ts";

export interface AnonExportArgs {
	/** "zip" exports every session of the cwd's session dir; anything else exports the current session. */
	mode: "current" | "zip";
	/** --no-images: strip embedded image data blocks. */
	removeImages: boolean;
	/** --level fast|full (default full). */
	level: RedactionLevel;
	/** --out <dir>; defaults to ./pi-anon-export-<timestamp>/ (cwd itself in zip mode). */
	out?: string;
	/** --secret <literal|file>, repeatable. */
	secrets: string[];
	/** --env-file <path>, repeatable. Replaces the default shell rc file set. */
	envFiles: string[];
}

export const USAGE =
	"/anon-export [zip] [--no-images] [--level fast|full] [--out <dir>] [--secret <literal|file>] [--env-file <path>]";

const VALUE_FLAGS = new Set(["--level", "--out", "--secret", "--env-file"]);

/**
 * Split a raw argument string into tokens, honoring quotes.
 * Returns an error object for an unterminated quote.
 */
export function tokenizeArgs(raw: string): string[] | { error: string } {
	const tokens: string[] = [];
	let current = "";
	let started = false;
	let quote: "'" | '"' | null = null;

	for (let i = 0; i < raw.length; i++) {
		const ch = raw.charAt(i);

		if (quote === "'") {
			if (ch === "'") quote = null;
			else current += ch;
			started = true;
			continue;
		}

		if (quote === '"') {
			if (ch === '"') {
				quote = null;
			} else if (ch === "\\" && (raw.charAt(i + 1) === '"' || raw.charAt(i + 1) === "\\")) {
				current += raw.charAt(++i);
			} else {
				current += ch;
			}
			started = true;
			continue;
		}

		if (ch === "'" || ch === '"') {
			quote = ch;
			started = true;
			continue;
		}

		// Outside quotes a backslash only escapes whitespace, a quote or another
		// backslash: `C:\Users\me` stays a path instead of losing its separators.
		if (ch === "\\" && i + 1 < raw.length && /[\s"'\\]/.test(raw.charAt(i + 1))) {
			current += raw.charAt(++i);
			started = true;
			continue;
		}

		if (/\s/.test(ch)) {
			if (started) {
				tokens.push(current);
				current = "";
				started = false;
			}
			continue;
		}

		current += ch;
		started = true;
	}

	if (quote !== null) {
		return { error: `Unterminated ${quote === '"' ? "double" : "single"} quote in arguments` };
	}
	if (started) tokens.push(current);
	return tokens;
}

type ValueResult = { value: string; index: number } | { error: string };

function takeValue(
	flag: string,
	inline: string | undefined,
	tokens: readonly string[],
	index: number,
): ValueResult {
	if (inline !== undefined) {
		if (inline.length === 0) return { error: `${flag} requires a value` };
		return { value: inline, index };
	}
	const next = tokens[index + 1];
	if (next === undefined || next.startsWith("--")) {
		return { error: `${flag} requires a value (use ${flag}=VALUE for values that start with "--")` };
	}
	return { value: next, index: index + 1 };
}

/** Parse command arguments. Returns an error message for invalid input. */
export function parseAnonExportArgs(raw: string): AnonExportArgs | { error: string } {
	const tokenized = tokenizeArgs(raw);
	if ("error" in tokenized) return tokenized;
	const tokens = tokenized;

	const args: AnonExportArgs = {
		mode: "current",
		removeImages: false,
		level: "full",
		secrets: [],
		envFiles: [],
	};

	for (let i = 0; i < tokens.length; i++) {
		const token = tokens[i] as string;
		const eq = token.startsWith("--") ? token.indexOf("=") : -1;
		const flag = eq >= 0 ? token.slice(0, eq) : token;
		const inline = eq >= 0 ? token.slice(eq + 1) : undefined;

		if (!VALUE_FLAGS.has(flag) && inline !== undefined) {
			return { error: `${flag} does not take a value\nUsage: ${USAGE}` };
		}

		switch (flag) {
			case "zip":
				args.mode = "zip";
				break;
			case "--no-images":
				args.removeImages = true;
				break;
			case "--level": {
				const taken = takeValue(flag, inline, tokens, i);
				if ("error" in taken) return taken;
				if (taken.value !== "fast" && taken.value !== "full") {
					return { error: `--level must be "fast" or "full" (got ${JSON.stringify(taken.value)})` };
				}
				args.level = taken.value;
				i = taken.index;
				break;
			}
			case "--out": {
				const taken = takeValue(flag, inline, tokens, i);
				if ("error" in taken) return taken;
				args.out = taken.value;
				i = taken.index;
				break;
			}
			case "--secret": {
				const taken = takeValue(flag, inline, tokens, i);
				if ("error" in taken) return taken;
				args.secrets.push(taken.value);
				i = taken.index;
				break;
			}
			case "--env-file": {
				const taken = takeValue(flag, inline, tokens, i);
				if ("error" in taken) return taken;
				args.envFiles.push(taken.value);
				i = taken.index;
				break;
			}
			default:
				return { error: `Unknown argument: ${token}\nUsage: ${USAGE}` };
		}
	}

	return args;
}
