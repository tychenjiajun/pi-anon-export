// Path helpers shared by argument parsing, secret discovery and the export
// handler.
//
// Command arguments arrive as one raw string typed into the pi prompt, so a
// leading `~` is never expanded by a shell — it is expanded here instead.

import { homedir } from "node:os";
import { join, resolve } from "node:path";

const TILDE_PREFIXES = ["~/", "~\\"] as const;

/**
 * Expand a leading `~` or `~/…` to the user's home directory.
 * `~user` (a named home directory) is left untouched — we do not guess.
 */
export function expandHome(input: string, home: string = homedir()): string {
	if (input === "~") return home;
	for (const prefix of TILDE_PREFIXES) {
		if (input.startsWith(prefix)) return join(home, input.slice(prefix.length));
	}
	return input;
}

/** Expand `~`, then resolve the result against `cwd` so relative paths work as typed. */
export function resolveUserPath(input: string, cwd: string, home: string = homedir()): string {
	return resolve(cwd, expandHome(input, home));
}
