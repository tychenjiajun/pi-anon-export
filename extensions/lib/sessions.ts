// Session location and safe reading.
//
// Pi stores sessions as JSONL under (by default) ~/.pi/agent/sessions/--<path>--/
// where <path> is the cwd with the leading slash removed and "/", "\", ":"
// replaced by "-". Storage can be overridden by (highest precedence first):
// --session-dir, PI_CODING_AGENT_SESSION_DIR, the sessionDir setting.
//
// Inside a running pi, ctx.sessionManager.getSessionDir() already reflects all
// of those, so the extension prefers it and only falls back to resolving
// precedence here (or when getSessionDir is unavailable).

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";

/** Environment override for session storage (lowest CLI precedence). */
export const SESSION_ENV_VAR = "PI_CODING_AGENT_SESSION_DIR";

/** Encode a cwd into pi's session directory name: --<path>-- */
export function encodeSessionDirName(cwd: string): string {
	const resolved = resolve(cwd);
	return `--${resolved.replace(/^[/\\]/, "").replace(/[/\\:]/g, "-")}--`;
}

/** Default session directory for a cwd: ~/.pi/agent/sessions/--<path>-- */
export function defaultSessionDir(cwd: string): string {
	return join(homedir(), ".pi", "agent", "sessions", encodeSessionDirName(cwd));
}

export interface ResolvedSessionDir {
	dir: string;
	source: "session-manager" | "env" | "settings" | "default";
}

export interface ResolveSessionDirOptions {
	cwd: string;
	/** Value from ctx.sessionManager.getSessionDir(), if available. Highest precedence. */
	sessionManagerDir?: string | undefined;
	/** sessionDir from pi settings, if available. Relative paths resolve from cwd. */
	settingsDir?: string | undefined;
	/** Env to read (defaults to process.env). Injectable for tests. */
	env?: NodeJS.ProcessEnv;
}

/** Resolve the session directory honoring env var and settings fallbacks. */
export function resolveSessionDir(options: ResolveSessionDirOptions): ResolvedSessionDir {
	const { cwd, sessionManagerDir, settingsDir } = options;
	const env = options.env ?? process.env;

	if (sessionManagerDir && sessionManagerDir.trim().length > 0) {
		return { dir: resolve(sessionManagerDir), source: "session-manager" };
	}

	const envDir = env[SESSION_ENV_VAR];
	if (envDir && envDir.trim().length > 0) {
		return { dir: resolve(envDir), source: "env" };
	}

	if (settingsDir && settingsDir.trim().length > 0) {
		// Per pi docs, relative sessionDir resolves from the working directory.
		return { dir: resolve(cwd, settingsDir), source: "settings" };
	}

	return { dir: defaultSessionDir(cwd), source: "default" };
}

export interface SkippedFile {
	path: string;
	error: string;
}

export interface SessionFileList {
	/** Absolute paths of *.jsonl files, most recently modified first. */
	files: string[];
	/** Files that could not be inspected; skipped without failing the batch. */
	skipped: SkippedFile[];
}

/** List *.jsonl session files in a directory (non-recursive), newest first. */
export function listSessionFiles(dir: string): SessionFileList {
	const files: string[] = [];
	const skipped: SkippedFile[] = [];
	if (!existsSync(dir)) return { files, skipped };

	let entries: string[];
	try {
		entries = readdirSync(dir);
	} catch (error) {
		skipped.push({ path: dir, error: String(error) });
		return { files, skipped };
	}

	for (const entry of entries) {
		if (!entry.endsWith(".jsonl")) continue;
		const path = join(dir, entry);
		try {
			const stat = statSync(path);
			if (!stat.isFile()) continue;
			files.push(path);
		} catch (error) {
			skipped.push({ path, error: String(error) });
		}
	}

	files.sort((a, b) => {
		try {
			return statSync(b).mtimeMs - statSync(a).mtimeMs;
		} catch {
			return a < b ? -1 : 1;
		}
	});

	return { files, skipped };
}

export type SafeReadResult =
	| { ok: true; content: string }
	| { ok: false; path: string; error: string };

/** Read a session file; failures are reported, never thrown, so a batch survives bad files. */
export function readSessionFileSafe(path: string): SafeReadResult {
	try {
		return { ok: true, content: readFileSync(path, "utf-8") };
	} catch (error) {
		return { ok: false, path, error: String(error) };
	}
}
