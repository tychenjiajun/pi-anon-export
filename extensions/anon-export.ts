// pi-anon-export — anonymized session export for the pi coding agent.
//
// /anon-export            export the current session, anonymized, as JSONL
// /anon-export zip        export every session of the current working
//                         directory's session folder, zipped with a manifest
//
// Flags (both modes):
//   --no-images           strip embedded image data blocks
//   --level fast|full     redaction depth (default: full)
//   --out <dir>           output directory (default: ./pi-anon-export-<ts>/)
//   --secret <lit|file>   extra literal secret(s); a value that is a readable
//                         file path is treated as one-secret-per-line
//
// Everything runs locally; no data leaves the machine.
//
// Session location: ctx.sessionManager.getSessionDir()/getSessionFile() when
// available (they already honor --session-dir / PI_CODING_AGENT_SESSION_DIR /
// the sessionDir setting); otherwise the directory is derived from the cwd
// using pi's --<path>-- naming convention (see lib/sessions.ts).

import { mkdirSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";

import type {
	ExtensionAPI,
	ExtensionCommandContext,
	ExtensionFactory,
} from "@earendil-works/pi-coding-agent";

import { createAnonymizer, type Anonymizer } from "./lib/anonymize.ts";
import {
	emptyCounts,
	mergeCounts,
	redactSessionJsonl,
	type RedactionCounts,
	type RedactionLevel,
} from "./lib/redact.ts";
import { buildLiteralSecrets, computeSecretHash, defaultEnvFile, type SecretEntry } from "./lib/secrets.ts";
import {
	listSessionFiles,
	readSessionFileSafe,
	resolveSessionDir,
} from "./lib/sessions.ts";
import { buildExportZip } from "./lib/zip.ts";

export interface AnonExportArgs {
	/** "zip" exports every session of the cwd's session dir; anything else exports the current session. */
	mode: "current" | "zip";
	/** --no-images: strip embedded image data blocks. */
	removeImages: boolean;
	/** --level fast|full (default full). */
	level: RedactionLevel;
	/** --out <dir>; defaults to ./pi-anon-export-<timestamp>/ */
	out?: string;
	/** --secret <literal|file>, repeatable. */
	secrets: string[];
}

export const USAGE =
	"/anon-export [zip] [--no-images] [--level fast|full] [--out <dir>] [--secret <literal|file>]";

/** Parse command arguments. Returns an error message for invalid input. */
export function parseAnonExportArgs(raw: string): AnonExportArgs | { error: string } {
	const tokens = raw.trim().length > 0 ? raw.trim().split(/\s+/) : [];
	const args: AnonExportArgs = { mode: "current", removeImages: false, level: "full", secrets: [] };

	for (let i = 0; i < tokens.length; i++) {
		const token = tokens[i];
		if (token === undefined) continue;
		switch (token) {
			case "zip":
				args.mode = "zip";
				break;
			case "--no-images":
				args.removeImages = true;
				break;
			case "--level": {
				const value = tokens[++i];
				if (value !== "fast" && value !== "full") {
					return { error: `--level must be "fast" or "full" (got ${JSON.stringify(value ?? "")})` };
				}
				args.level = value;
				break;
			}
			case "--out": {
				const value = tokens[++i];
				if (!value) return { error: "--out requires a directory argument" };
				args.out = value;
				break;
			}
			case "--secret": {
				const value = tokens[++i];
				if (!value) return { error: "--secret requires a literal value or file path" };
				args.secrets.push(value);
				break;
			}
			default:
				return { error: `Unknown argument: ${token}\nUsage: ${USAGE}` };
		}
	}

	return args;
}

/** Notify when UI is available, log otherwise (json/print modes have no UI). */
function notify(
	ctx: Pick<ExtensionCommandContext, "hasUI" | "ui" | "mode">,
	message: string,
	type: "info" | "warning" | "error",
): void {
	if (ctx.hasUI) {
		ctx.ui.notify(message, type);
	} else {
		// eslint-disable-next-line no-console
		console.log(`[anon-export] ${type}: ${message}`);
	}
}

function timestampSlug(): string {
	return new Date().toISOString().replace(/[:.]/g, "-").replace(/,/g, "-");
}

function formatCounts(counts: RedactionCounts): string {
	const parts: string[] = [];
	if (counts.secret_replacements > 0) parts.push(`secrets=${counts.secret_replacements}`);
	if (counts.images_removed > 0) parts.push(`images_removed=${counts.images_removed}`);
	if (counts.images_flagged > 0) parts.push(`images_flagged=${counts.images_flagged}`);
	if (counts.dropped_lines > 0) parts.push(`dropped_lines=${counts.dropped_lines}`);
	for (const [key, value] of Object.entries(counts.anonymizer)) {
		if (value > 0) parts.push(`${key}=${value}`);
	}
	return parts.length > 0 ? parts.join(", ") : "no redactions";
}

export const anonExportCommand: ExtensionFactory = (pi: ExtensionAPI) => {
	pi.registerCommand("anon-export", {
		description:
			"Export the current session (or all cwd sessions with 'zip') as anonymized JSONL, locally",
		getArgumentCompletions: (prefix) => {
			const values = ["zip", "--no-images", "--level fast", "--level full", "--out", "--secret"];
			const filtered = values.filter((v) => v.startsWith(prefix));
			return filtered.length > 0 ? filtered.map((v) => ({ value: v, label: v })) : null;
		},
		handler: async (rawArgs: string, ctx: ExtensionCommandContext) => {
			const parsed = parseAnonExportArgs(rawArgs);
			if ("error" in parsed) {
				notify(ctx, parsed.error, "error");
				return;
			}
			const args = parsed;

			// --- Locate sessions -------------------------------------------------
			// getSessionDir()/getSessionFile() already honor --session-dir,
			// PI_CODING_AGENT_SESSION_DIR and the sessionDir setting. Fall back to
			// resolving those ourselves when the manager doesn't provide them.
			let managerDir: string | undefined;
			try {
				managerDir = ctx.sessionManager.getSessionDir();
			} catch {
				managerDir = undefined;
			}

			let settingsDir: string | undefined;
			try {
				settingsDir = pi.getSettings().sessionDir;
			} catch {
				settingsDir = undefined;
			}

			const { dir: sessionDir, source: dirSource } = resolveSessionDir({
				cwd: ctx.cwd,
				sessionManagerDir: managerDir,
				settingsDir,
			});

			// --- Collect source files --------------------------------------------
			const sources: Array<{ path: string; name: string }> = [];
			const listSkipped: Array<{ path: string; error: string }> = [];

			if (args.mode === "current") {
				let currentFile: string | undefined;
				try {
					currentFile = ctx.sessionManager.getSessionFile();
				} catch {
					currentFile = undefined;
				}
				if (!currentFile) {
					// No live session file (e.g. print mode): fall back to the most
					// recent session in the resolved directory.
					const { files, skipped } = listSessionFiles(sessionDir);
					listSkipped.push(...skipped);
					const newest = files[0];
					if (!newest) {
						notify(
							ctx,
							`No current session file and no sessions found in ${sessionDir} (dir source: ${dirSource})`,
							"error",
						);
						return;
					}
					currentFile = newest;
				}
				sources.push({ path: resolve(currentFile), name: basename(resolve(currentFile)) });
			} else {
				const { files, skipped } = listSessionFiles(sessionDir);
				listSkipped.push(...skipped);
				for (const file of files) {
					sources.push({ path: file, name: basename(file) });
				}
				if (sources.length === 0) {
					notify(ctx, `No *.jsonl sessions found in ${sessionDir} (dir source: ${dirSource})`, "error");
					return;
				}
			}

			// --- Secrets & output paths -------------------------------------------
			const secrets: SecretEntry[] = buildLiteralSecrets({
				envFile: defaultEnvFile(),
				secretInputs: args.secrets,
			});
			const secretHash = computeSecretHash(secrets);

			const outDir = resolve(ctx.cwd, args.out ?? `./pi-anon-export-${timestampSlug()}/`);
			try {
				mkdirSync(outDir, { recursive: true });
			} catch (error) {
				notify(ctx, `Failed to create output directory ${outDir}: ${String(error)}`, "error");
				return;
			}

			// --- Redact ------------------------------------------------------------
			// One anonymizer per run keeps value mappings consistent across files.
			const anonymizer: Anonymizer | undefined = args.level === "full" ? createAnonymizer() : undefined;

			const totals = emptyCounts();
			const readSkipped: Array<{ path: string; error: string }> = [];
			const zipFiles: Array<{ archivePath: string; content: string }> = [];
			const zipManifestFiles: Array<{
				source: string;
				archivePath: string;
				redactionCounts: RedactionCounts;
			}> = [];
			let written: string[] = [];

			for (const source of sources) {
				const read = readSessionFileSafe(source.path);
				if (!read.ok) {
					// Fail-safe: skip unreadable files, never abort the whole batch.
					readSkipped.push({ path: read.path, error: read.error });
					continue;
				}

				const { lines, counts } = redactSessionJsonl(read.content, {
					level: args.level,
					removeImages: args.removeImages,
					secrets,
					anonymizer,
				});
				mergeCounts(totals, counts);
				const content = lines.length > 0 ? `${lines.join("\n")}\n` : "";

				if (args.mode === "zip") {
					zipFiles.push({ archivePath: source.name, content });
					zipManifestFiles.push({ source: source.name, archivePath: source.name, redactionCounts: counts });
				} else {
					const outPath = join(outDir, source.name);
					try {
						writeFileSync(outPath, content, "utf-8");
						written.push(outPath);
					} catch (error) {
						notify(ctx, `Failed to write ${outPath}: ${String(error)}`, "error");
						return;
					}
				}
			}

			const allSkipped = [...listSkipped, ...readSkipped];
			let outputPath: string;

			if (args.mode === "zip") {
				if (zipFiles.length === 0) {
					notify(ctx, "No sessions could be read; nothing exported.", "error");
					return;
				}
				const zipBytes = buildExportZip(zipFiles, {
					generatedAt: new Date().toISOString(),
					level: args.level,
					removeImages: args.removeImages,
					fileCount: zipFiles.length,
					skipped: allSkipped,
					files: zipManifestFiles,
				});
				outputPath = join(outDir, `pi-anon-export-${timestampSlug()}.zip`);
				try {
					writeFileSync(outputPath, zipBytes);
				} catch (error) {
					notify(ctx, `Failed to write ${outputPath}: ${String(error)}`, "error");
					return;
				}
			} else {
				outputPath = written[0] ?? outDir;
			}

			// --- Report -----------------------------------------------------------
			const summary =
				`Exported ${zipFiles.length || written.length} session(s) → ${outputPath}\n` +
				`Redactions (${args.level}${args.removeImages ? ", no-images" : ""}): ${formatCounts(totals)}\n` +
				`Secret set: ${secrets.length} literal(s), ${secretHash.slice(0, 15)}…\n` +
				(allSkipped.length > 0 ? `Skipped ${allSkipped.length} unreadable file(s).\n` : "") +
				(totals.images_flagged > 0
					? "⚠ Images were KEPT and flagged for manual review — check before sharing."
					: "");

			notify(ctx, summary, allSkipped.length > 0 || totals.images_flagged > 0 ? "warning" : "info");
		},
	});
};

export default anonExportCommand;
