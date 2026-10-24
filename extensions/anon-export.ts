// pi-anon-export — anonymized session export for the pi coding agent.
//
// /anon-export            export the current session, anonymized, as JSONL
// /anon-export zip        export every session of the current working
//                         directory's session folder, zipped with a manifest
//
// Flags (both modes):
//   --no-images                 strip embedded image data blocks
//   --level fast|full           redaction depth (default: full)
//   --out <dir>                 output directory (default: ./pi-anon-export-<ts>/
//                               for the current session, the cwd for zip mode)
//   --secret <lit|file>         extra literal secret(s); a value that is a
//                               readable file path is read one secret per line
//   --env-file <path>           env file(s) to scan INSTEAD of the default shell
//                               rc files (~/.zshrc, ~/.zshenv, ~/.bashrc, …)
//
// Everything runs locally; no data leaves the machine.
//
// Session location: ctx.sessionManager.getSessionDir()/getSessionFile() when
// available (they already honor --session-dir / PI_CODING_AGENT_SESSION_DIR /
// the sessionDir setting); otherwise the directory is derived from the cwd
// using pi's --<path>-- naming convention (see lib/sessions.ts).

import { mkdirSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";

import {
	getAgentDir,
	type ExtensionAPI,
	type ExtensionCommandContext,
	type ExtensionFactory,
} from "@earendil-works/pi-coding-agent";

import { parseAnonExportArgs, USAGE, type AnonExportArgs } from "./lib/args.ts";
import { createAnonymizer, type Anonymizer } from "./lib/anonymize.ts";
import { resolveUserPath } from "./lib/paths.ts";
import {
	countResidualSecrets,
	emptyCounts,
	mergeCounts,
	redactSessionJsonl,
	type RedactionCounts,
} from "./lib/redact.ts";
import {
	buildLiteralSecrets,
	computeSecretFingerprint,
	defaultEnvFiles,
} from "./lib/secrets.ts";
import { listSessionFiles, readSessionFileSafe, resolveSessionDir } from "./lib/sessions.ts";
import { writeExportZip, type ExportZipFile } from "./lib/zip.ts";

export { parseAnonExportArgs, USAGE };
export type { AnonExportArgs };

/** Notify through the TUI when there is one; otherwise report on STDERR (never stdout). */
function notify(
	ctx: Pick<ExtensionCommandContext, "hasUI" | "ui">,
	message: string,
	type: "info" | "warning" | "error",
): void {
	if (ctx.hasUI) {
		ctx.ui.notify(message, type);
		return;
	}
	// stdout may be a machine-readable stream in print/json mode.
	process.stderr.write(`[anon-export] ${type}: ${message}\n`);
}

function timestampSlug(): string {
	return new Date().toISOString().replace(/[:.]/g, "-");
}

function formatCounts(counts: RedactionCounts): string {
	const parts: string[] = [];
	if (counts.secret_replacements > 0) parts.push(`secrets=${counts.secret_replacements}`);
	if (counts.images_removed > 0) parts.push(`images_removed=${counts.images_removed}`);
	if (counts.images_flagged > 0) parts.push(`images_flagged=${counts.images_flagged}`);
	for (const [key, value] of Object.entries(counts.anonymizer)) {
		if (value > 0) parts.push(`${key}=${value}`);
	}
	return parts.length > 0 ? parts.join(", ") : "no redactions";
}

function piAgentDir(): string | undefined {
	try {
		return getAgentDir();
	} catch {
		return undefined;
	}
}

export const anonExportExtension: ExtensionFactory = (pi: ExtensionAPI) => {
	pi.registerCommand("anon-export", {
		description:
			"Export the current session (or all cwd sessions with 'zip') as anonymized JSONL, locally",
		getArgumentCompletions: (prefix) => {
			const values = [
				"zip",
				"--no-images",
				"--level fast",
				"--level full",
				"--out",
				"--secret",
				"--env-file",
			];
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
				agentDir: piAgentDir(),
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
				sources.push({ path: resolveUserPath(currentFile, ctx.cwd), name: basename(currentFile) });
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
			// --env-file replaces the default shell rc set: predictable, and it makes
			// hermetic runs possible (tests must never read the real ~/.zshrc).
			const envFiles =
				args.envFiles.length > 0
					? args.envFiles.map((path) => resolveUserPath(path, ctx.cwd))
					: defaultEnvFiles();
			const { secrets, warnings } = buildLiteralSecrets({
				envFiles,
				secretInputs: args.secrets,
				cwd: ctx.cwd,
				warnMissingEnvFiles: args.envFiles.length > 0,
			});
			const secretSet = computeSecretFingerprint(secrets);

			const stamp = timestampSlug();
			const defaultOut = args.mode === "zip" ? ctx.cwd : `./pi-anon-export-${stamp}/`;
			const outDir = resolveUserPath(args.out ?? defaultOut, ctx.cwd);
			if (args.mode === "current" || args.out !== undefined) {
				try {
					mkdirSync(outDir, { recursive: true });
				} catch (error) {
					notify(ctx, `Failed to create output directory ${outDir}: ${String(error)}`, "error");
					return;
				}
			}

			// --- Redact ------------------------------------------------------------
			// One anonymizer per run keeps value mappings consistent across files.
			const anonymizer: Anonymizer | undefined = args.level === "full" ? createAnonymizer() : undefined;

			const totals = emptyCounts();
			const readSkipped: Array<{ path: string; error: string }> = [];
			const zipFiles: ExportZipFile[] = [];
			const written: string[] = [];
			let residualSecrets = 0;

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
				// Second pass: nothing we set out to remove may survive (catches
				// regressions in the anonymizer or in the secret matcher).
				residualSecrets += countResidualSecrets(content, secrets);

				if (args.mode === "zip") {
					zipFiles.push({
						source: source.name,
						archivePath: source.name,
						content,
						redactionCounts: counts,
					});
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
			const verification = { residualSecrets, secretSet };
			let outputPath: string;

			if (args.mode === "zip") {
				if (zipFiles.length === 0) {
					notify(ctx, "No sessions could be read; nothing exported.", "error");
					return;
				}
				// One timestamp for the whole run, and a flat artifact name inside
				// --out: no more <dir>/<dir>.zip nesting.
				outputPath = join(outDir, `pi-anon-export-${stamp}.zip`);
				try {
					writeExportZip({
						path: outputPath,
						files: zipFiles,
						level: args.level,
						removeImages: args.removeImages,
						verification,
						skipped: allSkipped,
					});
				} catch (error) {
					notify(ctx, `Failed to write ${outputPath}: ${String(error)}`, "error");
					return;
				}
			} else {
				if (written.length === 0) {
					notify(ctx, "No sessions could be read; nothing exported.", "error");
					return;
				}
				outputPath = written[0] as string;
			}

			// --- Report -----------------------------------------------------------
			const lines: string[] = [
				`Exported ${args.mode === "zip" ? zipFiles.length : written.length} session(s) → ${outputPath}`,
				`Redactions (${args.level}${args.removeImages ? ", no-images" : ""}): ${formatCounts(totals)}`,
				`Secret set: ${secrets.length} literal(s)${args.mode === "zip" ? " (fingerprint in manifest.json)" : ""}`,
			];
			if (totals.dropped_lines > 0) {
				lines.push(`Dropped ${totals.dropped_lines} unparseable line(s) — never passed through.`);
			}
			if (allSkipped.length > 0) lines.push(`Skipped ${allSkipped.length} unreadable file(s).`);
			if (totals.images_flagged > 0) {
				lines.push("⚠ Images were KEPT and flagged for manual review — check before sharing.");
			}
			if (residualSecrets > 0) {
				lines.push(
					`✖ VERIFICATION FAILED: ${residualSecrets} known secret occurrence(s) survived redaction. Do NOT share this export.`,
				);
			} else if (secrets.length > 0) {
				lines.push("Verified: no known secret literal remains in the output.");
			}
			if (warnings.length > 0) lines.push(...warnings.map((warning) => `Note: ${warning}`));

			const needsAttention =
				residualSecrets > 0 || allSkipped.length > 0 || totals.images_flagged > 0;
			notify(ctx, lines.join("\n"), residualSecrets > 0 ? "error" : needsAttention ? "warning" : "info");
		},
	});
};

export default anonExportExtension;
