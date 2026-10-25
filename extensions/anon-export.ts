// pi-anon-export — anonymized session export for the pi coding agent.
//
// /anon-export            export the current session, anonymized, as JSONL
// /anon-export zip        export every session of the current working
//                         directory's session folder, zipped with a manifest
//
// Flags (both modes):
//   --no-images                 strip embedded image data blocks
//   --level fast|full           redaction depth (default: full)
//   --pii conservative|aggressive
//                               add name/street-address patterns (full level)
//   --out <dir>                 output directory (default: ./pi-anon-export-<ts>/
//                               for the current session, the cwd for zip mode)
//   --secret <lit|file>         extra literal secret(s); a value that is a
//                               readable file path is read one secret per line
//   --env-file <path>           env file(s) to scan INSTEAD of the default shell
//                               rc files (~/.zshrc, ~/.zshenv, ~/.zprofile, …)
//
// Output that still contains a known secret after redaction is written as
// *.UNSAFE (or -UNSAFE.zip) instead of its normal name, and an unattended run
// fails (non-zero exit) instead of reporting a clean export.
//
// Everything runs locally; no data leaves the machine.
//
// Session location: ctx.sessionManager.getSessionDir()/getSessionFile() when
// available (they already honor --session-dir / PI_CODING_AGENT_SESSION_DIR /
// the sessionDir setting); otherwise the directory is derived from the cwd
// using pi's --<path>-- naming convention (see lib/sessions.ts).

import { chmodSync, existsSync, mkdirSync, renameSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";

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
import { openExportZip, type ExportZipWriter } from "./lib/zip.ts";

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

/**
 * Report an error and make an unattended run (print/JSON mode) fail: a command
 * that could not export, or that produced an unsafe artifact, must not exit 0.
 * In the TUI the error notification is enough — pi's own exit code is not ours.
 */
function fail(ctx: ExtensionCommandContext, message: string): void {
	notify(ctx, message, "error");
	if (!ctx.hasUI) process.exitCode = 1;
}

/** Why each file was skipped, for the "nothing exported" failure path. */
function summarizeSkipped(skipped: ReadonlyArray<{ path: string; error: string }>): string {
	if (skipped.length === 0) return "";
	const shown = skipped.slice(0, 5).map((entry) => `  - ${basename(entry.path)}: ${entry.error}`);
	if (skipped.length > shown.length) shown.push(`  - … ${skipped.length - shown.length} more`);
	return `\n${shown.join("\n")}`;
}

/** Quarantine suffix for output that still contains a known secret literal. */
const UNSAFE_SUFFIX = ".UNSAFE";

function timestampSlug(): string {
	return new Date().toISOString().replace(/[:.]/g, "-");
}

/** Let the TUI repaint between files instead of blocking it for the whole run. */
function yieldToEventLoop(): Promise<void> {
	return new Promise((done) => setImmediate(done));
}

/**
 * True when both paths name the same file, following symlinks and hard links
 * (and, on a case-insensitive filesystem, a differently-cased spelling).
 * A plain string compare let `--out ./o` destroy the live session when
 * `o/s.jsonl` was a symlink or hard link to it.
 */
function isSameFile(left: string, right: string): boolean {
	try {
		const a = statSync(left);
		const b = statSync(right);
		return a.dev === b.dev && a.ino === b.ino;
	} catch {
		return false;
	}
}

/** True when `dir` (or any parent) is a git working tree. */
function isInsideGitRepo(dir: string): boolean {
	let current = resolve(dir);
	for (;;) {
		if (existsSync(join(current, ".git"))) return true;
		const parent = dirname(current);
		if (parent === current) return false;
		current = parent;
	}
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
			// Complete the LAST token only, but keep what was already typed: the
			// previous version compared the whole prefix, so nothing completed after
			// the first word (`zip --` returned null).
			const flags = ["zip", "--no-images", "--level", "--pii", "--out", "--secret", "--env-file"];
			const values: Record<string, readonly string[]> = {
				"--level": ["fast", "full"],
				"--pii": ["conservative", "aggressive"],
			};
			const match = /^(.*\s)?(\S*)$/.exec(prefix);
			const head = match?.[1] ?? "";
			const last = match?.[2] ?? "";
			const previous = head.trim().split(/\s+/).filter(Boolean).pop() ?? "";
			const pool =
				Object.hasOwn(values, previous) && (last.length === 0 || !last.startsWith("-"))
					? (values[previous] ?? [])
					: flags;
			const filtered = pool.filter((candidate) => candidate.startsWith(last));
			return filtered.length > 0
				? filtered.map((candidate) => ({ value: `${head}${candidate}`, label: candidate }))
				: null;
		},
		handler: async (rawArgs: string, ctx: ExtensionCommandContext) => {
			const parsed = parseAnonExportArgs(rawArgs);
			if ("error" in parsed) {
				fail(ctx, parsed.error);
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
						fail(
							ctx,
							`No current session file and no sessions found in ${sessionDir} (dir source: ${dirSource})`,
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
					fail(ctx, `No *.jsonl sessions found in ${sessionDir} (dir source: ${dirSource})`);
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
					// 0700: the directory holds redacted-but-still-private transcripts.
					mkdirSync(outDir, { recursive: true, mode: 0o700 });
				} catch (error) {
					fail(ctx, `Failed to create output directory ${outDir}: ${String(error)}`);
					return;
				}
			}

			// --- Redact ------------------------------------------------------------
			// One anonymizer per run keeps value mappings consistent across files.
			const anonymizer: Anonymizer | undefined =
				args.level === "full" ? createAnonymizer({ aggressivePii: args.pii === "aggressive" }) : undefined;

			const totals = emptyCounts();
			const readSkipped: Array<{ path: string; error: string }> = [];
			const written: string[] = [];
			const quarantined: string[] = [];
			let residualSecrets = 0;
			let exportedCount = 0;

			// The zip writer is opened BEFORE the loop and fed one session at a time,
			// so a project's whole redacted set is never held in memory (the memory
			// claim only holds if the entries are streamed as they are produced).
			const zipPath = args.mode === "zip" ? join(outDir, `pi-anon-export-${stamp}.zip`) : undefined;
			let zipWriter: ExportZipWriter | undefined;
			if (zipPath !== undefined) {
				try {
					zipWriter = openExportZip({
						path: zipPath,
						level: args.level,
						removeImages: args.removeImages,
					});
				} catch (error) {
					fail(ctx, `Failed to create ${zipPath}: ${String(error)}`);
					return;
				}
			}

			for (const [index, source] of sources.entries()) {
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
				if (lines.length === 0) {
					// Everything was unparseable (binary/UTF-16/truncated session) or the
					// session is simply empty (a rotated/just-created file). Writing a
					// 0-byte artifact would report a clean export of nothing.
					readSkipped.push({
						path: source.path,
						error:
							counts.dropped_lines > 0
								? `${counts.dropped_lines} unparseable line(s), no session content`
								: "empty session (no JSONL entries)",
					});
					continue;
				}
				const content = lines.length > 0 ? `${lines.join("\n")}\n` : "";

				// Second pass, per file, BEFORE the file gets a shareable name: nothing
				// we set out to remove may survive (catches regressions in the
				// anonymizer or in the secret matcher). A file that still contains a
				// known secret is written as *.UNSAFE instead of its normal name, so a
				// script or a careless `cp` cannot pass it off as a clean export.
				const fileResidual = countResidualSecrets(content, secrets);
				residualSecrets += fileResidual;
				const outName = fileResidual > 0 ? `${source.name}${UNSAFE_SUFFIX}` : source.name;

				if (zipWriter !== undefined) {
					try {
						zipWriter.add({
							source: source.name,
							archivePath: outName,
							content,
							redactionCounts: counts,
						});
					} catch (error) {
						zipWriter.abort();
						fail(ctx, `Failed to write ${zipPath}: ${String(error)}`);
						return;
					}
				} else {
					const outPath = join(outDir, outName);
					// `--out <session dir>` would otherwise overwrite the live session
					// that pi is still appending to (and there is no backup). The
					// inode comparison also catches symlinks and hard links to it.
					if (resolve(outPath) === resolve(source.path) || isSameFile(outPath, source.path)) {
						fail(
							ctx,
							`Refusing to overwrite the source session ${source.path} — choose a different --out`,
						);
						return;
					}
					try {
						// 0600: a redacted transcript is still private data. `mode` only
						// applies to a fresh file, so tighten a re-exported one too.
						writeFileSync(outPath, content, { encoding: "utf-8", mode: 0o600 });
						try {
							chmodSync(outPath, 0o600);
						} catch {
							// best effort: the content is written, permissions are secondary
						}
					} catch (error) {
						fail(ctx, `Failed to write ${outPath}: ${String(error)}`);
						return;
					}
					written.push(outPath);
				}
				if (fileResidual > 0) quarantined.push(outName);
				exportedCount += 1;

				// Yield periodically so a long folder does not freeze the TUI.
				if (index % 8 === 7) await yieldToEventLoop();
			}

			const allSkipped = [...listSkipped, ...readSkipped];
			const verification = { residualSecrets, secretSet };
			let outputPath: string;

			if (args.mode === "zip") {
				if (zipWriter === undefined || exportedCount === 0) {
					zipWriter?.abort();
					fail(ctx, `No sessions could be read; nothing exported.${summarizeSkipped(allSkipped)}`);
					return;
				}
				try {
					zipWriter.finish({ verification, skipped: allSkipped });
				} catch (error) {
					fail(ctx, `Failed to write ${zipPath}: ${String(error)}`);
					return;
				}
				outputPath = zipPath as string;
				if (residualSecrets > 0) {
					// The archive is closed and renamed into place at this point, so a
					// rename is all that is needed to quarantine it.
					const unsafePath = outputPath.replace(/\.zip$/, `-UNSAFE.zip`);
					try {
						renameSync(outputPath, unsafePath);
						outputPath = unsafePath;
					} catch (error) {
						notify(ctx, `Could not rename ${outputPath} to its quarantine name: ${String(error)}`, "warning");
					}
				}
			} else {
				if (written.length === 0) {
					fail(ctx, `No sessions could be read; nothing exported.${summarizeSkipped(allSkipped)}`);
					return;
				}
				outputPath = written[0] as string;
			}

			// --- Report -----------------------------------------------------------
			const insideGitRepo = isInsideGitRepo(outDir);
			const modeFlags = [
				args.level,
				args.pii === "aggressive" ? "pii=aggressive" : "",
				args.removeImages ? "no-images" : "",
			].filter((part) => part.length > 0);
			const lines: string[] = [
				`Exported ${exportedCount} session(s) → ${outputPath}`,
				`Redactions (${modeFlags.join(", ")}): ${formatCounts(totals)}`,
				`Secret set: ${secrets.length} literal(s)${args.mode === "zip" ? " (fingerprint in manifest.json)" : ""}`,
			];
			if (args.pii === "aggressive" && args.level === "fast") {
				lines.push("Note: --pii has no effect at --level fast (no anonymizer runs).");
			}
			if (totals.dropped_lines > 0) {
				lines.push(
					`Dropped ${totals.dropped_lines} line(s) that could not be parsed or processed — never passed through.`,
				);
			}
			if (allSkipped.length > 0) {
				lines.push(`Skipped ${allSkipped.length} unreadable or empty file(s).`);
			}
			if (totals.images_flagged > 0) {
				lines.push("⚠ Images were KEPT and flagged for manual review — check before sharing.");
			}
			if (quarantined.length > 0) {
				lines.push(
					`Quarantined ${quarantined.length} file(s) as *${UNSAFE_SUFFIX}: ${quarantined.join(", ")}`,
				);
			}
			if (residualSecrets > 0) {
				lines.push(
					`✖ VERIFICATION FAILED: ${residualSecrets} known secret occurrence(s) survived redaction. Do NOT share ${outputPath}.`,
				);
			} else if (secrets.length > 0) {
				lines.push(
					args.level === "fast"
						? "Verified: no known secret literal remains (fast level: emails/PII were not scanned)."
						: "Verified: no known secret literal remains in the output.",
				);
			} else {
				lines.push(
					"⚠ No secret literals were found to verify against — check the output yourself before sharing.",
				);
			}
			if (insideGitRepo) {
				lines.push(
					`⚠ ${outDir} is inside a git working tree — keep the export out of commits (add it to .gitignore).`,
				);
			}
			if (warnings.length > 0) lines.push(...warnings.map((warning) => `Note: ${warning}`));

			const needsAttention =
				allSkipped.length > 0 ||
				totals.images_flagged > 0 ||
				quarantined.length > 0 ||
				insideGitRepo;
			if (residualSecrets > 0) {
				fail(ctx, lines.join("\n"));
				return;
			}
			notify(ctx, lines.join("\n"), needsAttention ? "warning" : "info");
		},
	});
};

export default anonExportExtension;
