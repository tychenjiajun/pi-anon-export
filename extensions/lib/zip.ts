// Zip packaging for multi-session exports, using fflate (pure JS, offline).
//
// Two ways in:
// - `openExportZip()` returns a writer you call `add()` on as each session is
//   redacted, so a project's whole redacted set is never held in memory. The
//   manifest is written last, from the entries that were actually added, so a
//   hash can never attest a different file than the one in the archive.
// - `writeExportZip()` is the array-based convenience wrapper.
//
// The archive is streamed straight to disk (`<path>.<pid>-<random>.part`, then
// renamed): fflate's output chunks are written as they are produced instead of
// being buffered into one giant Uint8Array. The part file is created and
// fchmod-ed 0600 — a redacted export is still private data — and its name is
// unique per run, so concurrent runs cannot interleave.
//
// A killed process can leave its part file behind (content is already redacted,
// but it is litter); nothing sweeps foreign part files, deliberately.
//
// `manifest.json` travels with the archive, so anything written into it must
// survive being shared: skipped-file paths are reduced to a basename (pi's
// `--<cwd>--` session directory names embed the local username and the project
// path) and fs error messages are rewritten to match.

import { createHash, randomBytes } from "node:crypto";
import { closeSync, fchmodSync, openSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { basename } from "node:path";

import { strToU8, Zip, ZipDeflate } from "fflate";

import type { RedactionCounts, RedactionLevel } from "./redact.ts";
import type { SecretFingerprint } from "./secrets.ts";

export interface ZipManifestEntry {
	/** Source file name (basename of the original .jsonl). */
	source: string;
	/** Name of the redacted file inside the archive. */
	archivePath: string;
	/** sha256 of the redacted content written into the archive. */
	sha256: string;
	/** Redaction counts applied to this file (per file, not cumulative). */
	redactionCounts: RedactionCounts;
}

/** Proof that the export was checked after redaction. */
export interface ZipVerification {
	/** Known secret literals still found in the emitted content. Must be 0 to share. */
	residualSecrets: number;
	/** Salted fingerprint of the secret set that was applied (no values). */
	secretSet: SecretFingerprint;
}

export interface ZipManifest {
	generatedAt: string;
	/** Redaction level applied ("fast" | "full"). */
	level: RedactionLevel;
	/** Whether images were stripped. */
	removeImages: boolean;
	/** Number of source session files included in the archive. */
	fileCount: number;
	verification: ZipVerification;
	/**
	 * Files skipped because they could not be read or listed.
	 * Sanitized for sharing: never an absolute path (see `sanitizeSkippedEntry`).
	 */
	skipped: Array<{ path: string; error: string }>;
	files: ZipManifestEntry[];
}

/** One redacted session destined for the archive. */
export interface ExportZipFile {
	source: string;
	archivePath: string;
	/** Already-redacted JSONL content. */
	content: string;
	/** Per-file redaction counts. */
	redactionCounts: RedactionCounts;
}

export interface WriteExportZipOptions {
	/** Destination .zip path. Written via a per-run `.part` file + rename. */
	path: string;
	files: readonly ExportZipFile[];
	level: RedactionLevel;
	removeImages: boolean;
	verification: ZipVerification;
	skipped?: ReadonlyArray<{ path: string; error: string }>;
	generatedAt?: string;
	/** Chunk size used when feeding content to the compressor (default 1 MiB). */
	chunkSize?: number;
}

export interface ExportZipDescriptor {
	/** Destination .zip path. Written via a per-run `.part` file + rename. */
	path: string;
	level: RedactionLevel;
	removeImages: boolean;
	/** Chunk size used when feeding content to the compressor (default 1 MiB). */
	chunkSize?: number;
}

export interface ExportZipFinishOptions {
	verification: ZipVerification;
	skipped?: ReadonlyArray<{ path: string; error: string }>;
	generatedAt?: string;
}

/** Incremental archive writer: `add()` per session, then `finish()`. */
export interface ExportZipWriter {
	/** Path of the in-progress file (`<path>.<pid>-<random>.part`). */
	readonly partPath: string;
	/** Append one redacted session. Throws on I/O failure (call `abort()` then). */
	add(file: ExportZipFile): void;
	/** Write `manifest.json`, finish the archive and rename it into place. */
	finish(options: ExportZipFinishOptions): ZipManifest;
	/** Close and delete the partial archive. Safe to call more than once. */
	abort(): void;
}

/** sha256 (hex) of a UTF-8 string. */
export function sha256Hex(content: string): string {
	return createHash("sha256").update(content, "utf-8").digest("hex");
}

const DEFAULT_CHUNK_SIZE = 1024 * 1024;

/**
 * A skipped path as it may appear in a SHARED manifest.
 * pi's session directories are named `--<cwd with / and : replaced>--`, i.e.
 * they embed the local username and project path, so they are collapsed.
 */
export function sanitizeSkippedPath(path: string): string {
	const name = basename(path);
	return name.startsWith("--") && name.endsWith("--") ? "<session-directory>" : name;
}

/**
 * Sanitize one skipped-file entry for the manifest.
 * Node's fs errors embed the path they failed on (`ENOENT: … open '/Users/me/…'`),
 * which would otherwise put the home directory into a shared archive.
 */
export function sanitizeSkippedEntry(entry: { path: string; error: string }): {
	path: string;
	error: string;
} {
	const path = sanitizeSkippedPath(entry.path);
	return { path, error: entry.error.split(entry.path).join(path) };
}

function pushChunked(file: ZipDeflate, bytes: Uint8Array, chunkSize: number): void {
	if (bytes.length === 0) {
		file.push(new Uint8Array(0), true);
		return;
	}
	const size = Math.max(1, chunkSize);
	for (let offset = 0; offset < bytes.length; offset += size) {
		const end = Math.min(offset + size, bytes.length);
		file.push(bytes.subarray(offset, end), end >= bytes.length);
	}
}

/** writeSync can write fewer bytes than requested; loop until everything is out. */
function writeAll(fd: number, bytes: Uint8Array): void {
	let offset = 0;
	while (offset < bytes.length) {
		offset += writeSync(fd, bytes.subarray(offset));
	}
}

/**
 * Build the manifest for a set of files (hashes included) without writing a zip.
 * Exported for tests and for callers that only need the report.
 */
export function buildManifest(
	files: readonly ExportZipFile[],
	options: Omit<WriteExportZipOptions, "path" | "files" | "chunkSize">,
): ZipManifest {
	return {
		generatedAt: options.generatedAt ?? new Date().toISOString(),
		level: options.level,
		removeImages: options.removeImages,
		fileCount: files.length,
		verification: options.verification,
		skipped: (options.skipped ?? []).map(sanitizeSkippedEntry),
		files: files.map((file) => ({
			source: file.source,
			archivePath: file.archivePath,
			sha256: sha256Hex(file.content),
			redactionCounts: file.redactionCounts,
		})),
	};
}

/** Open an incremental export archive. Creates the `<path>.part` file immediately. */
export function openExportZip(options: ExportZipDescriptor): ExportZipWriter {
	const chunkSize = options.chunkSize ?? DEFAULT_CHUNK_SIZE;
	// A per-run part file: two runs started in the same millisecond used to share
	// `${path}.part` and interleave their bytes, so one of them reported success
	// on an archive that belonged to the other.
	const partPath = `${options.path}.${process.pid}-${randomBytes(4).toString("hex")}.part`;
	const fd = openSync(partPath, "w", 0o600);
	// `mode` only applies to a fresh file; a stale/hand-made part file must not
	// decide the permissions of the redacted archive.
	try {
		fchmodSync(fd, 0o600);
	} catch {
		// best effort: not every filesystem supports fchmod
	}

	const files: ZipManifestEntry[] = [];
	const archiveNames = new Set<string>();
	let fdOpen = true;
	let state: "open" | "done" | "broken" = "open";
	let pushError: Error | undefined;

	const assertOpen = (): void => {
		if (state === "done") throw new Error("Archive is already finished");
		if (state === "broken") throw new Error("Archive failed and cannot be written any more");
	};

	const closeFd = (): void => {
		if (!fdOpen) return;
		fdOpen = false;
		try {
			closeSync(fd);
		} catch {
			// already closed
		}
	};

	const removePart = (): void => {
		try {
			unlinkSync(partPath);
		} catch {
			// nothing to clean up
		}
	};

	// The fflate callback runs synchronously, but do not rely on that: capture
	// the error and rethrow it at a point where our caller's try/catch is live.
	const zip = new Zip((error, chunk) => {
		if (error) {
			pushError ??= error;
			return;
		}
		if (chunk !== undefined && chunk.length > 0) writeAll(fd, chunk);
	});

	const addEntry = (name: string, content: string): void => {
		if (pushError) throw pushError;
		const entry = new ZipDeflate(name, { level: 6 });
		zip.add(entry);
		if (pushError) throw pushError;
		pushChunked(entry, strToU8(content), chunkSize);
		if (pushError) throw pushError;
	};

	return {
		partPath,

		add(file) {
			assertOpen();
			// Duplicate entry names would make the archive hold one file while the
			// manifest attests two different sha256 values.
			if (archiveNames.has(file.archivePath)) {
				throw new Error(`Duplicate archive entry: ${file.archivePath}`);
			}
			archiveNames.add(file.archivePath);
			addEntry(file.archivePath, file.content);
			// Hash the exact content that was just compressed, in the same step,
			// so the manifest can never describe a different file.
			files.push({
				source: file.source,
				archivePath: file.archivePath,
				sha256: sha256Hex(file.content),
				redactionCounts: file.redactionCounts,
			});
		},

		finish(finishOptions) {
			assertOpen();
			const manifest: ZipManifest = {
				generatedAt: finishOptions.generatedAt ?? new Date().toISOString(),
				level: options.level,
				removeImages: options.removeImages,
				fileCount: files.length,
				verification: finishOptions.verification,
				skipped: (finishOptions.skipped ?? []).map(sanitizeSkippedEntry),
				files,
			};
			try {
				addEntry("manifest.json", `${JSON.stringify(manifest, null, 2)}\n`);
				zip.end();
				if (pushError) throw pushError;
				closeFd();
				renameSync(partPath, options.path);
				state = "done";
			} catch (error) {
				state = "broken";
				closeFd();
				removePart();
				throw error;
			}
			return manifest;
		},

		abort() {
			if (state === "open") state = "broken";
			closeFd();
			removePart();
		},
	};
}

/**
 * Write redacted sessions plus `manifest.json` into a zip archive at `path`.
 * Returns the manifest that was embedded. Throws on I/O failure; the partially
 * written `.part` file is removed in that case.
 */
export function writeExportZip(options: WriteExportZipOptions): ZipManifest {
	const writer = openExportZip(options);
	try {
		for (const file of options.files) writer.add(file);
		return writer.finish({
			verification: options.verification,
			skipped: options.skipped,
			generatedAt: options.generatedAt,
		});
	} catch (error) {
		writer.abort();
		throw error;
	}
}
