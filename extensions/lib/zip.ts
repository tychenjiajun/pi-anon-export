// Zip packaging for multi-session exports, using fflate (pure JS, offline).
//
// The manifest is DERIVED from the files that are actually written, in the
// same loop, so a hash can never attest a different file than the one in the
// archive (the previous API paired two parallel arrays by index).
//
// The archive is streamed straight to disk: only one redacted file is held in
// memory at a time, and fflate's output chunks are written as they are
// produced instead of being buffered into one giant Uint8Array.

import { createHash } from "node:crypto";
import { closeSync, openSync, renameSync, unlinkSync, writeSync } from "node:fs";

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
	/** Files skipped because they could not be read or listed. */
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
	/** Destination .zip path. Written via `<path>.part` + rename. */
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

/** sha256 (hex) of a UTF-8 string. */
export function sha256Hex(content: string): string {
	return createHash("sha256").update(content, "utf-8").digest("hex");
}

const DEFAULT_CHUNK_SIZE = 1024 * 1024;

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
		skipped: [...(options.skipped ?? [])],
		files: files.map((file) => ({
			source: file.source,
			archivePath: file.archivePath,
			sha256: sha256Hex(file.content),
			redactionCounts: file.redactionCounts,
		})),
	};
}

/**
 * Write redacted sessions plus `manifest.json` into a zip archive at `path`.
 * Returns the manifest that was embedded. Throws on I/O failure; the partially
 * written `.part` file is removed in that case.
 */
export function writeExportZip(options: WriteExportZipOptions): ZipManifest {
	const manifest = buildManifest(options.files, options);
	const chunkSize = options.chunkSize ?? DEFAULT_CHUNK_SIZE;
	const partPath = `${options.path}.part`;

	const fd = openSync(partPath, "w");
	try {
		const zip = new Zip((error, chunk) => {
			if (error) throw error;
			if (chunk !== undefined && chunk.length > 0) writeSync(fd, chunk);
		});

		for (const file of options.files) {
			const entry = new ZipDeflate(file.archivePath, { level: 6 });
			zip.add(entry);
			pushChunked(entry, strToU8(file.content), chunkSize);
		}

		const manifestEntry = new ZipDeflate("manifest.json", { level: 6 });
		zip.add(manifestEntry);
		pushChunked(manifestEntry, strToU8(`${JSON.stringify(manifest, null, 2)}\n`), chunkSize);

		zip.end();
		closeSync(fd);
		renameSync(partPath, options.path);
	} catch (error) {
		try {
			closeSync(fd);
		} catch {
			// already closed
		}
		try {
			unlinkSync(partPath);
		} catch {
			// nothing to clean up
		}
		throw error;
	}

	return manifest;
}
