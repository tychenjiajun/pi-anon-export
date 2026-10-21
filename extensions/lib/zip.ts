// Zip packaging for multi-session exports, using fflate (pure JS, offline).

import { createHash } from "node:crypto";

import { strToU8, zipSync } from "fflate";

import type { RedactionCounts } from "./redact.ts";

export interface ZipManifestEntry {
	/** Source file name (basename of the original .jsonl). */
	source: string;
	/** Name of the redacted file inside the archive. */
	archivePath: string;
	/** sha256 of the redacted content written into the archive. */
	sha256: string;
	/** Redaction counts applied to this file. */
	redactionCounts: RedactionCounts;
}

export interface ZipManifest {
	generatedAt: string;
	/** Redaction level applied ("fast" | "full"). */
	level: string;
	/** Whether images were stripped. */
	removeImages: boolean;
	/** Number of source session files processed. */
	fileCount: number;
	/** Files skipped because they could not be read. */
	skipped: Array<{ path: string; error: string }>;
	files: ZipManifestEntry[];
}

/** sha256 (hex) of a UTF-8 string. */
export function sha256Hex(content: string): string {
	return createHash("sha256").update(content, "utf-8").digest("hex");
}

/** Build a zip containing redacted JSONL files plus a manifest.json. */
export function buildExportZip(
	files: Array<{ archivePath: string; content: string }>,
	manifest: Omit<ZipManifest, "files"> & { files: Omit<ZipManifestEntry, "sha256">[] },
): Uint8Array {
	const zippable: Record<string, Uint8Array> = {};
	for (const file of files) {
		zippable[file.archivePath] = strToU8(file.content);
	}

	const fullManifest: ZipManifest = {
		...manifest,
		files: manifest.files.map((entry, index) => ({
			...entry,
			sha256: sha256Hex(files[index]?.content ?? ""),
		})),
	};

	zippable["manifest.json"] = strToU8(`${JSON.stringify(fullManifest, null, 2)}\n`);
	return zipSync(zippable);
}
