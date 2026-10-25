// HTML output for /anon-export.
//
// pi's HTML exporter is not part of the public extension API, but /anon-export
// must produce the same HTML file as /export. We therefore reuse pi's own
// exporter instead of maintaining a copy of its template:
//
//   1. write the ALREADY-REDACTED JSONL to a private temp file,
//   2. open it with pi's public SessionManager and call pi's internal
//      `exportSessionToHtml()` (the same function behind /export),
//   3. delete the temp file.
//
// The import is resolved from the extension's peer dependency at runtime, so it
// follows whichever pi version is actually running. If a build of pi does not
// ship those files (for example a single-file binary), we fail with an explicit
// message that tells the user to pick a `.jsonl` path instead of silently
// producing a different artifact.

import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";

import { SessionManager } from "@earendil-works/pi-coding-agent";

interface ExportHtmlOptions {
	outputPath?: string;
	themeName?: string;
}

type ExportSessionToHtml = (
	sessionManager: unknown,
	state?: unknown,
	options?: ExportHtmlOptions,
) => Promise<string>;

interface PiInternalModules {
	exportSessionToHtml: ExportSessionToHtml;
	appName: string;
}

let cachedModules: PiInternalModules | undefined;

function resolvePackageEntry(): URL {
	// `import.meta.resolve` is available in the Node versions pi supports and in
	// the bundled runtime. The cast keeps this file compiling against older
	// @types/node releases that do not declare it yet.
	const resolver = (import.meta as ImportMeta & { resolve?: (specifier: string) => string }).resolve;
	const entry = resolver?.("@earendil-works/pi-coding-agent");
	if (!entry || !entry.startsWith("file:")) {
		throw new Error(
			"HTML export needs pi's own HTML exporter, but this pi build does not expose it; use a .jsonl output path instead",
		);
	}
	return new URL(entry);
}

async function loadPiInternals(): Promise<PiInternalModules> {
	if (cachedModules) return cachedModules;

	const entry = resolvePackageEntry();
	let exportSessionToHtml: unknown;
	let appName: unknown;
	try {
		const htmlModule = (await import(new URL("./core/export-html/index.js", entry).href)) as {
			exportSessionToHtml?: unknown;
		};
		const configModule = (await import(new URL("./config.js", entry).href)) as {
			APP_NAME?: unknown;
		};
		exportSessionToHtml = htmlModule.exportSessionToHtml;
		appName = configModule.APP_NAME;
	} catch (error) {
		throw new Error(
			`HTML export needs pi's own HTML exporter, but it could not be loaded (${error instanceof Error ? error.message : String(error)}); use a .jsonl output path instead`,
		);
	}

	if (typeof exportSessionToHtml !== "function") {
		throw new Error(
			"HTML export needs pi's own HTML exporter, but this pi build does not expose it; use a .jsonl output path instead",
		);
	}

	cachedModules = {
		exportSessionToHtml: exportSessionToHtml as ExportSessionToHtml,
		appName: typeof appName === "string" && appName.length > 0 ? appName : "pi",
	};
	return cachedModules;
}

/**
 * `/export` names a no-path HTML export `<APP_NAME>-session-<session-file>.html`
 * in the current directory. Return the same name resolved against `cwd`.
 */
export async function defaultHtmlPath(
	cwd: string,
	sessionBasename: string,
): Promise<string> {
	const { appName } = await loadPiInternals();
	return resolve(cwd, `${appName}-session-${sessionBasename}.html`);
}

export interface WriteAnonymizedHtmlOptions {
	/** Absolute output path. */
	outputPath: string;
	/** Source session basename, used only for the temp input file name. */
	sessionBasename: string;
	themeName?: string | undefined;
	/** Already-redacted system prompt / tool metadata to include, like /export. */
	state?: unknown;
}

/**
 * Render already-redacted JSONL to HTML and write it to `outputPath`.
 * Throws when pi's exporter is unavailable or the destination cannot be written.
 */
export async function writeAnonymizedHtml(
	jsonl: string,
	options: WriteAnonymizedHtmlOptions,
): Promise<string> {
	const { exportSessionToHtml } = await loadPiInternals();
	const tempDir = mkdtempSync(join(tmpdir(), "pi-anon-export-"));
	const inputName = basename(options.sessionBasename).endsWith(".jsonl")
		? basename(options.sessionBasename)
		: `${basename(options.sessionBasename)}.jsonl`;
	try {
		const inputPath = join(tempDir, inputName);
		// The temp copy is the same private data as the final export.
		writeFileSync(inputPath, jsonl, { encoding: "utf-8", mode: 0o600 });
		try {
			chmodSync(inputPath, 0o600);
		} catch {
			// best effort
		}
		const sessionManager = SessionManager.open(inputPath);
		const written = await exportSessionToHtml(sessionManager, options.state, {
			outputPath: options.outputPath,
			themeName: options.themeName,
		});
		try {
			chmodSync(written, 0o600);
		} catch {
			// best effort: the content is written, permissions are secondary
		}
		return written;
	} finally {
		rmSync(tempDir, { recursive: true, force: true });
	}
}
