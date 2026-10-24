// Minimal assertion harness shared by the offline smoke tests.
// Run with `npm run smoke` (no network, no pi process required).

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { inspect } from "node:util";

let passed = 0;
let failed = 0;
const failures: string[] = [];

export function group(name: string): void {
	console.log(`\n${name}`);
}

/** Run one check. Failures are collected so the whole suite always runs. */
export async function ok(name: string, fn: () => void | Promise<void>): Promise<void> {
	try {
		await fn();
		passed += 1;
		console.log(`  ✓ ${name}`);
	} catch (error) {
		failed += 1;
		const detail = error instanceof Error ? (error.stack ?? error.message) : inspect(error);
		failures.push(`${name}\n${detail}`);
		console.error(`  ✗ ${name}`);
	}
}

export function summary(label: string): void {
	console.log(`\n${label}: ${passed} passed, ${failed} failed`);
	if (failed > 0) {
		console.error(`\n${failures.join("\n\n")}`);
		process.exitCode = 1;
	}
}

export interface TempDir {
	path: string;
	cleanup: () => void;
}

export function makeTempDir(prefix: string): TempDir {
	const path = mkdtempSync(join(tmpdir(), `${prefix}-`));
	return {
		path,
		cleanup: () => rmSync(path, { recursive: true, force: true }),
	};
}

export interface StderrCapture {
	read: () => string;
	restore: () => void;
}

/** Capture process.stderr writes (the extension reports to stderr when there is no UI). */
export function captureStderr(): StderrCapture {
	const original = process.stderr.write;
	let captured = "";
	process.stderr.write = ((chunk: unknown): boolean => {
		captured += String(chunk);
		return true;
	}) as typeof process.stderr.write;
	return {
		read: () => captured,
		restore: () => {
			process.stderr.write = original;
		},
	};
}
