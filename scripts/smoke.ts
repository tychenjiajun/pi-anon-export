// Smoke test for pi-anon-export (run: npm run smoke).
// Fully offline: only reads/writes under fixtures/ and a temp dir.

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { unzipSync, strFromU8 } from "fflate";

import { createAnonymizer } from "../extensions/lib/anonymize.ts";
import { redactSessionJsonl } from "../extensions/lib/redact.ts";
import { buildLiteralSecrets, computeSecretHash } from "../extensions/lib/secrets.ts";
import { buildExportZip, type ZipManifest } from "../extensions/lib/zip.ts";
import { parseAnonExportArgs } from "../extensions/anon-export.ts";
import { encodeSessionDirName, resolveSessionDir } from "../extensions/lib/sessions.ts";

const fixtureSession = readFileSync(new URL("../fixtures/sample-session.jsonl", import.meta.url), "utf-8");
const fixtureEnv = new URL("../fixtures/sample-env", import.meta.url).pathname;

let passed = 0;
function ok(name: string, fn: () => void): void {
	fn();
	passed += 1;
	console.log(`  ✓ ${name}`);
}

const secrets = buildLiteralSecrets({ envFile: fixtureEnv });
const secretValues = secrets.map((s) => s.value);

ok("secrets discovered from env file (sensitive names only)", () => {
	const names = secrets.map((s) => s.name).sort();
	assert.deepEqual(names, ["DEMO_API_KEY", "DEPLOY_GITHUB_TOKEN", "SESSION_COOKIE", "STRIPE_LIVE_KEY"]);
	// Sorted by value length descending
	const lengths = secrets.map((s) => s.value.length);
	assert.deepEqual(lengths, [...lengths].sort((a, b) => b - a));
});

ok("computeSecretHash is stable and prefixed", () => {
	const h1 = computeSecretHash(secrets);
	const h2 = computeSecretHash([...secrets].reverse());
	assert.equal(h1, h2, "hash must be independent of order");
	assert.match(h1, /^sha256:[0-9a-f]{64}$/);
});

// --- fast level -------------------------------------------------------------

const fast = redactSessionJsonl(fixtureSession, { level: "fast", removeImages: false, secrets });

ok("fast: all secret literals replaced with [REDACTED_<NAME>]", () => {
	const out = fast.lines.join("\n");
	for (const value of secretValues) {
		assert.ok(!out.includes(value), `secret literal must not survive: ${value}`);
	}
	assert.ok(out.includes("[REDACTED_DEPLOY_GITHUB_TOKEN]"));
	assert.ok(out.includes("[REDACTED_STRIPE_LIVE_KEY]"));
	assert.ok(out.includes("[REDACTED_SESSION_COOKIE]"));
	assert.ok(fast.counts.secret_replacements >= 3);
});

ok("fast: corrupt JSON line is dropped, others kept", () => {
	const parsedLines = fast.lines.length;
	const totalNonEmpty = fixtureSession.split("\n").filter((l) => l.trim().length > 0).length;
	assert.equal(fast.counts.dropped_lines, 1);
	assert.equal(parsedLines, totalNonEmpty - 1);
	assert.ok(!fast.lines.some((l) => l.includes("DELIBERATELY CORRUPT")));
	// Every emitted line must itself be valid JSON
	for (const line of fast.lines) assert.doesNotThrow(() => JSON.parse(line));
});

ok("fast: image kept but flagged without --no-images", () => {
	assert.equal(fast.counts.images_removed, 0);
	assert.equal(fast.counts.images_flagged, 1);
	assert.ok(fast.lines.some((l) => l.includes("iVBORw0KGgo")));
});

ok("fast: emails untouched at fast level (placeholder anonymizer not applied)", () => {
	const out = fast.lines.join("\n");
	assert.ok(out.includes("alice@northwind-labs.io"));
});

// --- full level -------------------------------------------------------------

const fullAnon = createAnonymizer();
const full = redactSessionJsonl(fixtureSession, {
	level: "full",
	removeImages: false,
	secrets,
	anonymizer: fullAnon,
});

ok("full: secrets replaced and emails anonymized", () => {
	const out = full.lines.join("\n");
	for (const value of secretValues) assert.ok(!out.includes(value));
	assert.ok(!out.includes("alice@northwind-labs.io"), "email must be anonymized at full level");
	assert.ok(/redacted-user_[0-9a-f]{8}@example\.com/.test(out));
	assert.ok((full.counts.anonymizer.email ?? 0) >= 2, "anonymizer must count emails");
});

// --- --no-images ------------------------------------------------------------

const noImages = redactSessionJsonl(fixtureSession, {
	level: "fast",
	removeImages: true,
	secrets,
});

ok("--no-images: image data replaced with [IMAGE_REMOVED]", () => {
	assert.equal(noImages.counts.images_removed, 1);
	assert.equal(noImages.counts.images_flagged, 0);
	assert.ok(noImages.lines.some((l) => l.includes("[IMAGE_REMOVED]")));
	assert.ok(!noImages.lines.some((l) => l.includes("iVBORw0KGgo")));
});

// --- zip --------------------------------------------------------------------

ok("zip: archive contains redacted files + manifest.json with sha256 and counts", () => {
	const tmp = mkdtempSync(join(tmpdir(), "pi-anon-export-smoke-"));
	try {
		const files = [
			{ archivePath: "session-a.jsonl", content: `${full.lines.join("\n")}\n` },
			{ archivePath: "session-b.jsonl", content: `${noImages.lines.join("\n")}\n` },
		];
		const bytes = buildExportZip(files, {
			generatedAt: new Date().toISOString(),
			level: "full",
			removeImages: true,
			fileCount: 2,
			skipped: [],
			files: [
				{ source: "session-a.jsonl", archivePath: "session-a.jsonl", redactionCounts: full.counts },
				{ source: "session-b.jsonl", archivePath: "session-b.jsonl", redactionCounts: noImages.counts },
			],
		});

		const outPath = join(tmp, "export.zip");
		writeFileSync(outPath, bytes);
		assert.ok(readFileSync(outPath).length > 0, "zip artifact must exist and be non-empty");

		const entries = unzipSync(bytes);
		assert.ok(entries["session-a.jsonl"], "session-a in zip");
		assert.ok(entries["session-b.jsonl"], "session-b in zip");
		assert.ok(entries["manifest.json"], "manifest in zip");

		const manifest = JSON.parse(strFromU8(entries["manifest.json"])) as ZipManifest;
		assert.equal(manifest.fileCount, 2);
		assert.equal(manifest.files.length, 2);
		for (const entry of manifest.files) {
			assert.match(entry.sha256, /^[0-9a-f]{64}$/);
			assert.ok(entry.redactionCounts.dropped_lines >= 0);
		}
		// Redacted content inside the zip must not contain secrets
		const inner = strFromU8(entries["session-a.jsonl"]);
		for (const value of secretValues) assert.ok(!inner.includes(value));
	} finally {
		rmSync(tmp, { recursive: true, force: true });
	}
});

// --- arg parsing & session dir naming ---------------------------------------

ok("args: defaults and flags parse", () => {
	const def = parseAnonExportArgs("");
	assert.ok(!("error" in def));
	assert.equal(def.mode, "current");
	assert.equal(def.level, "full");
	assert.equal(def.removeImages, false);

	const all = parseAnonExportArgs("zip --no-images --level fast --out /tmp/x --secret lit1 --secret /path/to/file");
	assert.ok(!("error" in all));
	assert.equal(all.mode, "zip");
	assert.equal(all.level, "fast");
	assert.equal(all.removeImages, true);
	assert.equal(all.out, "/tmp/x");
	assert.deepEqual(all.secrets, ["lit1", "/path/to/file"]);

	assert.ok("error" in parseAnonExportArgs("--level bananas"));
	assert.ok("error" in parseAnonExportArgs("--wat"));
});

ok("sessions: cwd encoding and dir precedence (env > settings > default)", () => {
	assert.equal(encodeSessionDirName("/Users/demo/my project"), "--Users-demo-my project--");
	// Mirrors pi's own encoding: root cwd becomes "----"
	assert.equal(encodeSessionDirName("/"), "----");

	const fromEnv = resolveSessionDir({
		cwd: "/Users/demo/app",
		env: { PI_CODING_AGENT_SESSION_DIR: "/custom/sessions" },
		settingsDir: "/from/settings",
	});
	assert.equal(fromEnv.dir, "/custom/sessions");
	assert.equal(fromEnv.source, "env");

	const fromSettings = resolveSessionDir({ cwd: "/Users/demo/app", settingsDir: "rel/dir", env: {} });
	assert.equal(fromSettings.dir, "/Users/demo/app/rel/dir");
	assert.equal(fromSettings.source, "settings");

	const fromDefault = resolveSessionDir({ cwd: "/Users/demo/app", env: {} });
	assert.equal(fromDefault.source, "default");
	assert.ok(
		fromDefault.dir.endsWith(`--${"Users-demo-app"}--`),
		`unexpected default dir: ${fromDefault.dir}`,
	);
});

console.log(`\nsmoke: ${passed} checks passed`);
