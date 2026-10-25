// Smoke tests for pi-anon-export (run: npm run smoke).
// Fully offline: only reads/writes fixtures/ and temp directories.

import assert from "node:assert/strict";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	readdirSync,
	readFileSync,
	statSync,
	symlinkSync,
	utimesSync,
	writeFileSync,
} from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { strFromU8, unzipSync } from "fflate";

import { anonExportExtension, parseAnonExportArgs } from "../extensions/anon-export.ts";
import { createAnonymizer } from "../extensions/lib/anonymize.ts";
import { expandHome, resolveUserPath } from "../extensions/lib/paths.ts";
import {
	countResidualSecrets,
	emptyCounts,
	mergeCounts,
	redactSessionJsonl,
} from "../extensions/lib/redact.ts";
import {
	buildLiteralSecrets,
	computeSecretFingerprint,
	createSecretMatcher,
	defaultEnvFiles,
	MIN_SECRET_LENGTH,
	parseEnvFileSecrets,
	type SecretEntry,
} from "../extensions/lib/secrets.ts";
import {
	defaultSessionDir,
	encodeSessionDirName,
	listSessionFiles,
	resolveSessionDir,
} from "../extensions/lib/sessions.ts";
import {
	openExportZip,
	sanitizeSkippedEntry,
	sanitizeSkippedPath,
	sha256Hex,
	writeExportZip,
	type ExportZipFile,
	type ZipManifest,
} from "../extensions/lib/zip.ts";
import { captureStderr, group, makeTempDir, ok, summary } from "./harness.ts";

const fixtureUrl = (name: string): string => fileURLToPath(new URL(`../fixtures/${name}`, import.meta.url));
const fixtureSession = readFileSync(fixtureUrl("sample-session.jsonl"), "utf-8");
const fixtureEnv = fixtureUrl("sample-env");

const { secrets, warnings } = buildLiteralSecrets({ envFiles: [fixtureEnv] });
const secretValues = secrets.map((entry) => entry.value);

const fixtureLines = fixtureSession.split("\n").filter((line) => line.trim().length > 0);
const fixtureImage = (
	JSON.parse(fixtureLines[2] as string) as {
		message: { content: Array<{ type: string; data?: string }> };
	}
).message.content[1]?.data as string;

function sessionLine(text: string, email = ""): string {
	return `${JSON.stringify({
		type: "message",
		message: { role: "user", content: [{ type: "text", text: `${text} ${email}`.trim() }] },
	})}\n`;
}

function secretEntry(name: string, value: string): SecretEntry {
	return { name, value, replacement: `[REDACTED_${name}]` };
}

// ---------------------------------------------------------------------------
group("secrets: discovery and parsing");

await ok("env file scan finds only credential-looking names, longest first", () => {
	assert.deepEqual(
		secrets.map((entry) => entry.name).sort(),
		["DEMO_API_KEY", "DEPLOY_GITHUB_TOKEN", "SESSION_COOKIE", "STRIPE_LIVE_KEY"],
	);
	const lengths = secrets.map((entry) => entry.value.length);
	assert.deepEqual(lengths, [...lengths].sort((a, b) => b - a));
	assert.deepEqual(warnings, []);
});

await ok("export-line parsing handles quotes, comments, indentation and `#` in values", () => {
	assert.deepEqual(
		parseEnvFileSecrets(
			[
				'export A="quoted value" # trailing comment',
				"export B='single'",
				"export C=plain #comment",
				"export D=\"has spaces and = signs\"",
				"  export E=indented",
				"\texport F=also-indented",
				"export G=",
				"export H",
				"export 1BAD=nope",
			].join("\n"),
		),
		[
			{ name: "A", value: "quoted value" },
			{ name: "B", value: "single" },
			{ name: "C", value: "plain" },
			{ name: "D", value: "has spaces and = signs" },
			{ name: "E", value: "indented" },
			{ name: "F", value: "also-indented" },
		],
	);
});

await ok("a `#` inside a quoted value is part of the secret, not a comment", () => {
	// Truncating here used to redact only the prefix, leak the tail, and report
	// a clean verification pass (the needle was the truncated prefix).
	assert.deepEqual(parseEnvFileSecrets('export DB_PASSWORD="Tr0ub4dor#2024!x"'), [
		{ name: "DB_PASSWORD", value: "Tr0ub4dor#2024!x" },
	]);
	assert.deepEqual(parseEnvFileSecrets("export TOKEN='a#b c'"), [{ name: "TOKEN", value: "a#b c" }]);
	// Shell semantics for an unquoted value: end at whitespace, keep inner `#`.
	assert.deepEqual(parseEnvFileSecrets("export KEY=plain#not-a-comment"), [
		{ name: "KEY", value: "plain#not-a-comment" },
	]);
	// Escaped characters inside double quotes resolve to the real value.
	assert.deepEqual(parseEnvFileSecrets('export P="pa\\"ss"'), [{ name: "P", value: 'pa"ss' }]);
	// Quoted and unquoted segments concatenate, like a shell.
	assert.deepEqual(parseEnvFileSecrets('export M="/home/me"-token'), [
		{ name: "M", value: "/home/me-token" },
	]);
	// An unterminated quote keeps the remainder instead of dropping the secret.
	assert.deepEqual(parseEnvFileSecrets('export U="abc123'), [{ name: "U", value: "abc123" }]);
});

await ok("default env files cover the common shell rc files", () => {
	const files = defaultEnvFiles("/home/u");
	assert.ok(files.some((file) => file.endsWith(".zshrc")));
	assert.ok(files.some((file) => file.endsWith(".zprofile")));
	assert.ok(files.some((file) => file.endsWith(".bashrc")));
	assert.ok(files.every((file) => file.startsWith("/home/u/")));
});

await ok("short secret values are refused with a value-free warning", () => {
	const result = buildLiteralSecrets({ envFiles: [], secretInputs: ["a", "abc", "abcde"] });
	assert.equal(result.secrets.length, 1);
	assert.equal(result.secrets[0]?.value, "abcde");
	assert.equal(result.warnings.length, 1);
	const text = result.warnings.join("\n");
	assert.ok(text.includes(String(MIN_SECRET_LENGTH)), text);
	assert.ok(!text.includes("abcde"), "warning must not echo a secret value");
});

await ok("placeholder-shaped values are refused (cannot corrupt markers)", () => {
	const result = buildLiteralSecrets({ envFiles: [], secretInputs: ["REDACT", "secretvalue1"] });
	assert.equal(result.secrets.length, 1);
	assert.equal(result.secrets[0]?.value, "secretvalue1");
});

await ok("missing explicit env files are reported, missing defaults are not", () => {
	const explicit = buildLiteralSecrets({
		envFiles: [join("/definitely/not/here", "env")],
		warnMissingEnvFiles: true,
	});
	assert.equal(explicit.secrets.length, 0);
	assert.ok(explicit.warnings.some((warning) => warning.includes("Env file not found")));

	const defaults = buildLiteralSecrets({ envFiles: [join("/definitely/not/here", "env")] });
	assert.deepEqual(defaults.warnings, []);
});

await ok("secret files are read one per line and reported", () => {
	const tmp = makeTempDir("pi-anon-export-secretfile");
	try {
		const path = join(tmp.path, "secrets.txt");
		writeFileSync(path, "first-secret-value\n\nsecond-secret-value\n", "utf-8");
		const result = buildLiteralSecrets({ envFiles: [], secretInputs: [path], cwd: tmp.path });
		assert.deepEqual(
			result.secrets.map((entry) => entry.value).sort(),
			["first-secret-value", "second-secret-value"],
		);
		assert.ok(result.warnings.join("\n").includes("Read 2 secret(s) from 1 file(s)"));
	} finally {
		tmp.cleanup();
	}
});

await ok("matcher replaces in one pass, longest value first", () => {
	const matcher = createSecretMatcher([secretEntry("SHORT", "abcde"), secretEntry("LONG", "abcdef123")]);
	assert.ok(matcher);
	const replacements: string[] = [];
	const out = matcher.replace("abcdef123 then abcde", (entry) => replacements.push(entry.name));
	assert.equal(out, "[REDACTED_LONG] then [REDACTED_SHORT]");
	assert.deepEqual(replacements, ["LONG", "SHORT"]);
});

await ok("matcher never rewrites a marker it just inserted", () => {
	// "REDACT" would match inside "[REDACTED_X]"; it is filtered at build time
	// and the single-pass matcher never rescans inserted text either way.
	const matcher = createSecretMatcher([secretEntry("X", "REDACT"), secretEntry("Y", "valuable")]);
	assert.ok(matcher);
	assert.equal(matcher.replace("valuable"), "[REDACTED_Y]");
});

await ok("secret fingerprint is salted, order-independent and length-prefixed", () => {
	const a = secretEntry("A", "value-one");
	const b = secretEntry("B", "value-two");
	const ab = computeSecretFingerprint([a, b], "fixedsalt");
	const ba = computeSecretFingerprint([b, a], "fixedsalt");
	assert.equal(ab.digest, ba.digest);
	assert.notEqual(ab.digest, computeSecretFingerprint([a, b], "othersalt").digest);
	// Length prefixing: ["ab","c"] must not collide with ["a","bc"].
	const left = computeSecretFingerprint([secretEntry("X", "ab"), secretEntry("Y", "c")], "s");
	const right = computeSecretFingerprint([secretEntry("X", "a"), secretEntry("Y", "bc")], "s");
	assert.notEqual(left.digest, right.digest);
	assert.match(ab.digest, /^[0-9a-f]{64}$/);
	assert.equal(ab.algorithm, "sha256");
});

// ---------------------------------------------------------------------------
group("redaction pipeline");

const fast = redactSessionJsonl(fixtureSession, { level: "fast", removeImages: false, secrets });

await ok("fast: literal secrets are replaced with [REDACTED_<NAME>]", () => {
	const out = fast.lines.join("\n");
	for (const value of secretValues) assert.ok(!out.includes(value), `secret survived: ${value}`);
	assert.ok(out.includes("[REDACTED_DEPLOY_GITHUB_TOKEN]"));
	assert.ok(out.includes("[REDACTED_STRIPE_LIVE_KEY]"));
	assert.ok(out.includes("[REDACTED_SESSION_COOKIE]"));
	assert.ok(fast.counts.secret_replacements >= 3);
});

await ok("fast: corrupt and non-object JSON lines are dropped, the rest parses", () => {
	const total = fixtureLines.length;
	assert.equal(fast.counts.dropped_lines, 1);
	assert.equal(fast.lines.length, total - 1);
	assert.ok(!fast.lines.some((line) => line.includes("DELIBERATELY CORRUPT")));
	for (const line of fast.lines) assert.doesNotThrow(() => JSON.parse(line));

	const extra = redactSessionJsonl('123\n"string"\n[]\n{"ok":true}\n', {
		level: "fast",
		removeImages: false,
		secrets: [],
	});
	assert.equal(extra.counts.dropped_lines, 2);
	assert.equal(extra.lines.length, 2);
});

await ok("fast: images are kept and flagged without --no-images", () => {
	assert.equal(fast.counts.images_removed, 0);
	assert.equal(fast.counts.images_flagged, 1);
	assert.ok(fast.lines.some((line) => line.includes("iVBORw0KGgo")));
});

await ok("fast: emails are untouched", () => {
	assert.ok(fast.lines.join("\n").includes("alice@northwind-labs.io"));
});

const full = redactSessionJsonl(fixtureSession, {
	level: "full",
	removeImages: false,
	secrets,
	anonymizer: createAnonymizer(),
});

await ok("full: secrets replaced and emails anonymized", () => {
	const out = full.lines.join("\n");
	for (const value of secretValues) assert.ok(!out.includes(value));
	assert.ok(!out.includes("alice@northwind-labs.io"));
	assert.ok(/redacted-user_[0-9a-f]{8}@example\.com/.test(out));
	assert.ok((full.counts.anonymizer.email ?? 0) >= 2);
});

await ok("full: kept image payloads stay byte-identical (never anonymized)", () => {
	const line = full.lines.find((candidate) => candidate.includes('"id":"m2"'));
	assert.ok(line);
	const blocks = (JSON.parse(line) as { message: { content: Array<{ data?: string; mimeType?: string }> } })
		.message.content;
	const image = blocks.find((block) => typeof block.data === "string");
	assert.equal(image?.data, fixtureImage);
	assert.equal(image?.mimeType, "image/png");
	assert.equal(full.counts.images_flagged, 1);
});

const noImages = redactSessionJsonl(fixtureSession, {
	level: "full",
	removeImages: true,
	secrets,
	anonymizer: createAnonymizer(),
});

await ok("--no-images: image data replaced with [IMAGE_REMOVED]", () => {
	assert.equal(noImages.counts.images_removed, 1);
	assert.equal(noImages.counts.images_flagged, 0);
	assert.ok(noImages.lines.some((line) => line.includes("[IMAGE_REMOVED]")));
	assert.ok(!noImages.lines.some((line) => line.includes("iVBORw0KGgo")));
});

await ok("shared anonymizer reports per-file counts, not cumulative ones", () => {
	const shared = createAnonymizer();
	const results = ["a@one.io", "b@two.io", "c@three.io"].map((email) =>
		redactSessionJsonl(sessionLine("mail", email), {
			level: "full",
			removeImages: false,
			secrets: [],
			anonymizer: shared,
		}),
	);
	assert.deepEqual(
		results.map((result) => result.counts.anonymizer.email),
		[1, 1, 1],
	);
	const totals = results.reduce((acc, result) => mergeCounts(acc, result.counts), emptyCounts());
	assert.equal(totals.anonymizer.email, 3);
});

await ok("a secret inside a credential URL keeps its own marker (no double redaction)", () => {
	const urlSecrets = buildLiteralSecrets({ envFiles: [], secretInputs: ["hunter2-is-a-password"] }).secrets;
	const line = sessionLine("db postgres://app:hunter2-is-a-password@db.internal/prod");
	const out = redactSessionJsonl(line, { level: "full", removeImages: false, secrets: urlSecrets }).lines.join("");
	assert.ok(out.includes("[REDACTED_SECRET_1]"), out);
	assert.ok(!out.includes("hunter2-is-a-password"), out);
});

await ok("verification finds surviving secrets, including JSON-escaped ones", () => {
	assert.equal(countResidualSecrets(full.lines.join("\n"), secrets), 0);
	assert.ok(countResidualSecrets(fixtureSession, secrets) > 0, "original fixture must leak");
	const quoted = secretEntry("QUOTED", 'hunter2 with "quotes"');
	const content = `${JSON.stringify({ text: 'hunter2 with "quotes"' })}\n`;
	assert.ok(countResidualSecrets(content, [quoted]) > 0);
});

await ok("full: a >1MB string is still scanned for emails and PII (chunked, not skipped)", () => {
	// Tool output of this size is routine. Skipping the email/PII passes for it
	// silently leaked every address pasted into a big file or log.
	const filler = "lorem ipsum dolor sit amet \n".repeat(50_000); // ~1.4MB
	assert.ok(filler.length > 1024 * 1024);
	const mixed = `${filler}contact alice.smith@corp-mail.com and ssn 123-45-6789 /Users/alice/secret\n${filler}`;
	assert.ok(mixed.length > 2 * 1024 * 1024);

	const result = redactSessionJsonl(sessionLine(mixed), {
		level: "full",
		removeImages: false,
		secrets: [],
		anonymizer: createAnonymizer(),
	});
	const out = result.lines.join("\n");
	assert.ok(!out.includes("alice.smith@corp-mail.com"), "email survived chunking");
	assert.ok(!out.includes("123-45-6789"), "ssn survived chunking");
	assert.ok(!out.includes("/Users/alice/"), "username survived chunking");
	assert.ok((result.counts.anonymizer.email ?? 0) >= 1);
	assert.ok(out.length > mixed.length - 4096, "chunking must not drop content");
});

await ok("full: a PEM key inside a >1MB string is still replaced whole", () => {
	// The PEM body contains newlines, so the credential pass has to see the
	// WHOLE string: a whitespace-aligned chunk boundary would split it.
	const filler = "padding line for size \n".repeat(80_000); // ~1.7MB
	const pem = [
		"-----BEGIN RSA PRIVATE KEY-----",
		"MIIEowIBAAKCAQEA1234",
		"+morebase64material+morebase64material+morebase64material+",
		"-----END RSA PRIVATE KEY-----",
	].join("\n");
	const result = redactSessionJsonl(sessionLine(`${filler}${pem}\n${filler}`), {
		level: "full",
		removeImages: false,
		secrets: [],
		anonymizer: createAnonymizer(),
	});
	const out = result.lines.join("\n");
	assert.ok(!out.includes("MIIEowIBAAKCAQEA1234"), "PEM body survived");
	assert.ok(!out.includes("BEGIN RSA PRIVATE KEY"), "PEM header survived");
});

// ---------------------------------------------------------------------------
group("arguments and paths");

await ok("args: defaults", () => {
	const def = parseAnonExportArgs("");
	assert.ok(!("error" in def));
	assert.equal(def.mode, "current");
	assert.equal(def.level, "full");
	assert.equal(def.pii, "conservative");
	assert.equal(def.removeImages, false);
	assert.deepEqual(def.secrets, []);
	assert.deepEqual(def.envFiles, []);
});

await ok("args: all flags, including --flag=value and repeated values", () => {
	const all = parseAnonExportArgs(
		'zip --no-images --level=fast --pii aggressive --out /tmp/x --secret "lit with spaces" --secret=/path/f --env-file a --env-file=b',
	);
	assert.ok(!("error" in all));
	assert.equal(all.mode, "zip");
	assert.equal(all.level, "fast");
	assert.equal(all.pii, "aggressive");
	assert.equal(all.removeImages, true);
	assert.equal(all.out, "/tmp/x");
	assert.deepEqual(all.secrets, ["lit with spaces", "/path/f"]);
	assert.deepEqual(all.envFiles, ["a", "b"]);
});

await ok("args: invalid input is rejected instead of silently misparsed", () => {
	const cases = [
		"--level bananas",
		"--level",
		"--pii bananas",
		"--pii",
		"--wat",
		"--out --no-images",
		"--secret --level",
		"--out=",
		"--no-images=1",
		'--secret "unterminated',
	];
	for (const raw of cases) {
		assert.ok("error" in parseAnonExportArgs(raw), `expected an error for: ${raw}`);
	}
});

await ok("args: backslashes in unquoted paths survive (Windows)", () => {
	const parsed = parseAnonExportArgs("--out C:\\Users\\me\\share");
	assert.ok(!("error" in parsed));
	assert.equal(parsed.out, "C:\\Users\\me\\share");
	// A backslash before whitespace still escapes, shell-style.
	const spaced = parseAnonExportArgs("--out my\\ dir");
	assert.ok(!("error" in spaced));
	assert.equal(spaced.out, "my dir");
});

await ok("args: zip is recognized after other flags", () => {
	const parsed = parseAnonExportArgs("--level fast zip");
	assert.ok(!("error" in parsed));
	assert.equal(parsed.mode, "zip");
});

await ok("paths: ~ is expanded but ~user is left alone", () => {
	assert.equal(expandHome("~/share", "/home/u"), "/home/u/share");
	assert.equal(expandHome("~", "/home/u"), "/home/u");
	assert.equal(expandHome("~other/share", "/home/u"), "~other/share");
	assert.equal(resolveUserPath("~/share", "/cwd", "/home/u"), "/home/u/share");
	assert.equal(resolveUserPath("rel/dir", "/cwd", "/home/u"), "/cwd/rel/dir");
});

// ---------------------------------------------------------------------------
group("sessions");

await ok("sessions: cwd encoding matches pi", () => {
	assert.equal(encodeSessionDirName("/Users/demo/my project"), "--Users-demo-my project--");
	assert.equal(encodeSessionDirName("/"), "----");
	assert.ok(defaultSessionDir("/Users/demo/app", "/agent").endsWith("--Users-demo-app--"));
});

await ok("sessions: dir precedence and relative resolution against cwd", () => {
	const fromManager = resolveSessionDir({
		cwd: "/Users/demo/app",
		sessionManagerDir: "sessions-here",
		env: { PI_CODING_AGENT_SESSION_DIR: "/env/dir" },
		settingsDir: "/from/settings",
	});
	assert.deepEqual(fromManager, { dir: "/Users/demo/app/sessions-here", source: "session-manager" });

	const fromEnv = resolveSessionDir({
		cwd: "/Users/demo/app",
		env: { PI_CODING_AGENT_SESSION_DIR: "/custom/sessions" },
		settingsDir: "/from/settings",
	});
	assert.deepEqual(fromEnv, { dir: "/custom/sessions", source: "env" });

	const fromSettings = resolveSessionDir({
		cwd: "/Users/demo/app",
		settingsDir: "rel/dir",
		env: {},
	});
	assert.deepEqual(fromSettings, { dir: "/Users/demo/app/rel/dir", source: "settings" });

	const fromDefault = resolveSessionDir({
		cwd: "/Users/demo/app",
		agentDir: "/agent",
		env: {},
	});
	assert.deepEqual(fromDefault, { dir: "/agent/sessions/--Users-demo-app--", source: "default" });
});

await ok("sessions: listing is non-recursive, newest first, and reports non-files", () => {
	const tmp = makeTempDir("pi-anon-export-list");
	try {
		writeFileSync(join(tmp.path, "old.jsonl"), "{}\n", "utf-8");
		writeFileSync(join(tmp.path, "new.jsonl"), "{}\n", "utf-8");
		writeFileSync(join(tmp.path, "notes.txt"), "x", "utf-8");
		mkdirSync(join(tmp.path, "dir.jsonl"));
		symlinkSync(join(tmp.path, "missing.jsonl"), join(tmp.path, "dangling.jsonl"));
		const old = new Date("2020-01-01T00:00:00.000Z");
		utimesSync(join(tmp.path, "old.jsonl"), old, old);

		const { files, skipped } = listSessionFiles(tmp.path);
		assert.deepEqual(
			files.map((file) => file.split("/").pop()),
			["new.jsonl", "old.jsonl"],
		);
		assert.equal(skipped.length, 1);
		assert.ok(skipped[0]?.path.endsWith("dangling.jsonl"));
	} finally {
		tmp.cleanup();
	}
});

// ---------------------------------------------------------------------------
group("zip packaging");

await ok("zip: manifest hashes match the file they describe", () => {
	const tmp = makeTempDir("pi-anon-export-zip");
	try {
		const files: ExportZipFile[] = [
			{
				source: "original-a.jsonl",
				archivePath: "renamed-a.jsonl",
				content: `${full.lines.join("\n")}\n`,
				redactionCounts: full.counts,
			},
			{
				source: "original-b.jsonl",
				archivePath: "renamed-b.jsonl",
				content: `${noImages.lines.join("\n")}\n`,
				redactionCounts: noImages.counts,
			},
		];
		const zipPath = join(tmp.path, "export.zip");
		const manifest = writeExportZip({
			path: zipPath,
			files,
			level: "full",
			removeImages: true,
			verification: { residualSecrets: 0, secretSet: computeSecretFingerprint(secrets, "test") },
			skipped: [{ path: "/nope.jsonl", error: "EACCES" }],
		});

		assert.equal(manifest.fileCount, 2);
		// The manifest is embedded in a SHARED archive: skipped paths must not
		// carry the local directory (pi's `--<cwd>--` names embed the username
		// and project path), and fs errors that quote the path are rewritten.
		assert.deepEqual(manifest.skipped, [{ path: "nope.jsonl", error: "EACCES" }]);
		assert.equal(manifest.verification.residualSecrets, 0);
		assert.equal(manifest.verification.secretSet.salt, "test");

		const entries = unzipSync(new Uint8Array(readFileSync(zipPath)));
		assert.deepEqual(Object.keys(entries).sort(), [
			"manifest.json",
			"renamed-a.jsonl",
			"renamed-b.jsonl",
		]);
		const embedded = JSON.parse(strFromU8(entries["manifest.json"] as Uint8Array)) as ZipManifest;
		assert.deepEqual(embedded, manifest);
		for (const entry of embedded.files) {
			const content = strFromU8(entries[entry.archivePath] as Uint8Array);
			assert.equal(entry.sha256, sha256Hex(content), `hash mismatch for ${entry.archivePath}`);
			for (const value of secretValues) assert.ok(!content.includes(value));
		}
		assert.equal(embedded.files[0]?.redactionCounts.anonymizer.email, full.counts.anonymizer.email);
	} finally {
		tmp.cleanup();
	}
});

await ok("zip: skipped paths and fs errors are sanitized for sharing", () => {
	assert.equal(sanitizeSkippedPath("/Users/alice/.pi/agent/sessions/--Users-alice-app--"), "<session-directory>");
	assert.equal(sanitizeSkippedPath("/Users/alice/sessions/gone.jsonl"), "gone.jsonl");

	const entry = sanitizeSkippedEntry({
		path: "/Users/alice/sessions/gone.jsonl",
		error: "Error: EACCES: permission denied, open '/Users/alice/sessions/gone.jsonl'",
	});
	assert.equal(entry.path, "gone.jsonl");
	assert.ok(!entry.error.includes("/Users/alice"), entry.error);
	assert.ok(entry.error.includes("gone.jsonl"), entry.error);
});

await ok("zip: large content is chunked and round-trips exactly", () => {
	const tmp = makeTempDir("pi-anon-export-zip-big");
	try {
		const content = `${JSON.stringify({ text: "x".repeat(2_500_000) })}\n`;
		const zipPath = join(tmp.path, "big.zip");
		writeExportZip({
			path: zipPath,
			files: [{ source: "big.jsonl", archivePath: "big.jsonl", content, redactionCounts: emptyCounts() }],
			level: "fast",
			removeImages: false,
			verification: { residualSecrets: 0, secretSet: computeSecretFingerprint([], "s") },
			chunkSize: 128 * 1024,
		});
		const entries = unzipSync(new Uint8Array(readFileSync(zipPath)));
		assert.equal(strFromU8(entries["big.jsonl"] as Uint8Array), content);
	} finally {
		tmp.cleanup();
	}
});

await ok("zip: empty redacted content still produces a valid, empty entry", () => {
	const tmp = makeTempDir("pi-anon-export-zip-empty");
	try {
		const zipPath = join(tmp.path, "export.zip");
		const manifest = writeExportZip({
			path: zipPath,
			files: [
				{ source: "empty.jsonl", archivePath: "empty.jsonl", content: "", redactionCounts: emptyCounts() },
			],
			level: "full",
			removeImages: false,
			verification: { residualSecrets: 0, secretSet: computeSecretFingerprint([], "s") },
		});
		const entries = unzipSync(new Uint8Array(readFileSync(zipPath)));
		assert.equal(strFromU8(entries["empty.jsonl"] as Uint8Array), "");
		assert.equal(manifest.files[0]?.sha256, sha256Hex(""));
	} finally {
		tmp.cleanup();
	}
});

await ok("zip: a write failure leaves no .part file behind", () => {
	const tmp = makeTempDir("pi-anon-export-zip-fail");
	try {
		const zipPath = join(tmp.path, "missing-dir", "export.zip");
		assert.throws(() =>
			writeExportZip({
				path: zipPath,
				files: [
					{
						source: "a.jsonl",
						archivePath: "a.jsonl",
						content: "{}\n",
						redactionCounts: emptyCounts(),
					},
				],
				level: "fast",
				removeImages: true,
				verification: { residualSecrets: 0, secretSet: computeSecretFingerprint([], "s") },
			}),
		);
		assert.deepEqual(
			readdirSync(tmp.path).filter((name) => name.endsWith(".part")),
			[],
			"no partial archive may be left behind",
		);
	} finally {
		tmp.cleanup();
	}
});

await ok("zip: the streaming writer adds sessions one at a time and cleans up on abort", () => {
	const tmp = makeTempDir("pi-anon-export-zip-stream");
	try {
		const zipPath = join(tmp.path, "export.zip");
		const writer = openExportZip({ path: zipPath, level: "full", removeImages: true });
		assert.ok(writer.partPath.startsWith(`${zipPath}.`), writer.partPath);
		assert.ok(writer.partPath.endsWith(".part"), writer.partPath);
		assert.ok(existsSync(writer.partPath), "the part file is created immediately");
		assert.equal(statSync(writer.partPath).mode & 0o777, 0o600);

		writer.add({
			source: "a.jsonl",
			archivePath: "a.jsonl",
			content: "{}\n",
			redactionCounts: emptyCounts(),
		});
		writer.add({
			source: "b.jsonl",
			archivePath: "b.jsonl",
			content: "{}",
			redactionCounts: emptyCounts(),
		});
		const manifest = writer.finish({
			verification: { residualSecrets: 0, secretSet: computeSecretFingerprint([], "s") },
			skipped: [{ path: "/Users/alice/x.jsonl", error: "EACCES" }],
		});
		assert.equal(manifest.fileCount, 2);
		assert.deepEqual(manifest.skipped, [{ path: "x.jsonl", error: "EACCES" }]);
		assert.ok(!existsSync(writer.partPath), "the part file is renamed away");
		assert.throws(() => writer.add({
			source: "c.jsonl",
			archivePath: "c.jsonl",
			content: "",
			redactionCounts: emptyCounts(),
		}), /already finished/);
		writer.abort(); // must be a no-op after finish
		assert.ok(existsSync(zipPath));
		assert.deepEqual(Object.keys(unzipSync(new Uint8Array(readFileSync(zipPath)))).sort(), [
			"a.jsonl",
			"b.jsonl",
			"manifest.json",
		]);

		// Abort before finish removes the partial archive and is idempotent.
		const aborted = join(tmp.path, "aborted.zip");
		const doomed = openExportZip({ path: aborted, level: "fast", removeImages: false });
		doomed.add({ source: "a.jsonl", archivePath: "a.jsonl", content: "{}\n", redactionCounts: emptyCounts() });
		doomed.abort();
		doomed.abort();
		assert.ok(!existsSync(doomed.partPath));
		assert.ok(!existsSync(aborted));
	} finally {
		tmp.cleanup();
	}
});

// ---------------------------------------------------------------------------
group("end-to-end command handler");

interface FakeCommand {
	getArgumentCompletions?: (prefix: string) => Array<{ value: string; label: string }> | null;
	handler: (args: string, ctx: unknown) => Promise<void>;
}

interface FakeCtxOptions {
	cwd: string;
	sessionDir: string;
	sessionFile?: string;
	hasUI?: boolean;
}

function registerCommand(): FakeCommand {
	const commands: FakeCommand[] = [];
	const fakePi = {
		registerCommand: (_name: string, options: FakeCommand) => {
			commands.push(options);
		},
		getSettings: () => ({}),
	};
	anonExportExtension(fakePi as unknown as Parameters<typeof anonExportExtension>[0]);
	const command = commands[0];
	assert.ok(command, "extension must register exactly one command");
	return command;
}

const command = registerCommand();

function fakeCtx(options: FakeCtxOptions): { ctx: unknown; notices: Array<{ message: string; type: string }> } {
	const notices: Array<{ message: string; type: string }> = [];
	const ctx = {
		cwd: options.cwd,
		hasUI: options.hasUI ?? false,
		ui: {
			notify: (message: string, type: string) => notices.push({ message, type }),
		},
		sessionManager: {
			getSessionDir: () => options.sessionDir,
			getSessionFile: () => options.sessionFile,
		},
	};
	return { ctx, notices };
}

await ok("e2e: current session is exported, verified and reported on stderr", async () => {
	const sessions = makeTempDir("pi-anon-export-e2e-sessions");
	const out = makeTempDir("pi-anon-export-e2e-out");
	const sessionFile = join(sessions.path, "session-1.jsonl");
	writeFileSync(sessionFile, fixtureSession, "utf-8");
	// A re-export into an existing directory must tighten a pre-existing file.
	mkdirSync(join(out.path, "nested"), { recursive: true, mode: 0o755 });
	writeFileSync(join(out.path, "nested", "session-1.jsonl"), "stale", "utf-8");
	chmodSync(join(out.path, "nested", "session-1.jsonl"), 0o644);
	const stderr = captureStderr();
	try {
		const { ctx, notices } = fakeCtx({ cwd: out.path, sessionDir: sessions.path, sessionFile });
		await command.handler(`--env-file ${fixtureEnv} --out ./nested --secret extra-literal-value`, ctx);
		const report = stderr.read();
		assert.deepEqual(notices, []);
		assert.ok(report.includes("Exported 1 session(s)"), report);
		assert.ok(report.includes("Verified: no known secret literal remains"), report);
		assert.ok(!report.includes("extra-literal-value"), "report must not echo secrets");

		const exported = readFileSync(join(out.path, "nested", "session-1.jsonl"), "utf-8");
		assert.ok(!exported.includes("extra-literal-value"));
		for (const value of secretValues) assert.ok(!exported.includes(value));
		assert.ok(exported.endsWith("\n"));

		// A redacted transcript is still private data: the file is 0600 even when
		// it replaced a pre-existing 0644 one.
		assert.equal(statSync(join(out.path, "nested", "session-1.jsonl")).mode & 0o777, 0o600);
	} finally {
		stderr.restore();
		out.cleanup();
		sessions.cleanup();
	}
});

await ok("e2e: zip mode writes one timestamped archive in the cwd with a manifest", async () => {
	const sessions = makeTempDir("pi-anon-export-e2e-zip-sessions");
	const cwd = makeTempDir("pi-anon-export-e2e-zip-cwd");
	const stderr = captureStderr();
	try {
		writeFileSync(join(sessions.path, "a.jsonl"), fixtureSession, "utf-8");
		writeFileSync(join(sessions.path, "b.jsonl"), sessionLine("mail", "bob@example.org"), "utf-8");
		symlinkSync(join(sessions.path, "gone.jsonl"), join(sessions.path, "dangling.jsonl"));
		// The default zip destination is the cwd; inside a git tree the report must
		// say so, because committing a transcript is one `git add -A` away.
		mkdirSync(join(cwd.path, ".git"));

		const { ctx } = fakeCtx({ cwd: cwd.path, sessionDir: sessions.path });
		await command.handler(`zip --no-images --env-file ${fixtureEnv}`, ctx);

		const report = stderr.read();
		assert.ok(report.includes("Exported 2 session(s)"), report);
		assert.ok(report.includes("Skipped 1 unreadable or empty file(s)."), report);
		assert.ok(report.includes("inside a git working tree"), report);

		const archives = readdirSync(cwd.path).filter((name) => name.endsWith(".zip"));
		assert.equal(archives.length, 1);
		const zipPath = join(cwd.path, archives[0] as string);
		assert.match(zipPath.split("/").pop() ?? "", /^pi-anon-export-.*\.zip$/);
		assert.ok(!zipPath.includes(".part"));

		const entries = unzipSync(new Uint8Array(readFileSync(zipPath)));
		const manifest = JSON.parse(strFromU8(entries["manifest.json"] as Uint8Array)) as ZipManifest;
		assert.equal(manifest.fileCount, 2);
		assert.equal(manifest.skipped.length, 1);
		assert.equal(manifest.skipped[0]?.path, "dangling.jsonl");
		assert.ok(
			!strFromU8(entries["manifest.json"] as Uint8Array).includes(sessions.path),
			"a shared manifest must not carry absolute session paths",
		);
		assert.equal(manifest.verification.residualSecrets, 0);
		assert.equal(manifest.verification.secretSet.algorithm, "sha256");
		for (const entry of manifest.files) {
			const content = strFromU8(entries[entry.archivePath] as Uint8Array);
			assert.ok(!content.includes("iVBORw0KGgo"), "images must be stripped with --no-images");
			assert.equal(entry.sha256, sha256Hex(content));
		}
	} finally {
		stderr.restore();
		cwd.cleanup();
		sessions.cleanup();
	}
});

await ok("e2e: flags images kept, reports residual secrets and skips short secrets", async () => {
	const sessions = makeTempDir("pi-anon-export-e2e-warn-sessions");
	const out = makeTempDir("pi-anon-export-e2e-warn-out");
	const stderr = captureStderr();
	try {
		writeFileSync(join(sessions.path, "s.jsonl"), fixtureSession, "utf-8");
		const { ctx } = fakeCtx({
			cwd: out.path,
			sessionDir: sessions.path,
			sessionFile: join(sessions.path, "s.jsonl"),
		});
		await command.handler(`--env-file ${fixtureEnv} --secret ab`, ctx);
		const report = stderr.read();
		assert.ok(report.includes("Images were KEPT"), report);
		assert.ok(report.includes("shorter than 5 characters"), report);
	} finally {
		stderr.restore();
		out.cleanup();
		sessions.cleanup();
	}
});

await ok("e2e: falls back to the newest session when there is no live session file", async () => {
	const sessions = makeTempDir("pi-anon-export-e2e-fallback");
	const out = makeTempDir("pi-anon-export-e2e-fallback-out");
	const stderr = captureStderr();
	try {
		writeFileSync(join(sessions.path, "older.jsonl"), sessionLine("old"), "utf-8");
		const newest = join(sessions.path, "newer.jsonl");
		writeFileSync(newest, sessionLine("new"), "utf-8");
		const future = new Date(Date.now() + 60_000);
		utimesSync(newest, future, future);

		const { ctx } = fakeCtx({ cwd: out.path, sessionDir: sessions.path });
		await command.handler(`--env-file ${fixtureEnv} --level fast`, ctx);
		const report = stderr.read();
		assert.ok(report.includes("Exported 1 session(s)"), report);
		const exportedPath = /→ (.+)/.exec(report)?.[1]?.trim();
		assert.ok(exportedPath, report);
		assert.ok(exportedPath.endsWith("newer.jsonl"), exportedPath);
		assert.ok(readFileSync(exportedPath, "utf-8").length > 0);
	} finally {
		stderr.restore();
		out.cleanup();
		sessions.cleanup();
	}
});

await ok("e2e: a file that fails verification is quarantined as *.UNSAFE and the run exits non-zero", async () => {
	// The secret sits inside an image payload, which the pipeline deliberately
	// keeps byte-exact — so the verification pass really does find it. That is
	// the only way to exercise the quarantine path from the outside.
	const sessions = makeTempDir("pi-anon-export-e2e-unsafe-sessions");
	const out = makeTempDir("pi-anon-export-e2e-unsafe-out");
	const stderr = captureStderr();
	const previousExitCode = process.exitCode;
	try {
		const secret = "ghk_FAKETOKEN0000FAKE";
		writeFileSync(
			join(sessions.path, "leaky.jsonl"),
			`${JSON.stringify({
				type: "message",
				message: {
					role: "user",
					content: [{ type: "image", mimeType: "image/png", data: `iVBORw0KGgo${secret}${"A".repeat(300)}` }],
				},
			})}\n`,
			"utf-8",
		);

		const { ctx } = fakeCtx({ cwd: out.path, sessionDir: sessions.path });
		await command.handler(`--env-file ${fixtureEnv} --out ./nested`, ctx);

		const report = stderr.read();
		assert.ok(report.includes("VERIFICATION FAILED"), report);
		assert.ok(report.includes("Quarantined 1 file(s)"), report);
		assert.equal(process.exitCode, 1, "an unattended unsafe export must not exit 0");
		assert.deepEqual(readdirSync(join(out.path, "nested")), ["leaky.jsonl.UNSAFE"]);
		// A directory WE create is private too.
		assert.equal(statSync(join(out.path, "nested")).mode & 0o777, 0o700);
	} finally {
		stderr.restore();
		process.exitCode = previousExitCode;
		out.cleanup();
		sessions.cleanup();
	}
});

await ok("e2e: a zip that fails verification is renamed -UNSAFE.zip", async () => {
	const sessions = makeTempDir("pi-anon-export-e2e-zip-unsafe-sessions");
	const cwd = makeTempDir("pi-anon-export-e2e-zip-unsafe-cwd");
	const stderr = captureStderr();
	const previousExitCode = process.exitCode;
	try {
		const secret = "ghk_FAKETOKEN0000FAKE";
		writeFileSync(
			join(sessions.path, "leaky.jsonl"),
			`${JSON.stringify({ type: "message", message: { role: "user", content: [{ type: "image", mimeType: "image/png", data: `${secret}${"B".repeat(300)}` }] } })}\n`,
			"utf-8",
		);
		writeFileSync(join(sessions.path, "clean.jsonl"), sessionLine("nothing to see"), "utf-8");

		const { ctx } = fakeCtx({ cwd: cwd.path, sessionDir: sessions.path });
		await command.handler(`zip --env-file ${fixtureEnv}`, ctx);

		const report = stderr.read();
		assert.ok(report.includes("VERIFICATION FAILED"), report);
		assert.equal(process.exitCode, 1);

		const archives = readdirSync(cwd.path).filter((name) => name.endsWith(".zip"));
		assert.equal(archives.length, 1);
		assert.match(archives[0] as string, /-UNSAFE\.zip$/);

		const entries = unzipSync(new Uint8Array(readFileSync(join(cwd.path, archives[0] as string))));
		const manifest = JSON.parse(strFromU8(entries["manifest.json"] as Uint8Array)) as ZipManifest;
		assert.ok(manifest.verification.residualSecrets > 0);
		assert.deepEqual(Object.keys(entries).sort(), [
			"clean.jsonl",
			"leaky.jsonl.UNSAFE",
			"manifest.json",
		]);
	} finally {
		stderr.restore();
		process.exitCode = previousExitCode;
		cwd.cleanup();
		sessions.cleanup();
	}
});

await ok("e2e: errors notify instead of throwing, and fail an unattended run", async () => {
	const empty = makeTempDir("pi-anon-export-e2e-empty");
	const stderr = captureStderr();
	const previousExitCode = process.exitCode;
	try {
		const { ctx } = fakeCtx({ cwd: empty.path, sessionDir: empty.path });
		await command.handler("zip", ctx);
		assert.ok(stderr.read().includes("No *.jsonl sessions found"), stderr.read());
		assert.equal(process.exitCode, 1, "a failed export must not exit 0");

		const second = captureStderr();
		try {
			await command.handler("--level bananas", ctx);
			assert.ok(second.read().includes("--level must be"), second.read());
		} finally {
			second.restore();
		}
	} finally {
		stderr.restore();
		process.exitCode = previousExitCode;
		empty.cleanup();
	}
});

await ok("e2e: a TUI run reports errors without touching the process exit code", async () => {
	const empty = makeTempDir("pi-anon-export-e2e-ui-empty");
	const stderr = captureStderr();
	const previousExitCode = process.exitCode;
	try {
		const { ctx, notices } = fakeCtx({ cwd: empty.path, sessionDir: empty.path, hasUI: true });
		await command.handler("zip", ctx);
		assert.equal(notices.length, 1);
		assert.equal(notices[0]?.type, "error");
		assert.equal(process.exitCode, previousExitCode, "the TUI must not set the process exit code");
		assert.equal(stderr.read(), "", "with a UI nothing is written to stderr");
	} finally {
		stderr.restore();
		process.exitCode = previousExitCode;
		empty.cleanup();
	}
});

await ok("e2e: argument completions are offered", () => {
	const completions = command.getArgumentCompletions?.("");
	assert.ok(completions && completions.length > 0);
	assert.ok(completions.some((item) => item.value === "zip"));
	assert.equal(command.getArgumentCompletions?.("--zzz"), null);

	// Later tokens complete too, keeping what was already typed.
	const afterZip = command.getArgumentCompletions?.("zip --l");
	assert.ok(afterZip?.some((item) => item.value === "zip --level"), JSON.stringify(afterZip));
	const levelValue = command.getArgumentCompletions?.("--level f");
	assert.ok(levelValue?.some((item) => item.value === "--level fast"), JSON.stringify(levelValue));
});

summary("smoke");
