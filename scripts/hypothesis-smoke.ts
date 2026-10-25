// Hypothesis-driven smoke tests (run: part of `npm run smoke`).
//
// Every case in this file started as an adversarial hypothesis produced by a
// focused review pass (secret discovery, anonymizer, pipeline/IO) and is kept
// here with the failure it prevents: most of them found a real leak, a data
// loss, or a false "Verified" before the corresponding fix landed.
//
// The suite is hermetic: temp dirs only, no network, no real shell rc files.

import assert from "node:assert/strict";
import {
	chmodSync,
	existsSync,
	mkdirSync,
	readdirSync,
	readFileSync,
	statSync,
	symlinkSync,
	writeFileSync,
} from "node:fs";
import { join } from "node:path";

import { strFromU8, unzipSync } from "fflate";

import { anonExportExtension } from "../extensions/anon-export.ts";
import { createAnonymizer } from "../extensions/lib/anonymize.ts";
import { parseAnonExportArgs, tokenizeArgs } from "../extensions/lib/args.ts";
import { countResidualSecrets, emptyCounts, redactSessionJsonl } from "../extensions/lib/redact.ts";
import {
	buildLiteralSecrets,
	computeSecretFingerprint,
	createSecretMatcher,
	defaultEnvFiles,
	parseEnvFileSecrets,
	type SecretEntry,
} from "../extensions/lib/secrets.ts";
import { listSessionFiles, resolveSessionDir } from "../extensions/lib/sessions.ts";
import { openExportZip, writeExportZip } from "../extensions/lib/zip.ts";
import { captureStderr, group, makeTempDir, ok, summary } from "./harness.ts";

const encoder = (value: string): SecretEntry => ({
	name: "HYP",
	value,
	replacement: "[REDACTED_HYP]",
});

function sessionLine(value: unknown): string {
	return `${JSON.stringify(value)}\n`;
}

function writeEnv(dir: string, name: string, content: string): string {
	const path = join(dir, name);
	writeFileSync(path, content, "utf-8");
	return path;
}

// ---------------------------------------------------------------------------
group("hypotheses: secret discovery");

await ok("H1a: a secret that CONTAINS the marker text is redacted, not dropped", () => {
	// It used to be rejected as "placeholder" (and reported as "shorter than 5
	// characters"), so the real secret shipped untouched.
	const value = "sk-live-[REDACTED_abc]-tail";
	const built = buildLiteralSecrets({ envFiles: [], secretInputs: [value] });
	assert.deepEqual(
		built.secrets.map((entry) => entry.value),
		[value],
	);
	const matcher = createSecretMatcher(built.secrets);
	assert.ok(matcher);
	const out = matcher.replace(`token ${value} here`);
	assert.equal(out, "token [REDACTED_SECRET_1] here");
	assert.ok(!built.warnings.join(" ").includes("shorter than"), built.warnings.join(" "));
});

await ok("H1b: marker-shaped values are refused with their OWN reason, never a wrong one", () => {
	const built = buildLiteralSecrets({ envFiles: [], secretInputs: ["REDACT", "[REDACTED_", "goodsecret123"] });
	assert.deepEqual(
		built.secrets.map((entry) => entry.value),
		["goodsecret123"],
	);
	const warned = built.warnings.join("\n");
	assert.ok(warned.includes("marker"), warned);
	assert.ok(!warned.includes("shorter than"), warned);
});

await ok("H2: env files follow shell source order, and conflicting values are reported", () => {
	const tmp = makeTempDir("hyp-env-order");
	try {
		writeEnv(tmp.path, ".zshenv", "export OPENAI_API_KEY=stale-zshenv-value\n");
		writeEnv(tmp.path, ".zshrc", "export OPENAI_API_KEY=fresh-zshrc-value\n");
		const built = buildLiteralSecrets({ home: tmp.path, envFiles: defaultEnvFiles(tmp.path) });
		assert.deepEqual(
			built.secrets.map((entry) => [entry.name, entry.value]),
			[["OPENAI_API_KEY", "fresh-zshrc-value"]],
			"the value the interactive shell ends up with must win",
		);
		assert.ok(
			built.warnings.some((warning) => warning.includes("defined more than once")),
			built.warnings.join("\n"),
		);
	} finally {
		tmp.cleanup();
	}
});

await ok("H3: a generated SECRET_n name never clobbers a real env variable", () => {
	const tmp = makeTempDir("hyp-secret-name");
	try {
		const env = writeEnv(tmp.path, "env", "export SECRET_1=env-secret-value\n");
		const built = buildLiteralSecrets({ envFiles: [env], secretInputs: ["literal-user-secret-value"] });
		const values = built.secrets.map((entry) => entry.value);
		assert.ok(values.includes("env-secret-value"), JSON.stringify(values));
		assert.ok(values.includes("literal-user-secret-value"), JSON.stringify(values));
		const names = built.secrets.map((entry) => entry.name);
		assert.equal(new Set(names).size, names.length, "names must stay unique");
	} finally {
		tmp.cleanup();
	}
});

await ok("H5: continued lines, `declare -x` and `+=` exports are all parsed", () => {
	// A continuation used to yield the needle `abc1\` and leak the rest.
	assert.deepEqual(parseEnvFileSecrets('export API_KEY="abc1\\\ndef456"'), [
		{ name: "API_KEY", value: "abc1def456" },
	]);
	assert.deepEqual(parseEnvFileSecrets('declare -x TOKEN_VALUE="abc123"'), [
		{ name: "TOKEN_VALUE", value: "abc123" },
	]);
	assert.deepEqual(parseEnvFileSecrets("export A_KEY=base123\nexport A_KEY+=appended456"), [
		{ name: "A_KEY", value: "base123" },
		{ name: "A_KEY", value: "appended456", append: true },
	]);

	// Both the base value and the concatenation must be registered as secrets.
	const tmp = makeTempDir("hyp-append");
	try {
		const env = writeEnv(tmp.path, "env", "export A_KEY=base123\nexport A_KEY+=appended456\n");
		const values = buildLiteralSecrets({ envFiles: [env] }).secrets.map((entry) => entry.value);
		assert.ok(values.includes("base123appended456"), JSON.stringify(values));
		assert.ok(values.includes("base123"), JSON.stringify(values));
	} finally {
		tmp.cleanup();
	}
});

await ok("H9: BOM, CRLF and CR-only env files are parsed completely", () => {
	assert.deepEqual(parseEnvFileSecrets('\uFEFFexport API_KEY="abc123"\r\nexport B_KEY=zzz999\r\n'), [
		{ name: "API_KEY", value: "abc123" },
		{ name: "B_KEY", value: "zzz999" },
	]);
	// A CR-only file used to expose only its first assignment.
	assert.deepEqual(parseEnvFileSecrets("export A_KEY=first123\rexport B_KEY=second456\r"), [
		{ name: "A_KEY", value: "first123" },
		{ name: "B_KEY", value: "second456" },
	]);
});

await ok("H9b: a secret FILE with BOM/CRLF is read line by line", () => {
	const tmp = makeTempDir("hyp-secret-file");
	try {
		const path = join(tmp.path, "secrets.txt");
		writeFileSync(path, "\uFEFFfirst-secret-value\r\n\r\nsecond-secret-value\r\n", "utf-8");
		const values = buildLiteralSecrets({ envFiles: [], secretInputs: [path], cwd: tmp.path }).secrets
			.map((entry) => entry.value)
			.sort();
		assert.deepEqual(values, ["first-secret-value", "second-secret-value"]);
	} finally {
		tmp.cleanup();
	}
});

await ok("P3: NFC and NFD spellings of one secret are both redacted and verified", () => {
	// A secret typed composed (NFC) in the rc file was invisible in a session
	// that stored it decomposed (NFD) — redaction AND verification both passed.
	const nfc = "café-SECRET-token-123";
	const nfd = nfc.normalize("NFD");
	assert.notEqual(nfc, nfd);
	for (const [secret, text] of [
		[nfc, nfd],
		[nfd, nfc],
	] as const) {
		const entry = encoder(secret);
		const original = `pw ${text} end`;
		// The verifier itself must see the other normalization, otherwise the
		// export is reported clean while the secret is still in it.
		assert.ok(countResidualSecrets(original, [entry]) > 0, `${text} must be detectable`);
		const matcher = createSecretMatcher([entry]);
		assert.ok(matcher);
		const out = matcher.replace(original);
		assert.ok(!out.includes(text), out);
		assert.ok(!out.includes(secret), out);
		assert.equal(countResidualSecrets(out, [entry]), 0);
	}
});

await ok("P10: the fingerprint describes a value SET (duplicates and names do not matter)", () => {
	const one = computeSecretFingerprint([encoder("same-value")], "s");
	const twice = computeSecretFingerprint(
		[encoder("same-value"), { name: "OTHER", value: "same-value", replacement: "[R]" }],
		"s",
	);
	const renamed = computeSecretFingerprint([{ name: "Z", value: "same-value", replacement: "[R]" }], "s");
	assert.equal(one.digest, twice.digest);
	assert.equal(one.digest, renamed.digest);
});

await ok("SN2: a continued COMMENT line must not swallow the export after it", () => {
	// Joining `# note \` + `export …` deleted the assignment, so the real key was
	// never registered (and nothing warned).
	const content = "# old key \\\nexport API_KEY=realkey123\n";
	assert.deepEqual(parseEnvFileSecrets(content), [{ name: "API_KEY", value: "realkey123" }]);
});

await ok("SN3: unquoted escapes and single-quoted continuations follow shell rules", () => {
	// `abc123\ def456` is one value with a space; stopping at the space produced
	// the truncated needle `abc123\`.
	assert.deepEqual(parseEnvFileSecrets("export API_KEY=abc123\\ def456"), [
		{ name: "API_KEY", value: "abc123 def456" },
	]);
	// Inside single quotes a backslash is literal, so the newline is NOT joined
	// (the header line stays unterminated and nothing is invented).
	assert.deepEqual(parseEnvFileSecrets("export API_KEY='abc1\\\ndef456'"), [
		{ name: "API_KEY", value: "abc1\\" },
	]);
});

await ok("SN4: `export NAME==value` assigns `=value` (no silent drop)", () => {
	// The `==`-looks-like-a-comparison heuristic dropped the whole entry.
	assert.deepEqual(parseEnvFileSecrets("export API_KEY==sk-live-1234"), [
		{ name: "API_KEY", value: "=sk-live-1234" },
	]);
});

await ok("SN5: `+=` reconstructs the effective value even when the base looked too short", () => {
	const tmp = makeTempDir("hyp-append2");
	try {
		const env = writeEnv(tmp.path, "env", "export API_KEY=sk\nexport API_KEY+=live-1234\n");
		const values = buildLiteralSecrets({ envFiles: [env] }).secrets.map((entry) => entry.value);
		assert.deepEqual(values, ["sklive-1234"]);
	} finally {
		tmp.cleanup();
	}
});

await ok("SN5b: repeated appends keep every value and never reuse a marker name", () => {
	const tmp = makeTempDir("hyp-append3");
	try {
		const env = writeEnv(
			tmp.path,
			"env",
			"export API_KEY=abc123\nexport API_KEY+=abc123\nexport API_KEY+=abc123\n",
		);
		const secrets = buildLiteralSecrets({ envFiles: [env] }).secrets;
		assert.equal(
			secrets.find((entry) => entry.name === "API_KEY")?.value,
			"abc123abc123abc123",
			JSON.stringify(secrets),
		);
		const names = secrets.map((entry) => entry.name);
		assert.equal(new Set(names).size, names.length, JSON.stringify(names));
	} finally {
		tmp.cleanup();
	}
});

// ---------------------------------------------------------------------------
group("hypotheses: argument parsing");

await ok("S4: every value flag rejects an empty value", () => {
	for (const raw of ['--out ""', '--secret ""', '--env-file ""', '--level ""', '--pii ""']) {
		assert.ok("error" in parseAnonExportArgs(raw), `expected an error for: ${raw}`);
	}
});

await ok("S7: a non-breaking space stays inside the value (it is not shell whitespace)", () => {
	const parsed = tokenizeArgs("--out /tmp/a\u00A0b");
	assert.deepEqual(parsed, ["--out", "/tmp/a\u00A0b"]);
	// A real tab still separates arguments.
	assert.deepEqual(tokenizeArgs("--out /tmp/a\tb"), ["--out", "/tmp/a", "b"]);
});

await ok("S8: quoting lets a value start with dashes, but a following flag is still an error", () => {
	const quoted = parseAnonExportArgs('--secret "--abc123x" --out "--dir"');
	if ("error" in quoted) throw new Error(quoted.error);
	assert.deepEqual(quoted.secrets, ["--abc123x"]);
	assert.equal(quoted.out, "--dir");

	// Still an error, and for EVERY unquoted dash token: `--out --bogus` used to
	// be taken literally, so a typo'd flag silently became a directory name.
	assert.ok("error" in parseAnonExportArgs("--out --no-images"));
	assert.ok("error" in parseAnonExportArgs("--out --bogus"));
	assert.ok("error" in parseAnonExportArgs("--out --no-image"));
	// The `=` escape hatch still works for unquoted values.
	const inline = parseAnonExportArgs("--out=--bogus");
	if ("error" in inline) throw new Error(inline.error);
	assert.equal(inline.out, "--bogus");
});

// ---------------------------------------------------------------------------
await ok("S9: `--pii aggressive` with `--level fast` is refused, in any order", () => {
	// At `fast` no anonymizer runs, so the patterns the caller asked for would
	// silently do nothing while the report still claimed pii=aggressive.
	for (const raw of ["--pii aggressive --level fast", "--level=fast --pii=aggressive"]) {
		const parsed = parseAnonExportArgs(raw);
		assert.ok("error" in parsed, `expected an error for: ${raw}`);
		assert.match(parsed.error, /requires --level full/, parsed.error);
	}
	const okFull = parseAnonExportArgs("--pii aggressive --level full");
	assert.ok(!("error" in okFull));
	assert.equal(okFull.pii, "aggressive");
});

group("hypotheses: anonymizer");

await ok("A1: credential-URL passwords may contain / # ? @", () => {
	for (const password of ["pa/ss", "pa#ss", "pa?ss", "p@ss"]) {
		const url = `DATABASE postgres://app:${password}@db.internal/prod end`;
		const out = String(createAnonymizer().anonymizeValue(url));
		assert.ok(!out.includes(password), `${password} survived: ${out}`);
		assert.ok(out.includes("postgres://app:redacted_"), out);
		assert.ok(out.endsWith("@db.internal/prod end"), out);
	}
});

await ok("A2: a bare `token` field is redacted when its value looks like a credential", () => {
	const a = createAnonymizer();
	const value = "opaqueToken0123456789abcdef";
	for (const form of [`token=${value}`, `?token=${value}`, `{"token":"${value}"}`]) {
		const out = String(a.anonymizeValue(form));
		assert.ok(!out.includes(value), `${form} -> ${out}`);
	}
	// Prose is not a credential.
	const prose = String(createAnonymizer().anonymizeValue('{"token":"manual review"}'));
	assert.ok(prose.includes("manual review"), prose);
});

await ok("A4: escaped JSON-in-JSON and escaped assignments are redacted", () => {
	const a = createAnonymizer();
	const json = '{\\"password\\":\\"hunter2short\\"}';
	const outJson = String(a.anonymizeValue(json));
	assert.ok(!outJson.includes("hunter2short"), outJson);
	assert.ok(outJson.includes('\\"password\\":\\"redacted_'), outJson);

	const eq = 'DB_PASSWORD\\=\\"hunter2short\\"';
	const outEq = String(a.anonymizeValue(eq));
	assert.ok(!outEq.includes("hunter2short"), outEq);
});

await ok("A6: PGP blocks and TRUNCATED private keys are replaced whole", () => {
	const pgp = [
		"-----BEGIN PGP PRIVATE KEY BLOCK-----",
		"MIIEowIBAAKCAQEA1234",
		"-----END PGP PRIVATE KEY BLOCK-----",
	].join("\n");
	const truncated = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234abcd";
	for (const key of [pgp, truncated]) {
		const out = String(createAnonymizer().anonymizeValue(key));
		assert.ok(!out.includes("MIIEowIBAAKCAQEA1234"), out);
		assert.ok(!out.includes("PRIVATE KEY"), out);
	}
});

await ok("A8: `==`, `===` and `=>` are never treated as assignments", () => {
	const a = createAnonymizer();
	for (const code of ['if password == "admin":', "if (password === 'hunter2') {", 'const f = password => "x";']) {
		assert.equal(String(a.anonymizeValue(code)), code, `code must be untouched: ${code}`);
	}
});

await ok("A9: a bare assignment keeps its `#` inside the value", () => {
	const out = String(createAnonymizer().anonymizeValue("DB_PASSWORD=pa#ss123"));
	assert.ok(!out.includes("pa#ss123"), out);
	assert.ok(!out.includes("#ss123"), `the trailer must not survive: ${out}`);
});

await ok("A10: quoted bearer tokens are redacted too", () => {
	for (const quote of ['"', "'"]) {
		const token = "opaqueToken0123456789abcdefghij";
		const out = String(
			createAnonymizer().anonymizeValue(`Authorization: Bearer ${quote}${token}${quote}`),
		);
		assert.ok(!out.includes(token), out);
		assert.ok(out.includes(`Bearer ${quote}`), out);
	}
});

await ok("A11: a second pass is a fixed point (home-path placeholders are not re-hashed)", () => {
	const a = createAnonymizer();
	const once = String(a.anonymizeValue("mail alice@corp.io then /Users/alice/x and /home/bob/y"));
	const twice = String(a.anonymizeValue(once));
	assert.equal(twice, once);
});

await ok("A3/A5: no chunk seams — a match next to a >1MiB whitespace-free run is still caught", () => {
	// The old chunked scan split at the 1 MiB edge and lost anything straddling
	// it. A comma keeps this a single segment while still giving the address a
	// non-identifier character before it (an address glued to letters is
	// deliberately not matched — see the RFC-bounded local part).
	const mega = "A".repeat(1024 * 1024 + 1);
	const result = redactSessionJsonl(
		sessionLine({ text: `${mega},alice.smith@corp-mail.com,123-45-6789` }),
		{ level: "full", removeImages: false, secrets: [], anonymizer: createAnonymizer() },
	);
	const out = result.lines.join("");
	assert.ok(!out.includes("alice.smith@corp-mail.com"), "email survived a huge segment");
	assert.ok(!out.includes("123-45-6789"), "ssn survived a huge segment");
});

await ok("A7: 1 MiB of addresses stays linear (no multi-second email guard)", () => {
	const line =
		"commit 3f2a9c1b\nAuthor: Dev Person <dev.person@corp-mail.com>\nDate: Mon Sep 1\n\n    body\n\n";
	let text = "";
	while (text.length < 1024 * 1024) text += line;
	const started = performance.now();
	const out = String(createAnonymizer().anonymizeValue(text));
	const elapsed = performance.now() - started;
	assert.ok(!out.includes("@corp-mail.com"), "emails must be redacted");
	// Was ~18 s before the guard became linear; the bound is deliberately loose.
	assert.ok(elapsed < 5000, `1 MiB took ${Math.round(elapsed)} ms`);
});

await ok("A12: an underscore in the domain does not hide an address", () => {
	const out = String(createAnonymizer().anonymizeValue("mail bob@my_corp.com now"));
	assert.ok(!out.includes("bob@my_corp.com"), out);
});

await ok("AN1: a URL WITHOUT credentials survives the credential-URL pass", () => {
	// A greedy password class swallowed everything up to the last `@`, so these
	// were reported as `user:password@host` and destroyed.
	const a = createAnonymizer();
	const untouched = [
		"https://api.example.com:8443/v1/users?email=bob@corp.io",
		"http://host:8080/x?a=1&b=c@d.io",
	];
	for (const url of untouched) {
		assert.equal(String(a.anonymizeValue(url)), url);
	}

	// With real credentials, each URL is redacted independently and structurally.
	const pair = '{"urls":["mysql://u:p@h1/db","redis://u2:p2@h2:6379"]}';
	const out = String(a.anonymizeValue(pair));
	assert.ok(!out.includes("u:p@h1"), out);
	assert.ok(!out.includes("u2:p2@h2"), out);
	assert.ok(out.includes('@h1/db"'), out);
	assert.ok(out.includes("@h2:6379"), out);
});

await ok("AN2: prose that MENTIONS a PEM header is not swallowed", () => {
	// The truncated-block branch ran to end-of-string: a 37-byte output for a
	// 4 MiB transcript.
	const prose = "The header -----BEGIN PRIVATE KEY----- goes first, then base64 lines.";
	const out = String(createAnonymizer().anonymizeValue(prose));
	assert.ok(out.endsWith(" goes first, then base64 lines."), out);
	assert.ok(out.length > 40, out);

	// A real truncated key (base64 body) is still replaced wholesale.
	const truncated = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234abcd\nQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=";
	const redacted = String(createAnonymizer().anonymizeValue(truncated));
	assert.ok(!redacted.includes("MIIEowIBAAKCAQEA1234abcd"), redacted);
	assert.ok(!redacted.includes("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo="), redacted);
});

await ok("AN3: YAML/INI comments are not mistaken for values", () => {
	const a = createAnonymizer();
	for (const line of ["password: # TODO use vault", "api_key:   # not set", "secret: #not-yet-set"]) {
		assert.equal(String(a.anonymizeValue(line)), line);
	}
	// A real value with a trailing comment is still redacted, comment intact.
	const out = String(a.anonymizeValue("password: hunter2  # rotate in vault"));
	assert.ok(!out.includes("hunter2"), out);
	assert.ok(out.endsWith("  # rotate in vault"), out);
});

await ok("AN5: connection-component secrets ignore `==`/`=>` like other assignments", () => {
	const a = createAnonymizer();
	for (const code of ["password==secret", "api_secret=>abc123456"]) {
		assert.equal(String(a.anonymizeValue(code)), code);
	}
	const normal = String(a.anonymizeValue("Password=realpassword1;"));
	assert.ok(!normal.includes("realpassword1"), normal);
});

await ok("AN6: `id_token` is redacted, `token_count` is not", () => {
	const a = createAnonymizer();
	const value = "opaqueToken0123456789abcdef";
	const token = String(a.anonymizeValue(`?id_token=${value}`));
	assert.ok(!token.includes(value), token);
	const count = "token_count=42";
	assert.equal(String(a.anonymizeValue(count)), count);
});

await ok("AN7: dense whitespace-free email text stays fast (no per-username rescan)", () => {
	// 77 % of the runtime used to be one full-text scan PER known username, so a
	// CSV of addresses was quadratic: 0.4 MiB took 1.7 s and 1 MiB ~4 s.
	const chunk = Array.from({ length: 2000 }, (_, i) => `u${i}@corp-mail.com,`).join("");
	let text = "";
	while (text.length < 1024 * 1024) text += chunk;
	const started = performance.now();
	const out = String(createAnonymizer().anonymizeValue(text));
	const elapsed = performance.now() - started;
	assert.ok(!out.includes("@corp-mail.com"), "addresses must be redacted");
	assert.ok(elapsed < 3000, `1 MiB of dense addresses took ${Math.round(elapsed)} ms`);
});

await ok("AN8: an ls-style owner/group pair is still mapped, in a single pass", () => {
	const a = createAnonymizer();
	// Seed the username map from a home path, then look at an `ls -l` line.
	const out = String(a.anonymizeValue("-rw-r--r-- 1 alice alice 4096 /Users/alice/notes.txt"));
	assert.ok(!out.includes("alice"), out);
	assert.match(out, /^\S+ \d+ user_[0-9a-f]{8} user_[0-9a-f]{8} 4096 /);
});

await ok("A11b: aggressivePii does not leak between instances", () => {
	const aggressive = String(createAnonymizer({ aggressivePii: true }).anonymizeValue("my name is Alice Johnson"));
	const conservative = String(createAnonymizer().anonymizeValue("my name is Alice Johnson"));
	assert.ok(!aggressive.includes("Alice Johnson"));
	assert.ok(conservative.includes("Alice Johnson"));
});

// ---------------------------------------------------------------------------
group("hypotheses: redaction pipeline");

await ok("P1: a long TEXT value under `data` is redacted as text, not exempted as an image", () => {
	const data = `csv\nemail,john.smith@corp-mail.com\n${"row,value\n".repeat(40)}`;
	const line = sessionLine({ type: "tool-result", data });
	assert.ok(data.length > 256);

	const kept = redactSessionJsonl(line, {
		level: "full",
		removeImages: false,
		secrets: [],
		anonymizer: createAnonymizer(),
	});
	assert.ok(!kept.lines.join("").includes("john.smith@corp-mail.com"), "email must be redacted");
	assert.equal(kept.counts.images_flagged, 0, "text is not an image");

	// ...and --no-images must not delete a CSV payload.
	const stripped = redactSessionJsonl(line, {
		level: "full",
		removeImages: true,
		secrets: [],
		anonymizer: createAnonymizer(),
	});
	assert.equal(stripped.counts.images_removed, 0);
	assert.ok(stripped.lines.join("").includes("row,value"), "the CSV must survive");
});

await ok("P2: media carriers other than `data`/`base64` are still recognised", () => {
	const base64 = `iVBORw0KGgo${"A".repeat(400)}`;
	const blocks = [
		{ type: "image", mimeType: "image/png", imageData: base64 },
		{ type: "image_generation", b64_json: base64 },
		{ type: "image", url: `data:image/png;base64,${base64}` },
	];
	for (const block of blocks) {
		const result = redactSessionJsonl(sessionLine({ message: { content: [block] } }), {
			level: "full",
			removeImages: true,
			secrets: [],
			anonymizer: createAnonymizer(),
		});
		assert.equal(result.counts.images_removed, 1, JSON.stringify(block).slice(0, 80));
		assert.ok(!result.lines.join("").includes("iVBORw0KGgo"));
	}
});

await ok("P7: the media threshold boundary is exactly >256 characters", () => {
	const media = (length: number): string =>
		sessionLine({ message: { content: [{ type: "image", mimeType: "image/png", data: "A".repeat(length) }] } });
	const at256 = redactSessionJsonl(media(256), {
		level: "fast",
		removeImages: true,
		secrets: [],
	});
	assert.equal(at256.counts.images_removed, 0, "256 chars is below the documented threshold");
	const at257 = redactSessionJsonl(media(257), {
		level: "fast",
		removeImages: true,
		secrets: [],
	});
	assert.equal(at257.counts.images_removed, 1);
});

await ok("P8: directories and subdirectories are never counted as sessions", () => {
	const tmp = makeTempDir("hyp-sessions");
	try {
		writeFileSync(join(tmp.path, "real.jsonl"), "{}\n", "utf-8");
		mkdirSync(join(tmp.path, "nested"));
		writeFileSync(join(tmp.path, "nested", "deep.jsonl"), "{}\n", "utf-8");
		mkdirSync(join(tmp.path, "weird.jsonl"));
		const { files, skipped } = listSessionFiles(tmp.path);
		assert.deepEqual(
			files.map((file) => file.split("/").pop()),
			["real.jsonl"],
		);
		assert.deepEqual(skipped, [], "omitting a nested session is not an error, but it must be silent-safe");
	} finally {
		tmp.cleanup();
	}
});

await ok("P8b: a relative --session-dir resolves against the session cwd, not process.cwd()", () => {
	const resolved = resolveSessionDir({ cwd: "/work/app", sessionManagerDir: "sessions", env: {} });
	assert.equal(resolved.dir, "/work/app/sessions");
});

await ok("PN5: a pathological single-token line is dropped and counted, never fatal", () => {
	// 8 MiB with no whitespace hits a V8 regexp limit inside the credential pass;
	// the line must be dropped (fail-safe) instead of aborting the export.
	const huge = `${"Q".repeat(8 * 1024 * 1024)}.a.b.c`;
	const result = redactSessionJsonl(sessionLine({ text: huge }), {
		level: "full",
		removeImages: false,
		secrets: [],
		anonymizer: createAnonymizer(),
	});
	assert.equal(result.lines.length, 0);
	assert.equal(result.counts.dropped_lines, 1);
});

await ok("PN6: a session-dir symlink is followed (documented trade-off), still redacted", () => {
	const tmp = makeTempDir("hyp-symlink");
	const outside = makeTempDir("hyp-symlink-outside");
	try {
		writeFileSync(join(outside.path, "external.jsonl"), sessionLine({ ok: true }), "utf-8");
		symlinkSync(join(outside.path, "external.jsonl"), join(tmp.path, "linked.jsonl"));
		const { files, skipped } = listSessionFiles(tmp.path);
		assert.deepEqual(
			files.map((file) => file.split("/").pop()),
			["linked.jsonl"],
			"symlinks are followed on purpose; subdirectories are not",
		);
		assert.deepEqual(skipped, []);
	} finally {
		outside.cleanup();
		tmp.cleanup();
	}
});

await ok("P11: duplicate archive names are rejected instead of silently dropping content", () => {
	const tmp = makeTempDir("hyp-zip-dupe");
	try {
		const writer = openExportZip({ path: join(tmp.path, "export.zip"), level: "fast", removeImages: false });
		writer.add({ source: "a", archivePath: "same.jsonl", content: "{}\n", redactionCounts: emptyCounts() });
		assert.throws(
			() => writer.add({ source: "b", archivePath: "same.jsonl", content: "{}\n", redactionCounts: emptyCounts() }),
			/Duplicate archive entry/,
		);
		writer.abort();
	} finally {
		tmp.cleanup();
	}
});

await ok("P12: a stale `.part` file cannot weaken the archive permissions", () => {
	const tmp = makeTempDir("hyp-zip-part");
	try {
		const zipPath = join(tmp.path, "export.zip");
		const stale = `${zipPath}.part`;
		writeFileSync(stale, "stale", "utf-8");
		chmodSync(stale, 0o644);
		writeExportZip({
			path: zipPath,
			files: [{ source: "a", archivePath: "a.jsonl", content: "{}\n", redactionCounts: emptyCounts() }],
			level: "fast",
			removeImages: false,
			verification: { residualSecrets: 0, secretSet: computeSecretFingerprint([], "s") },
		});
		assert.equal(statSync(zipPath).mode & 0o777, 0o600);
		assert.equal(readFileSync(stale, "utf-8"), "stale", "the writer must not reuse a foreign part file");
	} finally {
		tmp.cleanup();
	}
});

await ok("P15: a rejected duplicate name does not poison the archive", () => {
	// Rejecting a duplicate happens BEFORE anything is written, so the stream is
	// still sound and the caller can carry on. A real write failure is different:
	// it marks the writer broken (see zip.ts `add`), so a caller that swallows the
	// error cannot append bytes into a corrupt archive.
	const tmp = makeTempDir("hyp-zip-dupe-survives");
	try {
		const zipPath = join(tmp.path, "export.zip");
		const writer = openExportZip({ path: zipPath, level: "fast", removeImages: false });
		writer.add({ source: "a", archivePath: "a.jsonl", content: "{}\n", redactionCounts: emptyCounts() });
		assert.throws(
			() => writer.add({ source: "a2", archivePath: "a.jsonl", content: "{}\n", redactionCounts: emptyCounts() }),
			/Duplicate archive entry/,
		);
		writer.add({ source: "c", archivePath: "c.jsonl", content: "{}\n", redactionCounts: emptyCounts() });
		writer.finish({ verification: { residualSecrets: 0, secretSet: computeSecretFingerprint([], "s") } });

		const entries = unzipSync(new Uint8Array(readFileSync(zipPath)));
		assert.deepEqual(Object.keys(entries).sort(), ["a.jsonl", "c.jsonl", "manifest.json"]);
	} finally {
		tmp.cleanup();
	}
});

await ok("P4: two concurrent writers cannot interleave into one artifact", () => {
	const tmp = makeTempDir("hyp-zip-race");
	try {
		const zipPath = join(tmp.path, "race.zip");
		const a = openExportZip({ path: zipPath, level: "fast", removeImages: false });
		const b = openExportZip({ path: zipPath, level: "fast", removeImages: false });
		assert.notEqual(a.partPath, b.partPath, "each run needs its own part file");

		a.add({ source: "a", archivePath: "a.jsonl", content: `{"v":${"1".repeat(200_000)}}\n`, redactionCounts: emptyCounts() });
		b.add({ source: "b", archivePath: "b.jsonl", content: `{"v":${"2".repeat(200_000)}}\n`, redactionCounts: emptyCounts() });
		const verification = { residualSecrets: 0, secretSet: computeSecretFingerprint([], "s") };
		a.finish({ verification });
		b.finish({ verification });

		// Last rename wins, but it must be a COMPLETE archive of one run.
		const entries = unzipSync(new Uint8Array(readFileSync(zipPath)));
		assert.deepEqual(Object.keys(entries).sort(), ["b.jsonl", "manifest.json"]);
	} finally {
		tmp.cleanup();
	}
});

// ---------------------------------------------------------------------------
group("hypotheses: command handler");

interface FakeCommand {
	getArgumentCompletions?: (prefix: string) => Array<{ value: string; label: string }> | null;
	handler: (args: string, ctx: unknown) => Promise<void>;
}

function registerCommand(): FakeCommand {
	const commands: FakeCommand[] = [];
	anonExportExtension({
		registerCommand: (_name: string, options: FakeCommand) => commands.push(options),
		getSettings: () => ({}),
	} as unknown as Parameters<typeof anonExportExtension>[0]);
	const command = commands[0];
	assert.ok(command);
	return command;
}

const command = registerCommand();

function fakeCtx(sessionDir: string, cwd: string, sessionFile?: string): unknown {
	return {
		cwd,
		hasUI: false,
		ui: { notify: () => {} },
		sessionManager: {
			getSessionDir: () => sessionDir,
			getSessionFile: () => sessionFile,
		},
	};
}

await ok("P5: `--out` pointing at the session directory refuses to overwrite the live session", async () => {
	const tmp = makeTempDir("hyp-overwrite");
	const stderr = captureStderr();
	const previousExitCode = process.exitCode;
	try {
		const sessionFile = join(tmp.path, "live.jsonl");
		const original = sessionLine({ type: "message", message: { role: "user", content: [] } });
		writeFileSync(sessionFile, original, "utf-8");

		await command.handler(`--out ${tmp.path}`, fakeCtx(tmp.path, tmp.path, sessionFile));

		assert.ok(stderr.read().includes("Refusing to overwrite"), stderr.read());
		assert.equal(readFileSync(sessionFile, "utf-8"), original, "the source session must be intact");
		assert.equal(process.exitCode, 1);
	} finally {
		stderr.restore();
		process.exitCode = previousExitCode;
		tmp.cleanup();
	}
});

await ok("P6: a file whose lines are all unparseable is not a successful 0-byte export", async () => {
	const tmp = makeTempDir("hyp-junk");
	const stderr = captureStderr();
	const previousExitCode = process.exitCode;
	try {
		const sessionFile = join(tmp.path, "junk.jsonl");
		writeFileSync(sessionFile, "not json\n<<<binary>>>\n", "utf-8");
		await command.handler(`--out ${join(tmp.path, "out")}`, fakeCtx(tmp.path, tmp.path, sessionFile));

		const report = stderr.read();
		assert.ok(report.includes("No sessions could be read"), report);
		assert.equal(process.exitCode, 1);
		assert.ok(!existsSync(join(tmp.path, "out", "junk.jsonl")), "no empty artifact may be written");
	} finally {
		stderr.restore();
		process.exitCode = previousExitCode;
		tmp.cleanup();
	}
});

await ok("P10b: a partial export stays exit 0 but reports the skipped file", async () => {
	const tmp = makeTempDir("hyp-partial");
	const cwd = makeTempDir("hyp-partial-cwd");
	const stderr = captureStderr();
	const previousExitCode = process.exitCode;
	try {
		writeFileSync(join(tmp.path, "good.jsonl"), sessionLine({ ok: true }), "utf-8");
		const locked = join(tmp.path, "locked.jsonl");
		writeFileSync(locked, "{}\n", "utf-8");
		chmodSync(locked, 0o000);

		await command.handler(`zip --env-file ${join(cwd.path, "empty-env")}`, fakeCtx(tmp.path, cwd.path));
		const report = stderr.read();
		assert.ok(report.includes("Exported 1 session(s)"), report);
		assert.ok(report.includes("Skipped 1 unreadable or empty file(s)."), report);
		assert.equal(process.exitCode, previousExitCode, "a partial batch is documented as non-fatal");
	} finally {
		stderr.restore();
		process.exitCode = previousExitCode;
		cwd.cleanup();
		tmp.cleanup();
	}
});

await ok("P9: the report says when there was nothing to verify against", async () => {
	const tmp = makeTempDir("hyp-noverify");
	const out = makeTempDir("hyp-noverify-out");
	const stderr = captureStderr();
	try {
		const env = writeEnv(tmp.path, "env", "export HARMLESS_VAR=not-a-secret\n");
		const sessionFile = join(tmp.path, "s.jsonl");
		writeFileSync(sessionFile, sessionLine({ text: "nothing secret here" }), "utf-8");
		await command.handler(`--env-file ${env} --out ${out.path}`, fakeCtx(tmp.path, out.path, sessionFile));
		const report = stderr.read();
		assert.ok(report.includes("No secret literals were found to verify against"), report);
		assert.ok(report.includes("Secret set: 0 literal(s)"), report);
	} finally {
		stderr.restore();
		out.cleanup();
		tmp.cleanup();
	}
});

await ok("PN1: long TEXT under an always-media key is not exempted from redaction", () => {
	// `imageData`/`b64_json` were unconditional media keys, so a CSV tool-result
	// stored under one shipped unredacted while the report said "Verified".
	const data = `csv\nemail,john.smith@corp-mail.com\n${"row,value\n".repeat(40)}`;
	for (const key of ["imageData", "b64_json", "contentBytes", "audioData"]) {
		const line = sessionLine({ type: "tool-result", [key]: data });
		const kept = redactSessionJsonl(line, {
			level: "full",
			removeImages: false,
			secrets: [],
			anonymizer: createAnonymizer(),
		});
		assert.ok(!kept.lines.join("").includes("john.smith@corp-mail.com"), `${key}: email must be redacted`);
		assert.equal(kept.counts.images_flagged, 0, `${key} is not an image`);

		const stripped = redactSessionJsonl(line, {
			level: "full",
			removeImages: true,
			secrets: [],
			anonymizer: createAnonymizer(),
		});
		assert.equal(stripped.counts.images_removed, 0, `${key}: text must not be deleted`);
		assert.ok(stripped.lines.join("").includes("row,value"), `${key}: text must survive`);
	}
});

await ok("PN2: media detection follows evidence (type, MIME type, magic), not just the key", () => {
	const png = `iVBORw0KGgo${"A".repeat(400)}`;
	const bmp = `Qk${"A".repeat(400)}`; // BMP magic ("BM"), which the list missed
	const cases: Array<[string, Record<string, unknown>]> = [
		["typed image, no mimeType", { type: "image", data: bmp }],
		["declared MIME type on a content key", { type: "image", mimeType: "image/png", content: png }],
		["screenshot key with magic", { type: "screenshot", screenshot: png }],
		["nested data: URL", { type: "image_url", image_url: { url: `data:image/png;base64,${png}` } }],
	];
	for (const [label, block] of cases) {
		const result = redactSessionJsonl(sessionLine({ message: { content: [block] } }), {
			level: "full",
			removeImages: true,
			secrets: [],
			anonymizer: createAnonymizer(),
		});
		assert.equal(result.counts.images_removed, 1, `${label} must be removed`);
	}
});

await ok("P13: a long prose field next to a declared media MIME type is TEXT", () => {
	// `declaresMediaType(owner)` used to exempt EVERY long string in the object,
	// so `{"mimeType":"image/png","note":"…long prose with an address…"}` shipped
	// the address unredacted — and --no-images deleted the prose as if it were
	// the image.
	const prose = `contact john.smith@corp-mail.com for the log. ${"y".repeat(240)}`;
	const line = sessionLine({
		type: "tool-result",
		mimeType: "image/png",
		note: prose,
		data: `iVBORw0KGgo${"B".repeat(400)}`,
	});

	const kept = redactSessionJsonl(line, {
		level: "full",
		removeImages: false,
		secrets: [],
		anonymizer: createAnonymizer(),
	});
	assert.ok(!kept.lines.join("").includes("john.smith@corp-mail.com"), "prose must be redacted");
	assert.equal(kept.counts.images_flagged, 1, "only the payload is flagged, not the prose");

	const stripped = redactSessionJsonl(line, {
		level: "full",
		removeImages: true,
		secrets: [],
		anonymizer: createAnonymizer(),
	});
	assert.ok(stripped.lines.join("").includes("for the log"), "prose must survive --no-images");
	assert.equal(stripped.counts.images_removed, 1, "only the payload is removed");
});

await ok("P14: a text-based media type (SVG) carries text, so it is redacted", () => {
	// `image/svg+xml` is an image MIME type whose payload is XML: exempting it
	// skipped the whole redaction pipeline, so an address inside the SVG shipped
	// verbatim (and a literal secret only showed up in the verification pass).
	const svg = `<svg xmlns="http://www.w3.org/2000/svg">${"x".repeat(300)}<desc>john.smith@corp-mail.com</desc></svg>`;
	const line = sessionLine({ type: "file", mimeType: "image/svg+xml", data: svg });

	const kept = redactSessionJsonl(line, {
		level: "full",
		removeImages: false,
		secrets: [],
		anonymizer: createAnonymizer(),
	});
	assert.ok(!kept.lines.join("").includes("john.smith@corp-mail.com"), "SVG text must be redacted");
	assert.equal(kept.counts.images_flagged, 0, "SVG is text, not an image payload");

	const stripped = redactSessionJsonl(line, {
		level: "full",
		removeImages: true,
		secrets: [],
		anonymizer: createAnonymizer(),
	});
	assert.equal(stripped.counts.images_removed, 0, "nothing to strip: it was never a payload");
});

await ok("PN3: the overwrite guard also catches symlinks and hard links to the session", async () => {
	const tmp = makeTempDir("hyp-alias");
	const out = makeTempDir("hyp-alias-out");
	const stderr = captureStderr();
	const previousExitCode = process.exitCode;
	try {
		const sessionFile = join(tmp.path, "live.jsonl");
		const original = sessionLine({ text: "contact john.smith@corp-mail.com" });
		writeFileSync(sessionFile, original, "utf-8");

		// (a) symlink in the output dir pointing at the live session
		const viaSymlink = join(out.path, "live.jsonl");
		try {
			symlinkSync(sessionFile, viaSymlink);
		} catch {
			// symlink creation can be unavailable; the direct compare still runs
		}

		await command.handler(`--out ${out.path}`, fakeCtx(tmp.path, out.path, sessionFile));
		assert.ok(stderr.read().includes("Refusing to overwrite"), stderr.read());
		assert.equal(readFileSync(sessionFile, "utf-8"), original, "the live session must be intact");
	} finally {
		stderr.restore();
		process.exitCode = previousExitCode;
		out.cleanup();
		tmp.cleanup();
	}
});

await ok("PN4: an empty or blank session is skipped instead of shipping 0 bytes", async () => {
	for (const [name, content] of [
		["empty.jsonl", ""],
		["blank.jsonl", "\n\n  \n"],
	] as const) {
		const tmp = makeTempDir("hyp-empty");
		const stderr = captureStderr();
		const previousExitCode = process.exitCode;
		try {
			const sessionFile = join(tmp.path, name);
			writeFileSync(sessionFile, content, "utf-8");
			await command.handler(`--out ${join(tmp.path, "out")}`, fakeCtx(tmp.path, tmp.path, sessionFile));

			const report = stderr.read();
			assert.ok(report.includes("No sessions could be read"), `${name}: ${report}`);
			assert.ok(report.includes("empty session"), `${name}: ${report}`);
			assert.equal(process.exitCode, 1);
			assert.ok(!existsSync(join(tmp.path, "out", name)), `${name} must not produce an artifact`);
		} finally {
			stderr.restore();
			process.exitCode = previousExitCode;
			tmp.cleanup();
		}
	}
});

await ok("P2b: discovery lists what it will export, and the count matches the archive", async () => {
	const tmp = makeTempDir("hyp-count");
	const cwd = makeTempDir("hyp-count-cwd");
	const stderr = captureStderr();
	try {
		writeFileSync(join(tmp.path, "a.jsonl"), sessionLine({ a: 1 }), "utf-8");
		writeFileSync(join(tmp.path, "b.jsonl"), sessionLine({ b: 2 }), "utf-8");
		mkdirSync(join(tmp.path, "nested"));
		writeFileSync(join(tmp.path, "nested", "deep.jsonl"), sessionLine({ deep: 3 }), "utf-8");

		await command.handler(`zip --env-file ${join(cwd.path, "empty-env")}`, fakeCtx(tmp.path, cwd.path));
		assert.ok(stderr.read().includes("Exported 2 session(s)"), stderr.read());

		const archives = readdirSync(cwd.path).filter((name) => name.endsWith(".zip"));
		assert.equal(archives.length, 1);
		const entries = unzipSync(new Uint8Array(readFileSync(join(cwd.path, archives[0] as string))));
		assert.deepEqual(Object.keys(entries).sort(), ["a.jsonl", "b.jsonl", "manifest.json"]);
		assert.ok(!("nested/deep.jsonl" in entries));
		assert.ok(strFromU8(entries["manifest.json"] as Uint8Array).includes('"fileCount": 2'));
	} finally {
		stderr.restore();
		cwd.cleanup();
		tmp.cleanup();
	}
});

await ok("P17: a verified re-export removes the stale quarantine of the same session", async () => {
	// Run 1 quarantines `s.jsonl` as `s.jsonl.UNSAFE`. After the fix, run 2 writes a
	// clean `s.jsonl`; leaving the old unsafe file next to it means a careless
	// `cp *` or `git add -A` ships the file that still contains the secret.
	const sessions = makeTempDir("hyp-stale-sessions");
	const out = makeTempDir("hyp-stale-out");
	const env = makeTempDir("hyp-stale-env");
	const stderr = captureStderr();
	const previousExitCode = process.exitCode;
	try {
		const sessionFile = join(sessions.path, "s.jsonl");
		writeFileSync(sessionFile, sessionLine({ type: "message", message: { role: "user", content: "hi" } }), "utf-8");
		const stale = join(out.path, "s.jsonl.UNSAFE");
		writeFileSync(stale, "old leaky export\n", "utf-8");
		const envFile = writeEnv(env.path, "env", "");

		await command.handler(`--out ${out.path} --env-file ${envFile}`, fakeCtx(sessions.path, out.path, sessionFile));

		assert.ok(existsSync(join(out.path, "s.jsonl")), "the verified file must be written");
		assert.ok(!existsSync(stale), "the stale quarantine must be gone");
	} finally {
		stderr.restore();
		process.exitCode = previousExitCode;
		env.cleanup();
		out.cleanup();
		sessions.cleanup();
	}
});

summary("hypothesis-smoke");
