// Anonymizer smoke tests (run: part of `npm run smoke`).
//
// One case per regex class plus the false-positive guards documented in
// extensions/lib/anonymize.ts. Assertions target the security property
// ("this value must not survive") rather than the exact placeholder shape,
// which is generated from a hash.

import assert from "node:assert/strict";

import { createAnonymizer, type Anonymizer } from "../extensions/lib/anonymize.ts";
import { group, ok, summary } from "./harness.ts";

const EMAIL_SHAPE = /[A-Za-z0-9._%+-]+@(?!example\.com)[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;

function fresh(): Anonymizer {
	return createAnonymizer();
}

group("anonymize: emails and their false-positive guards");

await ok("plain email is replaced with a stable example.com placeholder", () => {
	const a = fresh();
	const out = a.anonymizeValue("mail alice@northwind-labs.io now") as string;
	assert.ok(!out.includes("alice@northwind-labs.io"), out);
	assert.match(out, /^mail redacted-user_[0-9a-f]{8}@example\.com now$/);
	assert.equal(a.counts.email, 1);
});

await ok("email followed by a sentence-ending period keeps the period", () => {
	const out = fresh().anonymizeValue("ping bob@foo.io.") as string;
	assert.ok(!out.includes("bob@foo.io"), out);
	assert.match(out, /redacted-user_[0-9a-f]{8}@example\.com\.$/);
});

await ok("email inside a JSON string (quoted) is replaced", () => {
	const out = fresh().anonymizeValue('"contact": "alice@northwind-labs.io"') as string;
	assert.ok(!out.includes("alice@northwind-labs.io"), out);
});

await ok("email after a /-separated path segment is still replaced", () => {
	const out = fresh().anonymizeValue("path /srv/app/x then alice@northwind-labs.io") as string;
	assert.ok(!out.includes("alice@northwind-labs.io"), out);
});

await ok("path-shaped user@host with a slash is preserved (documented guard)", () => {
	const out = fresh().anonymizeValue("see dir/user@host.com/file now") as string;
	assert.equal(out, "see dir/user@host.com/file now");
});

await ok("URI userinfo is preserved (documented guard)", () => {
	const out = fresh().anonymizeValue("https://user@host.com/path") as string;
	assert.equal(out, "https://user@host.com/path");
});

await ok("reserved example.com addresses are preserved", () => {
	const out = fresh().anonymizeValue("x redacted-user_abcd1234@example.com y") as string;
	assert.equal(out, "x redacted-user_abcd1234@example.com y");
});

await ok("package versions are preserved", () => {
	assert.equal(fresh().anonymizeValue("lodash@4.17.21"), "lodash@4.17.21");
});

await ok("systemd unit names are preserved", () => {
	assert.equal(fresh().anonymizeValue("unit foo@bar.service"), "unit foo@bar.service");
});

await ok("git remotes with an unseen user are preserved, then rewritten once seen", () => {
	const a = fresh();
	assert.equal(
		a.anonymizeValue("git@github.com:stranger/repo.git"),
		"git@github.com:stranger/repo.git",
	);
	const mapped = a.anonymizeValue("home /Users/stranger/x") as string;
	assert.match(mapped, /^home \/Users\/user_[0-9a-f]{8}\/x$/);
	assert.match(
		a.anonymizeValue("git@github.com:stranger/repo.git") as string,
		/^git@github\.com:user_[0-9a-f]{8}\/repo\.git$/,
	);
});

await ok("backslash-separated email-ish text is over-redacted (accepted trade-off)", () => {
	const out = fresh().anonymizeValue("dir\\name@foo.com") as string;
	assert.ok(!out.includes("name@foo.com"), out);
});

group("anonymize: credentials");

await ok("prefixed API keys are replaced", () => {
	const a = fresh();
	const out = a.anonymizeValue("key sk_live_FAKEKEY1234567890 here") as string;
	assert.ok(!out.includes("sk_live_FAKEKEY1234567890"), out);
	assert.ok((a.counts.api_key ?? 0) >= 1, JSON.stringify(a.counts));
});

await ok("credential URL password is replaced, user kept", () => {
	const out = fresh().anonymizeValue("postgres://app:hunter2@db.internal:5432/prod") as string;
	assert.ok(!out.includes("hunter2"), out);
	assert.ok(out.startsWith("postgres://app:redacted_"), out);
});

await ok("query-string secret is replaced", () => {
	const out = fresh().anonymizeValue("curl 'https://api.x.io?api_key=abcd1234efgh5678ijkl'") as string;
	assert.ok(!out.includes("abcd1234efgh5678ijkl"), out);
});

await ok("quoted env assignment is replaced", () => {
	const out = fresh().anonymizeValue('DB_PASSWORD="s3cr3tValue99"') as string;
	assert.ok(!out.includes("s3cr3tValue99"), out);
});

await ok("bare env assignment is replaced", () => {
	const out = fresh().anonymizeValue("API_KEY=abcd1234efgh5678ijkl") as string;
	assert.ok(!out.includes("abcd1234efgh5678ijkl"), out);
});

await ok("bearer token is replaced, prefix kept", () => {
	const token =
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
	const a = fresh();
	const out = a.anonymizeValue(`Authorization: Bearer ${token}`) as string;
	assert.ok(!out.includes(token), out);
	assert.ok(out.startsWith("Authorization: Bearer redacted_"), out);
	assert.ok((a.counts.jwt ?? 0) >= 1, JSON.stringify(a.counts));
});

await ok("PEM private key block is replaced entirely", () => {
	const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA1234\n-----END RSA PRIVATE KEY-----";
	const a = fresh();
	const out = a.anonymizeValue(pem) as string;
	assert.ok(!out.includes("MIIEowIBAAKCAQEA1234"), out);
	assert.ok(!out.includes("BEGIN RSA PRIVATE KEY"), out);
	assert.ok((a.counts.private_key ?? 0) >= 1, JSON.stringify(a.counts));
});

group("anonymize: high-confidence PII and structured data");

await ok("SSN, phone and IP are replaced (CONSERVATIVE mode)", () => {
	const a = fresh();
	const out = a.anonymizeValue("ssn 123-45-6789 phone 555-123-4567 ip 10.1.2.3") as string;
	assert.ok(!out.includes("123-45-6789"), out);
	assert.ok(!out.includes("555-123-4567"), out);
	assert.ok(!out.includes("10.1.2.3"), out);
	assert.ok((a.counts.pii ?? 0) >= 3, JSON.stringify(a.counts));
});

await ok("home paths have the local username mapped, path kept", () => {
	const out = fresh().anonymizeValue("/Users/alice/projects/app") as string;
	assert.match(out, /^\/Users\/user_[0-9a-f]{8}\/projects\/app$/);
});

await ok("structured mapping traversal anonymizes values and keys", () => {
	const out = fresh().anonymizeValue({
		cwd: "/Users/alice/p",
		note: "mail alice@northwind-labs.io",
	}) as Record<string, string>;
	assert.ok(!JSON.stringify(out).includes("alice@northwind-labs.io"), JSON.stringify(out));
	assert.match(out["cwd"] ?? "", /user_[0-9a-f]{8}/);
});

await ok("assistant content blocks are anonymized too", () => {
	const out = fresh().anonymizeValue({
		role: "assistant",
		content: [{ type: "text", text: "mail bob@foo.io" }],
	}) as { content: Array<{ text: string }> };
	const text = out.content[0]?.text ?? "";
	assert.ok(!text.includes("bob@foo.io"), text);
});

await ok("same input maps to the same placeholder; different inputs differ", () => {
	const out = fresh().anonymizeValue("a@x.io a@x.io b@x.io") as string;
	const [first, second, third] = out.split(" ");
	assert.equal(first, second);
	assert.notEqual(first, third);
});

await ok("base64 media payloads are replaced when used standalone (camelCase keys)", () => {
	const a = fresh();
	const out = a.anonymizeValue({
		type: "image",
		data: `iVBORw0KGgo${"A".repeat(400)}`,
		mimeType: "image/png",
	}) as Record<string, string>;
	const input = `iVBORw0KGgo${"A".repeat(400)}`;
	assert.notEqual(out["data"], input, "payload must be replaced");
	assert.ok((out["data"] ?? "").length < 512, "placeholder must be small");
	assert.equal(out["mimeType"], "image/png");
	assert.equal(a.counts.media, 1);
});

await ok("no email from a mixed sentence survives", () => {
	const out = fresh().anonymizeValue("alice@a.io and bob@b.co and carol@c.dev in one line") as string;
	for (const email of ["alice@a.io", "bob@b.co", "carol@c.dev"]) {
		assert.ok(!out.includes(email), out);
	}
	const leftover = out.replace(/redacted-user_[0-9a-f]{8}@example\.com/g, "");
	assert.ok(!EMAIL_SHAPE.test(leftover), leftover);
});

summary("anonymize-smoke");
