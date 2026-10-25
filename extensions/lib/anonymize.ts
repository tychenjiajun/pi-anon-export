// Privacy-preserving anonymization for exported AI session records.
//
// SPDX-License-Identifier: Apache-2.0
// Copyright the TeichAI/teich authors. This file is a MODIFIED port of
// TeichAI/teich src/teich/anonymize.py (Apache-2.0); it was translated to
// TypeScript and adapted for pi session JSONL. The full license text is in
// LICENSE-APACHE at the repository root, and every deviation from the
// original is listed below (Apache-2.0 §4(b): changes are stated here).
//
// 移植自 TeichAI/teich src/teich/anonymize.py（Apache-2.0），保留其防误报守卫。
// Ported from the Apache-2.0 `TraceAnonymizer` class; every regex and
// false-positive guard below mirrors the Python source one-for-one unless a
// deviation is documented at the constant. Pure local text processing — no
// network, no third-party dependencies (only `node:crypto`).
//
// Deviations from the Python source (deliberate, see task notes):
// - `_map_username` uses `user_<hash8>` (sha256 hex prefix) instead of the
//   sequential `user<N>` counter so mappings are reproducible across runs.
// - The source joins a Python *set* in `_normalize_secret_name`, which makes
//   exact-name membership checks depend on per-process hash ordering; here
//   sensitive-name membership uses a deterministic sorted join (applied to
//   both the lookup table and the queried name), while `connection_string`
//   substring checks use the ordered snake-case name.
// - The source counts everything under `api_key`; this port splits the counts
//   into `api_key` / `credential` / `jwt` / `private_key` for reporting.
// - The source's size guard is gone: every string gets every pass. A guard
//   that skips the email/PII passes for large tool output leaks them, and any
//   chunked emulation of it can cut a match in half at a seam. Cost is bounded
//   by making the email guards linear per match (see `SegmentLocator`), so a
//   megabyte of addresses no longer takes seconds.
// - The source always disables its aggressive name/address PII patterns; this
//   port makes that a per-instance option (`aggressivePii`), surfaced as
//   `/anon-export --pii aggressive`.
// - Guards the source gets wrong, fixed here (each documented at its pattern):
//   credential-URL passwords may contain `/`, `#`, `?` and `@`; a single-word
//   `token` field is redacted when its value looks like a credential; quoted
//   bearer tokens and escaped JSON-in-JSON assignments are recognised; PEM
//   blocks may be PGP blocks or truncated (no END line); `==`/`===`/`=>` are
//   never treated as assignments; our own `user_<hash8>` placeholders are not
//   re-hashed on a second pass.
// - EMAIL_PATTERN: the source's trailing lookahead `(?![A-Za-z0-9._%+-])`
//   rejects an email directly followed by a sentence-ending period ("ping
//   bob@foo.io."), a common real-world miss (also present in the Python
//   source). Here a trailing `.` only blocks the match when it continues into
//   another label.
// - Code-host URL usernames (github.com/<user>/repo …) are rewritten ONLY
//   when the username is already in this instance's usernameMap (seen in a
//   home path or as an email local part); the source does not handle this
//   surface at all. The pattern also accepts scheme-less / scp-like forms
//   (`git:github.com/u/r`, `git@github.com:u/r`, host without trailing `/`).
// - Escape-sequence awareness in the email guards: session JSONL strings
//   routinely contain literal `\"`, `\n`, `\t` sequences. The source's
//   blanket "preceded/followed by backslash ⇒ path, skip" rules and its
//   segment computation therefore mis-classify `email\"`, `Chen\nemail@…`
//   as paths and leak them. A backslash adjacent to a quote/newline/tab is
//   treated as an escape (not a path); backslash-separated real paths and
//   `C:\` drives still skip. Additionally, a match preceded by a backslash
//   is retried shifted past it: if the remainder is still a full email it is
//   redacted (escape char preserved). Trade-off: contrived strings like
//   `dir\name@foo.com` get over-redacted to `dir\n` + placeholder — we accept
//   false positives to guarantee no email-shaped text leaks.
// - `isRedactedSecretValue` also recognises OUR markers (`[REDACTED_<NAME>]`,
//   case-insensitive). Without this, a known literal secret that was already
//   replaced inside a credential URL was re-redacted into an opaque
//   `redacted_secret_…` value, losing the "which secret was here" information.
//   The guard only ever prevents double-redaction of an already-redacted value.

import { createHash } from "node:crypto";

/** Export contract consumed by the rest of the package. */
export interface Anonymizer {
	/** Rewrite one value. Stateful: the same input maps to the same output within this instance. */
	anonymizeValue(value: unknown): unknown;
	/** Counts of rewritten values, keyed by category (e.g. "email"). */
	readonly counts: Record<string, number>;
}

export interface AnonymizerOptions {
	/**
	 * Enable the source's aggressive personal-name and street-address patterns
	 * (SSN / phone / IP are always active). Over-redacts code and prose, so it
	 * is off by default: `/anon-export --pii aggressive` turns it on.
	 */
	aggressivePii?: boolean;
}

// ---------------------------------------------------------------------------
// Deterministic fake-value generation (sha256-based, mirrors _dummy_sequence).
// ---------------------------------------------------------------------------

const DUMMY_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

function sha256(data: Buffer): Buffer {
	return createHash("sha256").update(data).digest();
}

/** Port of TraceAnonymizer._dummy_sequence: chained sha256 blocks mapped onto [a-zA-Z0-9]. */
function dummySequence(seed: string, length: number): string {
	const digest = sha256(Buffer.from(seed, "utf8"));
	const chars: string[] = [];
	let counter = 0;
	while (chars.length < length) {
		const counterBuf = Buffer.alloc(4);
		counterBuf.writeUInt32BE(counter >>> 0, 0);
		const block = sha256(Buffer.concat([digest, counterBuf]));
		for (const byte of block) {
			chars.push(DUMMY_ALPHABET.charAt(byte % DUMMY_ALPHABET.length));
		}
		counter += 1;
	}
	return chars.slice(0, length).join("");
}

/** sha256 hex digest prefix — used for the `user_<hash8>` username mapping. */
function hashHexPrefix(seed: string, length: number): string {
	return createHash("sha256").update(seed, "utf8").digest("hex").slice(0, length);
}

// ---------------------------------------------------------------------------
// RegExp helpers. Every pattern below carries the `g` flag so it can be used
// with both String.replace and the reset-based fullMatch/findMatch helpers.
// ---------------------------------------------------------------------------

function fullMatch(pattern: RegExp, value: string): boolean {
	pattern.lastIndex = 0;
	const match = pattern.exec(value);
	return match !== null && match[0].length === value.length;
}

function findMatch(pattern: RegExp, value: string): RegExpExecArray | null {
	pattern.lastIndex = 0;
	return pattern.exec(value);
}

function stripBothQuotes(value: string): string {
	return value.trim().replace(/^["']+|["']+$/g, "");
}

function startsWithAny(value: string, prefixes: readonly string[]): boolean {
	return prefixes.some((prefix) => value.startsWith(prefix));
}

function endsWithAny(value: string, suffixes: readonly string[]): boolean {
	return suffixes.some((suffix) => value.endsWith(suffix));
}

function hasAnyIntersection(words: ReadonlySet<string>, other: ReadonlySet<string>): boolean {
	for (const word of words) {
		if (other.has(word)) {
			return true;
		}
	}
	return false;
}

interface NamedGroups {
	readonly [name: string]: string | undefined;
}

function groupsOf(args: readonly unknown[]): NamedGroups {
	return (args[args.length - 1] ?? {}) as NamedGroups;
}

// ---------------------------------------------------------------------------
// Text-segment boundaries used by the URI-userinfo and path/package guards
// (Python `" \t\r\n\"'<>"`).
// ---------------------------------------------------------------------------

const SEGMENT_BOUNDARY_CLASS = "[ \\t\\r\\n\"'<>]";

/**
 * Locate the "segment" (the run between whitespace and quoting/bracketing
 * characters) that contains an offset, for offsets visited in ASCENDING order
 * — which is exactly how `String.replace` walks email matches.
 *
 * Deviation from the source: the Python guards call `lastIndexOf` eight times
 * per candidate (and scan the segment end eight more times), which is O(text)
 * per address. On ordinary tool output (a git log, a mail log, minified JSON)
 * that means ~18 s for 1 MiB and quadratic growth. A forward-only cursor makes
 * the whole email pass linear, and it is what lets every string be scanned
 * instead of skipping large ones.
 */
/** How much of a segment a guard needs to look at on each side of an address. */
const URI_PREFIX_WINDOW = 2048;
const SEGMENT_WINDOW = 512;

class SegmentLocator {
	private readonly text: string;
	private readonly boundary = new RegExp(SEGMENT_BOUNDARY_CLASS, "g");
	private start = 0;
	private end = -1;

	constructor(text: string) {
		this.text = text;
	}

	/**
	 * [start, end) of the segment containing `offset`; `end` may be the text
	 * length.
	 *
	 * The cursor only moves forward, so `end` saturates at the text length: an
	 * offset AT or PAST the end used to keep `end <= offset` true forever and
	 * spin, and a non-increasing offset would return a segment that does not
	 * contain it. Both are clamped here instead of handing the caller a hang.
	 */
	containing(offset: number): { start: number; end: number } {
		const target = offset >= this.text.length ? this.text.length - 1 : offset;
		while (this.end <= target && this.end < this.text.length) {
			this.start = this.end + 1;
			this.boundary.lastIndex = this.start;
			const match = this.boundary.exec(this.text);
			this.end = match === null ? this.text.length : match.index;
		}
		return { start: this.start, end: this.end };
	}
}

// ---------------------------------------------------------------------------
// Patterns (1:1 ports of the Python `re.compile` constants).
// ---------------------------------------------------------------------------

// Guarded by _looks_like_non_email_reference before replacing.
// Deviation from source: the trailing lookahead in the Python pattern
// `(?![A-Za-z0-9._%+-])` also rejects emails directly followed by a
// sentence-ending period ("ping bob@foo.io."), a common real-world miss
// present in the source too. We only reject a trailing `.` when it continues
// into another label.
// Deviation from source: `_` is allowed in the domain, because internal hosts
// (`bob@my_corp.com`) are real addresses and the source skipped them entirely.
// The local part is bounded to RFC 5321's 64 characters and the domain to 253:
// the unbounded class included `,`, so in comma-separated dense text the greedy
// run scanned to the end of the string and backtracked once per address —
// quadratic on a CSV of email addresses (1 MiB took ~4 s).
const EMAIL_BODY =
	"(?<![A-Za-z0-9._%+-])([A-Za-z0-9][A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{0,63}@[A-Za-z0-9._-]{1,253}\\.[A-Za-z]{2,24})(?!(?:\\.[A-Za-z0-9])|[A-Za-z0-9_%+-])";
const EMAIL_PATTERN = new RegExp(EMAIL_BODY, "g");
/** Fully-anchored copy used by the escape-shifted retry in replaceEmails. */
const EMAIL_FULL_TEST = new RegExp(`^(?:${EMAIL_BODY})$`);

const HOME_PATH_PATTERN =
	/(?<prefix>(?:[A-Za-z]:)?[\\/]+(?:home|Users)[\\/]+)(?<username>[^\\/:\s"'<>|]+)/gi;

// `name name` followed by a numeric size: an ls-style owner/group pair.
const OWNER_GROUP_PATTERN = /(?<!\S)([A-Za-z0-9._-]{3,})[ \t]+\1(?=[ \t]+\d)/gi;

const ENCODED_HOME_PATH_PATTERN =
	/(?:(?<![A-Za-z0-9])|(?<=\\n))(?<prefix>-(?:home|Users)-)(?<username>[A-Za-z0-9._]+)(?=$|[-\\/\s"'])/gi;

// Deviation from source (documented in file header): usernames embedded in
// code-host repository URLs (github.com/<user>/repo). The source only maps
// home-directory usernames; a GitHub URL path user is an equally direct
// identity. We ONLY touch usernames already present in the instance's
// usernameMap (i.e. previously seen in a home path or as an email local
// part), so arbitrary org/repo names are never rewritten.
const CODE_HOST_USERNAME_PATTERN =
	/(?<host>(?:\b[A-Za-z0-9._-]+@)?(?:https?:\/\/|git:|ssh:\/\/)?(?:www\.|gist\.)?(?:github\.com|gitlab\.com|bitbucket\.org|gitee\.com|codeberg\.org)[/:])(?<username>[A-Za-z0-9][A-Za-z0-9-]{0,38})(?=[\/\s"'`)\]>\]}]|$)/gi;

// Deviation from source: also matches `… PRIVATE KEY BLOCK` (PGP) and a
// TRUNCATED block with no END line (tool output cut mid-key), which would
// otherwise ship the key material verbatim.
// The truncated alternative only consumes a base64-ish body (>=16 chars per
// line), so prose that merely MENTIONS a header (`The header -----BEGIN
// PRIVATE KEY----- goes first…`) is not turned into a 37-byte write-off.
const PRIVATE_KEY_BLOCK_PATTERN =
	/-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----(?:[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|(?:\r?\n[ \t]*[A-Za-z0-9+/=]{16,}[ \t]*)+\r?\n?)/g;

// Each entry pairs the source's literal substring gates with its pattern so the
// expensive lookbehind regexes only run on text that could possibly match.
// Order mirrors the Python `_api_key_patterns` / `_api_key_gates` tuples.
const API_KEY_ENTRIES: readonly { readonly pattern: RegExp; readonly gates: readonly string[] }[] = [
	{ pattern: /(?:(?<![A-Za-z0-9])|(?<=\\n))(?<prefix>sk-or-v1-)(?<body>[A-Za-z0-9_-]{16,})/g, gates: ["sk-or-v1-"] },
	{ pattern: /(?:(?<![A-Za-z0-9])|(?<=\\n))(?<prefix>sk-ant-api03-)(?<body>[A-Za-z0-9_-]{16,})/g, gates: ["sk-ant-api03-"] },
	{ pattern: /(?:(?<![A-Za-z0-9])|(?<=\\n))(?<prefix>sk-proj-)(?<body>[A-Za-z0-9_-]{16,})/g, gates: ["sk-proj-"] },
	{ pattern: /(?:(?<![A-Za-z0-9])|(?<=\\n))(?<prefix>sk-)(?!or-v1-|ant-api03-|proj-)(?<body>[A-Za-z0-9_-]{20,})/g, gates: ["sk-"] },
	{ pattern: /(?:(?<![A-Za-z0-9])|(?<=\\n))(?<prefix>hf_)(?<body>[A-Za-z0-9]{20,})/g, gates: ["hf_"] },
	{ pattern: /(?:(?<![A-Za-z0-9])|(?<=\\n))(?<prefix>gsk_)(?<body>[A-Za-z0-9]{20,})/g, gates: ["gsk_"] },
	{ pattern: /(?:(?<![A-Za-z0-9])|(?<=\\n))(?<prefix>github_pat_)(?<body>[A-Za-z0-9_]{20,})/g, gates: ["github_pat_"] },
	{ pattern: /(?:(?<![A-Za-z0-9])|(?<=\\n))(?<prefix>gh[pousr]_)(?<body>[A-Za-z0-9_]{20,})/g, gates: ["ghp_", "gho_", "ghu_", "ghs_", "ghr_"] },
	{ pattern: /(?:(?<![A-Za-z0-9])|(?<=\\n))(?<prefix>glpat-)(?<body>[A-Za-z0-9_-]{20,})/g, gates: ["glpat-"] },
	{ pattern: /(?:(?<![A-Za-z0-9])|(?<=\\n))(?<prefix>lin_api_)(?<body>[A-Za-z0-9]{20,})/g, gates: ["lin_api_"] },
	{ pattern: /(?:(?<![A-Za-z0-9])|(?<=\\n))(?<prefix>npm_)(?<body>[A-Za-z0-9]{20,})/g, gates: ["npm_"] },
	{ pattern: /(?:(?<![A-Za-z0-9])|(?<=\\n))(?<prefix>pypi-)(?<body>[A-Za-z0-9_-]{20,})/g, gates: ["pypi-"] },
	{ pattern: /(?:(?<![A-Za-z0-9])|(?<=\\n))(?<prefix>sk_(?:live|test)_)(?<body>[A-Za-z0-9]{16,})/g, gates: ["sk_live_", "sk_test_"] },
	{ pattern: /(?:(?<![A-Za-z0-9])|(?<=\\n))(?<prefix>(?:rk|pk)_(?:live|test)_)(?<body>[A-Za-z0-9]{16,})/g, gates: ["rk_live_", "rk_test_", "pk_live_", "pk_test_"] },
	{ pattern: /(?:(?<![A-Za-z0-9])|(?<=\\n))(?<prefix>whsec_)(?<body>[A-Za-z0-9]{16,})/g, gates: ["whsec_"] },
	{ pattern: /(?:(?<![A-Za-z0-9])|(?<=\\n))(?<prefix>re_)(?<body>[A-Za-z0-9]{20,})/g, gates: ["re_"] },
	{ pattern: /(?:(?<![A-Za-z0-9])|(?<=\\n))(?<prefix>sq0(?:atp|csp)-)(?<body>[A-Za-z0-9_-]{20,})/g, gates: ["sq0atp-", "sq0csp-"] },
	{ pattern: /(?:(?<![A-Za-z0-9])|(?<=\\n))(?<prefix>xox[baprs]-)(?<body>[A-Za-z0-9-]{20,})/g, gates: ["xoxb-", "xoxa-", "xoxp-", "xoxr-", "xoxs-"] },
	{ pattern: /(?:(?<![A-Za-z0-9])|(?<=\\n))(?<prefix>AIza)(?<body>[A-Za-z0-9_-]{20,})/g, gates: ["AIza"] },
	{ pattern: /(?:(?<![A-Za-z0-9])|(?<=\\n))(?<prefix>GOCSPX-)(?<body>[A-Za-z0-9_-]{20,})/g, gates: ["GOCSPX-"] },
	{ pattern: /(?:(?<![A-Za-z0-9])|(?<=\\n))(?<prefix>ctx7sk-)(?<body>[A-Za-z0-9-]{20,})/g, gates: ["ctx7sk-"] },
	{ pattern: /(?:(?<![A-Za-z0-9])|(?<=\\n))(?<prefix>(?:AKIA|ASIA))(?<body>[A-Z0-9]{16})(?![A-Za-z0-9])/g, gates: ["AKIA", "ASIA"] },
	{ pattern: /(?:(?<![A-Za-z0-9])|(?<=\\n))(?<prefix>SK)(?<body>[0-9a-fA-F]{32})(?![A-Za-z0-9])/g, gates: ["SK"] },
	{ pattern: /(?:(?<![A-Za-z0-9])|(?<=\\n))(?<prefix>SG\.)(?<body>[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{20,})/g, gates: ["SG."] },
];

// JWT (three segments) and JWE (five segments). Lookbehinds ported verbatim;
// `(?<=\\n)` matches a literal backslash-n as seen inside JSONL payloads.
const JWE_PATTERN =
	/(?:(?<![A-Za-z0-9_-])|(?<=\\n))([A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})(?![A-Za-z0-9_-])/g;

const JWT_PATTERN =
	/(?:(?<![A-Za-z0-9_-])|(?<=\\n))([A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})(?![A-Za-z0-9_-])/g;

// Deviation from source: an optional matching quote is allowed, because
// `Authorization: Bearer "…"` (docs, curl snippets) was skipped entirely.
const BEARER_PATTERN =
	/(?<prefix>\bBearer\s+)(?<quote>["']?)(?<token>[A-Za-z0-9._~+/=-]{24,})\k<quote>/gi;

// Deviation from source: the password class also allows `@` (generated
// passwords contain it), and a greedy match resolved up to the last `@` of the
// run means `postgres://u:p@ss@host` redacts the whole password. `/`, `?` and
// `#` stay OUT of the class: they end the URL authority, so allowing them made
// `https://api.example.com:8443/v1/users?email=bob@corp.io` (a URL with no
// credentials at all) look like `user:password@host` and destroyed it.
const CREDENTIAL_URL_PATTERN =
	/\b(?<scheme>[A-Za-z][A-Za-z0-9+.-]{1,32}:\/\/)(?<user>[^:@/\s?#]*):(?<password>[^/\s?#]+)@/g;

// Second tier for the common "password pasted into a URL without escaping"
// case (`postgres://app:pa/ss#x@db/prod`). Limited to schemes that are always
// credential URLs, so `https://host:8080/path?x=a@b` can never be mistaken for
// credentials; here the password may contain `/`, `#` and `?` too.
const BROKEN_CREDENTIAL_URL_PATTERN =
	/\b(?<scheme>(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp|amqps|mssql|smtp|imap|ftp|ldap):\/\/)(?<user>[^:@/\s?#]*):(?<password>[^\s]+)@/gi;

// Escaped JSON-in-JSON (`{\"password\":\"hunter2short\"}`) and escaped
// `NAME\=\"value\"` assignments: a session string that itself contains JSONL
// (a transcript read as a tool result, a diff) is double-encoded, and the plain
// assignment patterns cannot see across the backslashes.
const ESCAPED_JSON_ASSIGNMENT_PATTERN =
	/(?<prefix>\\?"(?<name>[A-Za-z][A-Za-z0-9_.-]{1,120})\\?"[ \t]*:[ \t]*\\?")(?<value>(?:\\.|[^"\\\r\n])*)(?<suffix>\\?")/g;

const ESCAPED_EQUALS_ASSIGNMENT_PATTERN =
	/(?<prefix>(?<![A-Za-z0-9_.-])(?<name>[A-Za-z][A-Za-z0-9_.-]{1,120})[ \t]*\\?=[ \t]*\\?")(?<value>[^"\\\r\n]*)(?<suffix>\\?")/g;

const QUERY_SECRET_PATTERN =
	/(?<prefix>[?&](?<name>[A-Za-z0-9_.-]*(?:api[_-]?key|token|secret|password|signature|sig|access[_-]?key|client[_-]?secret)[A-Za-z0-9_.-]*)=)(?<value>[^&#\s"'<>]+)/g;

// Deviation from source: `=` followed by `=`/`<`/`>` is a comparison/arrow,
// not an assignment (`password==secret` used to be rewritten as
// `password=redacted_…`).
const CONNECTION_COMPONENT_SECRET_PATTERN =
	/(?<prefix>(?:^|[;,\s])(?<name>AccountKey|SharedAccessKey|SharedAccessSignature|Signature|Password|Pwd|AccessKeyId|SecretAccessKey|sig)=(?![=<>]))(?<value>[^;,\s]+)/gi;

// Separate fixed-quote alternatives keep failure linear (see source comment).
const QUOTED_ASSIGNMENT_PATTERNS: readonly RegExp[] = [
	/(?<prefix>(?<![A-Za-z0-9_.-])(?<key_quote>["']?)(?<name>[A-Za-z][A-Za-z0-9_.-]{1,120})\k<key_quote>[ \t]*(?:=|:)[ \t]*)(?<quote>")(?<value>(?:\\.|[^"\\\r\n])*)"/g,
	/(?<prefix>(?<![A-Za-z0-9_.-])(?<key_quote>["']?)(?<name>[A-Za-z][A-Za-z0-9_.-]{1,120})\k<key_quote>[ \t]*(?:=|:)[ \t]*)(?<quote>')(?<value>(?:\\.|[^'\\\r\n])*)'/g,
];

// Deviation from source: `=` followed by `=` or `>` is a comparison/arrow, not
// an assignment (`if password == "x"` used to be rewritten into
// `if password =redacted_… "x"`, destroying code and keeping the literal), and
// an unquoted value keeps its `#` (`DB_PASSWORD=pa#ss123` is one word in a
// shell; stopping at `#` shipped the trailer in plaintext).
const BARE_ASSIGNMENT_PATTERN =
	/(?<prefix>(?<![A-Za-z0-9_.-])(?<key_quote>["']?)(?<name>[A-Za-z][A-Za-z0-9_.-]{1,120})\k<key_quote>[ \t]*(?<op>=(?![=>])|:)[ \t]*)(?<value>[^"'\s]+)/g;

// The explicit identifier-character lookbehind is load-bearing: unlike a word
// boundary it cannot restart the match after every '-' in a UUID/tool-call run.
const GENERIC_SECRET_PATTERN =
	/(?<prefix>(?<![A-Za-z0-9_-])(?<name>[A-Za-z0-9][A-Za-z0-9_-]*)\b\\?["']?[^\S\r\n]*[:=][^\S\r\n]*\\?["']?)(?<value>[A-Za-z0-9_~+/=-]{24,})/gi;

// High-confidence PII.
const SSN_PATTERN = /(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)/g;

const PHONE_PATTERN =
	/(?<prefix>\b(?:phone|telephone|tel|call(?:\s+me)?\s+at)\s*[:=]?\s*)(?<value>(?:\+?1[\s.-]?)?(?:(?:\(\d{3}\)|\d{3})[\s.-]?)\d{3}[\s.-]?\d{4})/gi;

const IP_PATTERN =
	/(?<prefix>\b(?:ip|ip\s+address|host\s+address)\s*[:=]?\s*)(?<value>(?:\d{1,3}\.){3}\d{1,3})/gi;

// Aggressive patterns from the source; gated behind CONSERVATIVE === false.
// The Python source scopes `(?i)` to the prefix only, so the per-character case
// alternation below keeps the value case-sensitive (capitalized names).
const NAME_PATTERN =
	/(?<prefix>\b(?:[mM]y\s+[nN]ame\s+[iI]s|[fF]ull\s+[nN]ame\s*[:=]|[nN]ame\s*[:=])\s*)(?<value>[A-Z][A-Za-z'-]+(?:\s+[A-Z][A-Za-z'-]+){1,3})/g;

const ADDRESS_PATTERN =
	/(?<prefix>\b(?:address\s*[:=]|i\s+live\s+at)\s*)(?<value>\d{1,6}\s+[A-Za-z0-9][A-Za-z0-9 .'-]{1,80}(?:street|st|road|rd|avenue|ave|boulevard|blvd|lane|ln|drive|dr|court|ct|way)\b(?:,\s*[A-Za-z .'-]{2,40})?(?:,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?)?)/gi;

const PLACEHOLDER_SECRET_PATTERN =
	/^(?:<[^<>\r\n]{1,120}>|\$\{?[A-Z_][A-Z0-9_]*\}?|\{\{[^{}\r\n]{1,120}\}\}|(?:process\.env|os\.environ|getenv|env)\b.*|(?:your|insert|replace|example|sample|dummy|fake|test)[-_ .]*(?:api[-_ ]*)?(?:key|token|secret|password).*)$/is;

const PUBLIC_IDENTIFIER_PATTERNS: readonly RegExp[] = [
	/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/gi,
	/^(?:sha(?:1|224|256|384|512):)?[0-9a-f]{7,128}$/gi,
	/^(?:call|chatcmpl|cmpl|event|msg|req|request|resp|run|session|step|task|tool|toolu|trace)[_-][A-Za-z0-9_-]{8,}$/gi,
];

const SECRET_VALUE_CHARSET_PATTERN = /^[A-Za-z0-9_~+/=-]+$/g;

const BASE64_BLOB_PATTERN = /^[A-Za-z0-9+/=\s]+$/g;

// ---------------------------------------------------------------------------
// Reference data sets (ported verbatim from the Python class attributes).
// ---------------------------------------------------------------------------

/** Decoder-valid 1x1 placeholders; unsupported subtypes fall back per family. */
const MEDIA_PLACEHOLDER_BASE64: Readonly<Record<string, string>> = {
	"image/png": "iVBORw0KGgoAAAANSUhEUgAAAAIAAAACCAIAAAD91JpzAAAACXBIWXMAAAABAAAAAQBPJcTWAAAAC0lEQVR4nGNgQAYAAA4AAamRc7EAAAAASUVORK5CYII=",
	"image/jpeg": "/9j/4AAQSkZJRgABAgAAAQABAAD//gAQTGF2YzYxLjE5LjEwMQD/2wBDAAgEBAQEBAUFBQUFBQYGBgYGBgYGBgYGBgYHBwcICAgHBwcGBgcHCAgICAkJCQgICAgJCQoKCgwMCwsODg4RERT/xABLAAEBAAAAAAAAAAAAAAAAAAAACAEBAAAAAAAAAAAAAAAAAAAAABABAAAAAAAAAAAAAAAAAAAAABEBAAAAAAAAAAAAAAAAAAAAAP/AABEIAAIAAgMBIgACEQADEQD/2gAMAwEAAhEDEQA/AJ/AB//Z",
	"image/gif": "R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==",
	"image/webp": "UklGRiQAAABXRUJQVlA4IBgAAAAwAQCdASoCAAIAAgA0JaQAA3AA/vv9UAA=",
	"audio/wav": "UklGRpYAAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgATElTVBoAAABJTkZPSVNGVA0AAABMYXZmNjEuNy4xMDAAAGRhdGFQAAAAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIA=",
	"video/webm": "GkXfo59ChoEBQveBAULygQRC84EIQoKEd2VibUKHgQJChYECGFOAZwEAAAAAAAIFEU2bdLpNu4tTq4QVSalmU6yBoU27i1OrhBZUrmtTrIHWTbuMU6uEElTDZ1OsggEjTbuMU6uEHFO7a1OsggHv7AEAAAAAAABZAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVSalmsCrXsYMPQkBNgIxMYXZmNjEuNy4xMDBXQYxMYXZmNjEuNy4xMDBEiYhARAAAAAAAABZUrmvIrgEAAAAAAAA/14EBc8WIEWEZBnl2+u6cgQAitZyDdW5kiIEAhoVWX1ZQOYOBASPjg4QCYloA4JCwgRC6gRCagQJVsIRVuYEBElTDZ0B/c3OfY8CAZ8iZRaOHRU5DT0RFUkSHjExhdmY2MS43LjEwMHNz2mPAi2PFiBFhGQZ5dvruZ8ilRaOHRU5DT0RFUkSHmExhdmM2MS4xOS4xMDEgbGlidnB4LXZwOWfIoUWjiERVUkFUSU9ORIeTMDA6MDA6MDAuMDQwMDAwMDAwAB9DtnXC54EAo72BAACAgkmDQgAA8AD2BjgkHBhKAAAgQAAim///lXb23/SskhXr7zdPyoCRyEjNuPymkNJQgETBR424BAAAHFO7a5G7j7OBALeK94EB8YIBqPCBAw==",
};

const NON_PERSON_USERNAMES: ReadonlySet<string> = new Set([
	"all users",
	"default",
	"defaultuser0",
	"public",
	"shared",
]);

/** Our own home-path placeholders must not be hashed again on a second pass. */
const OWN_USERNAME_PLACEHOLDER_RE = /^user_[0-9a-f]{8}$/;

/**
 * True for directory names that are not a personal identity: system accounts
 * and placeholders this anonymizer already produced (`/Users/user_2bd806c9/x`
 * is a fixed point, as the contract promises).
 */
function isNonPersonUsername(username: string): boolean {
	const lowered = username.toLowerCase();
	return NON_PERSON_USERNAMES.has(lowered) || OWN_USERNAME_PLACEHOLDER_RE.test(lowered);
}

const SYSTEMD_UNIT_SUFFIXES: readonly string[] = [
	".automount",
	".device",
	".mount",
	".path",
	".scope",
	".service",
	".slice",
	".socket",
	".swap",
	".target",
	".timer",
];

const KNOWN_GIT_REMOTE_ADDRESSES: ReadonlySet<string> = new Set([
	"git@github.com",
	"git@ssh.github.com",
	"git@gitlab.com",
	"git@bitbucket.org",
]);

const NON_EMAIL_TLDS: ReadonlySet<string> = new Set([
	"automount",
	"device",
	"local",
	"localhost",
	"module",
	"mount",
	"path",
	"scope",
	"service",
	"slice",
	"socket",
	"swap",
	"target",
	"test",
	"timer",
]);

const RESERVED_EMAIL_DOMAINS: ReadonlySet<string> = new Set([
	"example.com",
	"example.net",
	"example.org",
]);

const KNOWN_PUBLIC_EMAIL_ADDRESSES: ReadonlySet<string> = new Set([
	"noreply@anthropic.com",
	"noreply@github.com",
]);

const PLACEHOLDER_SECRET_VALUES: ReadonlySet<string> = new Set([
	"api-key-here",
	"apikeyhere",
	"change-me",
	"changeme",
	"dummy",
	"example",
	"example-key",
	"fake",
	"insert-key-here",
	"placeholder",
	"replace-me",
	"replaceme",
	"sample",
	"test",
	"your-api-key",
	"your_api_key",
	"your-key-here",
	"your-secret-here",
	"your-token-here",
]);

/** Cheap substring gates; assignment/generic-secret scans are skipped without these. */
const SENSITIVE_GATE_WORDS: readonly string[] = [
	"pass",
	"pwd",
	"secret",
	"credential",
	"private",
	"token",
	"sig",
	"jwt",
	"key",
	"url",
	"uri",
	"dsn",
	"connection",
];

const STRUCTURED_PII_KEYS: ReadonlySet<string> = new Set([
	"address",
	"first_name",
	"full_name",
	"home_address",
	"ip_address",
	"last_name",
	"mobile",
	"phone",
	"phone_number",
	"social_security_number",
	"ssn",
	"street_address",
	"telephone",
]);

const SENSITIVE_EXACT_NAMES: ReadonlySet<string> = new Set([
	"access_token",
	"admin_password",
	"anon_key",
	"api_key",
	"apikey",
	"app_secret",
	"auth_secret",
	"auth_token",
	"aws_secret_access_key",
	"azure_storage_connection_string",
	"broker_url",
	"celery_broker_url",
	"client_secret",
	"connection_string",
	"cookie_secret",
	"dashboard_password",
	"database_dsn",
	"database_url",
	"db_password",
	"db_url",
	"direct_url",
	"django_secret_key",
	"dsn",
	"enc_key",
	"encryption_key",
	"firebase_private_key",
	"jwt_secret",
	"mail_password",
	"mail_url",
	"mongo_uri",
	"mongo_url",
	"mongodb_uri",
	"mongodb_url",
	"mysql_password",
	"mysql_url",
	"nextauth_secret",
	"password",
	"pgpassword",
	"postgres_password",
	"postgres_url",
	"postgresql_url",
	"private_key",
	"rabbitmq_url",
	"redis_password",
	"redis_url",
	"refresh_token",
	"root_password",
	"secret",
	"secret_key",
	"secret_key_base",
	"sentry_dsn",
	"service_role_key",
	"session_secret",
	"signing_secret",
	"smtp_password",
	"smtp_url",
	"ssh_private_key",
	"supabase_anon_key",
	"supabase_service_role_key",
	"vault_enc_key",
	"webhook_secret",
]);

// Retained from the source for reference fidelity (the Python class defines it
// but never reads it either).
const SENSITIVE_NAME_WORDS: ReadonlySet<string> = new Set([
	"auth",
	"bearer",
	"credential",
	"credentials",
	"jwt",
	"pass",
	"passwd",
	"password",
	"private",
	"pwd",
	"secret",
	"signature",
	"token",
]);

const SENSITIVE_KEY_CONTEXT_WORDS: ReadonlySet<string> = new Set([
	"access",
	"account",
	"admin",
	"anon",
	"api",
	"app",
	"auth",
	"aws",
	"azure",
	"client",
	"csrf",
	"dashboard",
	"enc",
	"encryption",
	"firebase",
	"google",
	"master",
	"private",
	"publishable",
	"root",
	"role",
	"secret",
	"service",
	"session",
	"signing",
	"supabase",
	"vault",
]);

const SENSITIVE_URL_CONTEXT_WORDS: ReadonlySet<string> = new Set([
	"amqp",
	"broker",
	"celery",
	"database",
	"db",
	"direct",
	"dsn",
	"mail",
	"mariadb",
	"mongo",
	"mongodb",
	"mysql",
	"postgres",
	"postgresql",
	"rabbitmq",
	"redis",
	"sentry",
	"smtp",
]);

const NON_SECRET_NAME_WORDS: ReadonlySet<string> = new Set([
	"allow",
	"at",
	"cache",
	"changed",
	"contains",
	"control",
	"count",
	"created",
	"dedupe",
	"enable",
	"enabled",
	"env",
	"expiry",
	"expires",
	"fence",
	"fencing",
	"has",
	"id",
	"idempotency",
	"length",
	"limit",
	"max",
	"min",
	"num",
	"number",
	"placeholder",
	"policy",
	"publickey",
	"require",
	"required",
	"supports",
	"tokenizer",
	"tokens",
	"ttl",
	"updated",
	"use",
	"uses",
	"version",
]);

const EMPTY_SECRET_VALUES: ReadonlySet<string> = new Set([
	"",
	"false",
	"nil",
	"none",
	"null",
	"true",
	"undefined",
]);

const PASSWORD_SECRET_WORDS: ReadonlySet<string> = new Set([
	"password",
	"passwd",
	"pwd",
	"secret",
	"credential",
	"credentials",
]);

const PRIVATE_CONTEXT_WORDS: ReadonlySet<string> = new Set([
	"credential",
	"key",
	"secret",
	"token",
]);

const SIGNATURE_CONTEXT_WORDS: ReadonlySet<string> = new Set([
	"access",
	"auth",
	"key",
	"secret",
	"shared",
	"signing",
	"webhook",
]);

const JWT_CONTEXT_WORDS: ReadonlySet<string> = new Set([
	"secret",
	"token",
	"key",
	"auth",
]);

// ---------------------------------------------------------------------------
// Secret-name normalization helpers.
//
// The Python source joins a *set* of words here, which makes exact-name
// membership depend on per-process hash iteration order. We normalize both the
// table and the queried name with the same sorted join so membership checks
// are deterministic, and keep the ordered snake-case form for the
// `connection_string` substring checks.
// ---------------------------------------------------------------------------

function secretNameWords(name: string): string[] {
	let normalized = name.replace(/([a-z0-9])([A-Z])/g, "$1_$2");
	normalized = normalized.replace(/[^A-Za-z0-9]+/g, "_").replace(/^_+|_+$/g, "").toLowerCase();
	return normalized.split("_").filter((part) => part !== "");
}

function sortedSecretNameKey(name: string): string {
	return [...secretNameWords(name)].sort().join("_");
}

const SENSITIVE_EXACT_NAME_KEYS: ReadonlySet<string> = new Set(
	[...SENSITIVE_EXACT_NAMES].map((name) => sortedSecretNameKey(name)),
);

// ---------------------------------------------------------------------------
// Secret-value guard helpers.
// ---------------------------------------------------------------------------

function isEmptySecretValue(value: string): boolean {
	return EMPTY_SECRET_VALUES.has(stripBothQuotes(value).toLowerCase());
}

function isRedactedSecretValue(value: string): boolean {
	// Deviation: compared case-insensitively so our own `[REDACTED_<NAME>]`
	// markers count as already-redacted (see the header notes).
	const lowered = stripBothQuotes(value).toLowerCase();
	return startsWithAny(lowered, ["redacted_", "<redacted", "[redacted"]);
}

function isPlaceholderSecretValue(value: string): boolean {
	const stripped = stripBothQuotes(value);
	return PLACEHOLDER_SECRET_VALUES.has(stripped.toLowerCase()) || fullMatch(PLACEHOLDER_SECRET_PATTERN, stripped);
}

// ---------------------------------------------------------------------------
// Base64 media detection (ports of _looks_like_base64_* / _redact_base64_media).
//
// Deviation from the Python source: the media-type lookup also accepts the
// camelCase keys pi writes (`mimeType`, `mediaType`). Without this, the ported
// media branch only ever fired for snake_case payloads, i.e. it was silently
// inert for real pi sessions.
//
// NOTE for the export pipeline: `lib/redact.ts` owns the image policy for
// /anon-export (--no-images → `[IMAGE_REMOVED]`, otherwise kept byte-exact).
// It intercepts every long `data`/`base64` string before the anonymizer sees
// it, so this branch never rewrites exported images — it is only reachable
// when the anonymizer is used standalone. Do not "fix" that by removing the
// interception: replacing payloads there would silently discard images the
// user asked to keep.
// ---------------------------------------------------------------------------

/** Media-type/MIME type keys seen in practice (snake_case upstream, camelCase from pi). */
const MEDIA_TYPE_KEYS = ["media_type", "mime_type", "mediaType", "mimeType"] as const;

function declaredMediaType(value: Record<string, unknown>): string | null {
	for (const key of MEDIA_TYPE_KEYS) {
		const candidate = value[key];
		if (typeof candidate === "string" && candidate.length > 0) return candidate;
	}
	return null;
}

function looksLikeBase64MediaSource(value: Record<string, unknown>): boolean {
	const sourceType = value["type"];
	const mediaType = declaredMediaType(value);
	return (
		((typeof sourceType === "string" && sourceType.toLowerCase() === "base64") ||
			(typeof mediaType === "string" &&
				["image/", "audio/", "video/"].some((prefix) => mediaType.toLowerCase().startsWith(prefix)))) &&
		typeof value["data"] === "string"
	);
}

function looksLikeBase64Blob(value: string): boolean {
	if (value.length < 256) {
		return false;
	}
	return fullMatch(BASE64_BLOB_PATTERN, value);
}

// ---------------------------------------------------------------------------
// The anonymizer.
// ---------------------------------------------------------------------------

class TraceAnonymizer implements Anonymizer {
	private readonly aggressivePii: boolean;
	private readonly countsInternal: Record<string, number> = {
		email: 0,
		username: 0,
		api_key: 0,
		credential: 0,
		jwt: 0,
		private_key: 0,
		pii: 0,
		media: 0,
	};
	private readonly emailMap = new Map<string, string>();
	private readonly usernameMap = new Map<string, string>();
	private readonly apiKeyMap = new Map<string, string>();
	private readonly apiReplacements = new Set<string>();

	constructor(aggressivePii: boolean) {
		this.aggressivePii = aggressivePii;
	}

	get counts(): Record<string, number> {
		return this.countsInternal;
	}

	anonymizeValue(value: unknown): unknown {
		if (typeof value === "string") {
			return this.anonymizeText(value);
		}
		if (Array.isArray(value)) {
			return value.map((item) => this.anonymizeValue(item));
		}
		if (value !== null && typeof value === "object") {
			return this.anonymizeMapping(value as Record<string, unknown>);
		}
		return value;
	}

	/** Port of TraceAnonymizer.anonymize_text. Every size gets every pass. */
	anonymizeText(text: string): string {
		const lowered = text.toLowerCase();
		let out = text;
		if (out.includes("@")) {
			out = this.replaceEmails(out);
		}
		out = this.anonymizeIdentityText(out, lowered);
		out = this.replaceApiKeys(out);
		out = this.replaceHighConfidencePii(out);
		return out;
	}

	// -------------------------------------------------------------------------
	// Structured-value traversal (ports of _anonymize_mapping and friends).
	// -------------------------------------------------------------------------

	private anonymizeMapping(value: Record<string, unknown>): Record<string, unknown> {
		const shouldRedactBase64Data = looksLikeBase64MediaSource(value);
		let mediaReplacement: { readonly type: string; readonly data: string } | null = null;
		const mediaData = value["data"];
		if (shouldRedactBase64Data && typeof mediaData === "string" && looksLikeBase64Blob(mediaData)) {
			mediaReplacement = this.redactBase64Media(declaredMediaType(value));
		}
		const role = value["role"];
		const isAssistantMessage = typeof role === "string" && role.toLowerCase() === "assistant";
		const redacted: Record<string, unknown> = {};
		for (const [key, item] of Object.entries(value)) {
			const redactedKey = this.anonymizeValue(key) as string;
			if (mediaReplacement !== null && key === "data") {
				redacted[redactedKey] = mediaReplacement.data;
			} else if (mediaReplacement !== null && (MEDIA_TYPE_KEYS as readonly string[]).includes(key)) {
				redacted[redactedKey] = mediaReplacement.type;
			} else if (isAssistantMessage && (key === "content" || key === "reasoning_content" || key === "thinking")) {
				// Assistant responses can echo credentials and personal data
				// supplied by users or tools — apply the same privacy rules.
				redacted[redactedKey] = this.anonymizeAssistantGeneratedValue(item);
			} else if (typeof item === "string" && isStructuredPiiKey(key)) {
				redacted[redactedKey] = this.redactStructuredPii(item);
			} else if (this.shouldRedactMappingValue(key, item)) {
				redacted[redactedKey] = this.redactMappingValue(key, item);
			} else {
				redacted[redactedKey] = this.anonymizeValue(item);
			}
		}
		if (mediaReplacement !== null && declaredMediaType(value) === null) {
			redacted["media_type"] = mediaReplacement.type;
		}
		return redacted;
	}

	private anonymizeAssistantGeneratedValue(value: unknown): unknown {
		if (typeof value === "string") {
			return this.anonymizeText(value);
		}
		if (Array.isArray(value)) {
			return value.map((item) => this.anonymizeAssistantContentBlock(item));
		}
		if (value !== null && typeof value === "object") {
			return this.anonymizeAssistantContentBlock(value);
		}
		return value;
	}

	private anonymizeAssistantContentBlock(value: unknown): unknown {
		if (value === null || typeof value !== "object" || Array.isArray(value)) {
			return this.anonymizeAssistantGeneratedValue(value);
		}
		const block = value as Record<string, unknown>;
		const blockType = block["type"];
		const allowedBlockTypes = new Set(["analysis", "reasoning", "redacted_thinking", "text", "thinking"]);
		if (typeof blockType !== "string" || !allowedBlockTypes.has(blockType.toLowerCase())) {
			// Tool calls and unknown structured blocks can contain credentials
			// copied from the environment — keep full anonymization there.
			return this.anonymizeValue(block);
		}
		const result: Record<string, unknown> = {};
		for (const [key, item] of Object.entries(block)) {
			result[this.anonymizeValue(key) as string] = this.anonymizeAssistantGeneratedValue(item);
		}
		return result;
	}

	private shouldRedactMappingValue(key: string, item: unknown): boolean {
		if (typeof item === "string") {
			return this.shouldRedactAssignment(key, item);
		}
		if (item === null || typeof item === "boolean") {
			return false;
		}
		if (typeof item === "number") {
			return this.isSensitiveName(key, String(item));
		}
		return false;
	}

	private redactMappingValue(key: string, item: unknown): string {
		return this.assignmentSecretReplacement(key, String(item));
	}

	private redactStructuredPii(value: string): string {
		this.bump("pii");
		return this.piiReplacement(value);
	}

	// -------------------------------------------------------------------------
	// Identity text: home paths, encoded variants, ls-style owner/group pairs.
	// -------------------------------------------------------------------------

	private anonymizeIdentityText(text: string, lowered: string): string {
		let out = text;
		if (lowered.includes("home") || lowered.includes("users")) {
			out = this.replaceUsernamesInPaths(out);
			out = this.replaceEncodedHomeUsernames(out);
		}
		if (this.usernameMap.size > 0) {
			out = this.replaceKnownUnixOwnerGroupUsernames(out);
			out = this.replaceMappedCodeHostUsernames(out);
		}
		return out;
	}

	private replaceMappedCodeHostUsernames(text: string): string {
		return text.replace(CODE_HOST_USERNAME_PATTERN, (...args: unknown[]): string => {
			const match = args[0] as string;
			const groups = groupsOf(args);
			const host = groups["host"] ?? "";
			const username = groups["username"];
			if (username === undefined) return match;
			const mapped = this.usernameMap.get(username.toLowerCase());
			// Only rewrite identities this instance has already classified as personal.
			if (mapped === undefined) return match;
			this.bump("username");
			return `${host}${mapped}`;
		});
	}

	private replaceUsernamesInPaths(text: string): string {
		return text.replace(HOME_PATH_PATTERN, (...args: unknown[]): string => {
			const match = args[0] as string;
			const groups = groupsOf(args);
			const username = groups["username"];
			if (username === undefined || isNonPersonUsername(username)) {
				return match;
			}
			this.bump("username");
			return `${groups["prefix"] ?? ""}${this.mapUsername(username)}`;
		});
	}

	private replaceEncodedHomeUsernames(text: string): string {
		return text.replace(ENCODED_HOME_PATH_PATTERN, (...args: unknown[]): string => {
			const match = args[0] as string;
			const groups = groupsOf(args);
			const username = groups["username"];
			if (username === undefined || isNonPersonUsername(username)) {
				return match;
			}
			this.bump("username");
			return `${groups["prefix"] ?? ""}${this.mapUsername(username)}`;
		});
	}

	/**
	 * `ls -l`-style `owner group` pairs (`alice alice 4096 …`).
	 *
	 * Deviation from source (performance): the source builds one regex per known
	 * username and scans the WHOLE text once per username, so a session with N
	 * names and M bytes costs O(N × M) — 2000 emails in one string made this 77 %
	 * of the runtime (1.7 s for 0.4 MiB). Here the text is scanned ONCE for the
	 * `name name` shape (backreference) and the match is looked up in the map.
	 */
	private replaceKnownUnixOwnerGroupUsernames(text: string): string {
		if (this.usernameMap.size === 0) return text;
		return text.replace(OWNER_GROUP_PATTERN, (match: string, name: string): string => {
			const mapped = this.usernameMap.get(name.toLowerCase());
			if (mapped === undefined) return match;
			this.bump("username", 2);
			return `${mapped} ${mapped}`;
		});
	}

	// -------------------------------------------------------------------------
	// Email replacement with the source's full false-positive guard chain.
	// -------------------------------------------------------------------------

	private replaceEmails(text: string): string {
		const segments = new SegmentLocator(text);
		return text.replace(EMAIL_PATTERN, (_match: string, captured: string, offset: number, whole: string): string => {
			let target = captured;
			let start = offset;
			let prefix = "";
			if (start > 0 && whole[start - 1] === "\\") {
				// Session strings routinely contain literal two-char escapes (JSON
				// inside JSON): `Chen\ntychen@x.com` — the regex starts on the
				// escape char (`n`), and the source's blanket "preceded by
				// backslash ⇒ path" rule then skips the whole match, leaking the
				// real email. Retry shifted past the escape char; if what remains
				// is still a full email, redact it (keeping the escape char).
				const shifted = captured.slice(1);
				if (!EMAIL_FULL_TEST.test(shifted)) {
					// Not an escape+email: keep the source's conservative skip.
					return captured;
				}
				prefix = captured.slice(0, 1);
				target = shifted;
				start += 1;
			}
			if (this.looksLikeNonEmailReference(target, start, start + target.length, whole, segments)) {
				return captured;
			}
			const key = target.toLowerCase();
			let mapped = this.emailMap.get(key);
			if (mapped === undefined) {
				const localPart = target.split("@")[0] ?? "";
				mapped = `redacted-${this.mapUsername(localPart)}@example.com`;
				this.emailMap.set(key, mapped);
			}
			this.bump("email");
			return prefix + mapped;
		});
	}

	private looksLikeNonEmailReference(
		value: string,
		start: number,
		end: number,
		text: string,
		segments: SegmentLocator,
	): boolean {
		if (start > 0 && text[start - 1] === "\\") {
			return true;
		}
		if (value.includes("`")) {
			return true;
		}
		if (value.includes("/") || value.includes("\\")) {
			return true;
		}
		if (this.looksLikeUriUserinfo(start, text, segments)) {
			return true;
		}
		const lowered = value.toLowerCase();
		if (KNOWN_PUBLIC_EMAIL_ADDRESSES.has(lowered)) {
			return true;
		}
		if (endsWithAny(lowered, SYSTEMD_UNIT_SUFFIXES)) {
			return true;
		}
		const domain = lowered.slice(lowered.lastIndexOf("@") + 1);
		const tld = domain.slice(domain.lastIndexOf(".") + 1);
		if (RESERVED_EMAIL_DOMAINS.has(domain) || domain.endsWith(".example")) {
			return true;
		}
		if (NON_EMAIL_TLDS.has(tld)) {
			return true;
		}
		if (KNOWN_GIT_REMOTE_ADDRESSES.has(lowered)) {
			return true;
		}
		if (looksLikePathOrPackageReference(start, end, text, segments)) {
			return true;
		}
		return false;
	}

	private looksLikeUriUserinfo(start: number, text: string, segments: SegmentLocator): boolean {
		// Bounded: a userinfo prefix is short, while the segment can be a whole
		// megabyte of minified JSON (the old unbounded slice made the email pass
		// O(matches × segment) on whitespace-free input).
		const segmentStart = Math.max(segments.containing(start).start, start - URI_PREFIX_WINDOW);
		const prefixSegment = text.slice(segmentStart, start);
		const schemeSeparator = prefixSegment.lastIndexOf("://");
		if (schemeSeparator === -1) {
			return false;
		}
		const scheme = prefixSegment.slice(0, schemeSeparator).split("/").pop() ?? "";
		if (!fullMatch(/^[A-Za-z][A-Za-z0-9+.-]*$/g, scheme)) {
			return false;
		}
		const authorityPrefix = prefixSegment.slice(schemeSeparator + 3);
		return !["/", "\\", "?", "#"].some((separator) => authorityPrefix.includes(separator));
	}

	// -------------------------------------------------------------------------
	// Credential-class replacement pipeline (ports of _replace_api_keys et al.).
	// -------------------------------------------------------------------------

	private replaceApiKeys(text: string): string {
		let out = text;
		if (out.includes("-----BEGIN ")) {
			out = out.replace(PRIVATE_KEY_BLOCK_PATTERN, (match: string): string =>
				this.replacePrivateKeyBlock(match));
		}
		for (const { pattern, gates } of API_KEY_ENTRIES) {
			if (gates.some((gate) => out.includes(gate))) {
				out = out.replace(pattern, (match: string): string => this.replacePrefixedKey(match));
			}
		}
		// A JWT needs at least two dots. Counted with indexOf instead of
		// `out.match(/\./g)`, which allocated one array slot per dot on
		// megabyte-size strings.
		const firstDot = out.indexOf(".");
		if (firstDot >= 0 && out.indexOf(".", firstDot + 1) >= 0) {
			out = out.replace(JWE_PATTERN, (_match: string, token: string): string => this.replaceJwt(token));
			out = out.replace(JWT_PATTERN, (_match: string, token: string): string => this.replaceJwt(token));
		}
		const lowered = out.toLowerCase();
		if (lowered.includes("bearer")) {
			out = out.replace(BEARER_PATTERN, (...args: unknown[]): string => {
				const match = args[0] as string;
				const groups = groupsOf(args);
				const prefix = groups["prefix"] ?? "";
				const quote = groups["quote"] ?? "";
				const token = groups["token"] ?? "";
				if (token.length === 0 || this.apiReplacements.has(token)) {
					return match;
				}
				return `${prefix}${quote}${this.genericRedactedReplacement(token, "credential", 24)}${quote}`;
			});
		}
		if (out.includes("://") && out.includes("@")) {
			const replaceUrlPassword = (...args: unknown[]): string => {
				const match = args[0] as string;
				const groups = groupsOf(args);
				const password = groups["password"] ?? "";
				if (isRedactedSecretValue(password)) {
					return match;
				}
				const replacement = this.secretReplacement(password);
				this.bump("credential");
				return `${groups["scheme"] ?? ""}${groups["user"] ?? ""}:${replacement}@`;
			};
			out = out.replace(CREDENTIAL_URL_PATTERN, replaceUrlPassword);
			out = out.replace(BROKEN_CREDENTIAL_URL_PATTERN, replaceUrlPassword);
		}
		if (SENSITIVE_GATE_WORDS.some((word) => lowered.includes(word))) {
			if (out.includes("=") && (out.includes("?") || out.includes("&"))) {
				out = out.replace(QUERY_SECRET_PATTERN, (...args: unknown[]): string =>
					this.replaceQuerySecret(args));
			}
			if (out.includes("=")) {
				out = out.replace(CONNECTION_COMPONENT_SECRET_PATTERN, (...args: unknown[]): string =>
					this.replaceConnectionComponentSecret(args));
			}
			if (out.includes("=") || out.includes(":")) {
				for (const pattern of QUOTED_ASSIGNMENT_PATTERNS) {
					out = out.replace(pattern, (...args: unknown[]): string =>
						this.replaceSensitiveQuotedAssignment(args));
				}
				out = out.replace(BARE_ASSIGNMENT_PATTERN, (...args: unknown[]): string =>
					this.replaceSensitiveBareAssignment(args));
				// Double-encoded JSON / escaped assignments (see the patterns).
				out = out.replace(ESCAPED_JSON_ASSIGNMENT_PATTERN, (...args: unknown[]): string =>
					this.replaceEscapedAssignment(args));
				out = out.replace(ESCAPED_EQUALS_ASSIGNMENT_PATTERN, (...args: unknown[]): string =>
					this.replaceEscapedAssignment(args));
				out = out.replace(GENERIC_SECRET_PATTERN, (...args: unknown[]): string =>
					this.replaceGenericSecret(args));
			}
		}
		return out;
	}

	private replaceQuerySecret(args: readonly unknown[]): string {
		const match = args[0] as string;
		const groups = groupsOf(args);
		const value = groups["value"] ?? "";
		const name = groups["name"] ?? "";
		const normalized = sortedSecretNameKey(name);
		const shouldRedact =
			normalized === "sig" || normalized === "signature"
				? this.looksLikeSecretValue(value)
				: this.shouldRedactAssignment(name, value);
		if (!shouldRedact) {
			return match;
		}
		const replacement = this.secretReplacement(`${name}=${value}`);
		this.bump("credential");
		return `${groups["prefix"] ?? ""}${replacement}`;
	}

	private replaceConnectionComponentSecret(args: readonly unknown[]): string {
		const match = args[0] as string;
		const groups = groupsOf(args);
		const value = groups["value"] ?? "";
		if (isRedactedSecretValue(value)) {
			return match;
		}
		const replacement = this.secretReplacement(`${groups["name"] ?? ""}=${value}`);
		this.bump("credential");
		return `${groups["prefix"] ?? ""}${replacement}`;
	}

	private replaceSensitiveQuotedAssignment(args: readonly unknown[]): string {
		const match = args[0] as string;
		const groups = groupsOf(args);
		const name = groups["name"] ?? "";
		const value = groups["value"] ?? "";
		if (!this.shouldRedactAssignment(name, value)) {
			return match;
		}
		const replacement = this.assignmentSecretReplacement(name, value);
		const quote = groups["quote"] ?? "";
		return `${groups["prefix"] ?? ""}${quote}${replacement}${quote}`;
	}

	private replaceSensitiveBareAssignment(args: readonly unknown[]): string {
		const match = args[0] as string;
		const groups = groupsOf(args);
		const name = groups["name"] ?? "";
		const [value, suffix] = this.splitBareAssignmentValue(groups["value"] ?? "");
		// `password: # TODO use vault` is a comment, not a value. A value that
		// CONTAINS `#` (`DB_PASSWORD=pa#ss123`) is still one shell word.
		if (value.startsWith("#")) {
			return match;
		}
		if (!this.shouldRedactAssignment(name, value)) {
			return match;
		}
		const replacement = this.assignmentSecretReplacement(name, value);
		return `${groups["prefix"] ?? ""}${replacement}${suffix}`;
	}

	/** `{\"password\":\"x\"}` / `NAME\\=\"x\"`: same rules, backslashes preserved. */
	private replaceEscapedAssignment(args: readonly unknown[]): string {
		const match = args[0] as string;
		const groups = groupsOf(args);
		const name = groups["name"] ?? "";
		const value = groups["value"] ?? "";
		if (!this.shouldRedactAssignment(name, value)) {
			return match;
		}
		return `${groups["prefix"] ?? ""}${this.assignmentSecretReplacement(name, value)}${
			groups["suffix"] ?? ""
		}`;
	}

	private replaceGenericSecret(args: readonly unknown[]): string {
		const match = args[0] as string;
		const groups = groupsOf(args);
		const token = groups["value"] ?? "";
		if (!this.isSensitiveName(groups["name"] ?? "", token)) {
			return match;
		}
		if (isRedactedSecretValue(token) || this.apiReplacements.has(token)) {
			return match;
		}
		const replacement = this.genericRedactedReplacement(token, "credential", 24);
		return `${groups["prefix"] ?? ""}${replacement}`;
	}

	private replacePrivateKeyBlock(token: string): string {
		let replacement = this.apiKeyMap.get(token);
		if (replacement === undefined) {
			replacement = `redacted_private_key_${dummySequence(token, 16)}`;
			this.apiKeyMap.set(token, replacement);
			this.apiReplacements.add(replacement);
		}
		this.bump("private_key");
		return replacement;
	}

	private replacePrefixedKey(token: string): string {
		let replacement = this.apiKeyMap.get(token);
		if (replacement === undefined) {
			replacement = `redacted_api_key_${dummySequence(token, 16)}`;
			this.apiKeyMap.set(token, replacement);
			this.apiReplacements.add(replacement);
		}
		this.bump("api_key");
		return replacement;
	}

	private replaceJwt(token: string): string {
		let replacement = this.apiKeyMap.get(token);
		if (replacement === undefined) {
			replacement = `redacted_jwt_${dummySequence(token, 16)}`;
			this.apiKeyMap.set(token, replacement);
			this.apiReplacements.add(replacement);
		}
		this.bump("jwt");
		return replacement;
	}

	/** Port of _replace_bearer's inline body (unprefixed `redacted_` placeholder). */
	private genericRedactedReplacement(
		token: string,
		category: string,
		length: number,
	): string {
		let replacement = this.apiKeyMap.get(token);
		if (replacement === undefined) {
			replacement = `redacted_${dummySequence(token, length)}`;
			this.apiKeyMap.set(token, replacement);
			this.apiReplacements.add(replacement);
		}
		this.bump(category);
		return replacement;
	}

	private assignmentSecretReplacement(name: string, value: string): string {
		if (findMatch(PRIVATE_KEY_BLOCK_PATTERN, value) !== null) {
			let replacement = this.apiKeyMap.get(value);
			if (replacement === undefined) {
				replacement = `redacted_private_key_${dummySequence(value, 16)}`;
				this.apiKeyMap.set(value, replacement);
				this.apiReplacements.add(replacement);
			}
			this.bump("private_key");
			return replacement;
		}
		if (this.looksLikeJwt(value)) {
			let replacement = this.apiKeyMap.get(value);
			if (replacement === undefined) {
				replacement = `redacted_jwt_${dummySequence(value, 16)}`;
				this.apiKeyMap.set(value, replacement);
				this.apiReplacements.add(replacement);
			}
			this.bump("jwt");
			return replacement;
		}
		const replacement = this.secretReplacement(`${name}=${value}`);
		this.bump("credential");
		return replacement;
	}

	private secretReplacement(token: string): string {
		let replacement = this.apiKeyMap.get(token);
		if (replacement === undefined) {
			replacement = `redacted_secret_${dummySequence(token, 16)}`;
			this.apiKeyMap.set(token, replacement);
			this.apiReplacements.add(replacement);
		}
		return replacement;
	}

	private splitBareAssignmentValue(value: string): [string, string] {
		let out = value;
		let suffix = "";
		while (out.length > 0 && (out.endsWith(",") || out.endsWith(";"))) {
			suffix = out.slice(-1) + suffix;
			out = out.slice(0, -1);
		}
		return [out, suffix];
	}

	// -------------------------------------------------------------------------
	// Secret sensitivity / placeholder heuristics.
	// -------------------------------------------------------------------------

	private shouldRedactAssignment(name: string, value: string): boolean {
		if (
			value.length === 0 ||
			isEmptySecretValue(value) ||
			isRedactedSecretValue(value) ||
			isPlaceholderSecretValue(value)
		) {
			return false;
		}
		return this.isSensitiveName(name, value);
	}

	private isSensitiveName(name: string, value: string): boolean {
		const sortedKey = sortedSecretNameKey(name);
		const ordered = secretNameWords(name).join("_");
		const wordList = secretNameWords(name);
		const words = new Set(wordList);
		if (SENSITIVE_EXACT_NAME_KEYS.has(sortedKey)) {
			return true;
		}
		// Deviation from source: the source bails out whenever ANY word is
		// non-secret, which made `id_token` (a real OAuth credential) invisible
		// because of its `id` prefix. The qualifier only counts when it is the
		// head noun (`token_count`, `api_key_length`, `key_id`).
		if (NON_SECRET_NAME_WORDS.has(wordList[wordList.length - 1] ?? "")) {
			return false;
		}
		if (ordered.endsWith("_connection_string") || ordered.includes("connection_string")) {
			return this.looksLikeSecretValue(value) || value.trim().length >= 8;
		}
		if (hasAnyIntersection(words, PASSWORD_SECRET_WORDS)) {
			return true;
		}
		if (words.has("private")) {
			return hasAnyIntersection(words, PRIVATE_CONTEXT_WORDS) || findMatch(PRIVATE_KEY_BLOCK_PATTERN, value) !== null;
		}
		if (words.has("token") && !NON_SECRET_NAME_WORDS.has(wordList[wordList.length - 1] ?? "")) {
			// Deviation from source: a bare `token` field was never redacted, so
			// `token=opaqueToken0123…` (a very common shape) went through. It is
			// still exempt when the value does not look like a credential, so
			// `token: "count"`-style prose is untouched.
			if (words.size === 1 && words.has("token")) {
				return this.looksLikeSecretValue(value);
			}
			return hasAnyIntersection(words, SENSITIVE_KEY_CONTEXT_WORDS) || this.looksLikeSecretValue(value);
		}
		if (words.has("signature") || words.has("sig")) {
			return hasAnyIntersection(words, SIGNATURE_CONTEXT_WORDS);
		}
		if (words.has("jwt")) {
			return hasAnyIntersection(words, JWT_CONTEXT_WORDS) || this.looksLikeJwt(value);
		}
		if (words.has("key")) {
			if (words.size === 1 && words.has("key")) {
				return false;
			}
			return hasAnyIntersection(words, SENSITIVE_KEY_CONTEXT_WORDS) || this.looksLikeSecretValue(value);
		}
		if (words.has("url") || words.has("uri") || words.has("dsn")) {
			return hasAnyIntersection(words, SENSITIVE_URL_CONTEXT_WORDS) || this.looksLikeCredentialUrl(value);
		}
		return false;
	}

	private looksLikeSecretValue(value: string): boolean {
		const stripped = value.trim();
		if (
			isEmptySecretValue(stripped) ||
			isRedactedSecretValue(stripped) ||
			isPlaceholderSecretValue(stripped)
		) {
			return false;
		}
		if (this.looksLikeJwt(stripped) || this.looksLikeCredentialUrl(stripped)) {
			return true;
		}
		if (findMatch(PRIVATE_KEY_BLOCK_PATTERN, stripped) !== null) {
			return true;
		}
		for (const { pattern } of API_KEY_ENTRIES) {
			if (findMatch(pattern, stripped) !== null) {
				return true;
			}
		}
		if (PUBLIC_IDENTIFIER_PATTERNS.some((pattern) => fullMatch(pattern, stripped))) {
			return false;
		}
		if (stripped.length >= 24 && fullMatch(SECRET_VALUE_CHARSET_PATTERN, stripped)) {
			let characterClasses = 0;
			if (/[a-z]/.test(stripped)) {
				characterClasses += 1;
			}
			if (/[A-Z]/.test(stripped)) {
				characterClasses += 1;
			}
			if (/[0-9]/.test(stripped)) {
				characterClasses += 1;
			}
			if (/[_~+/=-]/.test(stripped)) {
				characterClasses += 1;
			}
			return characterClasses >= 2;
		}
		return false;
	}

	private looksLikeJwt(value: string): boolean {
		const stripped = value.trim();
		return fullMatch(JWT_PATTERN, stripped) || fullMatch(JWE_PATTERN, stripped);
	}

	private looksLikeCredentialUrl(value: string): boolean {
		return findMatch(CREDENTIAL_URL_PATTERN, value) !== null;
	}

	// -------------------------------------------------------------------------
	// PII pass.
	// -------------------------------------------------------------------------

	private replaceHighConfidencePii(text: string): string {
		const replaceValue = (...args: unknown[]): string => {
			const groups = groupsOf(args);
			const value = groups["value"] ?? "";
			this.bump("pii");
			return `${groups["prefix"] ?? ""}${this.piiReplacement(value)}`;
		};
		let out = text.replace(SSN_PATTERN, (match: string): string => {
			this.bump("pii");
			return this.piiReplacement(match);
		});
		out = out.replace(PHONE_PATTERN, replaceValue);
		out = out.replace(IP_PATTERN, replaceValue);
		if (this.aggressivePii) {
			out = out.replace(NAME_PATTERN, replaceValue);
			out = out.replace(ADDRESS_PATTERN, replaceValue);
		}
		return out;
	}

	private piiReplacement(value: string): string {
		return `redacted_pii_${dummySequence(value, 16)}`;
	}

	// -------------------------------------------------------------------------
	// Media and username mapping.
	// -------------------------------------------------------------------------

	private redactBase64Media(declaredMediaType: string | null): { type: string; data: string } {
		const normalized = (declaredMediaType ?? "").toLowerCase().split(";")[0]?.trim() ?? "";
		let replacementType = normalized;
		if (!(replacementType in MEDIA_PLACEHOLDER_BASE64)) {
			if (normalized.startsWith("audio/")) {
				replacementType = "audio/wav";
			} else if (normalized.startsWith("video/")) {
				replacementType = "video/webm";
			} else {
				replacementType = "image/png";
			}
		}
		this.bump("media");
		return { type: replacementType, data: MEDIA_PLACEHOLDER_BASE64[replacementType] as string };
	}

	private mapUsername(username: string): string {
		const key = username.trim().toLowerCase();
		let mapped = this.usernameMap.get(key);
		if (mapped === undefined) {
			mapped = `user_${hashHexPrefix(key, 8)}`;
			this.usernameMap.set(key, mapped);
		}
		return mapped;
	}

	private bump(category: string, amount = 1): void {
		this.countsInternal[category] = (this.countsInternal[category] ?? 0) + amount;
	}
}

function isStructuredPiiKey(key: string): boolean {
	const normalized = key.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
	return STRUCTURED_PII_KEYS.has(normalized);
}

function looksLikePathOrPackageReference(
	start: number,
	end: number,
	text: string,
	segments: SegmentLocator,
): boolean {
	const previousChar = start > 0 ? text[start - 1] : "";
	const nextChar = end < text.length ? text[end] : "";
	if (previousChar === "/") {
		return true;
	}
	if (nextChar === "/") {
		return true;
	}
	const { start: segmentStart, end: segmentEnd } = segments.containing(start);
	// Same reason as in looksLikeUriUserinfo: bound the window so a huge
	// whitespace-free run cannot make this quadratic.
	const windowStart = Math.max(segmentStart, start - SEGMENT_WINDOW);
	const windowEnd = Math.min(segmentEnd, end + SEGMENT_WINDOW);
	const segment = text.slice(windowStart, windowEnd);
	// Deviation from source: backslashes are stripped before the path test.
	// Session JSONL nests JSON inside JSON (`\"`, `\\n`, …at arbitrary
	// depth); treating those as path separators silently skipped real emails
	// at every nesting level. Path detection therefore keys on `/` only, and
	// backslash-separated strings (`dir\name@foo.com`) are accepted as
	// over-redaction — false positives are safe, false negatives leak.
	const withoutBackslashes = segment.replace(/\\/g, "");
	if (withoutBackslashes.includes("/")) {
		return true;
	}
	if (/[@:]v?\d+(?:\.\d+){1,}/i.test(withoutBackslashes)) {
		return true;
	}
	return false;
}

/** Create a fresh, stateful anonymizer instance (one export run = one instance). */
export function createAnonymizer(options: AnonymizerOptions = {}): Anonymizer {
	return new TraceAnonymizer(options.aggressivePii === true);
}
