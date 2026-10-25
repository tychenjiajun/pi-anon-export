// Core redaction pipeline.
//
// For each JSONL line:
//   1. JSON.parse — unparseable lines are DROPPED and counted (fail-safe:
//      broken output is never emitted verbatim).
//   2. Structural pass — embedded media payloads (a long string under a
//      media key whose context or bytes identify it as image/audio/video) are
//      replaced with "[IMAGE_REMOVED]" when removeImages is set (--no-images),
//      otherwise kept but counted for manual review. Kept images are never
//      passed to the anonymizer: base64 must stay byte-exact or the image is
//      destroyed. A long `data` string that is clearly TEXT (`{type:
//      "tool-result", data: "csv,…"}`) is not a payload and goes through the
//      normal redaction pipeline instead of being exempted or deleted.
//   3. Literal secret replacement (single pass, longest value first).
//   4. At level "full", every remaining leaf value is additionally passed
//      through the shared Anonymizer (createAnonymizer(), lib/anonymize.ts).
//
// Output is re-serialized JSON. Returns { lines, counts } where `counts` are
// DELTAS for this call even when a shared anonymizer is reused across files.

import { createAnonymizer, type Anonymizer } from "./anonymize.ts";
import { createSecretMatcher, type SecretEntry } from "./secrets.ts";

export type RedactionLevel = "fast" | "full";

export interface RedactionCounts {
	/** Lines that failed JSON.parse and were dropped (never emitted). */
	dropped_lines: number;
	/** Image data blocks removed because --no-images was set. */
	images_removed: number;
	/** Image data blocks kept (no --no-images) — review manually before sharing. */
	images_flagged: number;
	/** Literal secret occurrences replaced with [REDACTED_<NAME>]. */
	secret_replacements: number;
	/** Additional counts accumulated by the anonymizer, for THIS file only. */
	anonymizer: Record<string, number>;
}

export function emptyCounts(): RedactionCounts {
	return {
		dropped_lines: 0,
		images_removed: 0,
		images_flagged: 0,
		secret_replacements: 0,
		anonymizer: {},
	};
}

export function mergeCounts(target: RedactionCounts, source: RedactionCounts): RedactionCounts {
	target.dropped_lines += source.dropped_lines;
	target.images_removed += source.images_removed;
	target.images_flagged += source.images_flagged;
	target.secret_replacements += source.secret_replacements;
	for (const [key, value] of Object.entries(source.anonymizer)) {
		target.anonymizer[key] = (target.anonymizer[key] ?? 0) + value;
	}
	return target;
}

export interface RedactOptions {
	/** "full" applies the value anonymizer; "fast" only does secrets/images/drop. */
	level: RedactionLevel;
	/** --no-images: strip image data blocks instead of keeping them. */
	removeImages: boolean;
	/** Literal secrets to replace (from secrets.buildLiteralSecrets). */
	secrets: readonly SecretEntry[];
	/**
	 * Anonymizer instance to use at level "full". Create ONE per export run so
	 * the same value maps consistently across all files. Counts returned by
	 * each call are per-file deltas, not the instance's lifetime totals.
	 */
	anonymizer?: Anonymizer;
}

/** Threshold above which a media-shaped string is treated as an embedded payload. */
export const IMAGE_DATA_MIN_LENGTH = 256;

/**
 * Carrier keys that hold an embedded media payload.
 * The first group is unambiguous (an OpenAI/Gemini-style b64 field); `data`,
 * `base64` and `blob` are shared with ordinary content (`{"type":"tool-result",
 * "data":"csv,…"}`), so for those the parent object must also look like media
 * or the value must carry a recognisable base64/data-URL magic. Keying the
 * image policy on the key name alone used to exempt any >256-char `data`
 * string from the entire redaction pipeline — and delete that data with
 * `--no-images`.
 */
const MEDIA_KEYS: ReadonlySet<string> = new Set([
	"b64_json",
	"imageData",
	"image_data",
	"audioData",
	"videoData",
	"fileData",
	"contentBytes",
]);

/** Keys that hold media only when the context (or the bytes) says so. */
const AMBIGUOUS_MEDIA_KEYS: ReadonlySet<string> = new Set(["data", "base64", "blob"]);

/**
 * Keys that are a payload when the parent says `type: image|audio|video`.
 * (`content` is a content *array* elsewhere, so it only counts with a type.)
 */
const TYPED_MEDIA_KEYS: ReadonlySet<string> = new Set([
	"content",
	"image",
	"audio",
	"video",
	"screenshot",
	"frame",
	"payload",
]);

const MEDIA_TYPE_KEYS = ["type", "mimeType", "mime_type", "mediaType", "media_type"] as const;
const MEDIA_TYPE_PREFIXES = ["image/", "audio/", "video/"] as const;
/** `data:image/png;base64,…` — a media URL under ANY key. */
const MEDIA_DATA_URL_RE = /^data:(?:image|audio|video)\//i;
/** Magic prefixes of the container formats we can recognise cheaply. */
const MEDIA_MAGIC_PREFIXES: readonly string[] = [
	"iVBOR", // png
	"/9j/", // jpeg
	"R0lGOD", // gif
	"UklGR", // webp / wav (RIFF)
	"GkXf", // webm
	"AAAAIGZ0eXA", // mp4 (ftyp box)
	"Qk", // bmp (BM)
	"SUk", // tiff (little endian, II*\0)
	"TU0", // tiff (big endian, MM\0*)
	"AAABAA", // ico
];

const IMAGE_REPLACEMENT = "[IMAGE_REMOVED]";

/** Lowercase MIME type declared on `owner`, if it is a media type. */
function declaredMediaTypeName(owner: Record<string, unknown> | undefined): string | null {
	if (owner === undefined) return null;
	for (const key of MEDIA_TYPE_KEYS) {
		const candidate = owner[key];
		if (typeof candidate !== "string") continue;
		const lowered = candidate.toLowerCase().split(";")[0]?.trim() ?? "";
		if (MEDIA_TYPE_PREFIXES.some((prefix) => lowered.startsWith(prefix))) return lowered;
	}
	return null;
}

function declaresMediaType(owner: Record<string, unknown> | undefined): boolean {
	return declaredMediaTypeName(owner) !== null;
}

/** Media types whose payload is text (so it must go through the text pipeline). */
const TEXTUAL_MEDIA_RE = /^(?:text\/|.*\+xml$|.*json$)/;

function startsWithMediaMagic(value: string): boolean {
	return MEDIA_MAGIC_PREFIXES.some((prefix) => value.startsWith(prefix));
}

const BASE64_BLOB_RE = /^[A-Za-z0-9+/=\s]+$/;

function declaresTypedMedia(owner: Record<string, unknown> | undefined): boolean {
	if (owner === undefined) return false;
	const type = owner["type"];
	return typeof type === "string" && ["image", "audio", "video"].includes(type.toLowerCase());
}

/** `{"type":"base64"}` is the legacy pi media block shape. */
function declaresBase64Type(owner: Record<string, unknown> | undefined): boolean {
	if (owner === undefined) return false;
	const type = owner["type"];
	return typeof type === "string" && type.toLowerCase() === "base64";
}

/**
 * True when this long string is an embedded media payload (image policy), not
 * ordinary text that merely sits under a media-ish key name.
 *
 * The decision is evidence-based on purpose: an unconditional key list (the
 * first version of this policy) exempted ANY long string under `b64_json` /
 * `imageData` from the whole redaction pipeline, so a CSV tool-result stored
 * under such a key shipped unredacted while the report said "Verified".
 * Unrecognised "media" is treated as TEXT, which only loses the ability to
 * strip it — never the redaction.
 */
function isMediaPayload(key: string, value: string, owner: Record<string, unknown> | undefined): boolean {
	if (value.length <= IMAGE_DATA_MIN_LENGTH) return false;
	// Bytes that identify themselves.
	if (MEDIA_DATA_URL_RE.test(value)) return true;
	if (startsWithMediaMagic(value)) return true;
	// The parent says what it is: a declared MIME type is evidence about the
	// PAYLOAD (and only for a payload-ish key); a bare `type: image` needs a
	// payload-ish key; `type: base64` needs the value to look like base64.
	const payloadKey =
		TYPED_MEDIA_KEYS.has(key) || MEDIA_KEYS.has(key) || AMBIGUOUS_MEDIA_KEYS.has(key);
	if (declaresMediaType(owner)) {
		// A declared MIME type is evidence about the PAYLOAD, not about every
		// long string that happens to sit next to it: `{"mimeType":"image/png",
		// "note":"…long prose…"}` exempted the prose from redaction and
		// (with --no-images) deleted it as if it were the image.
		// A text-based media type (image/svg+xml) carries TEXT, so it is redacted.
		const declared = declaredMediaTypeName(owner);
		return payloadKey && !(declared !== null && TEXTUAL_MEDIA_RE.test(declared));
	}
	if (declaresTypedMedia(owner) && payloadKey) {
		return true;
	}
	if (declaresBase64Type(owner)) return fullMatchBase64Blob(value);
	// An unambiguous carrier key whose value is a base64 blob.
	return MEDIA_KEYS.has(key) && fullMatchBase64Blob(value);
}

function fullMatchBase64Blob(value: string): boolean {
	return BASE64_BLOB_RE.test(value);
}

interface WalkState {
	options: RedactOptions;
	counts: RedactionCounts;
	redactSecrets: ReturnType<typeof createSecretMatcher>;
}

/**
 * Recursively process one parsed entry. Mutates plain containers in place.
 * `parentKey`/`owner` propagate the object key and its parent object, which is
 * what lets the image policy tell `{"type":"image","data":"iVBOR…"}` (payload)
 * from `{"type":"tool-result","data":"csv,…"}` (text).
 */
function walkValue(
	value: unknown,
	parentKey: string | undefined,
	state: WalkState,
	owner?: Record<string, unknown>,
): unknown {
	if (typeof value === "string") {
		if (parentKey !== undefined && isMediaPayload(parentKey, value, owner)) {
			if (state.options.removeImages) {
				state.counts.images_removed += 1;
				return IMAGE_REPLACEMENT;
			}
			// Kept by request. Deliberately untouched: any rewrite (including the
			// anonymizer) would corrupt the base64 payload.
			state.counts.images_flagged += 1;
			return value;
		}

		let out = value;
		if (state.redactSecrets) {
			out = state.redactSecrets.replace(out, () => {
				state.counts.secret_replacements += 1;
			});
		}

		if (state.options.level === "full" && state.options.anonymizer) {
			// Secrets were already replaced above; anonymize the (possibly redacted) text.
			return state.options.anonymizer.anonymizeValue(out);
		}
		return out;
	}

	if (Array.isArray(value)) {
		for (let i = 0; i < value.length; i++) {
			value[i] = walkValue(value[i], parentKey, state, owner);
		}
		return value;
	}

	if (value !== null && typeof value === "object") {
		const record = value as Record<string, unknown>;
		for (const key of Object.keys(record)) {
			record[key] = walkValue(record[key], key, state, record);
		}
		return record;
	}

	// Numbers, booleans, null: nothing to redact. The anonymizer only rewrites
	// strings (see anonymize.ts `anonymizeValue`), so calling it here would be a
	// no-op that only made the pipeline look more thorough than it is.
	return value;
}

export interface RedactResult {
	/** Redacted JSONL lines (one serialized JSON object per input line). */
	lines: string[];
	counts: RedactionCounts;
}

/**
 * Redact one session's JSONL content. Never throws for bad input: lines that
 * do not parse as JSON are dropped and counted (fail-safe).
 */
export function redactSessionJsonl(content: string, options: RedactOptions): RedactResult {
	const anonymizer =
		options.level === "full" ? (options.anonymizer ?? createAnonymizer()) : undefined;
	// The anonymizer instance is shared across files by design; snapshot its
	// lifetime counts so this call can report a delta (and so per-file manifest
	// counts stay per-file).
	const baseline: Record<string, number> = anonymizer ? { ...anonymizer.counts } : {};

	const state: WalkState = {
		options: { ...options, anonymizer },
		counts: emptyCounts(),
		redactSecrets: createSecretMatcher(options.secrets),
	};

	const lines: string[] = [];
	for (const rawLine of content.split("\n")) {
		const trimmed = rawLine.trim();
		if (trimmed.length === 0) continue;

		let parsed: unknown;
		try {
			parsed = JSON.parse(trimmed);
		} catch {
			// Fail-safe: drop the line entirely rather than leaking raw content.
			state.counts.dropped_lines += 1;
			continue;
		}

		if (parsed === null || typeof parsed !== "object") {
			// Session entries are objects; anything else is not a valid entry.
			state.counts.dropped_lines += 1;
			continue;
		}

		try {
			const processed = walkValue(parsed, undefined, state);
			lines.push(JSON.stringify(processed));
		} catch {
			// Defensive: if structural processing fails, drop the line.
			state.counts.dropped_lines += 1;
		}
	}

	if (anonymizer) {
		for (const [key, value] of Object.entries(anonymizer.counts)) {
			const delta = value - (baseline[key] ?? 0);
			if (delta !== 0) state.counts.anonymizer[key] = delta;
		}
	}

	return { lines, counts: state.counts };
}

/**
 * Second-pass verification: count how many known secret literals survive in
 * the emitted content. Anything above zero means the export must not be shared.
 *
 * Redacted output is JSON, so a secret containing `"`, `\\` or a newline only
 * appears in its escaped form (`JSON.stringify` applies `\\"`, `\\\\`, `\\n`).
 * Both forms are matched in ONE combined pass (same matcher as the redaction
 * step), so verification stays linear in the content size no matter how many
 * secrets are configured.
 */
export function countResidualSecrets(content: string, secrets: readonly SecretEntry[]): number {
	const needles = new Set<string>();
	for (const secret of secrets) {
		if (secret.value.length === 0) continue;
		needles.add(secret.value);
		const escaped = JSON.stringify(secret.value).slice(1, -1);
		if (escaped.length > 0) needles.add(escaped);
	}
	if (needles.size === 0) return 0;

	const matcher = createSecretMatcher(
		[...needles].map((value) => ({ name: "residual", value, replacement: "" })),
	);
	if (!matcher) return 0;

	let found = 0;
	matcher.replace(content, () => {
		found += 1;
	});
	return found;
}
