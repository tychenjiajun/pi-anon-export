// Core redaction pipeline.
//
// For each JSONL line:
//   1. JSON.parse — unparseable lines are DROPPED and counted (fail-safe:
//      broken output is never emitted verbatim).
//   2. Structural pass — image content blocks (a string under a `data` /
//      `base64` key longer than 256 chars) are replaced with "[IMAGE_REMOVED]"
//      when removeImages is set (--no-images), otherwise kept but counted for
//      manual review. Kept images are never passed to the anonymizer: base64
//      must stay byte-exact or the image is destroyed.
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

/** Threshold above which a `data`/`base64` string is treated as an embedded image. */
export const IMAGE_DATA_MIN_LENGTH = 256;

/** Object keys whose long string values are embedded media payloads. */
const IMAGE_DATA_KEYS: ReadonlySet<string> = new Set(["data", "base64"]);

const IMAGE_REPLACEMENT = "[IMAGE_REMOVED]";

interface WalkState {
	options: RedactOptions;
	counts: RedactionCounts;
	redactSecrets: ReturnType<typeof createSecretMatcher>;
}

/**
 * Recursively process one parsed entry. Mutates plain containers in place.
 * `parentKey` propagates the object key a value sits under, used to spot
 * image content blocks (`data` key with a long string value).
 */
function walkValue(value: unknown, parentKey: string | undefined, state: WalkState): unknown {
	if (typeof value === "string") {
		if (parentKey !== undefined && IMAGE_DATA_KEYS.has(parentKey) && value.length > IMAGE_DATA_MIN_LENGTH) {
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
			value[i] = walkValue(value[i], parentKey, state);
		}
		return value;
	}

	if (value !== null && typeof value === "object") {
		const record = value as Record<string, unknown>;
		for (const key of Object.keys(record)) {
			record[key] = walkValue(record[key], key, state);
		}
		return record;
	}

	// Numbers, booleans, null: anonymize leaf scalars too at full level so the
	// anonymizer can e.g. re-map identifiers or timestamps consistently.
	if (state.options.level === "full" && state.options.anonymizer) {
		return state.options.anonymizer.anonymizeValue(value);
	}
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
