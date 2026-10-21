// Core redaction pipeline.
//
// For each JSONL line:
//   1. JSON.parse — unparseable lines are DROPPED and counted (fail-safe:
//      broken output is never emitted verbatim).
//   2. Structural pass — image content blocks (a string under a `data` key
//      longer than 256 chars) are replaced with "[IMAGE_REMOVED]" when
//      removeImages is set (--no-images), otherwise kept but counted for
//      manual review.
//   3. Literal secret replacement — every occurrence of a discovered secret
//      value becomes [REDACTED_<NAME>].
//   4. At level "full", every leaf value is additionally passed through the
//      shared Anonymizer (createAnonymizer(), extensions/lib/anonymize.ts).
//
// Output is re-serialized JSON. Returns { lines, counts }.

import { createAnonymizer, type Anonymizer } from "./anonymize.ts";
import type { SecretEntry } from "./secrets.ts";

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
	/** Additional counts accumulated by the anonymizer (full level). */
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

export function totalRedactions(counts: RedactionCounts): number {
	const anonymizerTotal = Object.values(counts.anonymizer).reduce((a, b) => a + b, 0);
	return (
		counts.dropped_lines +
		counts.images_removed +
		counts.secret_replacements +
		anonymizerTotal
	);
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
	 * the same value maps consistently across all files. When omitted a fresh
	 * instance is created (fine for single-file runs / tests).
	 */
	anonymizer?: Anonymizer;
}

/** Threshold above which a `data` string is treated as an embedded image. */
export const IMAGE_DATA_MIN_LENGTH = 256;

const IMAGE_REPLACEMENT = "[IMAGE_REMOVED]";

interface WalkState {
	options: RedactOptions;
	counts: RedactionCounts;
}

/**
 * Recursively process one parsed entry. Mutates plain containers in place.
 * `parentKey` propagates the object key a value sits under, used to spot
 * image content blocks (`data` key with a long string value).
 */
function walkValue(value: unknown, parentKey: string | undefined, state: WalkState): unknown {
	if (typeof value === "string") {
		if (parentKey === "data" && value.length > IMAGE_DATA_MIN_LENGTH) {
			if (state.options.removeImages) {
				state.counts.images_removed += 1;
				return IMAGE_REPLACEMENT;
			}
			state.counts.images_flagged += 1;
			return value;
		}

		let out = value;
		for (const secret of state.options.secrets) {
			if (secret.value && out.includes(secret.value)) {
				const occurrences = out.split(secret.value).length - 1;
				state.counts.secret_replacements += occurrences;
				out = out.split(secret.value).join(secret.replacement);
			}
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
	const state: WalkState = {
		options: { ...options, anonymizer },
		counts: emptyCounts(),
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
		state.counts.anonymizer = { ...anonymizer.counts };
	}

	return { lines, counts: state.counts };
}
