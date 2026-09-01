// src/utils/env.js

/*
 * Centralized environment-variable parsing.
 *
 * Every tunable number in the backend flows through here so the whole
 * configuration surface behaves consistently:
 *
 *   - Durations accept a unit suffix or a bare value:
 *       "300"   -> 300 seconds   (bare values are seconds)
 *       "30s"   -> 30 seconds
 *       "15m"   -> 15 minutes
 *       "8h"    -> 8 hours
 *       "7d"    -> 7 days
 *       "2w"    -> 2 weeks
 *       "500ms" -> 0.5 seconds   (see durationFromEnvMs)
 *
 *   - Plain counts use numberFromEnv with an explicit minimum, so a typo
 *     like "abc" or "-5" falls back to the default instead of becoming
 *     NaN / a dangerous zero.
 *
 * Legacy variable names keep working: pass `legacyName` (and `legacyUnit`
 * when the old name's bare value meant something other than seconds, e.g.
 * SESSION_IDLE_TIMEOUT_HOURS where "8" meant 8 hours).
 */

const UNIT_SECONDS = {
  ms: 0.001,
  s: 1,
  m: 60,
  h: 3600,
  d: 86400,
  w: 604800,
};

/** Parses "300" | "30s" | "15m" | "8h" | "7d" | "500ms" into seconds. Returns null when unparseable. */
export function parseDurationToSeconds(raw) {
  if (typeof raw !== "string") return null;
  const match = raw.trim().toLowerCase().match(/^(\d+(?:\.\d+)?)(ms|s|m|h|d|w)?$/);
  if (!match) return null;
  const seconds = Number(match[1]) * UNIT_SECONDS[match[2] ?? "s"];
  return Number.isFinite(seconds) ? seconds : null;
}

/**
 * Reads a duration (seconds) from the environment.
 *
 * @param {string} name        primary env var, e.g. "SESSION_IDLE_TIMEOUT"
 * @param {number} fallback    seconds used when unset/invalid
 * @param {object} [options]
 * @param {string} [options.legacyName]  old variable name still honoured
 * @param {string} [options.legacyUnit]  unit a bare legacy value is in ("s"|"m"|"h"|"d"|"w")
 * @param {boolean} [options.allowZero]  treat 0 as valid (e.g. "disable this feature")
 */
export function durationFromEnv(name, fallback, options = {}) {
  const { legacyName, legacyUnit = "s", allowZero = false } = options;

  let seconds = parseDurationToSeconds(process.env[name]);

  if (seconds === null && legacyName) {
    const legacyRaw = process.env[legacyName];
    const legacySeconds = parseDurationToSeconds(legacyRaw);
    if (legacySeconds !== null) {
      // A suffixed legacy value ("8h") already carries its unit; a bare one
      // ("8") is expressed in legacyUnit (e.g. hours).
      const hasSuffix = /[a-z]\s*$/i.test(String(legacyRaw).trim());
      seconds = hasSuffix ? legacySeconds : legacySeconds * UNIT_SECONDS[legacyUnit];
    }
  }

  if (seconds === null || (!allowZero && seconds <= 0)) {
    return fallback;
  }
  return seconds;
}

/** Same as durationFromEnv but returns milliseconds (Redis lock TTLs etc.). */
export function durationFromEnvMs(name, fallbackMs, options = {}) {
  return durationFromEnv(name, fallbackMs / 1000, options) * 1000;
}

/**
 * Reads a plain count (attempts, page sizes, bcrypt rounds…) from the
 * environment. Invalid or below-minimum values fall back to the default.
 */
export function numberFromEnv(name, fallback, { minimum = 1, maximum = Number.MAX_SAFE_INTEGER } = {}) {
  const value = Number(process.env[name]);
  if (!Number.isFinite(value) || value < minimum || value > maximum) {
    return fallback;
  }
  return Math.floor(value);
}
