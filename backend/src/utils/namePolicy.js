// src/utils/namePolicy.js

/*
 * Display-name length policy, shared by registration and profile updates.
 *
 * NAME_MIN_LENGTH / NAME_MAX_LENGTH (backend/.env) control how long a name
 * may be — e.g. NAME_MIN_LENGTH=3 and NAME_MAX_LENGTH=10 enforces 3–10
 * characters. Both the API validation and the name-rules endpoint the
 * frontend sizes its input from read these, so one .env change moves
 * everything (input maxLength, hint text, server-side rejection message).
 */

import { numberFromEnv } from "./env.js";

export const NAME_MIN_LENGTH = numberFromEnv("NAME_MIN_LENGTH", 2, {
  minimum: 1,
  maximum: 100,
});

export const NAME_MAX_LENGTH = Math.max(
  NAME_MIN_LENGTH,
  numberFromEnv("NAME_MAX_LENGTH", 100, { minimum: 1, maximum: 200 }),
);
