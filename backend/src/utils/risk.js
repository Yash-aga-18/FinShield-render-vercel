// src/utils/risk.js

const numberFromEnv = (name, fallback, minimum = 0) => {
  const value = Number(process.env[name]);
  if (!Number.isFinite(value) || value < minimum) {
    return fallback;
  }
  return value;
};

const SCORES = Object.freeze({
  NEW_DEVICE: numberFromEnv("RISK_NEW_DEVICE_SCORE", 20),
  NEW_IP: numberFromEnv("RISK_NEW_IP_SCORE", 10),
  FAILED_LOGIN: numberFromEnv("RISK_FAILED_LOGIN_SCORE", 10),
  TOKEN_REPLAY: numberFromEnv("RISK_TOKEN_REPLAY_SCORE", 100),
});

const THRESHOLDS = Object.freeze({
  MEDIUM: numberFromEnv("RISK_MEDIUM_THRESHOLD", 30),
  HIGH: numberFromEnv("RISK_HIGH_THRESHOLD", 60),
  CRITICAL: numberFromEnv("RISK_CRITICAL_THRESHOLD", 100),
});

export const RISK_LEVEL = Object.freeze({
  LOW: "LOW",
  MEDIUM: "MEDIUM",
  HIGH: "HIGH",
  CRITICAL: "CRITICAL",
});

export const RISK_ACTION = Object.freeze({
  ALLOW: "ALLOW",
  ALLOW_AND_AUDIT: "ALLOW_AND_AUDIT",
  BLOCK_LOGIN: "BLOCK_LOGIN",
  REVOKE_AND_BLOCK: "REVOKE_AND_BLOCK",
});

const getRiskLevel = (score) => {
  if (score >= THRESHOLDS.CRITICAL) return RISK_LEVEL.CRITICAL;
  if (score >= THRESHOLDS.HIGH) return RISK_LEVEL.HIGH;
  if (score >= THRESHOLDS.MEDIUM) return RISK_LEVEL.MEDIUM;
  return RISK_LEVEL.LOW;
};

const getRiskAction = (level) => {
  switch (level) {
    case RISK_LEVEL.CRITICAL:
      return RISK_ACTION.REVOKE_AND_BLOCK;
    case RISK_LEVEL.HIGH:
      return RISK_ACTION.BLOCK_LOGIN;
    case RISK_LEVEL.MEDIUM:
      return RISK_ACTION.ALLOW_AND_AUDIT;
    default:
      return RISK_ACTION.ALLOW;
  }
};

/**
 * Pure risk calculation based strictly on server-derived telemetry signals.
 * Client-submitted parameters inside req.body are completely ignored.
 */
export const calculateRisk = ({
  newDevice = false,
  newIp = false,
  failedAttempts = 0,
  tokenReplay = false,
} = {}) => {
  const isNewDevice = Boolean(newDevice);
  const isNewIp = Boolean(newIp);
  const isTokenReplay = Boolean(tokenReplay);
  const failures = Math.max(0, Math.min(Number(failedAttempts) || 0, 10));

  let score = 0;
  const signals = [];

  if (isNewDevice) {
    score += SCORES.NEW_DEVICE;
    signals.push({ type: "NEW_DEVICE", score: SCORES.NEW_DEVICE });
  }

  if (isNewIp) {
    score += SCORES.NEW_IP;
    signals.push({ type: "NEW_IP", score: SCORES.NEW_IP });
  }

  if (failures > 0) {
    const failureScore = failures * SCORES.FAILED_LOGIN;
    score += failureScore;
    signals.push({
      type: "FAILED_LOGIN_ATTEMPTS",
      count: failures,
      score: failureScore,
    });
  }

  if (isTokenReplay) {
    score += SCORES.TOKEN_REPLAY;
    signals.push({ type: "TOKEN_REPLAY", score: SCORES.TOKEN_REPLAY });
  }

  const level = getRiskLevel(score);
  const action = getRiskAction(level);

  return { score, level, action, signals };
};