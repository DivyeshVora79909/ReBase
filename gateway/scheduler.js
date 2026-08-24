const { CronExpressionParser } = require("cron-parser");
const { RuntimeError } = require("./errors");

const MISFIRE_POLICIES = new Set(["coalesce", "skip", "all"]);
const MAX_MISFIRE_SCAN = 10000;
const MAX_SKIP_SEQUENCE = 1000;
const MAX_SKIP_SLOTS = 1000;

function normalizeSchedule(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new RuntimeError("INVALID_SCHEDULE", "Schedule must be an object", 400);
  }
  const cron = String(value.cron || "").trim();
  if (cron.length > 256 || cron.split(/\s+/).length !== 5) {
    throw new RuntimeError("INVALID_SCHEDULE_CRON", "Schedule cron must use five UTC fields", 400);
  }
  try {
    CronExpressionParser.parse(cron, { currentDate: new Date(), tz: "UTC" });
  } catch (error) {
    throw new RuntimeError("INVALID_SCHEDULE_CRON", error.message, 400);
  }
  const repeat = value.repeat == null ? null : Number(value.repeat);
  if (repeat !== null && (!Number.isSafeInteger(repeat) || repeat < 1)) {
    throw new RuntimeError("INVALID_SCHEDULE_REPEAT", "Schedule repeat must be a positive integer", 400);
  }
  const skip = value.skip == null ? [] : value.skip;
  if (!Array.isArray(skip) || skip.length > MAX_SKIP_SEQUENCE
    || skip.some((count) => !Number.isSafeInteger(count) || count < 0 || count > MAX_SKIP_SLOTS)) {
    throw new RuntimeError(
      "INVALID_SCHEDULE_SKIP",
      `Schedule skip must contain at most ${MAX_SKIP_SEQUENCE} integers between 0 and ${MAX_SKIP_SLOTS}`,
      400,
    );
  }
  const misfire = value.misfire || "coalesce";
  if (!MISFIRE_POLICIES.has(misfire)) {
    throw new RuntimeError("INVALID_SCHEDULE_MISFIRE", "Schedule misfire must be coalesce, skip, or all", 400);
  }
  return Object.freeze({ cron, repeat, skip: [...skip], misfire });
}

function nextCronDate(schedule, after, emissionIndex = 0) {
  const normalized = normalizeSchedule(schedule);
  let interval = CronExpressionParser.parse(normalized.cron, {
    currentDate: new Date(after),
    tz: "UTC",
  });
  let next = interval.next().toDate();
  const skips = normalized.skip.length ? normalized.skip[emissionIndex % normalized.skip.length] : 0;
  for (let count = 0; count < skips; count += 1) next = interval.next().toDate();
  return next;
}

function advancePast(schedule, dueAt, now, emissionIndex) {
  let nextAt = new Date(dueAt);
  for (let count = 0; count < MAX_MISFIRE_SCAN; count += 1) {
    nextAt = nextCronDate(schedule, nextAt, emissionIndex);
    if (nextAt.getTime() > now.getTime()) return nextAt;
  }
  throw new RuntimeError("SCHEDULE_MISFIRE_TOO_LARGE", "Schedule missed more than the supported catch-up window", 409);
}

function planOccurrence(schedule, dueAt, now = new Date(), emissionIndex = 0) {
  const normalized = normalizeSchedule(schedule);
  const due = new Date(dueAt);
  const current = new Date(now);
  if (Number.isNaN(due.getTime()) || Number.isNaN(current.getTime())) {
    throw new RuntimeError("INVALID_SCHEDULE_CURSOR", "Schedule cursor must be a valid datetime", 500);
  }
  if (due.getTime() > current.getTime()) {
    return Object.freeze({ emit: false, reason: "future", nextAt: due, nextIndex: emissionIndex });
  }

  const nextLogical = nextCronDate(normalized, due, emissionIndex);
  const missedAdditionalSlots = nextLogical.getTime() <= current.getTime();
  if (!missedAdditionalSlots || normalized.misfire === "all") {
    return Object.freeze({ emit: true, reason: "due", nextAt: nextLogical, nextIndex: emissionIndex + 1 });
  }
  if (normalized.misfire === "skip") {
    return Object.freeze({
      emit: false,
      reason: "misfire-skip",
      nextAt: advancePast(normalized, due, current, emissionIndex),
      nextIndex: emissionIndex,
    });
  }
  return Object.freeze({
    emit: true,
    reason: "misfire-coalesce",
    nextAt: advancePast(normalized, due, current, emissionIndex),
    nextIndex: emissionIndex + 1,
  });
}

function isExhausted(schedule, index) {
  const normalized = normalizeSchedule(schedule);
  return normalized.repeat !== null && index >= normalized.repeat;
}

function occurrenceContent(record, contract) {
  const content = { owned_by: record.owned_by };
  for (const field of contract.inputFields || []) {
    if (record[field] !== undefined) content[field] = structuredClone(record[field]);
  }
  return content;
}

module.exports = {
  isExhausted,
  MAX_MISFIRE_SCAN,
  MAX_SKIP_SEQUENCE,
  MAX_SKIP_SLOTS,
  nextCronDate,
  normalizeSchedule,
  occurrenceContent,
  planOccurrence,
};
