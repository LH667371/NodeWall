import { reactive } from "vue";

const STORAGE_KEY = "nodewall-timezone";
export const DEFAULT_TIME_ZONE = "Asia/Shanghai";

// Keep the list deliberately small and recognizable. The stored value is an
// IANA identifier so daylight-saving transitions and historical offsets are
// handled by the browser instead of by a fixed UTC offset in the UI.
export const timeZoneOptions = Object.freeze([
  { value: "Asia/Shanghai", labelKey: "timeZoneAsiaShanghai" },
  { value: "Asia/Tokyo", labelKey: "timeZoneAsiaTokyo" },
  { value: "Asia/Singapore", labelKey: "timeZoneAsiaSingapore" },
  { value: "UTC", labelKey: "timeZoneUTC" },
  { value: "Europe/London", labelKey: "timeZoneEuropeLondon" },
  { value: "Europe/Berlin", labelKey: "timeZoneEuropeBerlin" },
  { value: "America/Los_Angeles", labelKey: "timeZoneAmericaLosAngeles" },
  { value: "America/New_York", labelKey: "timeZoneAmericaNewYork" },
]);

function isValidTimeZone(value) {
  try {
    new Intl.DateTimeFormat("en-US", { timeZone: value }).format();
    return true;
  } catch {
    return false;
  }
}

function normalizeTimeZone(value) {
  const candidate = String(value || "").trim();
  return isValidTimeZone(candidate) ? candidate : DEFAULT_TIME_ZONE;
}

const initialTimeZone = typeof window !== "undefined"
  ? window.localStorage.getItem(STORAGE_KEY)
  : "";

export const timeState = reactive({
  timeZone: normalizeTimeZone(initialTimeZone),
});

export function setTimeZone(value) {
  timeState.timeZone = normalizeTimeZone(value);
  if (typeof window !== "undefined") {
    window.localStorage.setItem(STORAGE_KEY, timeState.timeZone);
  }
}

function dateValue(value) {
  if (value instanceof Date) return value;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

export function formatDateTime(value, locale = "zh-CN", options = {}) {
  const date = dateValue(value);
  if (!date) return "-";
  try {
    return new Intl.DateTimeFormat(locale, {
      timeZone: timeState.timeZone,
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      ...options,
    }).format(date);
  } catch {
    return date.toISOString();
  }
}

export function formatTime(value, locale = "zh-CN", options = {}) {
  const date = dateValue(value);
  if (!date) return "-";
  try {
    return new Intl.DateTimeFormat(locale, {
      timeZone: timeState.timeZone,
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      ...options,
    }).format(date);
  } catch {
    return date.toISOString();
  }
}

function zonedParts(date) {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: timeState.timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hourCycle: "h23",
  }).formatToParts(date);
  return Object.fromEntries(parts.filter((item) => item.type !== "literal").map((item) => [item.type, item.value]));
}

export function formatDateTimeLocalValue(value) {
  const date = dateValue(value) || new Date();
  const parts = zonedParts(date);
  return `${parts.year}-${parts.month}-${parts.day}T${parts.hour}:${parts.minute}`;
}

// datetime-local contains wall-clock fields without an offset. Interpret
// those fields in the selected IANA zone before sending an ISO timestamp to
// the API; otherwise a browser running in another zone silently shifts the
// monitoring query.
export function zonedDateTimeToDate(value) {
  const match = String(value || "").match(/^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?$/);
  if (!match) return null;
  const [, year, month, day, hour, minute, second = "00"] = match;
  const wallTime = Date.UTC(+year, +month - 1, +day, +hour, +minute, +second);
  const asUTC = new Date(wallTime);
  if (asUTC.toISOString().slice(0, 19) !== `${year}-${month}-${day}T${hour}:${minute}:${second}`) return null;

  const localTime = (instant) => {
    const parts = zonedParts(instant);
    return Date.UTC(+parts.year, +parts.month - 1, +parts.day, +parts.hour, +parts.minute, +parts.second);
  };
  const guess = new Date(wallTime + (wallTime - localTime(asUTC)));
  const delta = wallTime - localTime(guess);
  if (delta === 0) return guess;
  // The first offset may fall on the other side of a daylight-saving
  // transition. Round-trip the correction and reject nonexistent times.
  const corrected = new Date(guess.getTime() + delta);
  return localTime(corrected) === wallTime ? corrected : null;
}

export function useTimeZone() {
  return {
    state: timeState,
    options: timeZoneOptions,
    setTimeZone,
  };
}
