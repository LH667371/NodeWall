import { reactive } from "vue";

const STORAGE_KEY = "nodewall-theme-mode";
const VALID_MODES = new Set(["light", "dark", "system"]);

const state = reactive({
  mode: "system",
  resolved: "light",
});

let mediaQuery = null;
let initialized = false;

function normalizeMode(value) {
  const next = String(value || "").trim().toLowerCase();
  return VALID_MODES.has(next) ? next : "system";
}

function resolveMode(mode) {
  if (mode === "dark" || mode === "light") return mode;
  if (typeof window !== "undefined" && window.matchMedia) {
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }
  return "light";
}

function applyTheme() {
  state.resolved = resolveMode(state.mode);
  if (typeof document !== "undefined") {
    document.documentElement.dataset.theme = state.resolved;
    document.documentElement.dataset.themeMode = state.mode;
  }
}

function onSystemThemeChange() {
  if (state.mode === "system") applyTheme();
}

export function initializeTheme() {
  if (typeof window === "undefined") return;
  if (!initialized) {
    initialized = true;
    state.mode = normalizeMode(window.localStorage.getItem(STORAGE_KEY));
    mediaQuery = window.matchMedia?.("(prefers-color-scheme: dark)") || null;
    if (mediaQuery?.addEventListener) {
      mediaQuery.addEventListener("change", onSystemThemeChange);
    } else {
      // Safari versions that predate addEventListener on MediaQueryList.
      mediaQuery?.addListener?.(onSystemThemeChange);
    }
  }
  applyTheme();
}

export function setThemeMode(mode) {
  state.mode = normalizeMode(mode);
  if (typeof window !== "undefined") window.localStorage.setItem(STORAGE_KEY, state.mode);
  applyTheme();
}

export function useTheme() {
  initializeTheme();
  return {
    state,
    setThemeMode,
  };
}
