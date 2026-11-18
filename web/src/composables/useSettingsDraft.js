import { computed, reactive, ref, watch } from "vue";

const clone = (value) => value === undefined ? undefined : JSON.parse(JSON.stringify(value));
const equal = (left, right) => JSON.stringify(left) === JSON.stringify(right);

// Merge untouched fields from SSE while retaining local edits. Arrays are one
// field (for example MFA methods); nested policy objects merge by leaf value.
export function mergeSettingsDraft(draft, baseline, incoming, prefix = "") {
  const conflicts = [];
  for (const key of Object.keys(incoming || {})) {
    const path = prefix ? `${prefix}.${key}` : key;
    const next = incoming[key];
    if (next && typeof next === "object" && !Array.isArray(next)) {
      draft[key] ||= {};
      baseline[key] ||= {};
      conflicts.push(...mergeSettingsDraft(draft[key], baseline[key], next, path));
    } else if (equal(draft[key], baseline[key]) || equal(draft[key], next)) {
      draft[key] = clone(next);
      baseline[key] = clone(next);
    } else if (!equal(next, baseline[key])) {
      conflicts.push(path);
    }
  }
  return conflicts;
}

export function useSettingsDraft(readSnapshot, readETag, fields) {
  const select = (value) => Object.fromEntries(fields.map((key) => [key, clone(value?.[key])]));
  const draft = reactive(select(readSnapshot()));
  const baseline = select(readSnapshot());
  const conflicts = ref([]);
  const etag = ref(readETag?.() || "");
  const secretFields = fields.filter((key) => ["password", "private_key_pem", "certificate_pem"].includes(key));
  const dirty = computed(() => !equal(draft, select(readSnapshot())));

  function reset(value = readSnapshot()) {
    const next = select(value);
    Object.assign(draft, clone(next));
    Object.assign(baseline, clone(next));
    conflicts.value = [];
    etag.value = readETag?.() || "";
  }

  watch(() => [readSnapshot(), readETag?.()], () => {
    conflicts.value = mergeSettingsDraft(draft, baseline, select(readSnapshot()));
    if (etag.value && readETag?.() && etag.value !== readETag()) {
      // Redacted secrets cannot be merged from their public view. Require an
      // explicit reload if another save occurred while replacing a secret.
      conflicts.value.push(...secretFields.filter((key) => !equal(draft[key], baseline[key])));
    }
    if (!conflicts.value.length) etag.value = readETag?.() || "";
  }, { deep: true, flush: "sync" });

  return { draft, dirty, conflicts, etag, reset };
}
