<script setup>
import { computed } from "vue";
import { KeyRound, MonitorCog, ShieldCheck, Sparkles } from "@lucide/vue";
import { useI18n } from "@/lib/i18n";
import { useTheme } from "@/lib/theme";
import { formatDateTime } from "@/lib/time";

const props = defineProps({
  store: { type: Object, required: true },
});

const { t, state: i18nState, locales, setLocale } = useI18n();
const { state: themeState, setThemeMode } = useTheme();
const themeMode = computed({
  get: () => themeState.mode,
  set: (value) => setThemeMode(value),
});

const roleLabel = computed(() => {
  const role = String(props.store.state.authRole || "viewer");
  return t(`role${role.charAt(0).toUpperCase()}${role.slice(1)}`);
});

const accountSecurity = computed(() => props.store.state.accountSecurity);
const accountAuthAvailable = computed(() => !accountSecurity.value.loading && Boolean(accountSecurity.value.auth_enabled));
const otpSupported = computed(() => accountAuthAvailable.value);
const passkeyBrowserSupported = computed(() => (
  typeof window !== "undefined"
  && typeof navigator !== "undefined"
  && Boolean(window.PublicKeyCredential)
  && Boolean(navigator.credentials)
));

const passkeyOriginHint = computed(() => {
  if (typeof window === "undefined") return "";
  const hostname = String(window.location.hostname || "");
  const isIPv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(hostname);
  return !window.isSecureContext || isIPv4 ? t("passkeyOriginRequired") : "";
});

const passkeySupportHint = computed(() => {
  if (accountSecurity.value.loading) return "";
  if (!accountSecurity.value.auth_enabled) return t("authDisabled");
  if (!accountSecurity.value.passkey_enabled) return t("passkeyDisabled");
  if (!passkeyBrowserSupported.value) return t("passkeyBrowserUnsupported");
  return passkeyOriginHint.value;
});
const passkeySupported = computed(() => Boolean(accountAuthAvailable.value && !passkeySupportHint.value));

function beginOTPSetup() {
  props.store.openModal({
    title: t("otpSetupPasswordTitle"),
    copy: t("otpSetupPasswordCopy"),
    fields: [{ key: "current_password", label: t("currentPassword"), type: "password", placeholder: t("currentPassword") }],
    keepOpenOnError: true,
    onConfirm: ({ current_password: password }) => props.store.setupOTP(password),
  });
}

function confirmOTPDisable() {
  props.store.openModal({
    title: t("otpDisablePasswordTitle"),
    copy: t("otpDisablePasswordCopy"),
    fields: [
      { key: "current_password", label: t("currentPassword"), type: "password", placeholder: t("currentPassword") },
      { key: "code", label: t("otpCodePlaceholder"), inputmode: "numeric", placeholder: t("otpCodePlaceholder") },
    ],
    keepOpenOnError: true,
    onConfirm: ({ current_password: password, code }) => props.store.disableOTP(password, code),
  });
}

function beginPasskeyRegistration() {
  props.store.openModal({
    title: t("passkeyRegisterPasswordTitle"),
    copy: t("passkeyRegisterPasswordCopy"),
    fields: [{ key: "current_password", label: t("currentPassword"), type: "password", placeholder: t("currentPassword") }],
    keepOpenOnError: true,
    onConfirm: ({ current_password: password }) => props.store.registerPasskey(password),
  });
}

function beginPasswordChange() {
  props.store.openModal({
    title: t("accountPasswordAction"),
    copy: t("accountPasswordChangeCopy"),
    fields: [
      { key: "current_password", label: t("currentPassword"), type: "password", required: true, placeholder: t("currentPassword") },
      { key: "new_password", label: t("newPassword"), type: "password", required: true, placeholder: t("newPassword") },
      { key: "confirm_password", label: t("confirmPassword"), type: "password", required: true, placeholder: t("confirmPassword") },
    ],
    keepOpenOnError: true,
    onConfirm: async ({ current_password: currentPassword, new_password: newPassword, confirm_password: confirmPassword }) => {
      if (newPassword !== confirmPassword) throw new Error(t("passwordMismatch"));
      await props.store.changePassword(currentPassword, newPassword);
    },
  });
}

function confirmPasskeyDelete(item) {
  props.store.openModal({
    title: t("passkeyDeletePasswordTitle"),
    copy: t("passkeyDeletePasswordCopy"),
    fields: [{ key: "current_password", label: t("currentPassword"), type: "password", placeholder: t("currentPassword") }],
    keepOpenOnError: true,
    onConfirm: ({ current_password: password }) => props.store.deletePasskey(item.id, password),
  });
}

function formatPasskeyDate(value) {
  if (!value) return t("passkeyNeverUsed");
  return formatDateTime(value, i18nState.locale === "zh-CN" ? "zh-CN" : "en-US");
}
</script>

<template>
  <section class="page-grid account-page">
    <div class="page-heading">
      <div>
        <p>{{ t("accountEyebrow") }}</p>
        <h2>{{ t("accountTitle") }}</h2>
      </div>
      <span class="status-pill success"><ShieldCheck :size="15" /> {{ t("accountSessionActive") }}</span>
    </div>

    <div class="account-grid workspace-fill">
      <article class="panel account-profile-card">
        <div class="panel-head">
          <div>
            <p>{{ t("accountProfileEyebrow") }}</p>
            <h3>{{ t("accountProfileTitle") }}</h3>
          </div>
          <div class="account-avatar" aria-hidden="true">{{ (props.store.state.authUsername || "?").slice(0, 1).toUpperCase() }}</div>
        </div>
        <dl class="account-details">
          <div><dt>{{ t("username") }}</dt><dd>{{ props.store.state.authUsername || "-" }}</dd></div>
          <div><dt>{{ t("role") }}</dt><dd>{{ roleLabel }}</dd></div>
          <div><dt>{{ t("accountSessionStatus") }}</dt><dd>{{ t("accountSessionActive") }}</dd></div>
        </dl>
        <div class="account-password-link">
          <KeyRound :size="17" aria-hidden="true" />
          <div><strong>{{ t("accountPasswordTitle") }}</strong><p>{{ t("accountPasswordCopy") }}</p></div>
          <button class="ghost-button" type="button" @click="beginPasswordChange">{{ t("accountPasswordAction") }}</button>
        </div>
        <div class="account-email-box">
          <div>
            <strong>{{ t("accountEmailTitle") }}</strong>
            <p v-if="props.store.state.accountSecurity.email_verified">{{ props.store.state.accountSecurity.email }} · {{ t("emailVerified") }}</p>
            <p v-else>{{ t("accountEmailCopy") }}</p>
          </div>
          <div v-if="!props.store.state.accountSecurity.email_verified" class="account-email-form">
            <input v-model="props.store.state.forms.email" type="email" :placeholder="t('emailPlaceholder')" />
            <input v-model="props.store.state.forms.emailPassword" type="password" :placeholder="t('currentPassword')" />
            <button class="primary-button compact-button" @click="props.store.requestEmailVerification().catch(props.store.handleError)">{{ t("sendVerificationCode") }}</button>
            <input v-if="props.store.state.forms.emailRequestID" v-model="props.store.state.forms.emailCode" inputmode="numeric" :placeholder="t('emailCodePlaceholder')" />
            <button v-if="props.store.state.forms.emailRequestID" class="ghost-button compact-button" @click="props.store.confirmEmailVerification().catch(props.store.handleError)">{{ t("confirmEmail") }}</button>
          </div>
        </div>
      </article>

      <article class="panel">
        <div class="panel-head">
          <div>
            <p>{{ t("personalPreferencesEyebrow") }}</p>
            <h3>{{ t("personalPreferencesTitle") }}</h3>
          </div>
          <MonitorCog :size="21" class="panel-head-icon" aria-hidden="true" />
        </div>
        <div class="stack-list">
          <label class="field">
            <span>{{ t("themeMode") }}</span>
            <select v-model="themeMode">
              <option value="light">{{ t("themeLight") }}</option>
              <option value="dark">{{ t("themeDark") }}</option>
              <option value="system">{{ t("themeSystem") }}</option>
            </select>
          </label>
          <p class="field-hint">{{ t("themeResolved", { mode: t(`theme${themeState.resolved === "dark" ? "Dark" : "Light"}`) }) }}</p>
          <label class="field">
            <span>{{ t("localeLabel") }}</span>
            <select :value="i18nState.locale" @change="setLocale($event.target.value)">
              <option v-for="item in locales" :key="item.value" :value="item.value">{{ item.label }}</option>
            </select>
          </label>
          <p class="field-hint">{{ t("personalPreferencesStored") }}</p>
        </div>
      </article>

      <article class="panel panel-span-12 account-security-card">
        <div class="panel-head">
          <div>
            <p>{{ t("accountSecurityEyebrow") }}</p>
            <h3>{{ t("accountSecurityTitle") }}</h3>
          </div>
          <Sparkles :size="21" class="panel-head-icon" aria-hidden="true" />
        </div>
        <div class="security-method-grid">
          <div class="security-method-card">
            <div class="security-method-icon"><KeyRound :size="19" /></div>
            <div class="security-method-content">
              <strong>{{ t("otpTitle") }}</strong>
              <p v-if="props.store.state.accountSecurity.otp_enabled">{{ t("otpEnabledStatus", { count: props.store.state.accountSecurity.recovery_codes_remaining }) }}</p>
              <p v-else-if="otpSupported">{{ t("otpSetupCopy") }}</p>
              <p v-else class="field-hint passkey-origin-hint">{{ t("otpUnavailable") }}</p>
              <div v-if="otpSupported && !props.store.state.accountSecurity.otp_enabled && !props.store.state.accountSecurity.setup" class="security-method-form">
                <button class="primary-button compact-button" @click="beginOTPSetup">{{ t("otpStartSetup") }}</button>
              </div>
              <div v-else-if="otpSupported && !props.store.state.accountSecurity.otp_enabled && props.store.state.accountSecurity.setup" class="security-method-form">
                <label class="field"><span>{{ t("otpSecret") }}</span><input :value="props.store.state.accountSecurity.setup.secret" readonly /></label>
                <label class="field"><span>{{ t("otpURI") }}</span><input :value="props.store.state.accountSecurity.setup.otpauth_uri" readonly /></label>
                <input v-model="props.store.state.forms.otpCode" inputmode="numeric" :placeholder="t('otpCodePlaceholder')" />
                <button class="primary-button compact-button" @click="props.store.verifyOTP().catch(props.store.handleError)">{{ t("otpVerifyAndEnable") }}</button>
              </div>
              <div v-else-if="otpSupported && props.store.state.accountSecurity.otp_enabled" class="security-method-form">
                <button class="ghost-button danger-text compact-button" @click="confirmOTPDisable">{{ t("otpDisable") }}</button>
              </div>
              <div v-if="props.store.state.accountSecurity.recovery_codes.length" class="recovery-code-box">
                <strong>{{ t("recoveryCodesOnce") }}</strong>
                <code v-for="code in props.store.state.accountSecurity.recovery_codes" :key="code">{{ code }}</code>
              </div>
            </div>
            <span class="status-pill" :class="props.store.state.accountSecurity.otp_enabled ? 'success' : 'muted'">{{ props.store.state.accountSecurity.otp_enabled ? t("enabled") : t("disabled") }}</span>
          </div>
          <div class="security-method-card">
            <div class="security-method-icon"><ShieldCheck :size="19" /></div>
            <div class="security-method-content">
              <strong>{{ t("passkeyTitle") }}</strong>
              <p>{{ t("passkeyStageCopy") }}</p>
              <p v-if="passkeySupportHint" class="field-hint passkey-origin-hint">{{ passkeySupportHint }}</p>
              <p class="passkey-count">{{ t("passkeyCount", { count: props.store.state.accountSecurity.passkey_list.length }) }}</p>
              <div v-if="passkeySupported" class="security-method-form">
                <input v-model="props.store.state.forms.passkeyName" :placeholder="t('passkeyNamePlaceholder')" />
                <button class="primary-button compact-button" @click="beginPasskeyRegistration">{{ t("passkeyRegister") }}</button>
              </div>
              <p v-if="!props.store.state.accountSecurity.passkey_list.length" class="field-hint">{{ t("passkeyEmpty") }}</p>
              <div v-if="props.store.state.accountSecurity.passkey_list.length" class="passkey-list">
                <div v-for="item in props.store.state.accountSecurity.passkey_list" :key="item.id" class="passkey-row">
                  <span><strong>{{ item.name || t("passkeyUnnamed") }}</strong><small>{{ t("passkeyCreatedAt", { value: formatPasskeyDate(item.created_at) }) }}</small><small v-if="item.last_used_at">{{ t("passkeyLastUsedAt", { value: formatPasskeyDate(item.last_used_at) }) }}</small></span>
                  <button class="ghost-button danger-text compact-button" @click="confirmPasskeyDelete(item)">{{ t("passkeyDelete") }}</button>
                </div>
              </div>
            </div>
            <span class="status-pill" :class="passkeySupported ? 'success' : 'muted'">{{ passkeySupported ? t("securityMethodAvailable") : t("disabled") }}</span>
          </div>
        </div>
        <p class="panel-note">{{ t("accountSecurityRoadmap") }}</p>
      </article>
    </div>
  </section>
</template>
