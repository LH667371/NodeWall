package api

import (
	"html/template"
	"net/http"
	"time"
)

var forgotPasswordPage = template.Must(template.New("forgot-password").Parse(forgotPasswordHTML))

func (a *authManager) serveForgotPassword(w http.ResponseWriter, r *http.Request) {
	locale := loginLocaleFromRequest(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	_ = forgotPasswordPage.Execute(w, map[string]any{
		"Locale":        locale,
		"Messages":      loginMessages(locale),
		"ResendSeconds": int(emailChallengeCooldown / time.Second),
	})
}

const authBackdropCSS = `
      .login-shell,.recovery-shell{
        background:radial-gradient(ellipse at 12% 12%,rgba(45,212,191,.18),transparent 38%),
          radial-gradient(ellipse at 38% 79%,rgba(129,107,225,.16),transparent 42%),
          radial-gradient(ellipse at 83% 16%,rgba(56,189,248,.1),transparent 43%),
          linear-gradient(135deg,#0d1e2b,#0b1725 59%,#08121e);
      }
      /* The grid is static to limit repaints over remote desktop connections. */
      .login-shell:before,.recovery-shell:before{content:"";position:absolute;inset:0;pointer-events:none;background-image:linear-gradient(rgba(94,234,212,.06) 1px,transparent 1px),linear-gradient(90deg,rgba(94,234,212,.06) 1px,transparent 1px);background-size:44px 44px;mask-image:radial-gradient(ellipse at 19% 35%,#000,transparent 67%)}
`

const forgotPasswordHTML = `<!DOCTYPE html>
<html lang="{{.Locale}}">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>{{.Messages.forgotTitle}}</title>
    <link rel="icon" type="image/svg+xml" href="/nodewall-mark.svg" />
    <style>` + authBackdropCSS + `
      :root{color-scheme:dark}
      *{box-sizing:border-box}
      [hidden]{display:none!important}
      body{margin:0;background:#0a121d;color:#f8fafc;font-family:"IBM Plex Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
      .recovery-shell{position:relative;isolation:isolate;display:grid;min-height:100vh;align-content:start;justify-items:center;padding:clamp(24px,11vh,112px) 16px 40px}
      .recovery-panel{
        position:relative;width:min(100%,492px);padding:clamp(20px,4vw,32px);
        border:1px solid transparent;border-radius:22px;
        background:linear-gradient(#101f2e,#0d1a28) padding-box,linear-gradient(135deg,rgba(94,234,212,.62),rgba(56,189,248,.14) 48%,rgba(167,139,250,.42)) border-box;
        box-shadow:0 24px 64px rgba(2,6,23,.32);
      }
      .recovery-panel:before{content:"";position:absolute;top:-1px;left:26px;width:90px;height:2px;border-radius:2px;background:linear-gradient(90deg,transparent,#67e8df,transparent);pointer-events:none}
      .recovery-brand{display:flex;align-items:center;gap:11px;font-size:.9rem;font-weight:700;color:#d5f5f6}
      .recovery-mark{display:grid;place-items:center;width:38px;height:38px;border:1px solid #396970;border-radius:11px;background:#16323f}
      .recovery-mark img{display:block;width:26px;height:26px}
      h1{margin:18px 0 20px;font-size:clamp(1.55rem,4vw,2.05rem);line-height:1.2;letter-spacing:-.035em}
      .recovery-steps{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px;padding:0;margin:0 0 22px;list-style:none}
      .recovery-steps li{display:flex;min-width:0;min-height:46px;align-items:center;gap:8px;padding:8px 10px;border:1px solid #304357;border-radius:10px;color:#b8c7d5;font-size:.84rem;font-weight:600}
      .recovery-steps li[aria-current="step"]{border-color:#367a7d;background:#16313b;color:#c5fcf3}
      .recovery-step-number{flex:none;display:grid;place-items:center;width:21px;height:21px;border-radius:50%;background:#23384a;font-size:.72rem;font-variant-numeric:tabular-nums}
      [aria-current="step"] .recovery-step-number{background:#5eead4;color:#10262c}
      .recovery-form,.recovery-field{display:grid;min-width:0;gap:14px}
      .recovery-field{gap:7px}
      .recovery-lead{margin:0;color:#b8c7d5;font-size:.88rem;line-height:1.55}
      .recovery-field label{color:#d2dfeb;font-size:.84rem;font-weight:600}
      input,button,select{font:inherit}
      input{display:block;min-width:0;width:100%;min-height:44px;padding:10px 12px;border:1px solid #304357;border-radius:9px;background:#172536;color:#f8fafc}
      input::placeholder{color:#92a8ba}
      :is(input,button,a,select):focus-visible{outline:2px solid #5eead4;outline-offset:2px}
      .recovery-button{min-height:44px;padding:9px 12px;border:1px solid #3b5063;border-radius:9px;background:#172c3c;color:#d5f5f6;font-size:.88rem;font-weight:650;cursor:pointer}
      .recovery-button:hover:not(:disabled){border-color:#5eead4}
      .recovery-button:disabled{opacity:.55;cursor:default}
      .recovery-primary{width:100%;border-color:#3d9c9e;background:linear-gradient(105deg,#10776e,#087a9a);color:#fff}
      .recovery-account{display:flex;min-width:0;align-items:center;gap:12px;padding:9px 10px 9px 12px;border:1px solid #304357;border-radius:10px;background:#0d1926}
      .recovery-account>div{flex:1;min-width:0;overflow-wrap:anywhere}
      .recovery-account-label{display:block;margin-bottom:3px;color:#aabccc;font-size:.76rem}
      #recovery-account-name{font-size:.89rem}
      .recovery-account button{min-height:34px;padding:6px 9px}
      .recovery-code-row,.recovery-passwords{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:end;gap:10px}
      .recovery-passwords{grid-template-columns:repeat(2,minmax(0,1fr))}
      #recovery-code{letter-spacing:.13em;font-variant-numeric:tabular-nums}
      .recovery-feedback{min-height:1.4em;margin:12px 0 0;color:#fca5a5;font-size:.84rem;line-height:1.45;overflow-wrap:anywhere}
      .recovery-feedback[data-tone="notice"],.recovery-complete{color:#99f6e4}
      .recovery-complete{padding:14px;border:1px solid #376965;border-radius:10px;background:#122c31;font-size:.9rem;line-height:1.5}
      .recovery-footer{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:10px;margin-top:8px;padding-top:16px;border-top:1px solid #304357;font-size:.82rem}
      .recovery-back{display:inline-flex;gap:7px;align-items:center;color:#99f6e4;text-decoration:none}
      .recovery-back:hover{text-decoration:underline;text-underline-offset:3px}
      .recovery-locale{display:flex;align-items:center;gap:8px;color:#b8c7d5}
      .recovery-locale select{padding:7px 8px;border:1px solid #304357;border-radius:8px;background:#172536;color:#f8fafc}
      @media(max-width:450px){
        .recovery-passwords{grid-template-columns:minmax(0,1fr)}
        .recovery-steps li{padding-inline:7px;gap:6px}
      }
    </style>
  </head>
  <body>
    <main class="recovery-shell">
      <section class="recovery-panel" id="recovery-panel" aria-labelledby="recovery-title" data-resend-seconds="{{.ResendSeconds}}">
        <div class="recovery-brand"><span class="recovery-mark"><img src="/nodewall-mark.svg" alt="" /></span><span>NodeWall</span></div>
        <h1 id="recovery-title">{{.Messages.forgotHeading}}</h1>
        <ol class="recovery-steps" aria-label="{{.Messages.forgotStepsLabel}}">
          <li id="recovery-request-step" aria-current="step"><span class="recovery-step-number" aria-hidden="true">1</span>{{.Messages.forgotRequest}}</li>
          <li id="recovery-reset-step"><span class="recovery-step-number" aria-hidden="true">2</span>{{.Messages.forgotResetStep}}</li>
        </ol>
        <form class="recovery-form" id="recovery-request-form" method="post" action="/auth/forgot-password/request?lang={{.Locale}}">
          <p class="recovery-lead">{{.Messages.forgotHint}}</p>
          <div class="recovery-field">
            <label for="recovery-username">{{.Messages.usernamePlaceholder}}</label>
            <input id="recovery-username" name="username" type="text" autocomplete="username" autocapitalize="none" autocorrect="off" spellcheck="false" required />
          </div>
          <button class="recovery-button recovery-primary" id="recovery-request" type="submit" disabled>{{.Messages.forgotRequest}}</button>
        </form>
        <form class="recovery-form" id="recovery-reset-form" method="post" action="/auth/forgot-password/reset?lang={{.Locale}}" hidden>
          <div class="recovery-account">
            <div><span class="recovery-account-label">{{.Messages.usernamePlaceholder}}</span><strong id="recovery-account-name"></strong></div>
            <button class="recovery-button" id="recovery-edit" type="button">{{.Messages.forgotEditAccount}}</button>
          </div>
          <p class="recovery-lead">{{.Messages.forgotRequestSent}}</p>
          <div class="recovery-code-row">
            <div class="recovery-field">
              <label for="recovery-code">{{.Messages.forgotCode}}</label>
              <input id="recovery-code" name="code" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" required />
            </div>
            <button class="recovery-button" id="recovery-resend" type="button" disabled>{{.Messages.forgotResend}}</button>
          </div>
          <div class="recovery-passwords">
            <div class="recovery-field">
              <label for="recovery-password">{{.Messages.forgotNewPassword}}</label>
              <input id="recovery-password" name="new_password" type="password" autocomplete="new-password" required />
            </div>
            <div class="recovery-field">
              <label for="recovery-confirm">{{.Messages.forgotConfirmPassword}}</label>
              <input id="recovery-confirm" type="password" autocomplete="new-password" required />
            </div>
          </div>
          <button class="recovery-button recovery-primary" id="recovery-reset" type="submit" disabled>{{.Messages.forgotReset}}</button>
        </form>
        <div class="recovery-complete" id="recovery-complete" tabindex="-1" hidden>{{.Messages.forgotResetSuccess}}</div>
        <p class="recovery-feedback" id="recovery-feedback" role="status"></p>
        <footer class="recovery-footer">
          <a class="recovery-back" id="recovery-login-link" href="/login?lang={{.Locale}}"><span aria-hidden="true">←</span>{{.Messages.forgotBack}}</a>
          <div class="recovery-locale">
            <label for="recovery-locale">{{.Messages.localeLabel}}</label>
            <select id="recovery-locale">
              <option value="zh-CN" {{if eq .Locale "zh-CN"}}selected{{end}}>{{.Messages.localeChinese}}</option>
              <option value="en-US" {{if eq .Locale "en-US"}}selected{{end}}>{{.Messages.localeEnglish}}</option>
            </select>
          </div>
        </footer>
      </section>
    </main>
    <script>
      (() => {
        const element = (id) => document.getElementById('recovery-' + id);
        const requestForm = element('request-form');
        const resetForm = element('reset-form');
        const username = element('username');
        const code = element('code');
        const password = element('password');
        const confirmation = element('confirm');
        const locale = element('locale');
        const requestButton = element('request');
        const resendButton = element('resend');
        const resetButton = element('reset');
        const editButton = element('edit');
        const feedback = element('feedback');
        const complete = element('complete');
        const resendDelay = Number(element('panel').dataset.resendSeconds) * 1000;
        const messages = {
          request: {{.Messages.forgotRequest}},
          resend: {{.Messages.forgotResend}},
          reset: {{.Messages.forgotReset}},
          sending: {{.Messages.forgotSendPending}},
          resetting: {{.Messages.forgotResetPending}},
          resendAccepted: {{.Messages.forgotResendAccepted}},
          requestFailed: {{.Messages.forgotRequestFailed}},
          resetFailed: {{.Messages.forgotResetFailed}},
          missingUsername: {{.Messages.forgotUsernameRequired}},
          invalidCode: {{.Messages.forgotCodeInvalid}},
          mismatch: {{.Messages.forgotPasswordsMismatch}},
          shortPassword: {{.Messages.forgotPasswordTooShort}},
          rateLimited: {{.Messages.forgotRateLimited}},
          retryAfter: {{.Messages.loginRateLimited}},
          resetUncertain: {{.Messages.forgotResetUncertain}},
        };
        let activeRequest = null;
        let pending = '';
        const retryAt = { request: 0, reset: 0 };

        const showFeedback = (text, tone = 'error') => {
          feedback.dataset.tone = tone;
          feedback.textContent = text;
        };
        const showStep = (step) => {
          requestForm.hidden = step !== 'request';
          resetForm.hidden = step !== 'reset';
          complete.hidden = step !== 'complete';
          element('request-step').setAttribute('aria-current', step === 'request' ? 'step' : 'false');
          element('reset-step').setAttribute('aria-current', step === 'request' ? 'false' : 'step');
        };
        const updateControls = () => {
          const now = Date.now();
          const busy = pending !== '';
          const requestLocked = busy || now < retryAt.request;
          requestButton.disabled = requestLocked;
          resendButton.disabled = requestLocked || !activeRequest || now < activeRequest.resendAt;
          resetButton.disabled = busy || !activeRequest || now < retryAt.reset;
          editButton.disabled = locale.disabled = busy;
          username.readOnly = code.readOnly = password.readOnly = confirmation.readOnly = busy;
          requestButton.textContent = pending === 'request' ? messages.sending : messages.request;
          resendButton.textContent = pending === 'request' ? messages.sending : messages.resend;
          resetButton.textContent = pending === 'reset' ? messages.resetting : messages.reset;
          requestForm.setAttribute('aria-busy', String(pending === 'request' && !requestForm.hidden));
          resetForm.setAttribute('aria-busy', String(busy && !resetForm.hidden));
        };

        const post = async (action, form, payload) => {
          const fallback = action === 'request' ? messages.requestFailed : messages.resetFailed;
          let response;
          try {
            response = await fetch(form.action, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify(payload),
              credentials: 'same-origin',
              redirect: 'error',
            });
          } catch (_) {
            return { error: action === 'reset' ? messages.resetUncertain : fallback };
          }
          if (response.status === 429) {
            const seconds = Number(response.headers.get('Retry-After'));
            if (Number.isFinite(seconds) && seconds > 0) {
              retryAt[action] = Date.now() + seconds * 1000;
              window.setTimeout(updateControls, seconds * 1000);
              return { error: messages.retryAfter.replace('%d', Math.ceil(seconds)) };
            }
            return { error: messages.rateLimited };
          }
          const data = await response.json().catch(() => null);
          if (response.ok) return { data };
          const reason = String(data?.error || '');
          if (action === 'reset') {
            if (reason.includes('invalid or expired') || reason.includes('no longer valid')) return { error: messages.invalidCode };
            if (reason.includes('at least 8 characters')) return { error: messages.shortPassword };
          }
          return { error: fallback };
        };

        const sendCode = async (account) => {
          if (pending || Date.now() < retryAt.request) return;
          if (!account) {
            showFeedback(messages.missingUsername);
            username.focus();
            return;
          }
          // Returning to the same account during the mail cooldown should
          // keep its request ID rather than replace it with another response.
          if (activeRequest?.username.toLowerCase() === account.toLowerCase() && Date.now() < activeRequest.resendAt) {
            showStep('reset');
            code.focus();
            return;
          }
          const resending = !resetForm.hidden;
          pending = 'request';
          showFeedback('');
          updateControls();
          try {
            const result = await post('request', requestForm, { username: account });
            const data = result.data;
            if (data?.status !== 'accepted' || typeof data.request_id !== 'string' || !data.request_id) {
              showFeedback(result.error || messages.requestFailed);
              return;
            }
            activeRequest = { username: account, id: data.request_id, resendAt: Date.now() + resendDelay };
            element('account-name').textContent = account;
            code.value = '';
            showStep('reset');
            // The backend deliberately returns the same result for accounts
            // with no verified address. Keep the confirmation conditional.
            if (resending) showFeedback(messages.resendAccepted, 'notice');
            window.setTimeout(updateControls, resendDelay);
          } finally {
            pending = '';
            updateControls();
          }
          code.focus();
        };

        requestForm.addEventListener('submit', (event) => {
          event.preventDefault();
          return sendCode(username.value.trim());
        });
        resendButton.addEventListener('click', () => {
          if (activeRequest && Date.now() >= activeRequest.resendAt) return sendCode(activeRequest.username);
        });
        editButton.addEventListener('click', () => {
          if (pending) return;
          resetForm.reset();
          showStep('request');
          showFeedback('');
          username.focus();
        });
        resetForm.addEventListener('submit', async (event) => {
          event.preventDefault();
          if (pending || !activeRequest || Date.now() < retryAt.reset) return;
          const newPassword = password.value.trim();
          if (newPassword !== confirmation.value.trim()) {
            showFeedback(messages.mismatch);
            confirmation.focus();
            return;
          }
          pending = 'reset';
          showFeedback('');
          updateControls();
          try {
            const payload = { request_id: activeRequest.id, code: code.value.trim(), new_password: newPassword };
            const result = await post('reset', resetForm, payload);
            if (result.data?.status !== 'reset') {
              showFeedback(result.error || messages.resetUncertain);
              return;
            }
            activeRequest = null;
            resetForm.reset();
            showStep('complete');
            complete.focus();
            window.setTimeout(() => window.location.assign(element('login-link').href), 900);
          } finally {
            pending = '';
            updateControls();
          }
        });
        locale.addEventListener('change', () => {
          window.location.assign('/login/forgot?lang=' + encodeURIComponent(locale.value));
        });
        updateControls();
      })();
    </script>
  </body>
</html>`
