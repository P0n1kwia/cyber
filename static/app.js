'use strict';


const app = document.getElementById('app');
const state = { me: null, tab: 'articles', otp: null };

// ---- pomocnicze -------------------------------------------------------------

function h(tag, props = {}, ...kids) {
  const el = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === 'class') el.className = value;
    else if (key.startsWith('on')) el.addEventListener(key.slice(2), value);
    else if (value === true) el.setAttribute(key, '');
    else if (value !== false && value != null) el.setAttribute(key, value);
  }
  for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid);
  return el;
}
const field = (label, input) => h('label', {}, label, input);
const fmtDate = (sec) => new Date(sec * 1000).toLocaleString('pl-PL', { dateStyle: 'short', timeStyle: 'short' });
const can = (permission) => state.me.permissions.includes(permission);

function show(el, kind, content) {
  el.className = 'msg ' + kind;
  el.setAttribute('role', kind === 'error' ? 'alert' : 'status');
  el.replaceChildren(content);
}

function errBox(r) {
  const box = document.createElement('span');
  box.append(r.data.message || `Błąd (HTTP ${r.status})`);
  if (r.data.violations) box.append(h('ul', {}, r.data.violations.map((v) => h('li', {}, v))));
  return box;
}

async function api(method, path, body) {
  const res = await fetch('/api' + path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  let data = {};
  try { data = await res.json(); } catch { /* pusta odpowiedź */ }
  // 401 przy zalogowanym użytkowniku = sesja wygasła (np. po bezczynności) → ekran logowania
  if (res.status === 401 && state.me) renderLogin(data.message);
  return { ok: res.ok, status: res.status, data };
}

// ---- logowanie ---------------------------------------------------------------

// Pokazuje pozostały czas blokady konta i odblokowuje przycisk, gdy blokada wygaśnie.
function lockCountdown(msg, button, secs) {
  const end = Date.now() + secs * 1000;
  button.disabled = true;
  const tick = () => {
    const left = Math.ceil((end - Date.now()) / 1000);
    if (!msg.isConnected) return clearInterval(timer); // użytkownik opuścił ekran logowania
    if (left <= 0) {
      clearInterval(timer);
      button.disabled = false;
      return show(msg, 'info', 'Blokada wygasła. Możesz spróbować ponownie.');
    }
    show(msg, 'error', 'Konto jest zablokowane po zbyt wielu błędnych próbach. ' +
      `Pozostały czas blokady: ${Math.floor(left / 60)}:${String(left % 60).padStart(2, '0')}`);
  };
  const timer = setInterval(tick, 1000);
  tick();
}

function renderLogin(notice) {
  state.me = null;
  state.otp = null;
  const msg = h('div', { class: 'msg' });
  if (notice) show(msg, 'info', notice);
  const username = h('input', { autocomplete: 'username', required: true });
  const password = h('input', { type: 'password', autocomplete: 'current-password', required: true });
  const submit = h('button', { type: 'submit' }, 'Zaloguj');
  app.replaceChildren(h('form', {
    class: 'auth',
    onsubmit: async (e) => {
      e.preventDefault();
      const r = await api('POST', '/login', { username: username.value, password: password.value });
      password.value = '';
      if (r.data.error === 'account_locked') return lockCountdown(msg, submit, r.data.retry_after_secs);
      if (!r.ok) return show(msg, 'error', errBox(r));
      if (r.data.status === 'totp_required') return renderTotp();
      enterApp();
    },
  }, h('h1', {}, 'AuthLab'), field('Login', username), field('Hasło', password),
  submit, msg));
  username.focus();
}

function renderTotp() {
  const msg = h('div', { class: 'msg' });
  const code = h('input', { inputmode: 'numeric', autocomplete: 'one-time-code', required: true });
  app.replaceChildren(h('form', {
    class: 'auth',
    onsubmit: async (e) => {
      e.preventDefault();
      const r = await api('POST', '/login/totp', { code: code.value });
      code.value = '';
      if (r.ok) return enterApp();
      if (r.data.error === 'invalid_totp') return show(msg, 'error', errBox(r));
      renderLogin(r.data.message); // za dużo prób albo wygasła sesja logowania
    },
  }, h('h1', {}, 'Kod weryfikacyjny'), h('p', { class: 'muted' }, 'Wpisz kod z aplikacji uwierzytelniającej.'),
  field('Kod', code), h('button', { type: 'submit' }, 'Potwierdź'),
  h('button', { type: 'button', class: 'link', onclick: logout }, 'Anuluj'), msg));
  code.focus();
}

async function logout() {
  await api('POST', '/logout');
  renderLogin('Wylogowano.');
}

async function enterApp() {
  const r = await api('GET', '/me');
  if (!r.ok) return renderLogin();
  state.me = r.data;
  if (state.me.must_change_password) renderForcedChange();
  else { state.tab = 'articles'; renderApp(); }
}

// ---- zmiana hasła ------------------------------------------------------------

function passwordForm(onDone, forced) {
  const msg = h('div', { class: 'msg' });
  const oldPassword = h('input', { type: 'password', autocomplete: 'current-password', required: true });
  const newPassword = h('input', { type: 'password', autocomplete: 'new-password', required: true });
  const confirm = h('input', { type: 'password', autocomplete: 'new-password', required: true });
  return h('form', {
    onsubmit: async (e) => {
      e.preventDefault();
      const r = await api('POST', '/change-password', {
        old_password: oldPassword.value,
        new_password: newPassword.value,
        new_password_confirm: confirm.value,
      });
      if (!r.ok) return show(msg, 'error', errBox(r));
      oldPassword.value = newPassword.value = confirm.value = '';
      show(msg, 'ok', 'Hasło zostało zmienione.');
      if (onDone) onDone();
    },
  }, field(forced ? 'Hasło jednorazowe (obecne)' : 'Obecne hasło', oldPassword),
  field('Nowe hasło', newPassword), field('Powtórz nowe hasło', confirm),
  h('button', { type: 'submit' }, 'Zmień hasło'), msg);
}

function renderForcedChange() {
  app.replaceChildren(h('div', { class: 'auth' },
    h('h1', {}, 'Wymagana zmiana hasła'),
    h('p', {}, 'Logujesz się hasłem jednorazowym (albo Twoje hasło wygasło). Ustaw własne hasło, aby przejść dalej.'),
    passwordForm(enterApp, true),
    h('button', { class: 'link', onclick: logout }, 'Wyloguj')));
}

// ---- główny widok ------------------------------------------------------------

function renderApp() {
  const tabs = [['articles', 'Artykuły'], ['account', 'Moje konto']];
  if (can('users.manage')) tabs.push(['admin', 'Administracja']);
  const content = h('section');
  app.replaceChildren(
    h('header', { class: 'bar' },
      h('span', { class: 'brand' }, 'AuthLab'), h('span', { class: 'grow' }),
      h('span', { class: 'who' }, state.me.username), h('span', { class: 'muted' }, state.me.role),
      h('button', { class: 'plain', onclick: logout }, 'Wyloguj')),
    h('nav', {}, tabs.map(([id, label]) => h('button', {
      class: 'tab' + (state.tab === id ? ' active' : ''),
      onclick: () => { state.tab = id; renderApp(); },
    }, label))),
    content);
  ({ articles: renderArticles, account: renderAccount, admin: renderAdmin })[state.tab](content);
}

// ---- artykuły ----------------------------------------------------------------

async function renderArticles(el) {
  const r = await api('GET', '/articles');
  if (!r.ok) return el.replaceChildren(h('div', { class: 'msg error' }, errBox(r)));
  const parts = [];
  if (can('articles.create')) parts.push(newArticleForm());
  if (!r.data.articles.length) parts.push(h('p', { class: 'muted' }, 'Brak artykułów.'));
  parts.push(...r.data.articles.map(articleCard));
  el.replaceChildren(...parts);
}

function articleCard(a) {
  const mine = a.author === state.me.username;
  const canDelete = can('articles.delete_any') || (can('articles.delete_own') && mine);
  return h('article', { class: 'post' },
    h('h3', {}, a.title),
    h('p', { class: 'meta' }, h('span', {}, a.author ?? '(konto usunięte)'), h('span', {}, fmtDate(a.created_at))),
    h('p', { class: 'body' }, a.body),
    canDelete && h('button', {
      class: 'plain danger',
      onclick: async () => {
        if (!confirm('Usunąć artykuł?')) return;
        const r = await api('DELETE', '/articles/' + a.id);
        if (r.ok) renderApp(); else alert(r.data.message);
      },
    }, 'Usuń'));
}

function newArticleForm() {
  const msg = h('div', { class: 'msg' });
  const title = h('input', { maxlength: 200, required: true, placeholder: 'Tytuł' });
  const body = h('textarea', { rows: 4, required: true, placeholder: 'Treść' });
  return h('form', {
    class: 'block',
    onsubmit: async (e) => {
      e.preventDefault();
      const r = await api('POST', '/articles', { title: title.value, body: body.value });
      if (r.ok) renderApp(); else show(msg, 'error', errBox(r));
    },
  }, h('h2', {}, 'Nowy artykuł'), title, body, h('button', { type: 'submit' }, 'Dodaj'), msg);
}

// ---- moje konto --------------------------------------------------------------

function renderAccount(el) {
  const out = h('pre', { class: 'out' });
  const probe = (method, path, body) => h('button', {
    class: 'secondary',
    onclick: async () => {
      const r = await api(method, path, body);
      out.textContent = `${method} /api${path}\nHTTP ${r.status}\n${JSON.stringify(r.data, null, 2)}`;
    },
  }, `${method} /api${path}`);
  el.replaceChildren(
    h('div', { class: 'block' }, h('h2', {}, 'Zmiana hasła'), passwordForm()),
    totpCard(),
    h('div', { class: 'block' },
      h('h2', {}, 'Test autoryzacji'),
      h('p', { class: 'muted' }, 'Bezpośrednie wywołania API: serwer sam sprawdza uprawnienia roli, niezależnie od ' +
        'tego, jakie przyciski widać w interfejsie. Brak uprawnień = HTTP 403.'),
      h('div', { class: 'row' },
        probe('GET', '/admin/users'),
        probe('POST', '/articles', { title: 'Test autoryzacji', body: 'Wpis z zakładki Moje konto.' })),
      out));
}

function totpCard() {
  const card = h('div', { class: 'block' }, h('h2', {}, 'Uwierzytelnianie dwuskładnikowe (TOTP)'));
  const msg = h('div', { class: 'msg' });
  const codeInput = () => h('input', { inputmode: 'numeric', autocomplete: 'one-time-code', required: true });

  if (state.me.totp_enabled) {
    const password = h('input', { type: 'password', autocomplete: 'current-password', required: true });
    const code = codeInput();
    card.append(h('p', {}, 'Włączone.'), h('form', {
      onsubmit: async (e) => {
        e.preventDefault();
        const r = await api('POST', '/totp/disable', { password: password.value, code: code.value });
        if (!r.ok) return show(msg, 'error', errBox(r));
        state.me.totp_enabled = false;
        renderApp();
      },
    }, field('Hasło', password), field('Aktualny kod', code),
    h('button', { type: 'submit', class: 'danger' }, 'Wyłącz TOTP')), msg);
    return card;
  }

  const setup = h('div');
  card.append(h('button', {
    onclick: async () => {
      const r = await api('POST', '/totp/setup');
      if (!r.ok) return show(msg, 'error', errBox(r));
      const code = codeInput();
      setup.replaceChildren(
        h('img', { src: r.data.qr, alt: 'Kod QR', class: 'qr' }),
        h('p', {}, 'Sekret do ręcznego wpisania: ', h('code', {}, r.data.secret)),
        h('form', {
          onsubmit: async (e) => {
            e.preventDefault();
            const r2 = await api('POST', '/totp/enable', { code: code.value });
            if (!r2.ok) return show(msg, 'error', errBox(r2));
            state.me.totp_enabled = true;
            renderApp();
          },
        }, field('Kod z aplikacji', code), h('button', { type: 'submit' }, 'Potwierdź i włącz')));
    },
  }, 'Włącz TOTP'), setup, msg);
  return card;
}

// ---- administracja -----------------------------------------------------------

async function renderAdmin(el) {
  const [users, cfg] = await Promise.all([api('GET', '/admin/users'), api('GET', '/admin/settings')]);
  if (!users.ok) return el.replaceChildren(h('div', { class: 'msg error' }, errBox(users)));
  el.replaceChildren(...[otpBox(), usersCard(users.data.users), createUserCard(), cfg.ok && settingsCard(cfg.data)]
    .filter(Boolean));
}

function otpBox() {
  if (!state.otp) return null;
  const { username, password, expires } = state.otp;
  return h('div', { class: 'otp' },
    h('h2', {}, `Hasło jednorazowe dla ${username}`),
    h('p', {}, h('code', {}, password)),
    h('p', {}, `Ważne do ${fmtDate(expires)}. Wyświetlone tylko raz – przekaż je użytkownikowi. ` +
      'Przy pierwszym logowaniu musi ustawić własne hasło.'),
    h('button', { class: 'secondary', onclick: () => { state.otp = null; renderApp(); } }, 'Ukryj'));
}

function usersCard(users) {
  const rows = users.map((u) => {
    const protectedAccount = u.builtin; // tylko podpowiedź w UI – serwer i tak to egzekwuje
    const call = async (method, path, body) => {
      const r = await api(method, `/admin/users/${u.id}${path}`, body);
      if (!r.ok) alert(r.data.message);
      return r.ok ? r : null;
    };
    return h('tr', {},
      h('td', {}, h('strong', {}, u.username), u.builtin && h('span', { class: 'muted' }, ' (stałe)')),
      h('td', {}, u.full_name || '–'),
      h('td', {}, u.role),
      h('td', {}, h('span', { class: u.blocked ? 'tag bad' : 'tag' }, u.blocked ? 'zablokowany' : 'aktywny')),
      h('td', {}, u.one_time_expires_at
        ? ['jednorazowe', h('span', { class: 'sub' }, `do ${fmtDate(u.one_time_expires_at)}`)]
        : 'własne'),
      h('td', {}, h('div', { class: 'row' },
        h('button', { class: 'plain', onclick: () => editDialog(u) }, 'Edytuj'),
        h('button', {
          class: 'plain', disabled: protectedAccount,
          onclick: async () => { if (await call('PATCH', '', { blocked: !u.blocked })) renderApp(); },
        }, u.blocked ? 'Odblokuj' : 'Zablokuj'),
        h('button', {
          class: 'plain', disabled: protectedAccount,
          onclick: async () => {
            if (!confirm(`Wygenerować nowe hasło jednorazowe dla ${u.username}?`)) return;
            const r = await call('POST', '/reset-password');
            if (r) {
              state.otp = { username: u.username, password: r.data.one_time_password, expires: r.data.one_time_expires_at };
              renderApp();
            }
          },
        }, 'Reset hasła'),
        h('button', {
          class: 'plain danger', disabled: protectedAccount,
          onclick: async () => {
            if (confirm(`Usunąć użytkownika ${u.username}?`) && await call('DELETE', '')) renderApp();
          },
        }, 'Usuń'))));
  });
  return h('div', { class: 'block wide' }, h('h2', {}, `Użytkownicy (${users.length})`),
    h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, ['Login', 'Imię i nazwisko', 'Rola', 'Status', 'Hasło', 'Akcje'].map((t) => h('th', {}, t)))),
      h('tbody', {}, rows))));
}

function roleSelect(current, disabled) {
  return h('select', { disabled },
    ['Administrator', 'Redaktor', 'Czytelnik'].map((r) => h('option', { value: r, selected: r === current }, r)));
}

function editDialog(u) {
  const msg = h('div', { class: 'msg' });
  const name = h('input', { value: u.full_name });
  const role = roleSelect(u.role, u.builtin);
  const dialog = h('dialog', {}, h('form', {
    onsubmit: async (e) => {
      e.preventDefault();
      const body = { full_name: name.value };
      if (!role.disabled && role.value !== u.role) body.role = role.value;
      const r = await api('PATCH', '/admin/users/' + u.id, body);
      if (!r.ok) return show(msg, 'error', errBox(r));
      dialog.close();
      renderApp();
    },
  }, h('h2', {}, `Edycja: ${u.username}`), field('Imię i nazwisko', name), field('Rola', role),
  h('div', { class: 'row' }, h('button', { type: 'submit' }, 'Zapisz'),
    h('button', { type: 'button', class: 'secondary', onclick: () => dialog.close() }, 'Anuluj')), msg));
  dialog.addEventListener('close', () => dialog.remove());
  document.body.append(dialog);
  dialog.showModal();
}

function createUserCard() {
  const msg = h('div', { class: 'msg' });
  const username = h('input', { required: true, minlength: 3, maxlength: 32, autocomplete: 'off' });
  const name = h('input', { autocomplete: 'off' });
  const role = roleSelect('Czytelnik', false);
  return h('form', {
    class: 'block',
    onsubmit: async (e) => {
      e.preventDefault();
      const r = await api('POST', '/admin/users', { username: username.value, full_name: name.value, role: role.value });
      if (!r.ok) return show(msg, 'error', errBox(r));
      state.otp = { username: r.data.user.username, password: r.data.one_time_password, expires: r.data.one_time_expires_at };
      renderApp();
    },
  }, h('h2', {}, 'Nowy użytkownik'),
  h('div', { class: 'grid2' }, field('Login', username), field('Imię i nazwisko', name)),
  field('Rola', role), h('button', { type: 'submit' }, 'Utwórz i wygeneruj hasło jednorazowe'), msg);
}

function settingsCard(s) {
  const msg = h('div', { class: 'msg' });
  const number = (value, min, max) => h('input', { type: 'number', min, max, required: true, value });
  const minLength = number(s.min_length, 8, 64);
  const maxAge = number(s.password_max_age_days, 0, 3650);
  const idle = number(s.session_idle_minutes, 1, 1440);
  const maxAttempts = number(s.max_login_attempts, 1, 20);
  const noRepeats = h('input', { type: 'checkbox', checked: s.forbid_repeats });
  return h('form', {
    class: 'block',
    onsubmit: async (e) => {
      e.preventDefault();
      const r = await api('PUT', '/admin/settings', {
        min_length: Number(minLength.value),
        forbid_repeats: noRepeats.checked,
        password_max_age_days: Number(maxAge.value),
        session_idle_minutes: Number(idle.value),
        max_login_attempts: Number(maxAttempts.value),
      });
      if (r.ok) show(msg, 'ok', 'Ustawienia zapisane.'); else show(msg, 'error', errBox(r));
    },
  }, h('h2', {}, 'Polityka haseł, sesji i logowania'),
  field('Minimalna długość hasła', minLength),
  h('label', { class: 'check' }, noRepeats, 'Zakaz 3 lub więcej identycznych znaków z rzędu (aaa, 111)'),
  field('Ważność hasła w dniach (0 = bez wygasania)', maxAge),
  field('Czas bezczynności sesji (minuty)', idle),
  field('Błędne logowania do blokady konta na 15 minut', maxAttempts),
  h('button', { type: 'submit' }, 'Zapisz ustawienia'), msg);
}

// ---- start -------------------------------------------------------------------

enterApp();
