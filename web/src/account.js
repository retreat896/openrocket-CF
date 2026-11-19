import './style.css';
import { currentUser, signOut } from './base44.js';
import { $, avatar, confirmDialog, h, icon } from './common.js';

for (const el of document.querySelectorAll('[data-icon]')) el.replaceWith(icon(el.dataset.icon));

async function main() {
  const me = await currentUser();
  $('#loading').hidden = true;
  if (!me) {
    $('#signed-out').hidden = false;
    return;
  }

  const out = h('button', { class: 'ghost', title: 'Sign out' }, icon('logout'), 'Sign out');
  out.onclick = signOut;
  $('#me').replaceChildren(avatar(me), h('span', { class: 'name' }, me.name), out);
  $('#me').hidden = false;
  $('#account').hidden = false;
  $('#now').replaceChildren(
    h('div', { class: 'acct-card acct-open' },
      h('h3', {}, 'Free account'),
      h('p', {}, 'All features are included at no cost.'),
      h('p', { class: 'hint' }, `${me.name} · ${me.email}`),
    ),
  );

  $('#delete-account').onclick = async () => {
    if (!(await confirmDialog(
      'Delete your account?',
      'This permanently deletes your account, owned designs, memberships and custom motors. This cannot be undone.',
      'Delete account',
      true,
    ))) return;

    const response = await fetch('/auth/delete', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'X-ORC-Client': '1' },
    });
    if (!response.ok) {
      const value = await response.json().catch(() => null);
      throw new Error(value?.error || 'Could not delete the account.');
    }
    location.href = '/';
  };
}

main().catch((error) => {
  $('#loading').replaceChildren(h('p', { class: 'error' }, error.message));
  $('#loading').hidden = false;
});
