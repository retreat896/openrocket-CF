import './auth.css';

const loginTab = document.querySelector('#login-tab');
const registerTab = document.querySelector('#register-tab');
const loginForm = document.querySelector('#login-form');
const registerForm = document.querySelector('#register-form');
const errorBox = document.querySelector('#auth-error');

function showError(message) {
  errorBox.textContent = message;
  errorBox.hidden = false;
}

function selectTab(tab) {
  const login = tab === 'login';
  loginTab.classList.toggle('active', login);
  registerTab.classList.toggle('active', !login);
  loginTab.setAttribute('aria-selected', login ? 'true' : 'false');
  registerTab.setAttribute('aria-selected', login ? 'false' : 'true');
  loginForm.hidden = !login;
  registerForm.hidden = login;
  errorBox.hidden = true;
}

loginTab.addEventListener('click', () => selectTab('login'));
registerTab.addEventListener('click', () => selectTab('register'));
selectTab('login');

async function post(path, body) {
  const response = await fetch(path, {
    method: 'POST',
    credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-ORC-Client': '1' },
    body: JSON.stringify(body),
  });
  const value = await response.json().catch(() => null);
  if (!response.ok) throw new Error(value?.error || 'Request failed.');
  return value;
}

loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    await post('/auth/login', {
      email: document.querySelector('#login-email').value,
      password: document.querySelector('#login-password').value,
    });
    const next = new URLSearchParams(location.search).get('next');
    location.href = next && next.startsWith('/') ? next : '/';
  } catch (error) {
    showError(error.message);
  }
});

registerForm.addEventListener('submit', async (event) => {
  event.preventDefault();
  try {
    await post('/auth/register', {
      name: document.querySelector('#register-name').value,
      email: document.querySelector('#register-email').value,
      password: document.querySelector('#register-password').value,
    });
    const next = new URLSearchParams(location.search).get('next');
    location.href = next && next.startsWith('/') ? next : '/';
  } catch (error) {
    showError(error.message);
  }
});
