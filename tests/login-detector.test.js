const { describe, it } = require('node:test');
const assert = require('node:assert');
const LoginDetector = require('../src/analyzer/login-detector');
const { MockDocument, MockElement } = require('./test-utils');

describe('LoginDetector Tests', () => {
  it('identifies password field and awards high confidence (+50)', () => {
    const passwordInput = new MockElement('input', { type: 'password', name: 'user_password' });
    const doc = new MockDocument({
      children: [passwordInput]
    });

    const res = LoginDetector.detectInDocument(doc);
    assert.strictEqual(res.hasPasswordField, true);
    assert.ok(res.confidence >= 50, `Expected confidence >= 50, got ${res.confidence}`);
    assert.strictEqual(res.isLoginPage, true);
  });

  it('detects combined username + password + submit button login form', () => {
    const usernameInput = new MockElement('input', { type: 'text', name: 'username', autocomplete: 'username' });
    const passwordInput = new MockElement('input', { type: 'password', name: 'password', autocomplete: 'current-password' });
    const button = new MockElement('button', { type: 'submit' }, [], 'Sign In to Account');
    const form = new MockElement('form', { method: 'POST', action: '/auth/login' }, [usernameInput, passwordInput, button]);

    const doc = new MockDocument({
      url: 'https://example.com/login',
      title: 'Member Login Portal',
      children: [form]
    });

    const res = LoginDetector.detectInDocument(doc);
    assert.strictEqual(res.isLoginPage, true);
    assert.strictEqual(res.hasPasswordField, true);
    assert.strictEqual(res.hasUsernameField, true);
    assert.strictEqual(res.hasLoginButton, true);
    assert.strictEqual(res.hasAuthAutocomplete, true);
    assert.ok(res.confidence >= 80, `Expected confidence >= 80, got ${res.confidence}`);
  });

  it('correctly classifies a non-login page as isLoginPage = false', () => {
    const searchInput = new MockElement('input', { type: 'search', name: 'q', placeholder: 'Search products' });
    const button = new MockElement('button', {}, [], 'Search');
    const paragraph = new MockElement('p', {}, [], 'Welcome to our blog article about cooking recipes.');

    const doc = new MockDocument({
      url: 'https://recipes.example/blog/pasta-carbonara',
      title: 'Delicious Italian Pasta Recipe',
      children: [searchInput, button, paragraph]
    });

    const res = LoginDetector.detectInDocument(doc);
    assert.strictEqual(res.isLoginPage, false);
    assert.strictEqual(res.hasPasswordField, false);
    assert.ok(res.confidence < 35, `Expected low confidence for blog page, got ${res.confidence}`);
  });

  it('recognizes various authentication keywords in buttons and URLs', () => {
    assert.strictEqual(LoginDetector.matchesAnyKeyword('signin', ['signin']), true);
    assert.strictEqual(LoginDetector.matchesAnyKeyword('USER_AUTHENTICATION', ['auth']), true);
    assert.strictEqual(LoginDetector.matchesAnyKeyword('checkout_page', ['login', 'signin']), false);
  });
});
