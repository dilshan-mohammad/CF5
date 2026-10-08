/**
 * Test Utilities - Mock DOM & Privacy Spy for Node.js test runner
 */

class MockElement {
  constructor(tagName, attrs = {}, children = [], textContent = '') {
    this.tagName = (tagName || 'div').toUpperCase();
    this.attributes = Object.assign({}, attrs);
    this.children = children.slice();
    this.textContent = textContent;
    this.parentElement = null;
    this._valueAccessCount = 0;

    // Attach children's parent reference
    for (const c of this.children) {
      c.parentElement = this;
    }

    // PRIVACY ENFORCEMENT SPY
    // If anything tries to read `input.value` or similar user-content properties, record it!
    Object.defineProperty(this, 'value', {
      get: () => {
        this._valueAccessCount++;
        throw new Error(`[PRIVACY VIOLATION DETECTED] Attempted to read '.value' from <${this.tagName}>`);
      },
      set: (val) => {
        this._valueAccessCount++;
        throw new Error(`[PRIVACY VIOLATION DETECTED] Attempted to write '.value' to <${this.tagName}>`);
      }
    });

    Object.defineProperty(this, 'defaultValue', {
      get: () => {
        this._valueAccessCount++;
        throw new Error(`[PRIVACY VIOLATION DETECTED] Attempted to read '.defaultValue' from <${this.tagName}>`);
      }
    });
  }

  getAttribute(name) {
    return this.attributes[name] !== undefined ? String(this.attributes[name]) : null;
  }

  hasAttribute(name) {
    return this.attributes[name] !== undefined;
  }

  matchesSelector(sel) {
    const tag = this.tagName.toLowerCase();
    const cleanSel = sel.trim().toLowerCase();
    const cls = (this.getAttribute('class') || '').toLowerCase();
    const id = (this.getAttribute('id') || '').toLowerCase();
    const role = (this.getAttribute('role') || '').toLowerCase();

    if (cleanSel === '*' || cleanSel === tag) return true;

    if (cleanSel === 'input[type="password"]') {
      return tag === 'input' && (this.getAttribute('type') || '').toLowerCase() === 'password';
    }

    if (cleanSel.startsWith('.')) {
      const className = cleanSel.slice(1);
      return cls.split(/\s+/).some((c) => c === className || c.includes(className));
    }

    if (cleanSel.startsWith('#')) {
      return id === cleanSel.slice(1);
    }

    if (cleanSel === '[role="dialog"]') {
      return role === 'dialog';
    }

    if (cleanSel === '[aria-modal="true"]') {
      return this.getAttribute('aria-modal') === 'true';
    }

    if (cleanSel.includes('button')) {
      if (tag === 'button') return true;
      if (tag === 'input' && ['submit', 'button'].includes((this.getAttribute('type') || '').toLowerCase())) return true;
      if (tag === 'a' && this.getAttribute('role') === 'button') return true;
    }

    if (cleanSel.includes('modal') || cleanSel.includes('popup') || cleanSel.includes('dialog')) {
      if (tag === 'dialog' || role === 'dialog') return true;
      if (cls.includes('modal') || cls.includes('popup') || cls.includes('dialog')) return true;
      if (id.includes('modal') || id.includes('popup') || id.includes('dialog')) return true;
    }

    return false;
  }

  closest(selector) {
    const parts = selector.split(',').map((s) => s.trim());
    let curr = this;
    while (curr) {
      if (parts.some((p) => curr.matchesSelector(p))) {
        return curr;
      }
      curr = curr.parentElement;
    }
    return null;
  }

  querySelectorAll(selector) {
    const results = [];
    const parts = selector.split(',').map((s) => s.trim());

    const matchesAny = (node) => {
      return parts.some((p) => node.matchesSelector(p));
    };

    function traverse(node) {
      for (const child of node.children) {
        if (matchesAny(child)) {
          results.push(child);
        }
        traverse(child);
      }
    }

    traverse(this);
    return results;
  }
}

class MockDocument {
  constructor(options = {}) {
    this.title = options.title || '';
    this.location = {
      href: options.url || 'https://example.com/login',
      hostname: options.hostname || 'example.com',
      protocol: options.protocol || 'https:',
      pathname: options.pathname || '/login',
      origin: options.origin || 'https://example.com'
    };
    this.body = new MockElement('body', {}, options.children || []);
  }

  querySelectorAll(selector) {
    return this.body.querySelectorAll(selector);
  }
}

module.exports = {
  MockElement,
  MockDocument
};
