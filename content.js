(function () {
  const PANEL_ID = 'mailshield-panel';
  const PANEL_MESSAGE_KEY = 'mailshield-current-message';
  let lastScanAt = 0;
  let lastMessageKey = '';

  async function getStorageSettings() {
    return new Promise((resolve) => {
      chrome.storage.sync.get({ autoAnalyze: false }, (items) => resolve(items));
    });
  }

  function escapeHtml(value) {
    return String(value || '')
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function normalizeText(value) {
    return String(value || '').replace(/\s+/g, ' ').trim();
  }

  function createMessageKey(emailData) {
    const sender = normalizeText(emailData.sender || '');
    const subject = normalizeText(emailData.subject || '');
    const content = normalizeText(emailData.content || '').slice(0, 200);
    return `${sender}|${subject}|${content}`;
  }

  function findMessageContainer() {
    const selectors = [
      'div[role="main"]',
      'div[role="list"]',
      '.ii',
      '.nH',
      '.adn',
      'div[aria-label*="Mensaje"]',
      'div[role="article"]'
    ];

    for (const selector of selectors) {
      const element = document.querySelector(selector);
      if (element && (element.textContent || '').trim().length > 20) {
        return element;
      }
    }

    return document.body;
  }

  function getVisibleText(node) {
    if (!node) return '';
    return (node.textContent || '').replace(/\s+/g, ' ').trim();
  }

  function getEmailSender() {
    const selectors = [
      'span[email]',
      'a[href^="mailto:"]',
      '[data-sender-name]',
      'span[title*="@"]',
      '.g2',
      '.go',
      '.iw'
    ];

    for (const selector of selectors) {
      const nodeList = document.querySelectorAll(selector);
      for (const element of nodeList) {
        const text = getVisibleText(element);
        if (text && text.includes('@')) {
          return text;
        }
      }
    }

    return '';
  }

  function getEmailSenderName() {
    const candidate = document.querySelector('[data-sender-name]');
    if (candidate) return candidate.dataset.senderName || candidate.textContent || '';

    const selectors = ['.gD', '.hI', '.hN', '.g2', '.ig'];
    for (const selector of selectors) {
      const node = document.querySelector(selector);
      if (node) {
        const text = getVisibleText(node).replace(/\s*<.*?>\s*/g, '').trim();
        if (text && !text.includes('@')) {
          return text;
        }
      }
    }

    return '';
  }

  function getEmailSubject() {
    const selectors = ['h2', '.hP', '.ha', '.hN', '[data-thread-id]'];
    for (const selector of selectors) {
      const node = document.querySelector(selector);
      if (node) {
        const text = getVisibleText(node);
        if (text && text.length > 2) return text;
      }
    }
    return '';
  }

  function getEmailContent() {
    const container = findMessageContainer();
    if (!container) return '';

    const selectors = [
      'div[role="article"]',
      '.ii',
      '.gs',
      '.a3s',
      '.msg',
      '.adn',
      'div[dir="ltr"]'
    ];

    let bestMatch = '';

    for (const selector of selectors) {
      const nodes = container.querySelectorAll(selector);
      for (const node of nodes) {
        const text = getVisibleText(node);
        if (text.length > 40 && text.length > bestMatch.length) {
          bestMatch = text;
        }
      }
    }

    if (bestMatch) return bestMatch;

    const textChunks = Array.from(container.querySelectorAll('p, span, div'))
      .map((node) => getVisibleText(node))
      .filter((text) => text.length > 25)
      .sort((a, b) => b.length - a.length);

    return textChunks[0] || '';
  }

  function getEmailLinks() {
    const container = findMessageContainer();
    if (!container) return [];

    const links = [];
    const seen = new Set();

    container.querySelectorAll('a[href]').forEach((element) => {
      const href = element.getAttribute('href');
      if (!href || href === '#' || href.startsWith('javascript:')) return;
      const key = `${href}|${element.textContent}`;
      if (seen.has(key)) return;
      seen.add(key);
      links.push({
        href,
        text: normalizeText(element.textContent)
      });
    });

    return links;
  }

  function getCurrentEmailData() {
    return {
      sender: getEmailSender(),
      senderName: getEmailSenderName(),
      subject: getEmailSubject(),
      content: getEmailContent(),
      links: getEmailLinks()
    };
  }

  function getRiskClassMeta(riskLevel) {
    const meta = {
      low: {
        text: 'No encontramos señales importantes de peligro. Esto no garantiza que el correo sea seguro',
        icon: '✔️',
        color: '#1f7a45',
        bg: '#eaf7ee'
      },
      medium: {
        text: 'Este correo contiene algunas señales sospechosas. Revísalo antes de continuar',
        icon: '⚠️',
        color: '#8a5c00',
        bg: '#fff5db'
      },
      high: {
        text: 'Este correo presenta varias señales de posible fraude. No abras sus enlaces ni compartas información personal',
        icon: '🚫',
        color: '#b3261e',
        bg: '#fee9e7'
      },
      unknown: {
        text: 'No pudimos evaluar este correo con suficiente seguridad. Actúa con precaución',
        icon: 'ℹ️',
        color: '#0b57d0',
        bg: '#eaf2ff'
      }
    };

    return meta[riskLevel] || meta.unknown;
  }

  function renderPanel(result, emailData) {
    const existing = document.getElementById(PANEL_ID);
    const messageKey = createMessageKey(emailData);

    if (existing && existing.dataset.messageKey === messageKey) {
      existing.innerHTML = buildPanelContent(result, emailData);
      return;
    }

    if (existing) {
      existing.remove();
    }

    const panel = document.createElement('div');
    panel.id = PANEL_ID;
    panel.className = 'mailshield-panel';
    panel.dataset.messageKey = messageKey;
    panel.innerHTML = buildPanelContent(result, emailData);

    const mountTarget = document.querySelector('div[role="main"]') || document.body;
    if (mountTarget) {
      mountTarget.appendChild(panel);
    }
  }

  function buildPanelContent(result, emailData) {
    const meta = getRiskClassMeta(result.riskLevel || 'unknown');
    const findings = (result.findings || []).length ? result.findings : ['No se identificaron señales sospechosas claras.'];
    const recommendations = (result.recommendations || []).length ? result.recommendations : ['Verifica la autenticidad del correo antes de continuar.'];

    return `
      <div class="mailshield-panel-shell" style="background:${meta.bg}; border-left: 6px solid ${meta.color};">
        <div class="mailshield-header">
          <div class="mailshield-brand">
            <span class="mailshield-logo">M</span>
            <span>MailShield</span>
          </div>
          <div class="mailshield-status">${meta.icon} ${result.riskLevel ? result.riskLevel.toUpperCase() : 'DESCONOCIDO'}</div>
        </div>

        <div class="mailshield-summary">
          <div class="mailshield-risk-badge" style="color:${meta.color}; border-color:${meta.color};">
            Riesgo ${result.riskLevel ? result.riskLevel.toUpperCase() : 'DESCONOCIDO'}
          </div>
          <div class="mailshield-score">Puntuación: ${result.riskScore ?? 0}/100</div>
        </div>

        <div class="mailshield-alert" style="color:${meta.color};">
          <strong>${meta.icon} ${meta.text}</strong>
        </div>

        <div class="mailshield-section">
          <h3>¿Por qué recibiste esta alerta?</h3>
          <ul>
            ${findings.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}
          </ul>
        </div>

        <div class="mailshield-section">
          <h3>¿Qué deberías hacer?</h3>
          <ul>
            ${recommendations.map((item) => `<li>${escapeHtml(item)}</li>`).join('')}
          </ul>
        </div>

        <div class="mailshield-actions">
          <button type="button" class="mailshield-action-btn primary" data-mailshield-action="reanalyze">Volver a analizar</button>
          <button type="button" class="mailshield-action-btn secondary" data-mailshield-action="close">Cerrar</button>
        </div>
      </div>
    `;
  }

  function handleActions(event) {
    const button = event.target.closest('[data-mailshield-action]');
    if (!button) return;

    const { mailshieldAction } = button.dataset;
    if (mailshieldAction === 'close') {
      const panel = document.getElementById(PANEL_ID);
      if (panel) panel.remove();
    }

    if (mailshieldAction === 'reanalyze') {
      analyzeCurrentMessage(true);
    }
  }

  function analyzeCurrentMessage(force = false) {
    const now = Date.now();
    if (!force && now - lastScanAt < 800) {
      return;
    }

    lastScanAt = now;

    const emailData = getCurrentEmailData();
    const messageKey = createMessageKey(emailData);
    if (!messageKey) return;

    if (lastMessageKey === messageKey && !force && document.getElementById(PANEL_ID)) {
      return;
    }

    lastMessageKey = messageKey;

    const result = window.phishingDetector?.analyzeEmail ? window.phishingDetector.analyzeEmail(emailData) : {
      riskLevel: 'unknown',
      riskScore: 0,
      findings: ['No se pudo inicializar el detector de phishing.'],
      explanation: 'No pudimos evaluar este correo con suficiente seguridad.',
      recommendations: ['Intenta otra vez más adelante.'],
      confidence: 'low'
    };

    renderPanel(result, emailData);
  }

  function applyObserver() {
    const root = document.body;
    if (!root || root.dataset.mailshieldObserverAttached === 'true') return;

    const observer = new MutationObserver(() => {
      if (document.getElementById(PANEL_ID)) {
        return;
      }
      setTimeout(() => analyzeCurrentMessage(false), 250);
    });

    observer.observe(root, {
      childList: true,
      subtree: true,
      attributes: true
    });

    root.dataset.mailshieldObserverAttached = 'true';
  }

  document.addEventListener('click', handleActions);

  async function init() {
    const settings = await getStorageSettings();
    const shouldAutoAnalyze = !!settings.autoAnalyze;

    applyObserver();

    if (shouldAutoAnalyze) {
      analyzeCurrentMessage(true);
    }

    const panel = document.getElementById(PANEL_ID);
    if (!panel && shouldAutoAnalyze) {
      setTimeout(() => analyzeCurrentMessage(true), 600);
    }

    document.addEventListener('keydown', (event) => {
      if (event.key === 'Escape') {
        const panel = document.getElementById(PANEL_ID);
        if (panel) panel.remove();
      }
    });
  }

  init();
})();
