(function (globalScope) {
  const suspiciousPatterns = {
    urgency: [
      'urgente', 'actu*a ahora', 'hoy mismo', 'inmediatamente', 'sin demora',
      'bloquear', 'suspender', 'cerrar', 'desactivar', 'urgencia', 'ahora mismo'
    ],
    password: [
      'contraseña', 'password', 'clave de acceso', 'nueva contraseña', 'ingresa tu contraseña'
    ],
    banking: [
      'datos bancarios', 'número de cuenta', 'tarjeta', 'cvv', 'código de seguridad', 'banco', 'cuenta bancaria'
    ],
    verification: [
      'código de verificación', 'otp', 'one time password', 'código sms', 'verificar identidad'
    ],
    prize: [
      'premio', 'ganaste', 'herencia', 'sorteo', 'regalo inesperado', 'beca', 'donación'
    ],
    personal: [
      'dni', 'documento', 'dirección', 'código postal', 'número de teléfono', 'fecha de nacimiento', 'información personal'
    ],
    payment: [
      'pago urgente', 'debe abonar', 'transferencia', 'pagar ahora', 'recaudo', 'factura pendiente'
    ]
  };

  function normalizeText(value) {
    return String(value || '').toLowerCase().replace(/\s+/g, ' ').trim();
  }

  function truncateText(value, maxLength) {
    const text = String(value || '').trim();
    return text.length > maxLength ? `${text.slice(0, maxLength - 1)}…` : text;
  }

  function uniqueAdd(list, value) {
    if (!value || list.some((entry) => entry === value)) {
      return;
    }
    list.push(value);
  }

  function countMatches(text, patterns) {
    if (!text) return 0;
    return patterns.filter((pattern) => text.includes(normalizeText(pattern))).length;
  }

  function detectSuspiciousDomain(domain) {
    if (!domain) return [];
    const normalized = domain.toLowerCase();
    const issues = [];

    if (normalized.includes('xn--') || normalized.includes('bit.ly') || normalized.includes('tinyurl') || normalized.includes('goo.gl')) {
      issues.push('El dominio usa acortadores o técnicas de ocultación.');
    }

    if (/\d+\.\d+\.\d+\.\d+/.test(normalized)) {
      issues.push('La dirección parece apuntar a una IP en lugar de un dominio normal.');
    }

    if (/(paypal|bank|banc|security|secure|alert|verify|update|login|support|urgent)/.test(normalized)) {
      issues.push('El dominio imita marcas o servicios de confianza.');
    }

    return issues;
  }

  function extractDomain(url) {
    if (!url) return '';
    try {
      const cleanUrl = url.trim();
      const parser = new URL(cleanUrl, 'https://example.com');
      return parser.hostname.replace(/^www\./i, '');
    } catch (error) {
      const text = normalizeText(url);
      const match = text.match(/(?:https?:\/\/)?(?:www\.)?([^\s/]+\.[a-z]{2,})/i);
      return match ? match[1].replace(/^www\./i, '') : '';
    }
  }

  function looksLikeImitation(emailAddress, displayName) {
    const normalizedAddress = normalizeText(emailAddress || '');
    const normalizedName = normalizeText(displayName || '');
    if (!normalizedAddress.includes('@')) return false;

    const domain = normalizedAddress.split('@')[1] || '';
    const nameTerms = normalizedName.replace(/[^a-z0-9]/gi, '').toLowerCase();
    const domainTerms = domain.replace(/[^a-z0-9]/gi, '').toLowerCase();

    if (!domainTerms.length || !nameTerms.length) return false;

    if (domainTerms.includes('gmail') || domainTerms.includes('outlook') || domainTerms.includes('hotmail')) {
      return false;
    }

    const nameHints = /(banco|bank|paypal|apple|microsoft|google|amazon|netflix|dhl|ups|servientrega|santander|bbva|banorte|hsbc|paypal)/i;
    if (nameHints.test(displayName || '')) {
      return true;
    }

    return !domainTerms.includes(nameTerms.slice(0, 12)) && nameHints.test(displayName || '');
  }

  function findRiskSignals(emailData) {
    const findings = [];
    const score = { value: 0 };

    function addSignal(key, message, points) {
      uniqueAdd(findings, message);
      score.value += points;
    }

    if (!emailData) {
      addSignal('insufficient-data', 'No se pudo obtener información suficiente para evaluar el correo.', 8);
      return { findings, score: score.value };
    }

    const senderText = normalizeText(emailData.sender || '');
    const subjectText = normalizeText(emailData.subject || '');
    const contentText = normalizeText(emailData.content || '');
    const allText = `${senderText} ${subjectText} ${contentText}`;

    if (!senderText && !subjectText && !contentText) {
      addSignal('insufficient-data', 'El mensaje no aporta suficiente información para una evaluación fiable.', 10);
      return { findings, score: score.value };
    }

    if (emailData.sender && emailData.sender.includes('@')) {
      const domain = extractDomain(`mailto:${emailData.sender}`);
      const displayName = normalizeText(emailData.senderName || '');
      if (looksLikeImitation(emailData.sender, emailData.senderName)) {
        addSignal('sender-impersonation', 'El remitente intenta parecer una entidad conocida, pero la dirección no coincide con el nombre visible.', 20);
      }
      if (domain && /(?:bit\.ly|tinyurl|goo\.gl|link|redirect|verify|secure|update|alert)/.test(domain)) {
        addSignal('domain-suspicious', 'El dominio del remitente presenta indicios de suplantación o ocultación.', 12);
      }
      if (displayName && emailData.sender && emailData.sender.toLowerCase().includes('noreply') && !subjectText.includes('compra')) {
        addSignal('sender-reliability', 'El remitente no ofrece información clara para verificar su identidad.', 8);
      }
    }

    if (emailData.links && emailData.links.length > 0) {
      emailData.links.forEach((link) => {
        const text = normalizeText(link.text || '');
        const url = normalizeText(link.href || '');
        const domain = extractDomain(link.href || '');

        if (link.text && link.href && text && domain && !url.includes(domain)) {
          addSignal('link-mismatch', 'El texto visible del enlace no coincide con la dirección real a la que lleva.', 18);
        }

        if (link.href && !link.href.startsWith('mailto:') && !link.href.startsWith('tel:')) {
          const suspiciousIssues = detectSuspiciousDomain(domain);
          if (suspiciousIssues.length > 0) {
            addSignal('suspicious-domain', suspiciousIssues[0], 15);
          }

          if (/\d+\.\d+\.\d+\.\d+/.test(normalizeText(link.href))) {
            addSignal('ip-link', 'El enlace apunta a una dirección IP en lugar de un dominio reconocible.', 18);
          }
        }
      });
    }

    const passwordMatches = countMatches(allText, suspiciousPatterns.password);
    const bankingMatches = countMatches(allText, suspiciousPatterns.banking);
    const verificationMatches = countMatches(allText, suspiciousPatterns.verification);
    const prizeMatches = countMatches(allText, suspiciousPatterns.prize);
    const paymentMatches = countMatches(allText, suspiciousPatterns.payment);
    const personalMatches = countMatches(allText, suspiciousPatterns.personal);
    const urgencyMatches = countMatches(allText, suspiciousPatterns.urgency);

    if (passwordMatches > 0 || bankingMatches > 0) {
      addSignal('sensitive-request', 'El mensaje solicita contraseñas, datos bancarios o información sensible.', 18);
    }
    if (verificationMatches > 0) {
      addSignal('verification-code', 'Piden un código de verificación para desbloquear la cuenta.', 16);
    }
    if (prizeMatches > 0) {
      addSignal('unexpected-prize', 'El correo promete un premio o beneficio inesperado.', 12);
    }
    if (paymentMatches > 0 || urgencyMatches > 0) {
      addSignal('urgency-pressure', 'El mensaje te presiona para actuar rápidamente o pagar de inmediato.', 16);
    }
    if (personalMatches > 0) {
      addSignal('personal-info', 'Solicitan información personal que no parece necesaria para este tipo de correo.', 14);
    }

    const threats = ['suspender', 'bloquear', 'cerrar la cuenta', 'desactivar', 'confirmar de inmediato', 'acción requerida'];
    const hasThreat = threats.some((term) => allText.includes(term));
    if (hasThreat) {
      addSignal('account-threat', 'El correo amenaza con cerrar o bloquear la cuenta si no actúas enseguida.', 18);
    }

    const suspiciousSignalCount = findings.length;
    if (suspiciousSignalCount >= 3) {
      addSignal('combined-risk', 'Hay varias señales sospechosas a la vez, lo que aumenta el riesgo.', 8);
    }

    const riskScore = Math.min(score.value, 100);
    let riskLevel = 'low';
    let confidence = 'medium';

    if (!findings.length) {
      riskLevel = 'low';
      confidence = 'medium';
    } else if (riskScore >= 70) {
      riskLevel = 'high';
      confidence = 'high';
    } else if (riskScore >= 35) {
      riskLevel = 'medium';
      confidence = 'medium';
    } else if (riskScore > 0) {
      riskLevel = 'low';
      confidence = 'low';
    }

    const hasInsufficientSignals = findings.some((finding) => finding.toLowerCase().includes('suficiente') || finding.toLowerCase().includes('no se pudo'));
    if (hasInsufficientSignals && !findings.some((finding) => finding.toLowerCase().includes('contraseña') || finding.toLowerCase().includes('urgente') || finding.toLowerCase().includes('código') || finding.toLowerCase().includes('banco'))) {
      riskLevel = 'unknown';
      confidence = 'low';
    }

    const explanation = findings.length > 0
      ? `Se detectaron señales como ${findings.slice(0, 3).join(' · ')}`
      : 'No se observaron señales importantes de riesgo en este mensaje.';

    const recommendations = [
      'No abras enlaces si no estás seguro de la identidad del remitente.',
      'Verifica la web oficial del servicio en lugar de hacer clic directamente desde el correo.',
      'Si te piden contraseña, código de seguridad o datos bancarios, contacta directamente con la entidad.',
      'Si el mensaje te presiona a actuar enseguida, revisa la solicitud con calma antes de responder.'
    ];

    return {
      riskLevel,
      riskScore,
      findings: findings.map((item) => truncateText(item, 180)),
      explanation: truncateText(explanation, 220),
      recommendations,
      confidence
    };
  }

  function analyzeEmail(emailData) {
    const riskResult = findRiskSignals(emailData);

    if (!emailData || (!emailData.sender && !emailData.subject && !emailData.content)) {
      return {
        riskLevel: 'unknown',
        riskScore: 0,
        findings: ['No se pudo extraer contenido suficiente del correo para evaluarlo.'],
        explanation: 'No pudimos evaluar este correo con suficiente seguridad. Actúa con precaución.',
        recommendations: [
          'No abras enlaces ni compartas información personal.',
          'Confirma la identidad del remitente por otra vía.',
          'Si el remitente parece oficial, utiliza la aplicación o web oficial en lugar del enlace del correo.'
        ],
        confidence: 'low'
      };
    }

    return riskResult;
  }

  const api = { analyzeEmail };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  }

  globalScope.MailShieldDetector = api;
  globalScope.phishingDetector = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
