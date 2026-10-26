'use strict';

const assert = require('assert');
const { analyzeEmail } = require('../phishingDetector.js');

const tests = [
  {
    name: 'correo legítimo de confirmación de compra',
    email: {
      sender: 'pedidos@amazon.com',
      senderName: 'Amazon',
      subject: 'Confirmación de compra',
      content: 'Gracias por tu compra. Tu pedido se ha enviado correctamente y puedes revisar el seguimiento en la web oficial.',
      links: [{ href: 'https://www.amazon.com/your-orders', text: 'ver pedido' }]
    },
    expected: 'low'
  },
  {
    name: 'banco falso pide contraseña',
    email: {
      sender: 'soporte-banco@seguridaddigital-bank.com',
      senderName: 'Banco de Seguridad',
      subject: 'Actualiza tu contraseña urgente',
      content: 'Su cuenta será bloqueada hoy. Por favor, introduce tu contraseña y código de seguridad para evitar la suspensión inmediata.',
      links: [{ href: 'https://seguridaddigital-bank.com/actualizar', text: 'Actualizar ahora' }]
    },
    expected: 'high'
  },
  {
    name: 'mensaje amenaza con cerrar cuenta',
    email: {
      sender: 'alertas@paypal.com',
      senderName: 'PayPal',
      subject: 'Cuenta bloqueada',
      content: 'Si no actúas hoy mismo, tu cuenta será suspendida y se cerrará de forma permanente. Haz clic para confirmar.',
      links: [{ href: 'https://paypal-alert.com/confirmar', text: 'Confirmar' }]
    },
    expected: 'high'
  },
  {
    name: 'enlace cuyo destino no coincide con el texto visible',
    email: {
      sender: 'atencion@club-usuarios.es',
      senderName: 'Club de Usuarios',
      subject: 'Verifica tu cuenta',
      content: 'Haz clic en la web del club para completar la verificación.',
      links: [{ href: 'https://bit.ly/verify-account', text: 'www.club-usuarios.es' }]
    },
    expected: 'high'
  },
  {
    name: 'correo con señales contradictorias',
    email: {
      sender: 'info@newsletter.com',
      senderName: 'Newsletter',
      subject: 'Tu suscripción expiró',
      content: 'Puedes ponerte en contacto con nosotros. No pedimos datos sensibles y no hay presión urgente.',
      links: [{ href: 'https://newsletter.com/renew', text: 'renovar' }]
    },
    expected: 'low'
  },
  {
    name: 'correo con información insuficiente',
    email: {
      sender: '',
      senderName: '',
      subject: '',
      content: '',
      links: []
    },
    expected: 'unknown'
  }
];

for (const testCase of tests) {
  const result = analyzeEmail(testCase.email);
  assert.strictEqual(result.riskLevel, testCase.expected, `${testCase.name}: nivel esperado ${testCase.expected}, obtenido ${result.riskLevel}`);
}

const unknownResult = analyzeEmail({ sender: '', subject: '', content: 'No hay información relevante.', links: [] });
assert.notStrictEqual(unknownResult.riskLevel, 'high', 'Los correos sin información suficiente no deben clasificarse automáticamente como fraudulentos.');

console.log('Pruebas del detector de phishing ejecutadas correctamente.');
