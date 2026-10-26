# MailShield

MailShield es una extensión para Google Chrome que ayuda a detectar correos electrónicos fraudulentos en Gmail. Su objetivo es proteger especialmente a personas mayores frente a estafas digitales y phishing.

## Qué hace

- Detecta sospechas en remitente, asunto, contenido y enlaces.
- Calcula un nivel de riesgo: bajo, medio, alto o desconocido.
- Explica en lenguaje sencillo por qué se considera sospechoso un correo.
- Recomienda qué hacer antes de abrir enlaces o compartir información.
- Funciona localmente y no envía el contenido del correo a servicios externos.
- Permite activar un análisis automático cuando el usuario abre un correo.

## Arquitectura

- `manifest.json`: configuración de la extensión en Manifest V3.
- `content.js`: integración con Gmail y panel visual para analizar correos.
- `phishingDetector.js`: detector basado en reglas y puntuación.
- `styles.css`: estilo del panel en Gmail.
- `popup.html`, `popup.css`, `popup.js`: popup de la extensión.
- `tests/phishingDetector.test.js`: pruebas de ejemplo del detector.

## Cómo instalar la extensión

1. Descarga o clona este repositorio.
2. Abre Chrome y entra en `chrome://extensions`.
3. Activa `Modo desarrollador`.
4. Pulsa `Cargar extensión sin empaquetar`.
5. Selecciona la carpeta del proyecto.
6. Abre Gmail y revisa un correo.

## Cómo probarlo

1. Inicia sesión en Gmail.
2. Abre un correo.
3. Si está activo el análisis automático, el panel de MailShield aparecerá solo.
4. Si no lo está, usa el botón `Analizar con MailShield` que aparece en el panel integrado con Gmail.
5. Comprueba los resultados y revisa la explicación y recomendaciones.

## Restricciones del prototipo

- Este prototipo usa reglas y puntuación, no un modelo de IA real.
- La detección puede no identificar todos los casos complejos de phishing.
- Gmail puede cambiar su estructura DOM con el tiempo, por lo que la integración debe mantenerse actualizada.
- El análisis es local y no sustituye la revisión humana en mensajes realmente importantes.
- La extensión no bloquea ni modifica correos; solo advierte y recomienda acciones.

## Ejecución de pruebas

En la terminal, desde la carpeta del proyecto:

```bash
npm test
```

Las pruebas están preparadas para verificar algunos escenarios representativos, incluyendo:

- correo legítimo
- suplantación de banco
- amenaza de bloqueo
- enlace sospechoso
- señales contradictorias
- información insuficiente

## Notas de privacidad

- No se envía el contenido del correo a servidores externos.
- No se guardan contraseñas ni datos bancarios.
- No se almacenan correos completos de forma permanente.
- La evaluación se hace localmente en el navegador.

## Limitaciones técnicas

La primera versión no crea automáticamente una clasificación definitiva como "seguro" o "fraudulento" para todos los correos. La estrategia es continuar con la precaución y ofrecer información útil al usuario.
