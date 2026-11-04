# Privora Panel 5.0.0-dev.6.12 — CSP / CSRF Frontend Recovery

Fixes the WHM-side browser error `Cannot read properties of undefined (reading 'csrf')`.

Root cause: Privora correctly sends `Content-Security-Policy: script-src 'self'`, but the admin page still initialized `window.PRIVORA` through an inline script. The browser blocked that inline script, while external `app.js` later dereferenced `window.PRIVORA.csrf` for POST/PUT actions.

Recovery removes the inline script, makes `app.js` read the existing CSRF meta tag directly, cache-busts the external asset, and adds a new `frontend_csp` installer phase so fully installed dev.6.x hosts apply only this frontend repair on resume.
