# Privora Panel 5.0.0-dev.6.46 — Recovery-safe Update Center API

- Keeps `/api.php` machine-readable while normal panel PHP errors can still render the HTML Recovery Mode page.
- Adds an exact Nginx API location with `fastcgi_intercept_errors off`.
- Converts FastCGI transport failures for the API to a small JSON 503 response instead of HTML.
- Recovery-vhost reconciliation now repairs older configurations by adding the API exception.
- The browser recognizes legacy Recovery Mode HTML and treats it as a temporary retry condition rather than a package-validation failure.
- Retains 6.44 stable release trust and automatic Let’s Encrypt behavior.
