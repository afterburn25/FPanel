# Privora 5.0.0-dev.6.58 certification

Update package SHA-256: `16190d3941508ec67f16ba0fa673147965ba89c5447ad14cb0339a2d55f3c752`

Update package size: `17547500` bytes

New release public-key SHA-256: `b46f10757d8209ebb6e3379d35a5fdda982823407228925bace468a4c3edf412`

One-time trust transition script SHA-256: `1da2b8b403bdcf3ef248e5ada6101d48d2cfade2ac2e49f2912d4b583153e16a`

Windows Command Prompt launcher SHA-256: `ee5be4198186b400b4ed7391e986345e43a0ef0326174d49bd57cf278ed4ab10`

Certification:

- complete `scripts/verify.sh`: PASS
- exact 6.51 upload verifier + new trust: PASS
- exact 6.51 upload verifier + old trust: REJECT (expected)
- exact-package tamper test: REJECT (expected)
- ZIP integrity: PASS

The private signing key is not committed to GitHub.
