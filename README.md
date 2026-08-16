## Module:

### Directives:

    Syntax:  sign_certificate certificate;
    Default: ——
    Context: http, server, location

Sets the certificate (PEM file, optionally a full chain) used to sign values in this
context. A nested location may override it with its own `sign_certificate` /
`sign_certificate_key` pair; otherwise the certificate is inherited from the nearest
enclosing http/server/location block that defines one.

    Syntax:  sign_certificate_key certificate_key;
    Default: ——
    Context: http, server, location

Sets the private key matching `sign_certificate`. Required whenever `sign_certificate`
is set in the same context.

    Syntax:  sign_password_file password_file;
    Default: ——
    Context: http, server, location

Sets the password file used to decrypt `sign_certificate_key`, if it's encrypted (same
format as nginx's own `ssl_password_file`).

    Syntax:  sign_set $variable complex_value;
    Default: ——
    Context: http, server, location

Signs `complex_value` (may contain nginx variables) with the certificate/key configured
for this location, producing a detached PKCS7/CMS signature — including any intermediate
certificates from `sign_certificate` — encoded as base64, and stores it in `$variable`.
If no certificate is configured, or signing fails for any reason, `$variable` is set to
an empty string and a diagnostic is written to error_log; the request itself is not
failed.

No other nginx modules are required — `sign_set` is implemented on nginx's own variable
API, without depending on `ngx_devel_kit`.
