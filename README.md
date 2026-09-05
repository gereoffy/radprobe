# radprobe

A single-file RADIUS authentication probe / client that completes a **full TLS
handshake** (using Python's `ssl` module) and drives the inner tunnel traffic. It
can test and diagnose the common authentication methods seen on real-world RADIUS
servers (FreeRADIUS proxies, Windows NPS, eduroam-style setups):

- **EAP-PEAP** (inner EAP: MSCHAPv2 / GTC, or method probing)
- **EAP-TTLS** (inner PAP, inner EAP, or GTC)
- **EAP-TLS** outer type detection
- **bare EAP-MSCHAPv2** (no tunnel)
- **plain RADIUS PAP** (no EAP)

It also prints the server certificate chain captured from the TLS handshake, and
verifies the credential result cryptographically where possible (MSCHAPv2 `S=`
authenticator check).

It can be used two ways: as a **command-line tool** and as an **importable Python
module** via the `authenticate()` function. Both share the same parameters (see
[Parameters](#parameters)).

---

## Requirements

- **Python 3.7+** — standard library only, **no third-party dependencies**.
- Optional: **`cryptography`** (`pip install cryptography`) — only for printing
  detailed certificate fields (Subject/SAN/Issuer/Validity/Serial). Without it the
  probe still runs and prints the certificate count and the leaf SAN/CN names.

No installation step is needed: the tool is a single self-contained file
(`radprobe.py`). Copy it wherever you need it.

---

## Quick start

Command line:

```bash
# Auto-detect what the server offers, build the tunnel, list the certificate,
# do no inner authentication:
python3 radprobe.py --server 192.0.2.10 --secret s3cret --inner-auth none

# PEAP-MSCHAPv2 authentication:
python3 radprobe.py --server 192.0.2.10 --secret s3cret \
    --identity user@realm --password 'pw' --sni radius.example.org
```

As a library:

```python
from radprobe import authenticate, RESULT_ACCESS

state, message = authenticate(
    "192.0.2.10", "s3cret",
    identity="user@realm", password="pw", sni="radius.example.org",
)
if state == RESULT_ACCESS:
    print("authenticated")
else:
    print(f"not authenticated: {state} - {message}")
```

---

## Command-line usage

```
python3 radprobe.py --server <ip> --secret <psk> [options]
```

`--server` and `--secret` are required; everything else is optional (see the
[Parameters](#parameters) table). Run with `--help` for the built-in summary.

The tool prints a human-readable trace of the exchange to stdout (all messages go
to one place; there is no separate stderr channel) and exits with a status code
(see [Result states & exit codes](#result-states--exit-codes)). With `--debug`
extra debug-level lines are added to the same output.

### Examples

```bash
# 1) Let the server decide (auto). Any TLS tunnel type is used as-is; the
#    certificate is printed during the handshake.
python3 radprobe.py --server 192.0.2.10 --secret s3cret \
    --inner-auth none

# 2) PEAP-MSCHAPv2 (force PEAP, verify the server name against the cert SAN):
python3 radprobe.py --server 192.0.2.10 --secret s3cret \
    --auth peap --identity user@realm --password 'pw' \
    --sni radius.example.org

# 3) TTLS + PAP (anonymous outer identity, real inner identity):
python3 radprobe.py --server 192.0.2.10 --secret s3cret \
    --auth ttls --inner-auth pap \
    --identity anonymous@realm --inner-identity user@realm --password 'pw' \
    --sni radius.example.org

# 4) Bare EAP-MSCHAPv2 (no TLS tunnel):
python3 radprobe.py --server 192.0.2.10 --secret s3cret \
    --auth mschapv2 --identity user@realm --password 'pw'

# 5) Plain RADIUS PAP (no EAP at all):
python3 radprobe.py --server 192.0.2.10 --secret s3cret \
    --auth pap --identity user@realm --password 'pw'

# 6) Probe which inner EAP methods the server offers:
python3 radprobe.py --server 192.0.2.10 --secret s3cret \
    --auth peap --probe-methods --identity anonymous@realm

# 7) Certificate probing only, skip verification (e.g. private CA / self-signed):
python3 radprobe.py --server 192.0.2.10 --secret s3cret \
    --inner-auth none --unsafe-cert
```

---

## Library usage

Import `authenticate()` and call it with keyword arguments. Only `server` and
`secret` are positional/required; every other argument mirrors a CLI option and
uses the same default.

```python
from radprobe import (
    authenticate,
    RESULT_ACCESS, RESULT_REJECT, RESULT_ERROR, RESULT_NOAUTH,
)

state, message = authenticate(
    "192.0.2.10", "s3cret",
    auth="ttls",
    inner_auth="pap",
    identity="anonymous@realm",
    inner_identity="user@realm",
    password="pw",
    sni="radius.example.org",
    timeout=5.0,
)

if state == RESULT_ACCESS:
    ...        # credentials accepted
elif state == RESULT_REJECT:
    ...        # server rejected (wrong password / policy)
elif state == RESULT_NOAUTH:
    ...        # ran, but no authentication was attempted (probe / cert-only)
else:          # RESULT_ERROR
    ...        # could not complete (network, TLS/cert, config, protocol)
print(message) # short human-readable summary you can show to the user
```

`authenticate()` **always returns a `(state, message)` tuple and never raises**:
any network / TLS / configuration / protocol error is turned into
`(RESULT_ERROR, "<description>")`. It also resolves the NAS-IP-Address and builds
the optional RADIUS attributes internally, so you do not need to construct those
yourself.

### Async (asyncio)

Internally the library is async: the only blocking part is the RADIUS UDP
round-trip, and it is implemented with `asyncio`. `authenticate()` shown above is
just a thin synchronous wrapper that runs the async version to completion with
`asyncio.run()`. From async code (a Tornado/asyncio/FastAPI handler, etc.) call
the coroutine directly with the exact same arguments, so a multi-second wait (or a
timeout) never blocks the event loop:

```python
from radprobe import authenticate_async, RESULT_ACCESS

state, message = await authenticate_async(
    server, secret, auth="ttls", inner_auth="pap",
    identity="anonymous@realm", inner_identity=user,
    password=pw, sni="radius.example.org",
)
```

`authenticate()` and `authenticate_async()` take identical parameters and both
return the `(state, message)` tuple; `authenticate()` must **not** be called from
within a running event loop (`asyncio.run()` forbids that) — use
`authenticate_async()` there. The coroutine `probe()` is the async core that does
the actual work and **may raise** on error; `authenticate_async()` wraps it and
turns errors into `(RESULT_ERROR, message)`.

---

## Logging

By default all messages are printed with the builtin `print`. To redirect or
silence them, call `set_logger(target)` before `authenticate()`:

```python
import logging, sys
from radprobe import authenticate, set_logger

set_logger(None)                                   # discard everything (quiet)
set_logger(sys.stderr)                             # any stream (.write)
set_logger("radprobe.log")                         # append to a file (UTF-8)
set_logger(logging.getLogger("radprobe").info)     # a callback(message)
set_logger(print)                                  # back to the default
```

`set_logger()` accepts `None`, the builtin `print`, any stream object (something
with a `.write`, e.g. `sys.stdout`/`sys.stderr`/an open file), a filename string
(opened in append mode, UTF-8, line-flushed), or any callable taking a single
message string. It returns the previous logger, so you can restore it.

There is a single stream of messages, no stdout/stderr split. Debug-level lines
(the RADIUS traffic dump) are only produced when `debug=True` / `--debug`, and
they go to the same sink as the normal lines. With `set_logger(None)`, nothing is
printed and any error is still returned in the `message` from `authenticate()`.

## Parameters

The CLI flags and the `authenticate()` keyword arguments are the same thing under
two names. A `--flag-with-dashes` on the command line is the `flag_with_dashes`
keyword argument in `authenticate()`.

| CLI flag | `authenticate()` arg | Default | Meaning |
|---|---|---|---|
| `--server` | `server` | *(required)* | RADIUS/NPS server IP address. |
| `--secret` | `secret` | *(required)* | RADIUS shared secret (PSK). |
| `--port` | `port` | `1812` | RADIUS authentication UDP port. |
| `--identity` | `identity` | `"anonymous"` | Outer EAP identity (the name sent in the clear, before the tunnel). |
| `--password` | `password` | `None` | Password, used by TTLS/PAP, PEAP-MSCHAPv2, bare MSCHAPv2 and plain PAP. |
| `--password-encoding` | `password_encoding` | `"utf-8"` | Encoding for the cleartext password on the wire (plain PAP, TTLS-PAP, EAP-GTC). Use e.g. `cp1250` to mimic Windows supplicants that send accented passwords in the local ANSI code page. Does not affect MSCHAPv2 (always UTF-16LE) or the identity (always UTF-8). |
| `--auth` | `auth` | `"auto"` | Outermost method: `auto`, `peap`, `ttls`, `tls`, `mschapv2`, `pap`, `none` (see [Authentication methods](#authentication-methods)). |
| `--inner-auth` | `inner_auth` | `"eap"` | Inner authentication: `eap`, `pap`, `none` (see [Inner authentication](#inner-authentication)). |
| `--inner-identity` | `inner_identity` | `None` → falls back to `identity` | The real identity sent *inside* the tunnel. |
| `--sni` | `sni` | `None` | TLS SNI/hostname. When set (and verification is on) the server certificate name is also checked against it. |
| `--ca-cert` | `ca_cert` | `None` → system CAs | PEM file with the CA certificate(s) used to verify the server certificate. |
| `--unsafe-cert` (`--allow-unverified-cert`) | `unsafe_cert` | `False` | Disable server certificate verification (accept any/self-signed cert). Useful for cert probing or a private CA. |
| `--allow-tls13` | `allow_tls13` | `False` | Allow TLS 1.3. By default the handshake is capped at TLS 1.2 so the certificate is extractable from the cleartext handshake. |
| `--source-ip` | `source_ip` | `None` | Source IP address to bind to (multi-homed clients). |
| `--nas-ip` | `nas_ip` | `None` → `source_ip` or `127.0.0.1` | Value of the NAS-IP-Address attribute. |
| `--timeout` | `timeout` | `5.0` | UDP reply timeout in seconds. |
| `--probe-methods` | `probe_methods` | `False` | For inner EAP, walk through the candidate methods with Nak and report what the server offers. |
| `--service-type` | `service_type` | `None` | Optional Service-Type attribute (integer). |
| `--nas-port-type` | `nas_port_type` | `None` | Optional NAS-Port-Type attribute (e.g. `19` = Wireless-802.11). |
| `--calling-station-id` | `calling_station_id` | `None` | Optional Calling-Station-Id attribute (e.g. a MAC address). |
| `--framed-protocol` | `framed_protocol` | `None` | Optional Framed-Protocol attribute (integer). |
| `--debug` | `debug` | `False` | Add a short dump of the RADIUS traffic to the log output (debug level). |
| *(library only)* | `extra_attrs` | `None` | A list of raw `(type, value_bytes)` RADIUS attributes appended after the ones built from `service_type` / `nas_port_type` / `calling_station_id` / `framed_protocol`. |

---

## Authentication methods

Selected with `--auth` / `auth=`:

- **`auto`** *(default)* — use whatever the server offers, and never send a Nak.
  Any TLS tunnel type (PEAP/TTLS/TLS) is used as-is; a bare EAP-MSCHAPv2 offer is
  run if a `password` is given, otherwise it is just reported; any other
  non-tunnel offer (e.g. MD5) is reported.
- **`peap`** / **`ttls`** / **`tls`** — *force* that tunnel type. If the server
  offers a non-tunnel method, request the chosen type with a Legacy Nak.
- **`mschapv2`** — bare EAP-MSCHAPv2, no TLS tunnel (requires `password`).
- **`pap`** — plain RADIUS PAP, **not EAP** and no tunnel: a single Access-Request
  with User-Name + encrypted User-Password (requires `password`).
- **`none`** — like `auto` for tunnel types, but treats a non-tunnel offer as an
  error instead of using it.

## Inner authentication

Selected with `--inner-auth` / `inner_auth=` (applies inside a PEAP/TTLS tunnel):

- **`eap`** *(default)* — inner EAP. For PEAP the server-offered method is
  reported and, with a `password`, completed (MSCHAPv2, or GTC via Nak). For TTLS
  the inner EAP runs inside an EAP-Message AVP.
- **`pap`** — **TTLS only**: sends User-Name + User-Password AVPs inside the tunnel
  (cleartext password protected by TLS). Requires `password`.
- **`none`** — build the tunnel and print the certificate, but attempt no inner
  authentication. Useful for certificate probing.

---

## Result states & exit codes

`authenticate()` returns one of these `state` values (also exposed as module
constants), and the CLI maps them to a process exit code:

| State | Constant | CLI exit code | Meaning |
|---|---|---|---|
| `"access"` | `RESULT_ACCESS` | `0` | Server accepted (Access-Accept / EAP-Success). |
| `"reject"` | `RESULT_REJECT` | `1` | Server rejected (Access-Reject / EAP-Failure / wrong password). |
| `"noauth"` | `RESULT_NOAUTH` | `0` | Ran successfully, but no authentication was attempted (cert-only, method probe, or a non-tunnel offer with no password). |
| `"error"` | `RESULT_ERROR` | `2` | Could not complete: network timeout, TLS/certificate problem, configuration, or protocol error. On the CLI the message is printed to the log output. |

The second element of the tuple, `message`, is a short human-readable summary
suitable for showing to a user.

---

## Certificate verification

- Verification is **ON by default**: the server certificate chain is validated
  against the trusted CAs (system CAs, or `--ca-cert` if given).
- The **hostname** is only checked when you pass `--sni <name>` — the certificate's
  SAN/CN must match that name before any password is sent. Without `--sni` only the
  chain is verified (any validly-signed certificate is accepted), so for real
  authentication testing you should pass the expected server name.
- `--unsafe-cert` disables verification entirely (accepts any/self-signed cert) —
  handy for pure certificate probing or a private CA.
- The handshake is capped at **TLS 1.2 by default** so the certificate is
  recoverable from the cleartext handshake even if verification fails. With
  `--allow-tls13` only the leaf certificate is visible (via `getpeercert`).

The certificate chain is printed regardless of the outcome, using the
`cryptography` package for full detail when available, or a built-in DER parser
(SAN/CN names only) otherwise.

---

## Notes & limitations

- **PEAP cryptobinding is not computed.** Against servers that require it (some NPS
  configurations), a correct PEAP-MSCHAPv2 credential can still end in an
  Access-Reject. In that case the tool verifies the password via the MSCHAPv2 `S=`
  authenticator and reports it as correct in the message, while the state stays
  `reject` (the server's actual decision).
- **Outgoing EAP fragmentation is not implemented.** Very large client TLS flights
  (rare) that would not fit in a single RADIUS packet are not split.
- Inside TTLS, PAP sends the password in cleartext **inside** the TLS tunnel, as per
  RFC 5281.
- **Password character encoding.** The cleartext password (plain PAP, TTLS-PAP,
  EAP-GTC) is sent as UTF-8 by default. RADIUS does not mandate a charset for the
  password octets (RFC 8044 makes *text* attributes like User-Name UTF-8, but the
  password is opaque *string* octets), so real clients differ: Windows supplicants
  typically send accented passwords in the local ANSI code page (e.g. CP1250).
  Use `--password-encoding` / `password_encoding=` to match them. Identities are
  always UTF-8 (RFC 8044 / RFC 7542 NAI); MSCHAPv2 always uses UTF-16LE (RFC 2759).

## License

Released under the **MIT License** — see the [`LICENSE`](LICENSE) file. In short:
free to use, modify, and redistribute, with no warranty.

## Acknowledgments

Developed with the assistance of **Claude**, an AI assistant by Anthropic
(the original certificate-probe script it grew from was also written with Claude).
The design choices, live testing against real RADIUS realms, and protocol
debugging were driven by the author; copyright is the author's (see `LICENSE`).
