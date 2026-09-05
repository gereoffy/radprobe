#!/usr/bin/env python3
# Developed with the assistance of Claude (an AI assistant by Anthropic).
# MIT License - see the LICENSE file.
"""
RADIUS / EAP-PEAP + EAP-TTLS probe with a FULL TLS handshake (ssl module).

The original "cert-probe" hand-coded the outer TLS and closed the connection
after the certificate. This version uses the Python `ssl` module's MemoryBIO/wrap_bio
to COMPLETE the TLS handshake (up to Finished), then sends inner traffic
inside the tunnel:

  * PEAP  -> raw inner EAP (Identity, then reports the method offered by the
             server; optionally probing further methods with Nak)
  * TTLS  -> Diameter AVPs:
               - inner EAP in an EAP-Message AVP (auth=eap), reported the same way
               - PAP: User-Name + User-Password AVP (auth=pap), password inside
                 the TLS tunnel, without RADIUS encryption, null-padded to a
                 multiple of 16 (RFC 5281).

It still prints the server certificate chain (from the Certificate message that
arrives in cleartext during the handshake), even if the handshake does not complete.

Dependencies:
    No mandatory dependency (only the Python standard library is required).
    Optional: 'cryptography' (pip install cryptography) - only for detailed
    printing of certificate fields. Without it the probe still runs, only the
    certificate count/size is printed.

Example:
    # PEAP, just see which inner method the server offers:
    python3 radprobe.py --server 10.0.0.10 --secret titok

    # TTLS + PAP real authentication:
    python3 radprobe.py --server 10.0.0.10 --secret titok \
        --inner-auth pap --inner-identity user@dom --password Password123

    # PEAP, probe further inner methods with Nak:
    python3 radprobe.py --server 10.0.0.10 --secret titok --probe-methods
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import socket
import ssl
import struct
import sys

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID
    _HAVE_CRYPTOGRAPHY = True
except ImportError:
    _HAVE_CRYPTOGRAPHY = False


# ---------------------------------------------------------------------------
# Logging. All human-readable output goes through log(), so it can be
# redirected or silenced later (a set_logger() helper is planned). It defaults
# to the builtin print; reassign `log` to any print-compatible callable.
# ---------------------------------------------------------------------------
log = print


# ---------------------------------------------------------------------------
# Result states returned by probe() / run_tunnel() / run_bare_mschapv2(). Each
# of these returns a (state, message) tuple and never raises: state is one of
# the four constants below, message is a short human-readable summary a calling
# application can show to the user.
# ---------------------------------------------------------------------------
RESULT_ACCESS = "access"   # server accepted (Access-Accept / EAP-Success)
RESULT_REJECT = "reject"   # server rejected (Access-Reject / EAP-Failure / bad password)
RESULT_ERROR  = "error"    # could not complete (network, TLS/cert, config, protocol)
RESULT_NOAUTH = "noauth"   # tunnel/probe ran but no authentication was attempted


# ----------------------------------------------------------------------------
# RADIUS layer (RFC 2865 / RFC 3579 - EAP Message-Authenticator)
# ----------------------------------------------------------------------------

ACCESS_REQUEST = 1
ACCESS_ACCEPT = 2
ACCESS_REJECT = 3
ACCESS_CHALLENGE = 11

ATTR_USER_NAME = 1
ATTR_NAS_IP_ADDRESS = 4
ATTR_SERVICE_TYPE = 6
ATTR_FRAMED_PROTOCOL = 7
ATTR_REPLY_MESSAGE = 18
ATTR_CALLING_STATION_ID = 31
ATTR_STATE = 24
ATTR_NAS_IDENTIFIER = 32
ATTR_EAP_MESSAGE = 79
ATTR_MESSAGE_AUTHENTICATOR = 80
ATTR_NAS_PORT_TYPE = 61


def _encode_attr(t: int, value: bytes) -> bytes:
    if len(value) > 253:
        raise ValueError("a RADIUS attribute value can be at most 253 bytes")
    return bytes([t, len(value) + 2]) + value


def _split_chunks(data: bytes, size: int) -> list[bytes]:
    if not data:
        return [b""]
    return [data[i:i + size] for i in range(0, len(data), size)]


def build_access_request(
    radius_id: int,
    secret: bytes,
    eap_packet: bytes,
    username: str,
    nas_ip: str,
    state: bytes | None,
    extra_attrs: list[tuple[int, bytes]] | None = None,
) -> bytes:
    """Build an Access-Request, splitting the EAP payload into 253-byte EAP-Message
    attributes, and computing the Message-Authenticator HMAC-MD5 at the end (RFC 3579)."""
    request_authenticator = os.urandom(16)

    attrs: list[tuple[int, bytes]] = [
        (ATTR_USER_NAME, username.encode()),
        (ATTR_NAS_IP_ADDRESS, socket.inet_aton(nas_ip)),
        (ATTR_NAS_IDENTIFIER, b"python-peap-ttls-probe"),
    ]
    if extra_attrs:
        attrs.extend(extra_attrs)
    if state is not None:
        attrs.append((ATTR_STATE, state))
    for chunk in _split_chunks(eap_packet, 253):
        attrs.append((ATTR_EAP_MESSAGE, chunk))
    attrs.append((ATTR_MESSAGE_AUTHENTICATOR, b"\x00" * 16))  # placeholder

    body = b"".join(_encode_attr(t, v) for t, v in attrs)
    packet_len = 20 + len(body)
    header = bytes([ACCESS_REQUEST, radius_id]) + struct.pack(">H", packet_len) + request_authenticator
    packet = header + body

    mac = hmac.new(secret, packet, hashlib.md5).digest()
    packet = packet[:-16] + mac
    return packet


def _radius_encrypt_password(password: bytes, secret: bytes, authenticator: bytes) -> bytes:
    """RFC 2865 5.2 User-Password 'hiding': null-pad the password to a multiple of
    16, then XOR each block with MD5(secret + previous_block) (for the first block
    the previous value is the Request Authenticator)."""
    pad = (-len(password)) % 16 or 0
    if len(password) == 0:
        password = b"\x00" * 16
    elif pad:
        password += b"\x00" * pad
    out = b""
    prev = authenticator
    for i in range(0, len(password), 16):
        b = hashlib.md5(secret + prev).digest()
        chunk = bytes(p ^ x for p, x in zip(password[i:i + 16], b))
        out += chunk
        prev = chunk
    return out


def build_pap_access_request(radius_id: int, secret: bytes, username: str, password: str,
                             nas_ip: str, extra_attrs: list[tuple[int, bytes]] | None = None,
                             encoding: str = "utf-8") -> bytes:
    """Plain RADIUS PAP Access-Request (no EAP): User-Name + (encrypted)
    User-Password, + Message-Authenticator (RFC 3579). The password is encoded
    with `encoding` (default UTF-8); User-Name stays UTF-8 (RFC 8044 text)."""
    authenticator = os.urandom(16)
    enc_pw = _radius_encrypt_password(password.encode(encoding), secret, authenticator)
    attrs: list[tuple[int, bytes]] = [
        (ATTR_USER_NAME, username.encode()),
        (2, enc_pw),  # User-Password
        (ATTR_NAS_IP_ADDRESS, socket.inet_aton(nas_ip)),
        (ATTR_NAS_IDENTIFIER, b"python-peap-ttls-probe"),
    ]
    if extra_attrs:
        attrs.extend(extra_attrs)
    attrs.append((ATTR_MESSAGE_AUTHENTICATOR, b"\x00" * 16))  # placeholder, must be last

    body = b"".join(_encode_attr(t, v) for t, v in attrs)
    packet_len = 20 + len(body)
    header = bytes([ACCESS_REQUEST, radius_id]) + struct.pack(">H", packet_len) + authenticator
    packet = header + body
    mac = hmac.new(secret, packet, hashlib.md5).digest()
    packet = packet[:-16] + mac
    return packet


def parse_radius_packet(data: bytes) -> tuple[int, int, bytes, list[tuple[int, bytes]]]:
    code, ident = data[0], data[1]
    length = struct.unpack(">H", data[2:4])[0]
    authenticator = data[4:20]
    attrs: list[tuple[int, bytes]] = []
    pos = 20
    while pos < length:
        t = data[pos]
        l = data[pos + 1]
        v = data[pos + 2:pos + l]
        attrs.append((t, v))
        pos += l
    return code, ident, authenticator, attrs


def get_eap_message(attrs: list[tuple[int, bytes]]) -> bytes:
    return b"".join(v for t, v in attrs if t == ATTR_EAP_MESSAGE)


def get_state(attrs: list[tuple[int, bytes]]) -> bytes | None:
    for t, v in attrs:
        if t == ATTR_STATE:
            return v
    return None


def get_reply_messages(attrs: list[tuple[int, bytes]]) -> list[str]:
    msgs = []
    for t, v in attrs:
        if t == ATTR_REPLY_MESSAGE:
            try:
                msgs.append(v.decode("utf-8"))
            except UnicodeDecodeError:
                msgs.append(v.decode("latin-1", errors="replace"))
    return msgs


def reject_diagnostics(attrs: list[tuple[int, bytes]]) -> str:
    parts = []
    for msg in get_reply_messages(attrs):
        parts.append(f"Reply-Message: {msg}")
    eap_bytes = get_eap_message(attrs)
    if eap_bytes:
        preview = eap_bytes[:80].hex(" ")
        parts.append(f"EAP-Message in the reply ({len(eap_bytes)} bytes, first 80: {preview})")
    if not parts:
        parts.append("(the server gave no further reason in the reply)")
    return " | ".join(parts)


def accept_diagnostics(attrs: list[tuple[int, bytes]]) -> str:
    parts = [f"Reply-Message: {m}" for m in get_reply_messages(attrs)]
    return " | ".join(parts) if parts else "(no further attributes)"


# ----------------------------------------------------------------------------
# EAP layer (RFC 3748) + EAP-TLS/PEAP/TTLS fragmentation header (RFC 5216 flags)
# ----------------------------------------------------------------------------

EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4

EAP_TYPE_IDENTITY = 1
EAP_TYPE_NOTIFICATION = 2
EAP_TYPE_NAK = 3
EAP_TYPE_TLS = 13
EAP_TYPE_GTC = 6
EAP_TYPE_TTLS = 21
EAP_TYPE_PEAP = 25
EAP_TYPE_MSCHAPV2 = 26

EAP_TYPE_NAMES = {
    1: "Identity", 2: "Notification", 3: "Nak (Legacy)", 4: "MD5-Challenge",
    5: "OTP", 6: "GTC", 13: "EAP-TLS", 18: "EAP-SIM", 21: "EAP-TTLS",
    23: "EAP-AKA", 25: "PEAP", 26: "EAP-MSCHAPv2", 43: "EAP-FAST", 50: "EAP-AKA'",
    254: "Expanded/Capabilities",
}

# Outer tunnel types: all use the same "flags + optional 4-byte total-length + TLS
# data" fragmentation header (RFC 5216 format).
SUPPORTED_TLS_TUNNEL_TYPES = {
    EAP_TYPE_TLS: "EAP-TLS",
    EAP_TYPE_TTLS: "EAP-TTLS",
    EAP_TYPE_PEAP: "PEAP",
}

KNOWN_NON_TLS_EAP_TYPES = {
    4: "MD5-Challenge - no TLS/certificate",
    6: "EAP-GTC - no TLS/certificate",
    26: "EAP-MSCHAPv2 - direct challenge/response, no outer TLS tunnel",
    43: "EAP-FAST - PAC-based, not a TLS-Certificate flow (not supported)",
}

FLAG_LENGTH_INCLUDED = 0x80
FLAG_MORE_FRAGMENTS = 0x40
FLAG_START = 0x20


class EapPeapFrame:
    __slots__ = ("eap_code", "eap_id", "eap_type", "flags", "total_length", "payload")

    def __init__(self, eap_code, eap_id, eap_type, flags, total_length, payload):
        self.eap_code = eap_code
        self.eap_id = eap_id
        self.eap_type = eap_type
        self.flags = flags
        self.total_length = total_length
        self.payload = payload


def parse_eap_peap(eap_packet: bytes, expected_type: int | None = None) -> EapPeapFrame:
    """expected_type=None: detect the TLS tunnel type. Otherwise verify that the
    reply uses the same type."""
    code, ident = eap_packet[0], eap_packet[1]
    length = struct.unpack(">H", eap_packet[2:4])[0]
    if code in (EAP_SUCCESS, EAP_FAILURE):
        return EapPeapFrame(code, ident, expected_type or 0, 0, None, b"")
    eap_type = eap_packet[4]
    type_data = eap_packet[5:length]

    if eap_type not in SUPPORTED_TLS_TUNNEL_TYPES:
        if eap_type in KNOWN_NON_TLS_EAP_TYPES:
            raise ValueError(
                f"Server uses EAP type {eap_type}: {KNOWN_NON_TLS_EAP_TYPES[eap_type]}. "
                f"This cannot be used to build a TLS tunnel / fetch a certificate."
            )
        supported = ", ".join(f"{t}={n}" for t, n in SUPPORTED_TLS_TUNNEL_TYPES.items())
        raise ValueError(f"unexpected/unsupported EAP type: {eap_type} (supported: {supported})")
    if expected_type is not None and eap_type != expected_type:
        raise ValueError(
            f"server switched EAP type mid-conversation: {eap_type} "
            f"({SUPPORTED_TLS_TUNNEL_TYPES.get(eap_type, '?')}), previously {expected_type}"
        )

    flags = type_data[0]
    rest = type_data[1:]
    total_length = None
    if flags & FLAG_LENGTH_INCLUDED:
        total_length = struct.unpack(">I", rest[:4])[0]
        rest = rest[4:]
    return EapPeapFrame(code, ident, eap_type, flags, total_length, rest)


def build_eap_identity_response(eap_id: int, identity: str) -> bytes:
    type_data = bytes([EAP_TYPE_IDENTITY]) + identity.encode()
    return bytes([EAP_RESPONSE, eap_id]) + struct.pack(">H", 4 + len(type_data)) + type_data


def build_eap_nak(eap_id: int, desired_type: int) -> bytes:
    """Outer (non-tunneled) Legacy Nak: ask the server for a different EAP type
    than the one it offered (RFC 3748 5.3.1)."""
    type_data = bytes([EAP_TYPE_NAK, desired_type])
    return bytes([EAP_RESPONSE, eap_id]) + struct.pack(">H", 4 + len(type_data)) + type_data


def read_eap_header(eap_bytes: bytes) -> tuple[int, int, int | None]:
    """code/id/type fields of the raw EAP packet (without validation, so we can
    recognize non-tunnel types before Nak)."""
    code, ident = eap_bytes[0], eap_bytes[1]
    length = struct.unpack(">H", eap_bytes[2:4])[0]
    etype = eap_bytes[4] if length >= 5 and len(eap_bytes) >= 5 else None
    return code, ident, etype


# Outer Nak target types (--auth). 'mschapv2' = bare EAP-MSCHAPv2 (no tunnel).
OUTER_METHOD_MAP = {"peap": EAP_TYPE_PEAP, "ttls": EAP_TYPE_TTLS, "tls": EAP_TYPE_TLS,
                    "mschapv2": EAP_TYPE_MSCHAPV2}


def build_eap_peap_response(
    eap_id: int, eap_type: int, flags: int, payload: bytes = b"", total_length: int | None = None
) -> bytes:
    if total_length is not None:
        flags |= FLAG_LENGTH_INCLUDED
        type_data = bytes([flags]) + struct.pack(">I", total_length) + payload
    else:
        type_data = bytes([flags]) + payload
    full = bytes([eap_type]) + type_data
    return bytes([EAP_RESPONSE, eap_id]) + struct.pack(">H", 4 + len(full)) + full


# ----------------------------------------------------------------------------
# Inner EAP (PEAP raw / TTLS in an EAP-Message AVP)
# ----------------------------------------------------------------------------

def inner_eap_build(code: int, ident: int, eap_type: int, data: bytes = b"") -> bytes:
    body = bytes([eap_type]) + data
    return bytes([code, ident]) + struct.pack(">H", 4 + len(body)) + body


def inner_eap_parse(pkt: bytes) -> tuple[int, int, int | None, bytes]:
    code, ident = pkt[0], pkt[1]
    length = struct.unpack(">H", pkt[2:4])[0]
    etype = pkt[4] if length > 4 and len(pkt) > 4 else None
    edata = pkt[5:length] if length > 5 else b""
    return code, ident, etype, edata


# ----------------------------------------------------------------------------
# TTLS Diameter AVPs (RFC 5281)
# ----------------------------------------------------------------------------

AVP_USER_NAME = 1
AVP_USER_PASSWORD = 2
AVP_EAP_MESSAGE = 79


def ttls_avp(code: int, data: bytes, mandatory: bool = True, vendor_id: int | None = None) -> bytes:
    """Assemble one AVP. Length covers header+data (without padding), then
    null-padding to a 4-byte boundary follows."""
    flags = 0x40 if mandatory else 0x00
    hdr = 8
    if vendor_id is not None:
        flags |= 0x80
        hdr = 12
    length = hdr + len(data)
    out = struct.pack(">I", code) + bytes([flags]) + length.to_bytes(3, "big")
    if vendor_id is not None:
        out += struct.pack(">I", vendor_id)
    out += data
    out += b"\x00" * ((-len(out)) % 4)
    return out


def ttls_avp_parse(data: bytes) -> list[tuple[int, int, int | None, bytes]]:
    avps = []
    pos = 0
    while pos + 8 <= len(data):
        code = struct.unpack(">I", data[pos:pos + 4])[0]
        flags = data[pos + 4]
        length = int.from_bytes(data[pos + 5:pos + 8], "big")
        if length < 8:
            break
        vend = None
        dstart = pos + 8
        if flags & 0x80:
            vend = struct.unpack(">I", data[pos + 8:pos + 12])[0]
            dstart = pos + 12
        val = data[dstart:pos + length]
        avps.append((code, flags, vend, val))
        pos += length + ((-length) % 4)
    return avps


def ttls_pap_avps(username: str, password: str, encoding: str = "utf-8") -> bytes:
    pw = password.encode(encoding)
    pad = (-len(pw)) % 16  # null-pad to a multiple of 16 (RFC 5281)
    pw += b"\x00" * pad
    return ttls_avp(AVP_USER_NAME, username.encode()) + ttls_avp(AVP_USER_PASSWORD, pw)


# ----------------------------------------------------------------------------
# MSCHAPv2 (RFC 2759) - pure-Python MD4 + DES, no external dependency
# ----------------------------------------------------------------------------

def _md4(data: bytes) -> bytes:
    def lrot(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xffffffff
    msg = bytearray(data)
    bitlen = (8 * len(data)) & 0xffffffffffffffff
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", bitlen)
    A, B, C, D = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    F = lambda x, y, z: (x & y) | (~x & z) & 0xffffffff
    G = lambda x, y, z: (x & y) | (x & z) | (y & z)
    H = lambda x, y, z: x ^ y ^ z
    for off in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[off:off + 64]))
        a, b, c, d = A, B, C, D
        for k in range(0, 16, 4):
            a = lrot((a + F(b, c, d) + X[k]) & 0xffffffff, 3)
            d = lrot((d + F(a, b, c) + X[k + 1]) & 0xffffffff, 7)
            c = lrot((c + F(d, a, b) + X[k + 2]) & 0xffffffff, 11)
            b = lrot((b + F(c, d, a) + X[k + 3]) & 0xffffffff, 19)
        for k in range(4):
            a = lrot((a + G(b, c, d) + X[k] + 0x5a827999) & 0xffffffff, 3)
            d = lrot((d + G(a, b, c) + X[k + 4] + 0x5a827999) & 0xffffffff, 5)
            c = lrot((c + G(d, a, b) + X[k + 8] + 0x5a827999) & 0xffffffff, 9)
            b = lrot((b + G(c, d, a) + X[k + 12] + 0x5a827999) & 0xffffffff, 13)
        for k0, k1, k2, k3 in [(0, 8, 4, 12), (2, 10, 6, 14), (1, 9, 5, 13), (3, 11, 7, 15)]:
            a = lrot((a + H(b, c, d) + X[k0] + 0x6ed9eba1) & 0xffffffff, 3)
            d = lrot((d + H(a, b, c) + X[k1] + 0x6ed9eba1) & 0xffffffff, 9)
            c = lrot((c + H(d, a, b) + X[k2] + 0x6ed9eba1) & 0xffffffff, 11)
            b = lrot((b + H(c, d, a) + X[k3] + 0x6ed9eba1) & 0xffffffff, 15)
        A = (A + a) & 0xffffffff
        B = (B + b) & 0xffffffff
        C = (C + c) & 0xffffffff
        D = (D + d) & 0xffffffff
    return struct.pack("<4I", A, B, C, D)


_DES_IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6,
           64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
           61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
_DES_FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30,
           37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
           34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
_DES_E = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
          16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
_DES_P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9,
          19, 13, 30, 6, 22, 11, 4, 25]
_DES_PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3,
            60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37,
            29, 21, 13, 5, 28, 20, 12, 4]
_DES_PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
_DES_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
_DES_SBOX = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]


def _des_bits(data):
    out = []
    for byte in data:
        for i in range(7, -1, -1):
            out.append((byte >> i) & 1)
    return out


def _des_frombits(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        b = 0
        for j in range(8):
            b = (b << 1) | bits[i + j]
        out.append(b)
    return bytes(out)


def _des_perm(bits, table):
    return [bits[i - 1] for i in table]


def _des_encrypt(key8: bytes, block8: bytes) -> bytes:
    key = _des_bits(key8)
    k = _des_perm(key, _DES_PC1)
    C, D = k[:28], k[28:]
    subkeys = []
    for s in _DES_SHIFTS:
        C = C[s:] + C[:s]
        D = D[s:] + D[:s]
        subkeys.append(_des_perm(C + D, _DES_PC2))
    b = _des_perm(_des_bits(block8), _DES_IP)
    L, R = b[:32], b[32:]
    for sk in subkeys:
        er = _des_perm(R, _DES_E)
        x = [er[i] ^ sk[i] for i in range(48)]
        out = []
        for i in range(8):
            six = x[i * 6:i * 6 + 6]
            row = (six[0] << 1) | six[5]
            col = (six[1] << 3) | (six[2] << 2) | (six[3] << 1) | six[4]
            val = _DES_SBOX[i][row * 16 + col]
            out += [(val >> 3) & 1, (val >> 2) & 1, (val >> 1) & 1, val & 1]
        f = _des_perm(out, _DES_P)
        L, R = R, [L[i] ^ f[i] for i in range(32)]
    return _des_frombits(_des_perm(R + L, _DES_FP))


def _str_to_key(key7: bytes) -> bytes:
    o = [0] * 8
    o[0] = key7[0] >> 1
    o[1] = ((key7[0] & 0x01) << 6) | (key7[1] >> 2)
    o[2] = ((key7[1] & 0x03) << 5) | (key7[2] >> 3)
    o[3] = ((key7[2] & 0x07) << 4) | (key7[3] >> 4)
    o[4] = ((key7[3] & 0x0f) << 3) | (key7[4] >> 5)
    o[5] = ((key7[4] & 0x1f) << 2) | (key7[5] >> 6)
    o[6] = ((key7[5] & 0x3f) << 1) | (key7[6] >> 7)
    o[7] = key7[6] & 0x7f
    return bytes((b << 1) & 0xff for b in o)


def _mschap_challenge_response(challenge8: bytes, pwhash16: bytes) -> bytes:
    z = pwhash16 + b"\x00" * (21 - len(pwhash16))
    r = b""
    for i in range(0, 21, 7):
        r += _des_encrypt(_str_to_key(z[i:i + 7]), challenge8)
    return r


def mschap_generate_nt_response(auth_challenge: bytes, peer_challenge: bytes,
                                username: str, password: str) -> bytes:
    ch = hashlib.sha1(peer_challenge + auth_challenge + username.encode()).digest()[:8]
    pwhash = _md4(password.encode("utf-16-le"))
    return _mschap_challenge_response(ch, pwhash)


_MSCHAP_MAGIC1 = b"Magic server to client signing constant"
_MSCHAP_MAGIC2 = b"Pad to make it do more than one iteration"


def mschap_generate_authenticator_response(password: str, nt_response: bytes, peer_challenge: bytes,
                                           auth_challenge: bytes, username: str) -> str:
    """RFC 2759 8.7: compute the server's "S=..." response - this lets us verify
    that the password is correct (and that the server knows it too)."""
    pwhash = _md4(password.encode("utf-16-le"))
    pwhashhash = _md4(pwhash)
    digest = hashlib.sha1(pwhashhash + nt_response + _MSCHAP_MAGIC1).digest()
    ch = hashlib.sha1(peer_challenge + auth_challenge + username.encode()).digest()[:8]
    digest = hashlib.sha1(digest + ch + _MSCHAP_MAGIC2).digest()
    return "S=" + digest.hex().upper()


# EAP-MSCHAPv2 OpCodes (draft-kamath-pppext-eap-mschapv2)
MSCHAP_CHALLENGE = 1
MSCHAP_RESPONSE = 2
MSCHAP_SUCCESS = 3
MSCHAP_FAILURE = 4

EAP_TYPE_TLV = 33  # PEAP "Extensions" / Result-TLV


def mschapv2_handle(payload: bytes, username: str, password: str, state: dict):
    """Process one EAP-MSCHAPv2 message. Keeps the challenges in state so it can
    verify the Success 'S=' response (password_ok). Returns:
    (status, msdata_or_None, info)."""
    opcode = payload[0]
    if opcode == MSCHAP_CHALLENGE:
        mschap_id = payload[1]
        val_size = payload[4]
        auth_challenge = payload[5:5 + val_size]
        peer = os.urandom(16)
        ntresp = mschap_generate_nt_response(auth_challenge, peer, username, password)
        state.update(auth_challenge=auth_challenge, peer_challenge=peer,
                     nt_response=ntresp, username=username)
        response_field = peer + b"\x00" * 8 + ntresp + b"\x00"  # 16+8+24+1 = 49
        name = username.encode()
        msdata = (bytes([MSCHAP_RESPONSE, mschap_id])
                  + struct.pack(">H", 4 + 1 + 49 + len(name))
                  + bytes([49]) + response_field + name)
        return "continue", msdata, None
    if opcode == MSCHAP_SUCCESS:
        text = payload.decode("latin-1", "replace")
        idx = text.find("S=")
        recv_s = text[idx:idx + 42] if idx >= 0 else ""  # "S=" + 40 hex
        if all(k in state for k in ("auth_challenge", "peer_challenge", "nt_response", "username")):
            expected = mschap_generate_authenticator_response(
                password, state["nt_response"], state["peer_challenge"],
                state["auth_challenge"], state["username"])
            state["password_ok"] = bool(recv_s) and recv_s.upper() == expected.upper()
        return "success-ack", bytes([MSCHAP_SUCCESS]), (text[idx:] if idx >= 0 else text)
    if opcode == MSCHAP_FAILURE:
        text = payload.decode("latin-1", "replace")
        idx = text.find("E=")
        return "failure", None, (text[idx:] if idx >= 0 else text[4:])
    return "failure", None, f"unknown MSCHAPv2 OpCode: {opcode}"


def parse_result_tlv(tlv_data: bytes) -> tuple[int | None, bool]:
    """Read the Result TLV (type 3) status from the PEAP Extensions (type 33) TLV
    sequence, and indicate whether a Cryptobinding TLV (type 12) is present."""
    status = None
    has_cb = False
    pos = 0
    while pos + 4 <= len(tlv_data):
        t = struct.unpack(">H", tlv_data[pos:pos + 2])[0] & 0x3fff
        ln = struct.unpack(">H", tlv_data[pos + 2:pos + 4])[0]
        val = tlv_data[pos + 4:pos + 4 + ln]
        if t == 3 and len(val) >= 2:
            status = struct.unpack(">H", val[:2])[0]
        elif t == 12:
            has_cb = True
        pos += 4 + ln
    return status, has_cb




class TlsTunnel:
    def __init__(self, server_hostname: str | None, allow_tls13: bool = False,
                 verify: bool = True, ca_cert: str | None = None, check_hostname: bool = False):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if verify:
            ctx.verify_mode = ssl.CERT_REQUIRED
            ctx.check_hostname = check_hostname
            if ca_cert:
                ctx.load_verify_locations(ca_cert)
            else:
                ctx.load_default_certs()
        else:
            # Verification disabled (--unsafe-cert): self-signed/private cert is OK,
            # and we also allow weaker cipher suites (old NPS compatibility).
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            for spec in ("DEFAULT:@SECLEVEL=0", "DEFAULT"):
                try:
                    ctx.set_ciphers(spec)
                    break
                except ssl.SSLError:
                    continue
        # The Certificate is in cleartext only in TLS<=1.2; for the cert parser we
        # cap at 1.2 by default (this follows the classic PEAP/TTLS flow).
        try:
            if not allow_tls13:
                ctx.maximum_version = ssl.TLSVersion.TLSv1_2
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        except (ValueError, AttributeError):
            pass

        self._in = ssl.MemoryBIO()
        self._out = ssl.MemoryBIO()
        self._ssl = ctx.wrap_bio(
            self._in, self._out, server_side=False, server_hostname=server_hostname or None
        )
        self.handshake_done = False

    def do_handshake_step(self, incoming: bytes = b"") -> bytes:
        """Feed the incoming TLS bytes, advance the handshake one step, and return
        the outgoing TLS bytes (may be empty). SSLWantReadError is normal."""
        if incoming:
            self._in.write(incoming)
        try:
            self._ssl.do_handshake()
            self.handshake_done = True
        except ssl.SSLWantReadError:
            pass
        return self._out.read()

    def write_app(self, data: bytes) -> bytes:
        self._ssl.write(data)
        return self._out.read()

    def read_app(self, incoming: bytes) -> bytes:
        if incoming:
            self._in.write(incoming)
        chunks = []
        while True:
            try:
                d = self._ssl.read()
            except ssl.SSLWantReadError:
                break
            if not d:
                break
            chunks.append(d)
        return b"".join(chunks)

    def peer_cert_der(self) -> bytes | None:
        try:
            return self._ssl.getpeercert(binary_form=True)
        except Exception:
            return None

    def peer_dns_names(self) -> list[str]:
        """DNS names of the validated peer cert from the getpeercert() dict (stdlib,
        no cryptography). Empty if the cert was not validated (e.g. CERT_NONE) or has no SAN."""
        try:
            cert = self._ssl.getpeercert()  # dict, only if validated
        except Exception:
            return []
        if not cert:
            return []
        return [v for (t, v) in cert.get("subjectAltName", ()) if t == "DNS"]

    def cipher(self):
        try:
            return self._ssl.cipher()
        except Exception:
            return None

    def version(self):
        try:
            return self._ssl.version()
        except Exception:
            return None


# ----------------------------------------------------------------------------
# Parse TLS records for the Certificate chain (cleartext handshake, <=TLS1.2)
# ----------------------------------------------------------------------------

def extract_certificates(tls_stream: bytes) -> list[bytes]:
    certs: list[bytes] = []
    pos = 0
    while pos + 5 <= len(tls_stream):
        content_type = tls_stream[pos]
        rec_len = struct.unpack(">H", tls_stream[pos + 3:pos + 5])[0]
        rec_data = tls_stream[pos + 5:pos + 5 + rec_len]
        pos += 5 + rec_len
        if content_type != 0x16:
            continue
        hpos = 0
        while hpos + 4 <= len(rec_data):
            htype = rec_data[hpos]
            hlen = int.from_bytes(rec_data[hpos + 1:hpos + 4], "big")
            hbody = rec_data[hpos + 4:hpos + 4 + hlen]
            hpos += 4 + hlen
            if htype == 0x0B:  # Certificate
                total_certs_len = int.from_bytes(hbody[0:3], "big")
                cpos = 3
                end = 3 + total_certs_len
                while cpos < end:
                    clen = int.from_bytes(hbody[cpos:cpos + 3], "big")
                    cpos += 3
                    certs.append(hbody[cpos:cpos + clen])
                    cpos += clen
    return certs


def _der_len(data: bytes, pos: int) -> tuple[int, int]:
    """Read a DER length field (short/long form). Returns (length, new_position)."""
    b = data[pos]
    pos += 1
    if b < 0x80:
        return b, pos
    n = b & 0x7f
    return int.from_bytes(data[pos:pos + n], "big"), pos + n


def _cert_names_no_crypto(der: bytes) -> list[str]:
    """Extract SAN dNSNames (or CN fallback) from raw DER, without cryptography.
    We search for the OID in the byte stream, then parse the value next to it."""
    names: list[str] = []
    # SubjectAltName OID 2.5.29.17 -> 06 03 55 1D 11
    i = der.find(b"\x06\x03\x55\x1d\x11")
    if i >= 0:
        p = i + 5
        if der[p:p + 2] == b"\x01\x01":  # optional critical BOOLEAN
            p += 3
        if der[p:p + 1] == b"\x04":  # extnValue OCTET STRING
            p += 1
            olen, p = _der_len(der, p)
            octv = der[p:p + olen]
            if octv[:1] == b"\x30":  # SEQUENCE OF GeneralName
                q = 1
                slen, q = _der_len(octv, q)
                end = q + slen
                while q < end:
                    tag = octv[q]
                    q += 1
                    glen, q = _der_len(octv, q)
                    val = octv[q:q + glen]
                    q += glen
                    if tag == 0x82:  # dNSName (context [2] IMPLICIT IA5String)
                        try:
                            names.append(val.decode("ascii"))
                        except UnicodeDecodeError:
                            pass
    if not names:
        # CN fallback: OID 2.5.4.3 -> 06 03 55 04 03 (the subject CN; may also hit the
        # issuer CN, but modern certs almost always have a SAN, so this is rare)
        j = der.rfind(b"\x06\x03\x55\x04\x03")
        if j >= 0:
            p = j + 5
            if der[p:p + 1] in (b"\x0c", b"\x13", b"\x16", b"\x14"):  # UTF8/Printable/IA5/T61
                p += 1
                vlen, p = _der_len(der, p)
                names.append(der[p:p + vlen].decode("utf-8", "replace"))
    return names


def _cert_dns_names(der: bytes) -> list[str]:
    """DNS names of the leaf cert (SAN, or CN fallback) - with or without cryptography."""
    if _HAVE_CRYPTOGRAPHY:
        cert = x509.load_der_x509_certificate(der, default_backend())
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            names = list(san.get_values_for_type(x509.DNSName))
            if names:
                return names
        except x509.ExtensionNotFound:
            pass
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return [cn[0].value] if cn else []
    return _cert_names_no_crypto(der)


def _match_host(names: list[str], hostname: str):
    """True/False whether the hostname matches one of the names (single-level wildcard);
    None if there are no names at all."""
    if not names:
        return None
    host = hostname.lower().rstrip(".")
    for n in names:
        n = n.lower().rstrip(".")
        if n.startswith("*.") and "." in host:
            if host.split(".", 1)[1] == n[2:]:
                return True
        elif n == host:
            return True
    return False


def _hostname_matches(der_cert: bytes, hostname: str):
    """True/False based on the leaf cert SAN(DNS)/CN (from DER), None if no name can be extracted."""
    try:
        names = _cert_dns_names(der_cert)
    except Exception:
        return None
    return _match_host(names, hostname)


def print_certificates(der_certs: list[bytes]) -> None:
    if not der_certs:
        log("Could not extract a certificate from the handshake.")
        return
    if not _HAVE_CRYPTOGRAPHY:
        total = sum(len(d) for d in der_certs)
        log(f"\nThe server sent {len(der_certs)} certificate(s) ({total} bytes DER total).")
        leaf_names = _cert_names_no_crypto(der_certs[0])
        if leaf_names:
            log(f"  Leaf cert names (SAN/CN): {', '.join(leaf_names)}")
        log("  For detailed fields install the 'cryptography' package (pip install cryptography).")
        return
    log(f"\nThe server sent {len(der_certs)} certificate(s) (chain, leaf first):\n")
    for i, der in enumerate(der_certs, 1):
        try:
            cert = x509.load_der_x509_certificate(der, default_backend())
        except Exception as e:
            log(f"  [{i}] (not parseable: {e})")
            continue

        def cn_of(name: x509.Name) -> str:
            a = name.get_attributes_for_oid(NameOID.COMMON_NAME)
            return a[0].value if a else name.rfc4514_string()

        log(f"  [{i}] CN:         {cn_of(cert.subject)}")
        log(f"       Subject:    {cert.subject.rfc4514_string()}")
        try:
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            dns = san.get_values_for_type(x509.DNSName)
            if dns:
                log(f"       SAN (DNS):  {', '.join(dns)}")
        except x509.ExtensionNotFound:
            pass
        log(f"       Issuer:     {cn_of(cert.issuer)}  ({cert.issuer.rfc4514_string()})")
        try:
            nb, na = cert.not_valid_before_utc, cert.not_valid_after_utc
        except AttributeError:
            nb, na = cert.not_valid_before, cert.not_valid_after
        log(f"       Valid:      {nb}  ->  {na}")
        log(f"       Serial:     {cert.serial_number:x}")
        log()


# ----------------------------------------------------------------------------
# RADIUS conversation (UDP)
# ----------------------------------------------------------------------------

class RadiusConversation:
    def __init__(self, server, port, secret, nas_ip, timeout,
                 source_ip=None, extra_attrs=None, debug=False):
        self.server = server
        self.port = port
        self.secret = secret.encode()
        self.nas_ip = nas_ip
        self.timeout = timeout
        self.extra_attrs = extra_attrs or []
        self.debug = debug
        self.radius_id = os.urandom(1)[0]
        self.state: bytes | None = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if source_ip:
            try:
                self.sock.bind((source_ip, 0))
            except OSError as e:
                raise RuntimeError(f"Could not bind to source address {source_ip}: {e}") from e
        self.sock.settimeout(timeout)

    def _next_radius_id(self) -> int:
        self.radius_id = (self.radius_id + 1) % 256
        return self.radius_id

    def send_eap(self, eap_packet, username="anonymous", retries=3):
        packet = build_access_request(
            self._next_radius_id(), self.secret, eap_packet, username, self.nas_ip, self.state,
            extra_attrs=self.extra_attrs,
        )
        if self.debug:
            log(f"--> Access-Request ({len(packet)} byte)\n    EAP ({len(eap_packet)} byte): "
                  f"{eap_packet[:48].hex(' ')}...", file=sys.stderr)
        last_err = None
        for _ in range(retries):
            try:
                self.sock.sendto(packet, (self.server, self.port))
                data, _addr = self.sock.recvfrom(65535)
                if self.debug:
                    log(f"<-- reply ({len(data)} bytes, code={data[0]})", file=sys.stderr)
                code, ident, auth, attrs = parse_radius_packet(data)
                new_state = get_state(attrs)
                if new_state is not None:
                    self.state = new_state
                return code, attrs
            except socket.timeout as e:
                last_err = e
                continue
        raise TimeoutError(
            f"No reply from the RADIUS server ({self.server}:{self.port}) after {retries} attempts"
        ) from last_err

    def send_pap(self, username: str, password: str, retries: int = 3, encoding: str = "utf-8"):
        packet = build_pap_access_request(
            self._next_radius_id(), self.secret, username, password, self.nas_ip,
            extra_attrs=self.extra_attrs, encoding=encoding,
        )
        if self.debug:
            log(f"--> Access-Request PAP ({len(packet)} byte), User-Name={username}", file=sys.stderr)
        last_err = None
        for _ in range(retries):
            try:
                self.sock.sendto(packet, (self.server, self.port))
                data, _addr = self.sock.recvfrom(65535)
                if self.debug:
                    log(f"<-- reply ({len(data)} bytes, code={data[0]})", file=sys.stderr)
                code, ident, auth, attrs = parse_radius_packet(data)
                return code, attrs
            except socket.timeout as e:
                last_err = e
                continue
        raise TimeoutError(
            f"No reply from the RADIUS server ({self.server}:{self.port}) after {retries} attempts"
        ) from last_err


# ----------------------------------------------------------------------------
# Inner tunnel transport (PEAP raw vs TTLS AVP)
# ----------------------------------------------------------------------------

def inner_extract(eap_type: int, plain: bytes):
    """Extract the inner EAP from the decrypted tunnel content.
    Returns: (icode, iident, itype, idata) or None.
    PEAP: PEAPv0 stripped form (only Type + data, the Code/Id come from the outer
    PEAP header) OR full inner EAP (auto-detected). TTLS: full inner EAP from the
    EAP-Message AVP."""
    if eap_type == EAP_TYPE_TTLS:
        eap = b"".join(val for c, f, ve, val in ttls_avp_parse(plain) if c == AVP_EAP_MESSAGE)
        if len(eap) < 4:
            return None
        return inner_eap_parse(eap)
    if not plain:
        return None
    # Full inner EAP? (some PEAP implementations do not strip)
    if plain[0] in (EAP_REQUEST, EAP_RESPONSE, EAP_SUCCESS, EAP_FAILURE) and len(plain) >= 4:
        if struct.unpack(">H", plain[2:4])[0] == len(plain):
            return inner_eap_parse(plain)
    # PEAPv0 stripped: Code is implicitly Request, id from the outer header
    return EAP_REQUEST, None, plain[0], plain[1:]


def inner_send(eap_type: int, tunnel: TlsTunnel, iident: int | None,
               resp_type: int, resp_data: bytes = b"") -> bytes:
    """Wrap the inner EAP response into tunnel form and return it encrypted.
    TTLS: full inner EAP in an EAP-Message AVP. PEAP: we mirror the incoming
    packet's form - if the server sent full EAP (iident known, e.g.
    Extensions/TLV), we reply in full, echoing the inner id; if stripped
    (iident None, PEAPv0 inner method), the reply stays stripped (only Type + data)."""
    if eap_type == EAP_TYPE_TTLS:
        inner = inner_eap_build(EAP_RESPONSE, iident if iident is not None else 1, resp_type, resp_data)
        return tunnel.write_app(ttls_avp(AVP_EAP_MESSAGE, inner))
    if iident is not None:
        return tunnel.write_app(inner_eap_build(EAP_RESPONSE, iident, resp_type, resp_data))
    return tunnel.write_app(bytes([resp_type]) + resp_data)


# ----------------------------------------------------------------------------
# Main flow: handshake + inner tunnel
# ----------------------------------------------------------------------------

def run_tunnel(conv: RadiusConversation, eap_type: int, start_frame: EapPeapFrame, args) -> tuple[str, str]:
    verify = not args.unsafe_cert
    hostname = args.sni or None
    check_host = verify and hostname is not None
    tunnel = TlsTunnel(hostname if hostname else (None if verify else conv.server),
                       allow_tls13=args.allow_tls13, verify=verify,
                       ca_cert=args.ca_cert, check_hostname=check_host)
    if verify and not check_host:
        log("WARNING: cert verification = ONLY the chain (signed by a trusted CA); the server "
              "NAME is NOT verified. So any validly-signed cert would be accepted before the "
              "password is sent. For auth testing pass --sni <expected-name> (see the cert SAN below).",
              file=sys.stderr)
    elif verify and check_host:
        log(f"Cert verification: chain + hostname ({hostname}).", file=sys.stderr)
    else:
        log("Cert verification: DISABLED (--unsafe-cert).", file=sys.stderr)
    cert_capture = bytearray()
    inner_identity = args.inner_identity or args.identity

    # Candidates for Nak-probing (skip the ones already offered):
    nak_queue = [EAP_TYPE_MSCHAPV2, EAP_TYPE_GTC, 13, 25, 4, 50, 23]
    offered: list[int] = []
    tried_gtc_switch = False
    mschap_state: dict = {}

    phase = "handshake"
    server_frame = start_frame
    try:
        pending_out = tunnel.do_handshake_step()  # ClientHello
    except ssl.SSLError as e:
        raise RuntimeError(f"Could not produce the ClientHello: {e}") from e

    if len(pending_out) > 3500:
        log("WARNING: the outgoing TLS flight is >3500 bytes and may not fit in a single "
              "RADIUS packet (outgoing EAP fragmentation is not implemented).", file=sys.stderr)

    while True:
        # 1) Send the current outgoing TLS/tunnel data as a reply to server_frame
        reply = build_eap_peap_response(
            server_frame.eap_id, eap_type, flags=0,
            payload=pending_out,
            total_length=len(pending_out) if pending_out else None,
        )
        code, attrs = conv.send_eap(reply, username=args.identity)

        if code == ACCESS_ACCEPT:
            log(f"\n>> ACCESS-ACCEPT (authentication succeeded). {accept_diagnostics(attrs)}")
            return RESULT_ACCESS, "Access-Accept: authentication succeeded"
        if code == ACCESS_REJECT:
            log(f"\n>> ACCESS-REJECT. {reject_diagnostics(attrs)}")
            if mschap_state.get("password_ok"):
                log(">> BUT: the inner MSCHAPv2 succeeded, the password is CORRECT. The final "
                      "rejection is almost certainly due to mandatory PEAP Cryptobinding (which this "
                      "script does not compute). For credential testing the MSCHAPv2 result above is authoritative.")
                return RESULT_REJECT, "Access-Reject (credentials verified; likely mandatory PEAP cryptobinding)"
            return RESULT_REJECT, "Access-Reject"

        # 2) Collect the server flight (M-bit fragmentation -> empty ACK)
        flight = bytearray()
        while True:
            eap_bytes = get_eap_message(attrs)
            server_frame = parse_eap_peap(eap_bytes, expected_type=eap_type)
            if server_frame.eap_code == EAP_SUCCESS:
                log("\n>> EAP-Success in the tunnel.")
                return RESULT_ACCESS, "EAP-Success"
            if server_frame.eap_code == EAP_FAILURE:
                log("\n>> EAP-Failure in the tunnel." +
                      (f" Offered inner methods: {_fmt_types(offered)}" if offered else ""))
                return RESULT_REJECT, "EAP-Failure"
            flight.extend(server_frame.payload)
            if phase == "handshake":
                cert_capture.extend(server_frame.payload)
            if server_frame.flags & FLAG_MORE_FRAGMENTS:
                code, attrs = conv.send_eap(
                    build_eap_peap_response(server_frame.eap_id, eap_type, flags=0, payload=b""),
                    username=args.identity,
                )
                if code == ACCESS_REJECT:
                    log(f"\n>> ACCESS-REJECT after fragment ACK. {reject_diagnostics(attrs)}")
                    return RESULT_REJECT, "Access-Reject"
                if code == ACCESS_ACCEPT:
                    log(f"\n>> ACCESS-ACCEPT. {accept_diagnostics(attrs)}")
                    return RESULT_ACCESS, "Access-Accept"
                continue
            break
        server_tls = bytes(flight)

        # 3) Process by phase
        if phase == "handshake":
            try:
                pending_out = tunnel.do_handshake_step(server_tls)
            except ssl.SSLError as e:
                # Did not complete (e.g. cert verification failed, or EAP-TLS without a
                # client cert), but we can still extract the cert from the cleartext flight.
                certs = extract_certificates(bytes(cert_capture))
                if not certs and tunnel.peer_cert_der():
                    certs = [tunnel.peer_cert_der()]
                print_certificates(certs)
                if isinstance(e, ssl.SSLCertVerificationError):
                    raise RuntimeError(
                        f"The server certificate cannot be verified ({e}). If a private CA signed it, "
                        "pass --ca-cert <file>; for a hostname mismatch pass --sni <name>; "
                        "or use --unsafe-cert to skip verification "
                        "(e.g. just for cert probing). The certificate above came from the handshake."
                    ) from e
                raise RuntimeError(f"TLS handshake did not complete ({e}). "
                                   "The certificate(s) above were extracted from the start of the handshake.") from e

            if tunnel.handshake_done:
                certs = extract_certificates(bytes(cert_capture))
                if not certs and tunnel.peer_cert_der():
                    certs = [tunnel.peer_cert_der()]
                print_certificates(certs)

                # Explicit hostname check (belt-and-suspenders): in some environments
                # OpenSSL's built-in check_hostname does not fire over the MemoryBIO path, so
                # before anything (a password) goes out over the tunnel, we check it ourselves.
                if check_host and certs:
                    # Primary: getpeercert() (validated cert, stdlib). Fallback: DER parse.
                    names = tunnel.peer_dns_names()
                    m = _match_host(names, hostname) if names else _hostname_matches(certs[0], hostname)
                    if m is False:
                        raise RuntimeError(
                            f"The server certificate is NOT valid for '{hostname}' "
                            "(see the SAN/CN above). The password will NOT be sent. Pass the correct "
                            "--sni, or use --unsafe-cert to skip the hostname check."
                        )
                    if m is None:
                        log("WARNING: the hostname cannot be checked (could not extract a name "
                              "from the cert), relying only on chain verification.", file=sys.stderr)

                v, c = tunnel.version(), tunnel.cipher()
                log(f"TLS tunnel established: {v}, cipher: {c[0] if c else '?'}")

                if args.inner_auth == "none":
                    log("Inner authentication skipped (--inner-auth none).")
                    return RESULT_NOAUTH, "TLS tunnel and certificate OK; no inner authentication attempted"

                phase = "inner"
                if pending_out:
                    # Rare: there is one more handshake flight - send it first.
                    continue
                # Assemble the first inner message
                if eap_type == EAP_TYPE_PEAP:
                    # PEAP: empty ACK, the server sends the inner Identity Request
                    pending_out = b""
                elif args.inner_auth == "pap":
                    log(f"TTLS/PAP: sending User-Name='{inner_identity}' + User-Password...")
                    pending_out = tunnel.write_app(ttls_pap_avps(inner_identity, args.password or "", args.password_encoding))
                else:  # TTLS + inner EAP: the client initiates with an Identity Response
                    pending_out = inner_send(eap_type, tunnel, 1, EAP_TYPE_IDENTITY, inner_identity.encode())
                continue
            # handshake still in progress
            continue

        # ---- inner phase: server_tls is encrypted tunnel data ----
        plain = tunnel.read_app(server_tls)
        if args.debug and plain:
            log(f"    [inner] decrypted {len(plain)} bytes: {plain[:64].hex(' ')}", file=sys.stderr)

        if eap_type == EAP_TYPE_TTLS and args.inner_auth == "pap":
            # The PAP result usually comes as an outer Accept/Reject (handled above).
            # If we got some AVPs instead, report them.
            avps = ttls_avp_parse(plain)
            log(f"\n>> TTLS/PAP reply AVPs: {[(c, v[:40]) for c, f, ve, v in avps]}")
            return RESULT_ERROR, "unexpected TTLS/PAP reply inside the tunnel"

        extracted = inner_extract(eap_type, plain)
        if extracted is None:
            log(f"\n>> No processable inner EAP in the reply ({len(plain)} bytes): "
                  f"{plain[:48].hex(' ')}")
            return RESULT_ERROR, "no processable inner EAP in the tunnel reply"
        icode, iident, itype, idata = extracted

        if icode == EAP_SUCCESS:
            log("\n>> Inner EAP-Success.")
            return RESULT_ACCESS, "EAP-Success"
        if icode == EAP_FAILURE:
            log(f"\n>> Inner EAP-Failure. Offered inner methods: {_fmt_types(offered)}")
            return RESULT_REJECT, "EAP-Failure"

        # icode == Request
        if itype == EAP_TYPE_IDENTITY:
            pending_out = inner_send(eap_type, tunnel, iident, EAP_TYPE_IDENTITY, inner_identity.encode())
            continue

        # A real method request from the server
        name = EAP_TYPE_NAMES.get(itype, f"unknown ({itype})")
        if itype not in offered and itype != EAP_TYPE_TLV:
            offered.append(itype)
            log(f"  -> The server offers an inner EAP method: {name} ({itype})")

        if args.probe_methods and itype != EAP_TYPE_TLV:
            # Enumeration mode: walk through the candidates with Nak (at the end the
            # server typically replies EAP-Failure / "No mutually acceptable types").
            nxt = None
            while nak_queue:
                cand = nak_queue.pop(0)
                if cand not in offered:
                    nxt = cand
                    break
            if nxt is not None:
                if args.debug:
                    log(f"    [inner] Nak -> {EAP_TYPE_NAMES.get(nxt, nxt)} ({nxt})", file=sys.stderr)
                pending_out = inner_send(eap_type, tunnel, iident, EAP_TYPE_NAK, bytes([nxt]))
                continue
            log(f"\n>> Probing done. Observed inner methods: {_fmt_types(offered)}")
            return RESULT_NOAUTH, f"method probe complete; observed: {_fmt_types(offered)}"

        # PEAP Extensions / Result-TLV (after the inner auth): acknowledge with success.
        if itype == EAP_TYPE_TLV:
            status, has_cb = parse_result_tlv(idata)
            if has_cb:
                log(">> WARNING: the server sent a Cryptobinding TLV; we do not compute it. "
                      "If the policy requires it, it may reject.")
            st = 1 if (status is None or status == 1) else 2
            resp_tlv = struct.pack(">HHH", 0x8003, 2, st)  # Result TLV, Mandatory bit
            pending_out = inner_send(eap_type, tunnel, iident, EAP_TYPE_TLV, resp_tlv)
            continue

        # Inner MSCHAPv2 (PEAP-MSCHAPv2): challenge/response from --password.
        if itype == EAP_TYPE_MSCHAPV2 and args.password is not None:
            status, msdata, info = mschapv2_handle(idata, inner_identity, args.password, mschap_state)
            if status == "failure":
                log(f"\n>> Inner MSCHAPv2 failed (wrong password?): {info or '(no detail)'}")
                return RESULT_REJECT, "inner MSCHAPv2 failed (wrong password?)"
            if status == "success-ack":
                if mschap_state.get("password_ok"):
                    log(">> Inner MSCHAPv2 SUCCEEDED - the password is CORRECT "
                          "(server AuthenticatorResponse verified).")
                else:
                    log(">> Inner MSCHAPv2 Success, but the server's 'S=' response could not "
                          "be verified.")
            elif args.debug:
                log("    [inner] MSCHAPv2 challenge -> response", file=sys.stderr)
            pending_out = inner_send(eap_type, tunnel, iident, EAP_TYPE_MSCHAPV2, msdata)
            continue

        # Actually complete a cleartext-password method if --password is given:
        if itype == EAP_TYPE_GTC and args.password is not None:
            if args.debug:
                log("    [inner] EAP-GTC response: sending cleartext password", file=sys.stderr)
            pending_out = inner_send(eap_type, tunnel, iident, EAP_TYPE_GTC, args.password.encode(args.password_encoding))
            continue
        if args.password is not None and not tried_gtc_switch and itype not in (EAP_TYPE_GTC, EAP_TYPE_MSCHAPV2):
            # The server offers a method we do not handle (e.g. capabilities/254
            # or MD5): request a real method with Nak. MSCHAPv2 for PEAP, GTC for TTLS.
            tried_gtc_switch = True
            target = EAP_TYPE_MSCHAPV2 if eap_type == EAP_TYPE_PEAP else EAP_TYPE_GTC
            log(f">> Nak: requesting method switch to {EAP_TYPE_NAMES[target]} (instead of {name}).")
            pending_out = inner_send(eap_type, tunnel, iident, EAP_TYPE_NAK, bytes([target]))
            continue

        # No password, or the method cannot be done with a cleartext password: report and stop.
        log(f"\n>> First offered inner method: {name} ({itype}).")
        if len(offered) > 1:
            log(f">> Observed inner methods: {_fmt_types(offered)}")
        if args.password is None:
            log(">> Without a password we cannot complete it. PAP: --inner-auth pap --password ... ; "
                  "GTC: pass --password (the default 'eap' mode completes it via GTC).")
        else:
            log(f">> This method ({name}) cannot be completed by this script.")
        if args.password is None:
            return RESULT_ERROR, f"inner method {name} needs a password (--password)"
        return RESULT_ERROR, f"inner method {name} cannot be completed by this tool"


def _fmt_types(types: list[int]) -> str:
    return ", ".join(f"{EAP_TYPE_NAMES.get(t, '?')} ({t})" for t in types)


def run_bare_mschapv2(conv: RadiusConversation, eap_bytes: bytes, args) -> tuple[str, str]:
    """Bare EAP-MSCHAPv2 (no TLS tunnel): the challenge/response goes directly in
    the outer EAP."""
    username = args.identity
    mschap_state: dict = {}
    while True:
        icode, iident, etype, edata = inner_eap_parse(eap_bytes)
        if icode == EAP_SUCCESS:
            log("\n>> EAP-Success (MSCHAPv2 succeeded).")
            return RESULT_ACCESS, "EAP-Success: MSCHAPv2 succeeded"
        if icode == EAP_FAILURE:
            log("\n>> EAP-Failure.")
            return RESULT_REJECT, "EAP-Failure"
        if etype != EAP_TYPE_MSCHAPV2:
            log(f"\n>> Unexpected EAP type in the reply: {etype}")
            return RESULT_ERROR, f"unexpected EAP type in the reply: {etype}"
        status, msdata, info = mschapv2_handle(edata, username, args.password, mschap_state)
        if status == "failure":
            log(f"\n>> MSCHAPv2 failed (wrong password?): {info or '(no detail)'}")
            return RESULT_REJECT, "MSCHAPv2 failed (wrong password?)"
        if status == "success-ack":
            if mschap_state.get("password_ok"):
                log(">> MSCHAPv2 SUCCEEDED - the password is CORRECT "
                      "(server AuthenticatorResponse verified).")
            else:
                log(">> MSCHAPv2 Success, but the server's 'S=' response could not be verified.")
        eap_resp = inner_eap_build(EAP_RESPONSE, iident, EAP_TYPE_MSCHAPV2, msdata)
        code, attrs = conv.send_eap(eap_resp, username=args.identity)
        if code == ACCESS_ACCEPT:
            log(f"\n>> ACCESS-ACCEPT (MSCHAPv2 succeeded). {accept_diagnostics(attrs)}")
            return RESULT_ACCESS, "Access-Accept: MSCHAPv2 succeeded"
        if code == ACCESS_REJECT:
            log(f"\n>> ACCESS-REJECT. {reject_diagnostics(attrs)}")
            return RESULT_REJECT, "Access-Reject"
        eap_bytes = get_eap_message(attrs)


def _build_request_attrs(args) -> tuple[str, list[tuple[int, bytes]] | None]:
    """Resolve the NAS-IP-Address and build the optional RADIUS attribute list
    (Service-Type, NAS-Port-Type, Calling-Station-Id, Framed-Protocol). Shared by
    the CLI (main) and the library entry point (authenticate)."""
    nas_ip = args.nas_ip or args.source_ip or "127.0.0.1"
    extra: list[tuple[int, bytes]] = []
    if args.service_type is not None:
        extra.append((ATTR_SERVICE_TYPE, struct.pack(">I", args.service_type)))
    if args.nas_port_type is not None:
        extra.append((ATTR_NAS_PORT_TYPE, struct.pack(">I", args.nas_port_type)))
    if args.calling_station_id is not None:
        extra.append((ATTR_CALLING_STATION_ID, args.calling_station_id.encode()))
    if args.framed_protocol is not None:
        extra.append((ATTR_FRAMED_PROTOCOL, struct.pack(">I", args.framed_protocol)))
    return nas_ip, (extra or None)


def authenticate(
    server,
    secret,
    *,
    port=1812,
    identity="anonymous",
    password=None,
    password_encoding="utf-8",
    auth="auto",
    inner_auth="eap",
    inner_identity=None,
    sni=None,
    ca_cert=None,
    unsafe_cert=False,
    timeout=5.0,
    source_ip=None,
    nas_ip=None,
    probe_methods=False,
    allow_tls13=False,
    service_type=None,
    nas_port_type=None,
    calling_station_id=None,
    framed_protocol=None,
    debug=False,
    extra_attrs=None,
) -> tuple[str, str]:
    """Public library entry point with explicit keyword arguments. Only `server`
    and `secret` are required; everything else mirrors the CLI options and uses
    the same defaults. Runs the configured method via probe() and ALWAYS returns
    a (state, message) tuple (never raises): state is one of RESULT_ACCESS /
    RESULT_REJECT / RESULT_ERROR / RESULT_NOAUTH, message is a short summary.

    `extra_attrs`, if given, is a list of raw (type, value_bytes) RADIUS
    attributes appended after the ones built from service_type/nas_port_type/etc.
    """
    args = argparse.Namespace(
        server=server, secret=secret, port=port, identity=identity,
        password=password, password_encoding=password_encoding, auth=auth, inner_auth=inner_auth,
        inner_identity=inner_identity, sni=sni, ca_cert=ca_cert,
        unsafe_cert=unsafe_cert, timeout=timeout, source_ip=source_ip,
        nas_ip=nas_ip, probe_methods=probe_methods, allow_tls13=allow_tls13,
        service_type=service_type, nas_port_type=nas_port_type,
        calling_station_id=calling_station_id, framed_protocol=framed_protocol,
        debug=debug,
    )
    resolved_nas_ip, built_attrs = _build_request_attrs(args)
    if extra_attrs:
        built_attrs = (built_attrs or []) + list(extra_attrs)
    try:
        return probe(server, args, resolved_nas_ip, built_attrs or None)
    except (RuntimeError, ValueError, OSError) as e:
        return RESULT_ERROR, str(e)


def probe(server, args, nas_ip, extra_attrs) -> tuple[str, str]:
    try:
        "".encode(args.password_encoding)
    except LookupError:
        raise ValueError(f"unknown --password-encoding: {args.password_encoding!r}")
    conv = RadiusConversation(
        server, args.port, args.secret, nas_ip, args.timeout,
        source_ip=args.source_ip, extra_attrs=extra_attrs, debug=args.debug,
    )

    # Plain RADIUS PAP (no EAP): a single Access-Request with User-Name +
    # encrypted User-Password. This is the only method that sends no EAP at all,
    # so it is handled before the EAP Identity exchange below.
    if args.auth == "pap":
        if not args.password:
            raise RuntimeError("--auth pap needs --password (and --identity is the username).")
        log(f"Plain RADIUS PAP (no EAP), User-Name={args.identity}")
        code, attrs = conv.send_pap(args.identity, args.password or "", encoding=args.password_encoding)
        if code == ACCESS_ACCEPT:
            log(f"\n>> ACCESS-ACCEPT (PAP succeeded, the password is correct). {accept_diagnostics(attrs)}")
            return RESULT_ACCESS, "Access-Accept: PAP authentication succeeded"
        if code == ACCESS_REJECT:
            log(f"\n>> ACCESS-REJECT (wrong password, or the policy does not allow PAP). "
                  f"{reject_diagnostics(attrs)}")
            return RESULT_REJECT, "Access-Reject: wrong password or PAP not permitted"
        log(f"\n>> Unexpected RADIUS response code: {code}")
        return RESULT_ERROR, f"unexpected RADIUS response code {code}"

    # 1) EAP-Response/Identity -> starts the server's EAP/PEAP/TTLS flow.
    code, attrs = conv.send_eap(build_eap_identity_response(1, args.identity), username=args.identity)
    if code == ACCESS_REJECT:
        raise RuntimeError(
            "The server rejected the connection immediately at the Identity (common causes: "
            "unknown outer username, or a missing Connection Request Policy condition - "
            "see --service-type/--nas-port-type/--calling-station-id). "
            f"Diagnostics: {reject_diagnostics(attrs)}"
        )

    # 2) Outer EAP method negotiation. With --auth auto (default) we use whatever
    #    the server offers and never Nak. With an explicit --auth peap/ttls/tls we
    #    request that tunnel type with a Legacy Nak if the server offers a
    #    non-tunnel method (e.g. EAP-MSCHAPv2=26).
    desired = OUTER_METHOD_MAP.get(args.auth)  # None for auto / none / pap
    want_mschap = args.auth == "mschapv2"
    naks_sent: list[int] = []
    frame = None
    for _ in range(6):
        eap_bytes = get_eap_message(attrs)
        ocode, oid, otype = read_eap_header(eap_bytes)
        if ocode == EAP_FAILURE:
            extra = f" (Nak'd types: {_fmt_types(naks_sent)})" if naks_sent else ""
            raise RuntimeError(f"The server sent EAP-Failure during outer negotiation{extra}. "
                               f"{reject_diagnostics(attrs)}")
        if want_mschap and otype == EAP_TYPE_MSCHAPV2:
            if not args.password:
                raise RuntimeError("bare EAP-MSCHAPv2 needs --password (and --identity is the username).")
            log("Detected EAP type: EAP-MSCHAPv2 (26), bare (no tunnel).")
            return run_bare_mschapv2(conv, eap_bytes, args)
        if otype in SUPPORTED_TLS_TUNNEL_TYPES and not want_mschap:
            frame = parse_eap_peap(eap_bytes)
            break
        oname = EAP_TYPE_NAMES.get(otype, f"unknown ({otype})")
        log(f"The server offers an outer EAP method: {oname} ({otype})")
        if desired is None:
            # --auth auto / none: we do not Nak. Use whatever the server offered.
            if args.auth == "auto":
                if otype == EAP_TYPE_MSCHAPV2:
                    if not args.password:
                        return RESULT_NOAUTH, ("server offered bare EAP-MSCHAPv2 (26); "
                                               "pass a password to authenticate")
                    log("Auto: server-offered EAP-MSCHAPv2 (26), bare (no tunnel).")
                    return run_bare_mschapv2(conv, eap_bytes, args)
                return RESULT_NOAUTH, (f"server offered {oname} ({otype}), which auto does not "
                                       "handle; use --auth peap|ttls|tls|mschapv2 to force one")
            raise RuntimeError("This is not a TLS-tunnel outer type, and --auth none is set. "
                               "Try: --auth peap|ttls|tls|mschapv2")
        log(f"  -> Nak: requesting {EAP_TYPE_NAMES.get(desired, desired)} ({desired})")
        naks_sent.append(otype)
        code, attrs = conv.send_eap(build_eap_nak(oid, desired), username=args.identity)
        if code == ACCESS_REJECT:
            raise RuntimeError(
                f"The server rejected the Nak (for {EAP_TYPE_NAMES.get(desired, desired)}) - "
                f"this outer method is probably not enabled on this realm. "
                f"{reject_diagnostics(attrs)}"
            )
    if frame is None:
        raise RuntimeError("Could not reach a TLS-tunnel outer EAP type even after several Naks.")

    eap_type = frame.eap_type
    log(f"Detected EAP type: {SUPPORTED_TLS_TUNNEL_TYPES[eap_type]} (type number {eap_type})")
    if not (frame.flags & FLAG_START):
        log("WARNING: no Start flag in the first reply, continuing anyway.", file=sys.stderr)

    if eap_type == EAP_TYPE_TTLS and args.inner_auth == "pap" and not args.password:
        raise RuntimeError("TTLS/PAP needs --password (and --inner-identity is advisable).")

    return run_tunnel(conv, eap_type, frame, args)


def main() -> None:
    p = argparse.ArgumentParser(
        description="RADIUS EAP-PEAP/TTLS probe with a full TLS handshake (ssl module) + inner tunnel"
    )
    p.add_argument("--server", required=True, help="RADIUS/NPS server IP address")
    p.add_argument("--port", type=int, default=1812, help="RADIUS auth port (default: 1812)")
    p.add_argument("--secret", required=True, help="RADIUS shared secret (PSK)")
    p.add_argument("--identity", default="anonymous", help="Outer EAP identity")
    p.add_argument("--sni", default=None,
                   help="TLS SNI/hostname. If set and verification is on, the server certificate name "
                        "is also checked against it. Default: no SNI.")
    p.add_argument("--ca-cert", default=None,
                   help="CA certificate(s) file (PEM) to verify the server cert. If not given, the "
                        "system default CAs are used.")
    p.add_argument("--unsafe-cert", "--allow-unverified-cert", dest="unsafe_cert", action="store_true",
                   help="Disable server certificate verification (accept any/self-signed cert). "
                        "Verification is ON by default. Useful for cert probing or "
                        "a private CA.")
    p.add_argument("--source-ip", default=None, help="Source IP address (for multi-homed clients)")
    p.add_argument("--nas-ip", default=None, help="NAS-IP-Address attribute (default: --source-ip or 127.0.0.1)")
    p.add_argument("--timeout", type=float, default=5.0, help="UDP reply timeout (seconds)")

    p.add_argument("--auth", choices=["auto", "peap", "ttls", "tls", "mschapv2", "pap", "none"], default="auto",
                   help="Outermost authentication method. 'auto' (default): use whatever the server "
                        "offers - any TLS tunnel type (PEAP/TTLS/TLS) is used as-is; bare EAP-MSCHAPv2 "
                        "is run if --password is given, otherwise just reported; never sends a Nak. "
                        "'peap'/'ttls'/'tls': force that tunnel type (Legacy Nak if the server offers a "
                        "non-tunnel method). 'mschapv2': bare EAP-MSCHAPv2. 'pap': plain RADIUS PAP (NOT "
                        "EAP, no tunnel; needs --password). 'none': like auto for tunnels, but error on "
                        "a non-tunnel offer.")
    p.add_argument("--inner-auth", choices=["eap", "pap", "none"], default="eap",
                   help="Inner authentication: 'eap' (inner EAP, method report; default), "
                        "'pap' (TTLS only: User-Name+User-Password AVP), 'none' (cert+tunnel only).")
    p.add_argument("--inner-identity", default=None, help="Inner (real) identity; default: --identity")
    p.add_argument("--password", default=None, help="Password for TTLS/PAP/MSCHAPv2")
    p.add_argument("--password-encoding", dest="password_encoding", default="utf-8",
                   help="Character encoding for the cleartext PASSWORD on the wire (PAP and "
                        "EAP-GTC). Default: utf-8. Use e.g. cp1250 to match Windows supplicants "
                        "that send accented passwords in the local ANSI code page. Does not affect "
                        "MSCHAPv2 (fixed UTF-16LE) or the identity (UTF-8).")
    p.add_argument("--probe-methods", action="store_true",
                   help="For inner EAP, walk through the candidate methods with Nak and report what the "
                        "server offers.")
    p.add_argument("--allow-tls13", action="store_true",
                   help="Allow TLS 1.3 (default: max TLS1.2 so the Certificate is extractable in "
                        "cleartext). In TLS1.3 only the leaf cert is visible (getpeercert).")

    p.add_argument("--service-type", type=int, default=None, help="Optional Service-Type attribute")
    p.add_argument("--nas-port-type", type=int, default=None, help="Optional NAS-Port-Type (e.g. 19=Wireless-802.11)")
    p.add_argument("--calling-station-id", default=None, help="Optional Calling-Station-Id (e.g. MAC)")
    p.add_argument("--framed-protocol", type=int, default=None, help="Optional Framed-Protocol")
    p.add_argument("--debug", action="store_true", help="Short dump of RADIUS traffic to stderr")
    args = p.parse_args()

    state, message = authenticate(**vars(args))
    if state == RESULT_ERROR:
        log(f"ERROR: {message}", file=sys.stderr)
    sys.exit({RESULT_ACCESS: 0, RESULT_REJECT: 1, RESULT_NOAUTH: 0, RESULT_ERROR: 2}.get(state, 2))


if __name__ == "__main__":
    main()
