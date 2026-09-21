#! /usr/bin/python3
"""certwatch - SSL/TLS certificate expiry watcher.

Connects to the host:port pairs listed in certwatch.txt and reports how many
days are left until the certificate expires.

A plain verified connection only tells us something when OpenSSL is happy with
the whole chain: known CA, intermediate present, not expired yet, hostname
matches.  When it is not - expired cert, private/self-signed CA, missing
intermediate, wrong name - we reconnect with verification disabled (the same
idea as radprobe.py's --unsafe-cert: CERT_NONE, no hostname check, relaxed
ciphers, TLS capped at 1.2 so the Certificate message stays in cleartext) and
print the received chain in detail.  The days-left value then comes from the
unverified leaf, so an already expired certificate still gets a real (negative)
day count instead of a useless error.

RADIUS realms are handled as well: an "eduroam@edu-realm.com:1812" style entry
means the TLS handshake is carried inside EAP-PEAP / EAP-TTLS over RADIUS, to
the proxy configured below.  Only the outer tunnel is done - no inner
authentication, no password: we wait for the server certificate and then drop
the session, exactly the way we hang up after the cert on the TCP side.  (The
full conversation, with inner auth, is radprobe.py.)

Only the Python standard library is used; the certificates are parsed from
their DER form by the small X.509 reader below.

Usage:
    ./certwatch.py [emailaddress]
    (with an email address the report is piped to sendmail instead of stdout)
"""

import sys
import os
import ssl
import socket
import struct
import hmac
import hashlib
import datetime
import ipaddress
import re
import subprocess

HOSTLIST = "certwatch.txt"
TIMEOUT = 10                            # seconds, per connection / per RADIUS try
EHLO_NAME = "my.hostname.hu"            # name we announce in SMTP EHLO
MAIL_FROM = "Cert-watch <root@mydomain.hu>"

# RADIUS: every "identity@realm:1812" entry of the host list is sent to this proxy with this shared secret.
RADIUS_SERVER = "127.0.0.1"
RADIUS_SECRET = "testing123"
RADIUS_NAS_ID = "certwatch"
RADIUS_CALLING_STATION = "02-00-00-00-00-01"    # some policies want a MAC
RADIUS_RETRIES = 2                      # UDP: how many times a request is resent


# ---------------------------------------------------------------------------
# Minimal DER / X.509 reader
# ---------------------------------------------------------------------------

_OID_NAMES = {
    "2.5.4.3": "CN", "2.5.4.5": "serialNumber", "2.5.4.6": "C", "2.5.4.7": "L",
    "2.5.4.8": "ST", "2.5.4.9": "street", "2.5.4.10": "O", "2.5.4.11": "OU",
    "1.2.840.113549.1.9.1": "emailAddress",
    "0.9.2342.19200300.100.1.25": "DC",
}


def _tlv(buf, pos):
    """Read one DER TLV. Returns (tag, value, position after the element)."""
    tag = buf[pos]
    pos += 1
    if tag & 0x1f == 0x1f:                  # multi-byte tag number (not in X.509)
        while buf[pos] & 0x80:
            pos += 1
        pos += 1
    n = buf[pos]
    pos += 1
    if n & 0x80:                            # long form length
        k = n & 0x7f
        n = int.from_bytes(buf[pos:pos + k], "big")
        pos += k
    return tag, buf[pos:pos + n], pos + n


def _children(buf):
    """Split the value of a constructed element into a [(tag, value), ...] list."""
    out = []
    pos = 0
    while pos < len(buf):
        tag, val, pos = _tlv(buf, pos)
        out.append((tag, val))
    return out


def _oid(val):
    if not val:
        return ""
    parts = [str(val[0] // 40), str(val[0] % 40)]
    n = 0
    for b in val[1:]:
        n = (n << 7) | (b & 0x7f)
        if not b & 0x80:
            parts.append(str(n))
            n = 0
    return ".".join(parts)


def _string(tag, val):
    if tag == 0x1e:                         # BMPString
        return val.decode("utf-16-be", "replace")
    return val.decode("utf-8", "replace")


def _name(der):
    """X.501 Name -> [(attribute, value), ...] in certificate order."""
    out = []
    for _, rdn in _children(der):           # SET OF AttributeTypeAndValue
        for _, atv in _children(rdn):       # SEQUENCE { type, value }
            item = _children(atv)
            if len(item) >= 2:
                oid = _oid(item[0][1])
                out.append((_OID_NAMES.get(oid, oid), _string(item[1][0], item[1][1])))
    return out


def _name_str(name):
    return ", ".join("%s=%s" % (k, v) for k, v in name)


def _name_get(name, key):
    for k, v in name:
        if k == key:
            return v
    return ""


def _time(tag, val):
    """UTCTime / GeneralizedTime -> timezone aware (UTC) datetime."""
    s = val.decode("ascii", "replace").strip().rstrip("Z")
    if tag == 0x17:                         # UTCTime: 2 digit year
        s = ("19" if int(s[:2]) >= 50 else "20") + s
    fmt = "%Y%m%d%H%M%S" if len(s) >= 14 else "%Y%m%d%H%M"
    naive = datetime.datetime.strptime(s[:14], fmt)
    return naive.replace(tzinfo=datetime.timezone.utc)


def _general_names(val):
    """GeneralNames -> printable list (dNSName, IP, rfc822Name, URI)."""
    out = []
    for tag, v in _children(val):
        if tag == 0x82:                                     # dNSName
            out.append(v.decode("ascii", "replace"))
        elif tag == 0x87:                                   # iPAddress
            try:
                out.append(str(ipaddress.ip_address(bytes(v))))
            except ValueError:
                pass
        elif tag == 0x81:                                   # rfc822Name
            out.append("email:" + v.decode("ascii", "replace"))
        elif tag == 0x86:                                   # URI
            out.append("URI:" + v.decode("ascii", "replace"))
    return out


class Cert(object):
    """Just enough of an X.509 certificate for a readable report."""

    def __init__(self, der):
        self.der = bytes(der)
        _, cert_body, _ = _tlv(self.der, 0)         # Certificate SEQUENCE
        _, tbs, _ = _tlv(cert_body, 0)              # tbsCertificate SEQUENCE
        f = _children(tbs)
        i = 1 if f and f[0][0] == 0xa0 else 0       # [0] version, optional
        self.serial = int.from_bytes(f[i][1], "big"); i += 1
        i += 1                                      # signature AlgorithmIdentifier
        self.issuer = _name(f[i][1]); i += 1
        validity = _children(f[i][1]); i += 1
        self.not_before = _time(*validity[0])
        self.not_after = _time(*validity[1])
        self.subject = _name(f[i][1]); i += 1
        i += 1                                      # subjectPublicKeyInfo
        self.san = []
        self.is_ca = False
        for tag, val in f[i:]:
            if tag != 0xa3:                         # [3] extensions
                continue
            for _, exts in _children(val):          # Extensions SEQUENCE
                for _, ext in _children(exts):      # SEQUENCE OF Extension
                    item = _children(ext)
                    if len(item) < 2:
                        continue
                    oid = _oid(item[0][1])
                    inner = _children(item[-1][1])  # extnValue OCTET STRING content
                    if not inner:
                        continue
                    if oid == "2.5.29.17":          # subjectAltName
                        self.san = _general_names(inner[0][1])
                    elif oid == "2.5.29.19":        # basicConstraints
                        bc = _children(inner[0][1])
                        self.is_ca = bool(bc and bc[0][0] == 0x01
                                          and bc[0][1] and bc[0][1][0])

    @property
    def cn(self):
        return _name_get(self.subject, "CN") or _name_str(self.subject)

    @property
    def issuer_name(self):
        """The CA in recognizable form: the organization, and in brackets the
        name of the issuing (intermediate) CA - that one alone, e.g. "YR1",
        would not say much."""
        o = _name_get(self.issuer, "O")
        cn = _name_get(self.issuer, "CN")
        if o and cn:
            return "%s (%s)" % (o, cn)
        return o or cn or _name_str(self.issuer)

    @property
    def self_signed(self):
        return self.subject == self.issuer

    @property
    def names(self):
        """Names the cert is valid for: SAN dNSNames, or the CN as fallback."""
        dns = [n for n in self.san if ":" not in n]
        return dns if dns else ([self.cn] if self.cn else [])

    def days_left(self, now):
        return (self.not_after - now).days

    def matches(self, hostname):
        """True/False, or None if there is no usable name in the cert."""
        names = self.names
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


def fmt_time(dt):
    return dt.strftime("%Y-%m-%d %H:%M:%SZ")


# ---------------------------------------------------------------------------
# Transports.  The TLS handshake below is driven by hand over a MemoryBIO pair,
# so it does not care what carries the records: a TCP socket, or EAP-Message
# attributes of RADIUS packets.  Both transports offer the same two methods:
# send(bytes) and recv() -> bytes.
# ---------------------------------------------------------------------------

def connect(host, port):
    """Connected socket, ready for the TLS handshake (STARTTLS already done)."""
    sock = socket.create_connection((host, port), TIMEOUT)
    try:
        def get():
            return sock.recv(1024)

        def send(s, welc=True):
            if welc:
                get()           # read welcome msg
            sock.sendall(s)     # send cmd
            get()               # read reply

        if port in (25, 587):   # smtp starttls
            send(("EHLO %s\r\n" % EHLO_NAME).encode())
            send(b"STARTTLS\r\n", False)
        elif port == 143:       # imap starttls
            send(b"1 STARTTLS\r\n")
        elif port == 21:        # ftp starttls
            send(b"AUTH TLS\r\n")
    except Exception:
        sock.close()
        raise
    return sock


class TcpTransport(object):
    """TLS records over a plain TCP connection."""

    def __init__(self, host, port):
        self.sock = connect(host, port)

    def send(self, data):
        self.sock.sendall(data)

    def recv(self):
        return self.sock.recv(16384)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# RADIUS / EAP transport
#
# The TLS handshake of an EAP-PEAP / EAP-TTLS tunnel travels in EAP-Message
# attributes of RADIUS Access-Requests.  We only do the outer tunnel: identity,
# method negotiation, then the handshake until the certificate is on the table.
# No inner authentication and no password is ever sent; the half-finished
# RADIUS session is dropped by the server on its own timeout.
# ---------------------------------------------------------------------------

ACCESS_REQUEST, ACCESS_REJECT, ACCESS_CHALLENGE = 1, 3, 11
ATTR_USER_NAME, ATTR_NAS_IP, ATTR_SERVICE_TYPE = 1, 4, 6
ATTR_REPLY_MESSAGE, ATTR_STATE, ATTR_CALLING_STATION = 18, 24, 31
ATTR_NAS_IDENTIFIER, ATTR_NAS_PORT_TYPE = 32, 61
ATTR_EAP_MESSAGE, ATTR_MESSAGE_AUTHENTICATOR = 79, 80

EAP_RESPONSE, EAP_SUCCESS, EAP_FAILURE = 2, 3, 4
EAP_TYPE_IDENTITY, EAP_TYPE_NAK = 1, 3
EAP_FLAG_LENGTH, EAP_FLAG_MORE = 0x80, 0x40
TUNNEL_TYPES = {13: "EAP-TLS", 21: "EAP-TTLS", 25: "EAP-PEAP"}


def eap_identity(eap_id, identity):
    body = bytes([EAP_TYPE_IDENTITY]) + identity.encode()
    return bytes([EAP_RESPONSE, eap_id]) + struct.pack(">H", 4 + len(body)) + body


def eap_nak(eap_id, wanted_type):
    """Legacy Nak: ask for a different EAP type than the offered one (RFC 3748)."""
    body = bytes([EAP_TYPE_NAK, wanted_type])
    return bytes([EAP_RESPONSE, eap_id]) + struct.pack(">H", 4 + len(body)) + body


def eap_tls_payload(eap_id, eap_type, payload):
    """EAP response carrying our TLS flight; an empty payload is the ACK of a
    fragmented server flight."""
    if payload:
        body = (bytes([eap_type, EAP_FLAG_LENGTH])
                + struct.pack(">I", len(payload)) + payload)
    else:
        body = bytes([eap_type, 0])
    return bytes([EAP_RESPONSE, eap_id]) + struct.pack(">H", 4 + len(body)) + body


def parse_eap(eap):
    """(code, id, type, flags, tls payload) of an EAP packet."""
    code, eap_id = eap[0], eap[1]
    length = min(struct.unpack(">H", eap[2:4])[0], len(eap))
    if code in (EAP_SUCCESS, EAP_FAILURE) or length < 5:
        return code, eap_id, None, 0, b""
    eap_type = eap[4]
    flags = eap[5] if length >= 6 else 0
    payload = eap[10:length] if flags & EAP_FLAG_LENGTH else eap[6:length]
    return code, eap_id, eap_type, flags, payload


def radius_request(rid, eap_packet, identity, nas_ip, state):
    """Access-Request with the EAP packet split into 253 byte EAP-Message
    attributes, closed by the Message-Authenticator HMAC-MD5 (RFC 3579)."""
    pairs = [
        (ATTR_USER_NAME, identity.encode()),
        (ATTR_NAS_IP, socket.inet_aton(nas_ip)),
        (ATTR_NAS_IDENTIFIER, RADIUS_NAS_ID.encode()),
        (ATTR_SERVICE_TYPE, struct.pack(">I", 2)),      # Framed
        (ATTR_NAS_PORT_TYPE, struct.pack(">I", 19)),    # Wireless-802.11
        (ATTR_CALLING_STATION, RADIUS_CALLING_STATION.encode()),
    ]
    if state is not None:
        pairs.append((ATTR_STATE, state))
    for pos in range(0, len(eap_packet), 253):
        pairs.append((ATTR_EAP_MESSAGE, eap_packet[pos:pos + 253]))
    pairs.append((ATTR_MESSAGE_AUTHENTICATOR, b"\x00" * 16))   # placeholder, last
    body = b"".join(bytes([t, len(v) + 2]) + v for t, v in pairs)
    packet = (bytes([ACCESS_REQUEST, rid]) + struct.pack(">H", 20 + len(body))
              + os.urandom(16) + body)
    return packet[:-16] + hmac.new(RADIUS_SECRET.encode(), packet, hashlib.md5).digest()


def radius_parse(data):
    """(code, [(type, value), ...]) of a RADIUS packet."""
    length = min(struct.unpack(">H", data[2:4])[0], len(data))
    attrs = []
    pos = 20
    while pos + 2 <= length:
        t, l = data[pos], data[pos + 1]
        if l < 2:
            break
        attrs.append((t, data[pos + 2:pos + l]))
        pos += l
    return data[0], attrs


def attr_join(attrs, t):
    return b"".join(v for k, v in attrs if k == t)


def attr_first(attrs, t):
    for k, v in attrs:
        if k == t:
            return v
    return None


def reply_message(attrs):
    msgs = [v.decode("utf-8", "replace") for k, v in attrs if k == ATTR_REPLY_MESSAGE]
    return " (%s)" % "; ".join(msgs) if msgs else ""


class RadiusTransport(object):
    """TLS records inside an EAP-PEAP / EAP-TTLS tunnel, over RADIUS/UDP."""

    def __init__(self, identity, port):
        self.identity = identity
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(TIMEOUT)
        self.sock.connect((RADIUS_SERVER, port))
        self.nas_ip = self.sock.getsockname()[0]
        self.rid = os.urandom(1)[0]
        self.state = None
        self.attrs = []
        self.eap_id = 1
        self.eap_type = None
        self.method = "EAP"
        self._negotiate()

    def _exchange(self, eap_packet):
        """One Access-Request / Access-Challenge round trip."""
        self.rid = (self.rid + 1) % 256
        packet = radius_request(self.rid, eap_packet, self.identity, self.nas_ip, self.state)
        for _ in range(RADIUS_RETRIES):
            self.sock.send(packet)
            try:
                data = self.sock.recv(4096)
            except socket.timeout:
                continue                # UDP: the request or the reply was lost
            code, attrs = radius_parse(data)
            state = attr_first(attrs, ATTR_STATE)
            if state is not None:
                self.state = state
            if code == ACCESS_REJECT:
                raise RuntimeError("RADIUS Access-Reject%s" % reply_message(attrs))
            if code != ACCESS_CHALLENGE:
                raise RuntimeError("unexpected RADIUS reply code %d%s"
                                   % (code, reply_message(attrs)))
            self.attrs = attrs
            return attrs
        raise socket.timeout("no reply from the RADIUS server %s" % RADIUS_SERVER)

    def _negotiate(self):
        """Identity, then get the server onto a TLS tunnel type (Nak if needed)."""
        attrs = self._exchange(eap_identity(self.eap_id, self.identity))
        wanted = [25, 21]               # ask for PEAP first, then TTLS
        for _ in range(1 + len(wanted)):
            eap = attr_join(attrs, ATTR_EAP_MESSAGE)
            if len(eap) < 4:
                raise RuntimeError("no EAP-Message in the RADIUS reply")
            code, self.eap_id, etype, _, _ = parse_eap(eap)
            if code == EAP_FAILURE:
                raise RuntimeError("EAP-Failure during the outer negotiation")
            if etype in TUNNEL_TYPES:
                self.eap_type = etype
                self.method = TUNNEL_TYPES[etype]
                return
            attrs = self._exchange(eap_nak(self.eap_id, wanted.pop(0)))
        raise RuntimeError("the server offers no EAP tunnel type (PEAP/TTLS) "
                           "for this identity")

    def send(self, data):
        # No outgoing fragmentation: our flights fit in one RADIUS packet (we
        # never send a client certificate, that is what would not fit).
        self._exchange(eap_tls_payload(self.eap_id, self.eap_type, data))

    def recv(self):
        """The server's TLS flight, reassembled from the EAP fragments (M bit)."""
        flight = bytearray()
        while True:
            eap = attr_join(self.attrs, ATTR_EAP_MESSAGE)
            if len(eap) < 4:
                raise RuntimeError("no EAP-Message in the RADIUS reply")
            code, self.eap_id, etype, flags, payload = parse_eap(eap)
            if code in (EAP_SUCCESS, EAP_FAILURE):
                raise RuntimeError("EAP-%s instead of the TLS handshake"
                                   % ("Success" if code == EAP_SUCCESS else "Failure"))
            if etype != self.eap_type:
                raise RuntimeError("the server switched EAP type mid-handshake (%s)" % etype)
            flight += payload
            if not flags & EAP_FLAG_MORE:
                return bytes(flight)
            self._exchange(eap_tls_payload(self.eap_id, self.eap_type, b""))   # ACK

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Unverified handshake (radprobe.py --unsafe-cert style) + chain extraction
# ---------------------------------------------------------------------------

def unsafe_context(allow_tls13):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    # Verification disabled: an expired / self-signed / private-CA cert is fine
    # here, we only want to look at it. Weaker cipher suites are allowed too, so
    # that old servers still talk to us.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    for spec in ("DEFAULT:@SECLEVEL=0", "DEFAULT"):
        try:
            ctx.set_ciphers(spec)
            break
        except ssl.SSLError:
            continue
    # The Certificate message is in cleartext only in TLS<=1.2, so we cap there
    # by default: then the whole chain can be read out of the handshake stream
    # even if the handshake itself dies later on.
    try:
        # MINIMUM_SUPPORTED, not TLSv1: it means the same "as old as this
        # OpenSSL still allows", but naming TLSv1 is deprecated since py3.10.
        ctx.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        if not allow_tls13:
            ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    except (ValueError, AttributeError):
        pass
    return ctx


def tls_probe(transport, ctx, sni, stop_after_cert=False):
    """Drive the handshake by hand over the transport, keeping the raw bytes.
    Returns (list of DER certs, error or None).  With stop_after_cert we hang up
    as soon as the certificate is in: that is all we came for."""
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    try:
        tls = ctx.wrap_bio(incoming, outgoing, server_hostname=sni)
    except Exception as e:      # e.g. IDNA problem with the name
        return [], e
    raw = bytearray()
    certs = []
    err = None
    while True:
        done = False
        try:
            tls.do_handshake()
            done = True
        except ssl.SSLWantReadError:
            pass
        except Exception as e:
            err, done = e, True
        out = outgoing.read()
        if out:
            try:
                transport.send(out)     # our flight, or the alert when it failed
            except Exception as e:
                if not done:
                    err, done = e, True
        if done:
            break
        try:
            chunk = transport.recv()
        except Exception as e:
            err = e
            break
        if not chunk:
            incoming.write_eof()
            err = ssl.SSLError("the peer closed the connection during the handshake")
            break
        raw += chunk
        incoming.write(chunk)
        if stop_after_cert:
            certs = extract_certificates(bytes(raw))
            if certs:
                break
    if not certs:
        certs = extract_certificates(bytes(raw))    # TLS<=1.2: cleartext Certificate
    if not certs:
        certs = peer_chain(tls)                     # TLS1.3 / encrypted handshake
    return certs, err


def extract_certificates(stream):
    """Pull the Certificate chain out of a captured cleartext handshake."""
    body = bytearray()
    pos = 0
    while pos + 5 <= len(stream):
        ctype = stream[pos]
        rec_len = int.from_bytes(stream[pos + 3:pos + 5], "big")
        rec = stream[pos + 5:pos + 5 + rec_len]
        pos += 5 + rec_len
        if ctype == 0x16:                       # handshake record
            body += rec
    certs = []
    pos = 0
    while pos + 4 <= len(body):
        htype = body[pos]
        hlen = int.from_bytes(body[pos + 1:pos + 4], "big")
        hbody = bytes(body[pos + 4:pos + 4 + hlen])
        pos += 4 + hlen
        if htype != 0x0B or len(hbody) < 3:     # Certificate
            continue
        end = min(3 + int.from_bytes(hbody[0:3], "big"), len(hbody))
        cpos = 3
        while cpos + 3 <= end:
            clen = int.from_bytes(hbody[cpos:cpos + 3], "big")
            cpos += 3
            certs.append(hbody[cpos:cpos + clen])
            cpos += clen
    return [c for c in certs if c]


def peer_chain(tls):
    """Chain from the TLS object itself (get_unverified_chain needs py3.13+,
    otherwise only the leaf is available)."""
    for meth in ("get_unverified_chain", "get_verified_chain"):
        try:
            certs = getattr(tls, meth)()
        except Exception:
            continue
        ders = [bytes(c) for c in (certs or ()) if isinstance(c, (bytes, bytearray))]
        if ders:
            return ders
    try:
        der = tls.getpeercert(binary_form=True)
        if der:
            return [der]
    except Exception:
        pass
    return []


# ---------------------------------------------------------------------------
# Probing one host
# ---------------------------------------------------------------------------

def clean_error(e):
    """Shortest useful form of an exception."""
    msg = re.sub(r"\s*\(_ssl\.c:\d+\)", "",
                 getattr(e, "verify_message", None) or str(e)).strip()
    if isinstance(e, (ssl.SSLError, OSError)):      # these speak for themselves
        return msg or e.__class__.__name__
    return "%s: %s" % (e.__class__.__name__, msg) if msg else e.__class__.__name__


def describe(hostname, certs, now):
    """Detail lines about a received (unverified) chain.  hostname=None (RADIUS
    identity) means there is no name to check the certificate against."""
    out = []
    parsed = []
    for der in certs:
        try:
            parsed.append(Cert(der))
        except Exception as e:
            parsed.append(e)
    leaf = parsed[0] if parsed and isinstance(parsed[0], Cert) else None
    if leaf and hostname:
        match = leaf.matches(hostname)
        out.append("hostname %s: %s" % (
            hostname, {True: "ok", False: "NO MATCH", None: "no name in cert"}[match]))
    out.append("chain received: %d certificate(s)" % len(certs))
    for i, c in enumerate(parsed, 1):
        if not isinstance(c, Cert):
            out.append("[%d] unparseable certificate: %s" % (i, c))
            continue
        flags = []
        if c.is_ca:
            flags.append("CA")
        if c.self_signed:
            flags.append("self-signed")
        out.append("[%d] subject: %s%s" % (
            i, _name_str(c.subject), "  (%s)" % ", ".join(flags) if flags else ""))
        if c.san:
            out.append("    SAN:     %s" % ", ".join(c.san))
        out.append("    issuer:  %s" % _name_str(c.issuer))
        days = c.days_left(now)
        state = ("EXPIRED %d days ago" % -days if days < 0 else
                 "not valid yet" if c.not_before > now else
                 "%d days left" % days)
        out.append("    valid:   %s -> %s  (%s)" % (
            fmt_time(c.not_before), fmt_time(c.not_after), state))
        out.append("    serial:  %x" % c.serial)
    return out


class TcpTarget(object):
    """A host:port entry: implicit TLS, or STARTTLS on the ports we know."""

    check_hostname = True

    def __init__(self, host, port):
        self.host, self.port = host, port
        self.hostname = host            # the name the cert has to be valid for
        self.sni = host

    def open(self):
        return TcpTransport(self.host, self.port)


class RadiusTarget(object):
    """An identity@realm:1812 entry: EAP-PEAP/TTLS tunnel through the RADIUS
    proxy.  The identity is not a hostname, so only the chain is verified - a
    RADIUS certificate is issued for the radius server's own name, which has
    nothing to do with the realm."""

    check_hostname = False
    hostname = None
    sni = None

    def __init__(self, identity, port):
        self.identity, self.port = identity, port

    def open(self):
        return RadiusTransport(self.identity, self.port)


def make_target(host, port):
    return RadiusTarget(host, port) if port==1812 else TcpTarget(host, port)


def test_cert(target):
    """Returns (days left or None, summary line, detail lines)."""
    now = datetime.datetime.now(datetime.timezone.utc)

    # 1. the normal, fully verified handshake
    try:
        transport = target.open()
    except Exception as e:
        return None, "CONNECT FAILED: %s" % clean_error(e), []
    tunnel = getattr(transport, "method", "")       # EAP-PEAP / EAP-TTLS
    try:
        ctx = ssl.create_default_context()
        if not target.check_hostname:
            ctx.check_hostname = False
        certs, err = tls_probe(transport, ctx, target.sni)
        if err is not None:
            raise err
        if not certs:
            raise RuntimeError("no certificate received")
        cert = Cert(certs[0])
        return (cert.days_left(now),
                "%s  %s%s" % (fmt_time(cert.not_after), cert.issuer_name,
                              "  [%s]" % tunnel if tunnel else ""), [])
    except Exception as e:
        verify_err = e
    finally:
        transport.close()

    # 2. it failed - look at the certificates without verifying anything
    certs, hs_err = [], None
    for allow_tls13 in (False, True):
        try:
            transport = target.open()
        except Exception as e:
            return None, "CONNECT FAILED: %s" % clean_error(e), []
        try:
            certs, hs_err = tls_probe(transport, unsafe_context(allow_tls13),
                                      target.sni, stop_after_cert=True)
        except Exception as e:
            hs_err = e
        finally:
            transport.close()
        if certs:
            break

    summary = "UNVERIFIED: %s" % clean_error(verify_err)
    if not certs:
        detail = ["could not get any certificate from the server"]
        if hs_err is not None:
            detail.append("unverified handshake also failed: %s" % clean_error(hs_err))
        return None, summary, detail

    detail = describe(target.hostname, certs, now)
    if tunnel:
        detail.insert(0, "tunnel: %s" % tunnel)
    if hs_err is not None:
        detail.append("(the unverified handshake did not complete either: %s)"
                      % clean_error(hs_err))
    try:
        leaf = Cert(certs[0])
    except Exception:
        return None, summary, detail
    return leaf.days_left(now), summary, detail


# ---------------------------------------------------------------------------
# Check every host from the list, report sorted by days left
# ---------------------------------------------------------------------------

data = []
for line in open(HOSTLIST, "rt"):
    i = line.split("#")[0].strip()
    if not i:
        continue                # skip empty lines / comments
    host, port = i.rsplit(":", 1)
    d, e, detail = test_cert(make_target(host, int(port)))
    data.append((d, e, host, port, detail))

# unknown (no certificate at all) first, then by days left
data.sort(key=lambda x: (x[0] is not None, x[0] if x[0] is not None else 0, x[2]))

reply = ""
for d, e, host, port, detail in data:
    reply += ("%4s  %s:%s " % ("?" if d is None else d, host, port)).ljust(32) + str(e) + "\n"
    for line in detail:
        reply += " " * 8 + line + "\n"

header = "From: %s\nSubject: cert-watcher status\n" % MAIL_FROM
# A certificate subject/issuer may well be non-ASCII (accented organization
# names), so the mail is sent as UTF-8 - the old us-ascii encoding silently
# dropped those characters.
mime = ("MIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=utf-8\n"
        "Content-Transfer-Encoding: 8bit\n")

if len(sys.argv) > 1:
    subprocess.run(["/usr/sbin/sendmail"] + sys.argv[1:],
                   input=(header + mime + "\n" + reply).encode("utf-8"))
else:
    print(header + "\n" + reply)
