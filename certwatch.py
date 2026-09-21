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

Only the Python standard library is used; the certificates are parsed from
their DER form by the small X.509 reader below.

Usage:
    ./certwatch.py [emailaddress]
    (with an email address the report is piped to sendmail instead of stdout)
"""

import sys
import ssl
import socket
import datetime
import ipaddress
import re
import subprocess

HOSTLIST = "certwatch.txt"
TIMEOUT = 10                            # seconds, per connection
EHLO_NAME = "FIXME.to.myhostname.hu"    # name we announce in SMTP EHLO
MAIL_FROM = "Cert-watch <root@FIXME.to.myhostname.hu>"


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
# Connection: TCP + the STARTTLS dance where it is needed
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


def tls_probe(sock, host, allow_tls13):
    """Drive the unverified handshake manually; returns (der_certs, error)."""
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    ctx = unsafe_context(allow_tls13)
    try:
        tls = ctx.wrap_bio(incoming, outgoing, server_hostname=host)
    except Exception as e:      # e.g. IDNA problem with server_hostname
        return [], e
    raw = bytearray()
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
                sock.sendall(out)
            except OSError as e:
                err = err or e
                done = True
        if done:
            break
        try:
            chunk = sock.recv(16384)
        except OSError as e:
            err = e
            break
        if not chunk:
            incoming.write_eof()
            err = err or ssl.SSLError("server closed the connection during the handshake")
            break
        raw += chunk
        incoming.write(chunk)
    certs = extract_certificates(bytes(raw))    # TLS<=1.2: cleartext Certificate
    if not certs:
        certs = peer_chain(tls)                 # TLS1.3 / encrypted handshake
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


def describe(host, certs, now):
    """Detail lines about a received (unverified) chain."""
    out = []
    parsed = []
    for der in certs:
        try:
            parsed.append(Cert(der))
        except Exception as e:
            parsed.append(e)
    leaf = parsed[0] if parsed and isinstance(parsed[0], Cert) else None
    if leaf:
        match = leaf.matches(host)
        out.append("hostname %s: %s" % (
            host, {True: "ok", False: "NO MATCH", None: "no name in cert"}[match]))
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


def test_cert(host, port):
    """Returns (days left or None, summary line, detail lines)."""
    now = datetime.datetime.now(datetime.timezone.utc)

    # 1. the normal, fully verified connection
    try:
        sock = connect(host, port)
    except Exception as e:
        return None, "CONNECT FAILED: %s" % clean_error(e), []
    try:
        with sock:
            with ssl.create_default_context().wrap_socket(
                    sock, server_hostname=host) as ssock:
                cert = Cert(ssock.getpeercert(binary_form=True))
        return cert.days_left(now), "%s  %s" % (fmt_time(cert.not_after), cert.issuer_name), []
    except Exception as e:
        verify_err = e

    # 2. it failed - look at the certificates without verifying anything
    certs, hs_err = [], None
    for allow_tls13 in (False, True):
        try:
            sock = connect(host, port)
        except Exception as e:
            return None, "CONNECT FAILED: %s" % clean_error(e), []
        try:
            with sock:
                certs, hs_err = tls_probe(sock, host, allow_tls13)
        except Exception as e:
            hs_err = e
        if certs:
            break

    summary = "UNVERIFIED: %s" % clean_error(verify_err)
    if not certs:
        detail = ["could not get any certificate from the server"]
        if hs_err is not None:
            detail.append("unverified handshake also failed: %s" % clean_error(hs_err))
        return None, summary, detail

    detail = describe(host, certs, now)
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
    d, e, detail = test_cert(host, int(port))
    data.append((d, e, host, port, detail))

# unknown (no certificate at all) first, then by days left
data.sort(key=lambda x: (x[0] is not None, x[0] if x[0] is not None else 0, x[2]))

reply = "From: %s\nSubject: cert-watcher status\n\n" % MAIL_FROM
for d, e, host, port, detail in data:
    reply += ("%4s  %s:%s " % ("?" if d is None else d, host, port)).ljust(32) + str(e) + "\n"
    for line in detail:
        reply += " " * 8 + line + "\n"

if len(sys.argv) > 1:
    subprocess.run(["/usr/sbin/sendmail"] + sys.argv[1:],
                   input=reply.encode("us-ascii", errors="ignore"))
else:
    print(reply)
