#!/usr/bin/env python3
"""
RADIUS / EAP-PEAP tanusitvany-lekerdezo kliens (MS-CHAPv2 nelkul).

Csak addig viszi vegig a PEAP outer TLS handshake-et, amig a szerver el nem
kuldi a tanusitvany-lancat (ServerHello -> Certificate -> ServerHelloDone).
A ClientKeyExchange/Finished lepesekre NINCS szukseg, mert PEAP-ban a szerver
tanusitvanya mar a hitelesites elott, a TLS-alagut felepitesenek elso
flight-jaban megerkezik - a belso MSCHAPv2 csak EZUTAN kovetkezne.

Fuggosegek:
    pip install cryptography

Hasznalat:
    python3 radius_peap_cert_probe.py --server 10.0.0.10 --secret "titok"
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import os
import socket
import struct
import sys
from dataclasses import dataclass, field

try:
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID
except ImportError:
    sys.exit("HIBA: hianyzik a 'cryptography' csomag. Telepitsd: pip install cryptography")


# ----------------------------------------------------------------------------
# RADIUS reteg (RFC 2865 / RFC 3579 - EAP Message-Authenticator)
# ----------------------------------------------------------------------------

ACCESS_REQUEST = 1
ACCESS_ACCEPT = 2
ACCESS_REJECT = 3
ACCESS_CHALLENGE = 11

ATTR_USER_NAME = 1
ATTR_NAS_IP_ADDRESS = 4
ATTR_STATE = 24
ATTR_NAS_IDENTIFIER = 32
ATTR_EAP_MESSAGE = 79
ATTR_MESSAGE_AUTHENTICATOR = 80


def _encode_attr(t: int, value: bytes) -> bytes:
    if len(value) > 253:
        raise ValueError("egy RADIUS attributum erteke max 253 byte lehet")
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
) -> bytes:
    """Felepiti az Access-Request csomagot, a szukseg szerint tobb EAP-Message
    attributumra darabolva az EAP payloadot (attributum-szintu fragmentacio),
    es a vegen kiszamitja a Message-Authenticator HMAC-MD5-öt (RFC 3579)."""
    request_authenticator = os.urandom(16)

    attrs: list[tuple[int, bytes]] = [
        (ATTR_USER_NAME, username.encode()),
        (ATTR_NAS_IP_ADDRESS, socket.inet_aton(nas_ip)),
        (ATTR_NAS_IDENTIFIER, b"python-peap-cert-probe"),
    ]
    if state is not None:
        attrs.append((ATTR_STATE, state))
    for chunk in _split_chunks(eap_packet, 253):
        attrs.append((ATTR_EAP_MESSAGE, chunk))
    attrs.append((ATTR_MESSAGE_AUTHENTICATOR, b"\x00" * 16))  # placeholder

    body = b"".join(_encode_attr(t, v) for t, v in attrs)
    packet_len = 20 + len(body)
    header = bytes([ACCESS_REQUEST, radius_id]) + struct.pack(">H", packet_len) + request_authenticator
    packet = header + body

    # Message-Authenticator = HMAC-MD5(teljes csomag, a mezo helyen csupa nulla
    # bytekkal), a titkos kulccsal (secret) mint HMAC kulcs.
    mac = hmac.new(secret, packet, hashlib.md5).digest()
    packet = packet[:-16] + mac  # az utolso attributum eppen a Message-Authenticator value-ja
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
    """A valaszban tobb EAP-Message attributum is lehet (attributum-szintu
    fragmentacio egy RADIUS csomagon belul) - ezeket sorrendben osszefuzve
    kapjuk vissza a teljes EAP csomagot."""
    return b"".join(v for t, v in attrs if t == ATTR_EAP_MESSAGE)


def get_state(attrs: list[tuple[int, bytes]]) -> bytes | None:
    for t, v in attrs:
        if t == ATTR_STATE:
            return v
    return None


# ----------------------------------------------------------------------------
# EAP reteg (RFC 3748) + EAP-PEAP fragmentacios fejlec (RFC 5216-stilus flags)
# ----------------------------------------------------------------------------

EAP_REQUEST = 1
EAP_RESPONSE = 2
EAP_SUCCESS = 3
EAP_FAILURE = 4

EAP_TYPE_IDENTITY = 1
EAP_TYPE_PEAP = 25

FLAG_LENGTH_INCLUDED = 0x80
FLAG_MORE_FRAGMENTS = 0x40
FLAG_START = 0x20


@dataclass
class EapPeapFrame:
    eap_code: int
    eap_id: int
    flags: int
    total_length: int | None
    payload: bytes


def parse_eap_peap(eap_packet: bytes) -> EapPeapFrame:
    code, ident = eap_packet[0], eap_packet[1]
    length = struct.unpack(">H", eap_packet[2:4])[0]
    if code in (EAP_SUCCESS, EAP_FAILURE):
        return EapPeapFrame(code, ident, 0, None, b"")
    eap_type = eap_packet[4]
    type_data = eap_packet[5:length]
    if eap_type != EAP_TYPE_PEAP:
        raise ValueError(f"varatlan EAP tipus: {eap_type} (25=PEAP vart)")
    flags = type_data[0]
    rest = type_data[1:]
    total_length = None
    if flags & FLAG_LENGTH_INCLUDED:
        total_length = struct.unpack(">I", rest[:4])[0]
        rest = rest[4:]
    return EapPeapFrame(code, ident, flags, total_length, rest)


def build_eap_identity_response(eap_id: int, identity: str) -> bytes:
    type_data = bytes([EAP_TYPE_IDENTITY]) + identity.encode()
    body = bytes([EAP_RESPONSE, eap_id]) + struct.pack(">H", 4 + len(type_data)) + type_data
    return body


def build_eap_peap_response(eap_id: int, flags: int, payload: bytes = b"") -> bytes:
    type_data = bytes([flags]) + payload
    full = bytes([EAP_TYPE_PEAP]) + type_data
    body = bytes([EAP_RESPONSE, eap_id]) + struct.pack(">H", 4 + len(full)) + full
    return body


# ----------------------------------------------------------------------------
# Minimalis, kezzel epitett TLS 1.2 ClientHello
# ----------------------------------------------------------------------------

# Csak olyan cipher suite-okat ajanlunk fel, amikhez a kiszolgalo valasza
# (ServerHello + Certificate) meg a kulcscsere resze elott, tiszta szovegben
# erkezik - ez minden TLS 1.2 RSA/ECDHE-RSA suite-ra igaz, szoval bovebb
# kompatibilitas kedveert mindkettobol ajanlunk fel nehanyat.
CIPHER_SUITES = [
    0xC027,  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    0xC013,  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    0xC028,  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    0xC014,  # TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    0x003C,  # TLS_RSA_WITH_AES_128_CBC_SHA256
    0x002F,  # TLS_RSA_WITH_AES_128_CBC_SHA
    0x003D,  # TLS_RSA_WITH_AES_256_CBC_SHA256
    0x0035,  # TLS_RSA_WITH_AES_256_CBC_SHA
]


def _tls_extension(ext_type: int, data: bytes) -> bytes:
    return struct.pack(">HH", ext_type, len(data)) + data


def build_client_hello_record() -> bytes:
    client_version = b"\x03\x03"  # TLS 1.2
    rnd = os.urandom(32)
    session_id = b"\x00"

    cs_bytes = b"".join(struct.pack(">H", c) for c in CIPHER_SUITES)
    cipher_suites = struct.pack(">H", len(cs_bytes)) + cs_bytes

    compression = b"\x01\x00"  # 1 modszer, null

    sig_algs = [0x0401, 0x0501, 0x0403, 0x0503, 0x0201]  # rsa/ecdsa pkcs1 + sha256/384/1
    ext_sig_algs = _tls_extension(
        0x000D, struct.pack(">H", len(sig_algs) * 2) + b"".join(struct.pack(">H", a) for a in sig_algs)
    )

    groups = [0x0017, 0x0018, 0x001D]  # secp256r1, secp384r1, x25519
    ext_groups = _tls_extension(
        0x000A, struct.pack(">H", len(groups) * 2) + b"".join(struct.pack(">H", g) for g in groups)
    )

    ext_point_fmt = _tls_extension(0x000B, bytes([1, 0x00]))  # uncompressed
    ext_renego = _tls_extension(0xFF01, b"\x00")  # empty renegotiated_connection

    extensions = ext_sig_algs + ext_groups + ext_point_fmt + ext_renego

    body = (
        client_version
        + rnd
        + session_id
        + cipher_suites
        + compression
        + struct.pack(">H", len(extensions))
        + extensions
    )
    handshake_msg = bytes([0x01]) + len(body).to_bytes(3, "big") + body  # 0x01 = ClientHello
    record = bytes([0x16]) + b"\x03\x03" + struct.pack(">H", len(handshake_msg)) + handshake_msg
    return record


# ----------------------------------------------------------------------------
# TLS rekordok / handshake uzenetek parse-olasa (Certificate kibontasahoz)
# ----------------------------------------------------------------------------

def extract_certificates(tls_stream: bytes) -> list[bytes]:
    """Vegigmegy a (tobb TLS rekordot is tartalmazo) bajtfolyamon, es
    kibontja a Certificate (handshake type=11) uzenetben talalhato DER
    tanusitvany-lancot."""
    certs: list[bytes] = []
    pos = 0
    while pos + 5 <= len(tls_stream):
        content_type = tls_stream[pos]
        rec_len = struct.unpack(">H", tls_stream[pos + 3:pos + 5])[0]
        rec_data = tls_stream[pos + 5:pos + 5 + rec_len]
        pos += 5 + rec_len

        if content_type != 0x16:  # csak Handshake rekordok erdekelnek
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


def print_certificates(der_certs: list[bytes]) -> None:
    if not der_certs:
        print("Nem erkezett tanusitvany a valaszban.")
        return

    print(f"\nA szerver {len(der_certs)} tanusitvanyt kuldott (lanc, level elsonek):\n")
    for i, der in enumerate(der_certs, 1):
        cert = x509.load_der_x509_certificate(der, default_backend())

        def cn_of(name: x509.Name) -> str:
            attrs = name.get_attributes_for_oid(NameOID.COMMON_NAME)
            return attrs[0].value if attrs else name.rfc4514_string()

        print(f"  [{i}] CN:         {cn_of(cert.subject)}")
        print(f"       Subject:    {cert.subject.rfc4514_string()}")
        print(f"       Kibocsato:  {cn_of(cert.issuer)}  ({cert.issuer.rfc4514_string()})")
        try:
            not_before = cert.not_valid_before_utc
            not_after = cert.not_valid_after_utc
        except AttributeError:  # regebbi 'cryptography' verzio
            not_before = cert.not_valid_before
            not_after = cert.not_valid_after
        print(f"       Ervenyes:   {not_before}  ->  {not_after}")
        print(f"       Sorozatszam:{cert.serial_number:x}")
        print()


# ----------------------------------------------------------------------------
# Fo folyamat
# ----------------------------------------------------------------------------

class RadiusConversation:
    def __init__(self, server: str, port: int, secret: str, nas_ip: str, timeout: float):
        self.server = server
        self.port = port
        self.secret = secret.encode()
        self.nas_ip = nas_ip
        self.timeout = timeout
        self.radius_id = os.urandom(1)[0]
        self.state: bytes | None = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(timeout)

    def _next_radius_id(self) -> int:
        self.radius_id = (self.radius_id + 1) % 256
        return self.radius_id

    def send_eap(self, eap_packet: bytes, username: str = "anonymous", retries: int = 3) -> tuple[int, list[tuple[int, bytes]]]:
        packet = build_access_request(
            self._next_radius_id(), self.secret, eap_packet, username, self.nas_ip, self.state
        )
        last_err: Exception | None = None
        for attempt in range(retries):
            try:
                self.sock.sendto(packet, (self.server, self.port))
                data, _ = self.sock.recvfrom(65535)
                code, ident, auth, attrs = parse_radius_packet(data)
                new_state = get_state(attrs)
                if new_state is not None:
                    self.state = new_state
                return code, attrs
            except socket.timeout as e:
                last_err = e
                continue
        raise TimeoutError(f"Nincs valasz a RADIUS szervertol ({self.server}:{self.port}) {retries} probalkozas utan") from last_err


def probe_certificate(server: str, port: int, secret: str, identity: str, nas_ip: str, timeout: float) -> list[bytes]:
    conv = RadiusConversation(server, port, secret, nas_ip, timeout)

    # 1) EAP-Response/Identity - ez inditja a szerver oldali EAP/PEAP folyamatot.
    #    Az outer identity ertekenek NEM kell valos felhasznalonak lennie:
    #    a NPS meg a felhasznalo/jelszo ellenorzese ELOTT elkuldi a tanusitvanyat
    #    a TLS handshake reszekent.
    eap_id = 1
    code, attrs = conv.send_eap(build_eap_identity_response(eap_id, identity), username=identity)
    if code == ACCESS_REJECT:
        raise RuntimeError("A szerver azonnal elutasitotta a kapcsolatot (Access-Reject) mar az Identity-nel.")
    eap_bytes = get_eap_message(attrs)
    frame = parse_eap_peap(eap_bytes)
    if not (frame.flags & FLAG_START):
        print("FIGYELEM: a szerver elso valasza nem tartalmazott PEAP Start jelzest, folytatjuk azert.", file=sys.stderr)

    # 2) ClientHello elkuldese (egyetlen fragmensben, mivel a ClientHello kicsi).
    client_hello = build_client_hello_record()
    code, attrs = conv.send_eap(build_eap_peap_response(frame.eap_id, flags=0, payload=client_hello), username=identity)
    if code == ACCESS_REJECT:
        raise RuntimeError("A szerver elutasitotta a ClientHello-t (Access-Reject).")

    # 3) A szerver ServerHello+Certificate+ServerHelloDone flight-jenek
    #    osszegyujtese - ez tobb EAP-fragmensre (M bit) is szethullhat,
    #    ilyenkor ures ACK-kal kell kernünk a kovetkezo darabot.
    tls_buffer = bytearray()
    while True:
        eap_bytes = get_eap_message(attrs)
        frame = parse_eap_peap(eap_bytes)

        if frame.eap_code == EAP_FAILURE:
            raise RuntimeError("A szerver EAP-Failure-t kuldott a TLS handshake kozben.")
        if frame.eap_code == EAP_SUCCESS:
            break

        tls_buffer.extend(frame.payload)

        if frame.flags & FLAG_MORE_FRAGMENTS:
            # ures ACK a kovetkezo fragmensert
            code, attrs = conv.send_eap(build_eap_peap_response(frame.eap_id, flags=0, payload=b""), username=identity)
            if code == ACCESS_REJECT:
                raise RuntimeError("A szerver elutasitotta a fragmens ACK-ot (Access-Reject).")
            continue
        else:
            # ez volt az utolso fragmens ebben a flight-ban - megvan, amire
            # szuksegunk van (a tanusitvanyig biztosan eljutottunk), leallunk.
            break

    return extract_certificates(bytes(tls_buffer))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="RADIUS/EAP-PEAP szerver-tanusitvany lekerdezo (MS-CHAPv2 nelkul, csak a TLS cert megjelenitesehez)"
    )
    parser.add_argument("--server", required=True, help="RADIUS/NPS szerver IP cime")
    parser.add_argument("--port", type=int, default=1812, help="RADIUS auth port (alap: 1812)")
    parser.add_argument("--secret", required=True, help="RADIUS megosztott kulcs (PSK)")
    parser.add_argument("--identity", default="anonymous", help="Outer EAP identity (nem kell valodi felhasznalo)")
    parser.add_argument("--nas-ip", default="127.0.0.1", help="A NAS-IP-Address attributumhoz kuldott sajat IP")
    parser.add_argument("--timeout", type=float, default=5.0, help="UDP valasz timeout masodpercben")
    args = parser.parse_args()

    try:
        certs = probe_certificate(args.server, args.port, args.secret, args.identity, args.nas_ip, args.timeout)
    except (TimeoutError, RuntimeError, ValueError) as e:
        sys.exit(f"HIBA: {e}")

    print_certificates(certs)


if __name__ == "__main__":
    main()
