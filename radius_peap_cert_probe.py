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
ATTR_SERVICE_TYPE = 6
ATTR_FRAMED_PROTOCOL = 7
ATTR_CALLING_STATION_ID = 31
ATTR_STATE = 24
ATTR_NAS_IDENTIFIER = 32
ATTR_EAP_MESSAGE = 79
ATTR_MESSAGE_AUTHENTICATOR = 80
ATTR_NAS_PORT_TYPE = 61


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
    extra_attrs: list[tuple[int, bytes]] | None = None,
) -> bytes:
    """Felepiti az Access-Request csomagot, a szukseg szerint tobb EAP-Message
    attributumra darabolva az EAP payloadot (attributum-szintu fragmentacio),
    es a vegen kiszamitja a Message-Authenticator HMAC-MD5-öt (RFC 3579).

    extra_attrs: tovabbi RADIUS attributumok (pl. Service-Type, NAS-Port-Type,
    Calling-Station-Id) - sok NPS Connection Request / Network Policy ezeket
    a feltetelek reszekent megkoveteli, enelkul mar az elso Access-Request-et
    elutasitja, meg mielott az EAP targyalas elkezdodne."""
    request_authenticator = os.urandom(16)

    attrs: list[tuple[int, bytes]] = [
        (ATTR_USER_NAME, username.encode()),
        (ATTR_NAS_IP_ADDRESS, socket.inet_aton(nas_ip)),
        (ATTR_NAS_IDENTIFIER, b"python-peap-cert-probe"),
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
EAP_TYPE_TLS = 13
EAP_TYPE_TTLS = 21
EAP_TYPE_PEAP = 25

# Ez a harom EAP-tipus mind ugyanazt a "flags byte + opcionalis 4-byte
# total-length + TLS adat" fragmentacios fejlecformatumot hasznalja
# (RFC 5216 EAP-TLS format, amit a PEAP es a TTLS is atvett), ezert a
# kulso TLS handshake / tanusitvany-lekerdezes szempontjabol azonosan
# kezelhetok - csak az EAP tipusszam ter el.
SUPPORTED_TLS_TUNNEL_TYPES = {
    EAP_TYPE_TLS: "EAP-TLS",
    EAP_TYPE_TTLS: "EAP-TTLS",
    EAP_TYPE_PEAP: "PEAP",
}

FLAG_LENGTH_INCLUDED = 0x80
FLAG_MORE_FRAGMENTS = 0x40
FLAG_START = 0x20


@dataclass
class EapPeapFrame:
    eap_code: int
    eap_id: int
    eap_type: int
    flags: int
    total_length: int | None
    payload: bytes


def parse_eap_peap(eap_packet: bytes, expected_type: int | None = None) -> EapPeapFrame:
    """expected_type=None eseten barmilyen ismert TLS-alagut tipust (EAP-TLS,
    EAP-TTLS, PEAP) elfogad es a talalt tipust adja vissza - igy a hivo fel
    tudja ismerni, melyik EAP modszert hasznalja a szerver. Ha expected_type
    meg van adva, ellenorzi, hogy a valasz ugyanazt a tipust hasznalja-e
    (a tunnel felepitese kozben, hogy ne csuszjunk at masik tipusra)."""
    code, ident = eap_packet[0], eap_packet[1]
    length = struct.unpack(">H", eap_packet[2:4])[0]
    if code in (EAP_SUCCESS, EAP_FAILURE):
        return EapPeapFrame(code, ident, expected_type or 0, 0, None, b"")
    eap_type = eap_packet[4]
    type_data = eap_packet[5:length]

    if eap_type not in SUPPORTED_TLS_TUNNEL_TYPES:
        supported = ", ".join(f"{t}={n}" for t, n in SUPPORTED_TLS_TUNNEL_TYPES.items())
        raise ValueError(f"varatlan/nem tamogatott EAP tipus: {eap_type} (tamogatott tipusok: {supported})")
    if expected_type is not None and eap_type != expected_type:
        raise ValueError(
            f"a szerver menet kozben mas EAP tipusra valtott: {eap_type} "
            f"({SUPPORTED_TLS_TUNNEL_TYPES.get(eap_type, '?')}), "
            f"korabban {expected_type} ({SUPPORTED_TLS_TUNNEL_TYPES.get(expected_type, '?')}) volt"
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
    body = bytes([EAP_RESPONSE, eap_id]) + struct.pack(">H", 4 + len(type_data)) + type_data
    return body


def build_eap_peap_response(eap_id: int, eap_type: int, flags: int, payload: bytes = b"") -> bytes:
    type_data = bytes([flags]) + payload
    full = bytes([eap_type]) + type_data
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
    def __init__(
        self,
        server: str,
        port: int,
        secret: str,
        nas_ip: str,
        timeout: float,
        source_ip: str | None = None,
        extra_attrs: list[tuple[int, bytes]] | None = None,
    ):
        self.server = server
        self.port = port
        self.secret = secret.encode()
        self.nas_ip = nas_ip
        self.timeout = timeout
        self.extra_attrs = extra_attrs or []
        self.radius_id = os.urandom(1)[0]
        self.state: bytes | None = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if source_ip:
            # A forras IP-re bindolt UDP socketrol kimeno csomagok EZZEL a
            # cimmel jelennek meg a szerver oldalan - igy tobb-cimu kliens
            # eseten kikenyszerithetjuk, hogy melyik interfeszrol/cimrol
            # menjen ki a keres (pl. ha az NPS policy csak egy adott
            # forras IP-t enged).
            try:
                self.sock.bind((source_ip, 0))
            except OSError as e:
                raise RuntimeError(
                    f"Nem sikerult a socketet a(z) {source_ip} forras cimre bindolni: {e}"
                ) from e
        self.sock.settimeout(timeout)

    def _next_radius_id(self) -> int:
        self.radius_id = (self.radius_id + 1) % 256
        return self.radius_id

    def send_eap(self, eap_packet: bytes, username: str = "anonymous", retries: int = 3) -> tuple[int, list[tuple[int, bytes]]]:
        packet = build_access_request(
            self._next_radius_id(), self.secret, eap_packet, username, self.nas_ip, self.state,
            extra_attrs=self.extra_attrs,
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


def probe_certificate(
    server: str,
    port: int,
    secret: str,
    identity: str,
    nas_ip: str,
    timeout: float,
    source_ip: str | None = None,
    extra_attrs: list[tuple[int, bytes]] | None = None,
) -> list[bytes]:
    conv = RadiusConversation(server, port, secret, nas_ip, timeout, source_ip=source_ip, extra_attrs=extra_attrs)

    # 1) EAP-Response/Identity - ez inditja a szerver oldali EAP/PEAP folyamatot.
    #    Az outer identity ertekenek NEM kell valos felhasznalonak lennie:
    #    a NPS meg a felhasznalo/jelszo ellenorzese ELOTT elkuldi a tanusitvanyat
    #    a TLS handshake reszekent.
    eap_id = 1
    code, attrs = conv.send_eap(build_eap_identity_response(eap_id, identity), username=identity)
    if code == ACCESS_REJECT:
        raise RuntimeError(
            "A szerver azonnal elutasitotta a kapcsolatot (Access-Reject) mar az Identity-nel "
            "(gyakori ok: ismeretlen/nem engedelyezett outer felhasznalonev, vagy hianyzo "
            "Connection Request Policy feltetel - lasd --service-type/--nas-port-type/--calling-station-id)."
        )
    eap_bytes = get_eap_message(attrs)
    frame = parse_eap_peap(eap_bytes)  # meg nem tudjuk melyik tipus, most ismerjuk fel
    eap_type = frame.eap_type
    print(f"Felismert EAP tipus: {SUPPORTED_TLS_TUNNEL_TYPES[eap_type]} (tipusszam {eap_type})", file=sys.stderr)
    if not (frame.flags & FLAG_START):
        print("FIGYELEM: a szerver elso valasza nem tartalmazott Start jelzest, folytatjuk azert.", file=sys.stderr)

    # 2) ClientHello elkuldese (egyetlen fragmensben, mivel a ClientHello kicsi).
    #    Ugyanazt az EAP tipust hasznaljuk a valaszunkban, amit a szerver az
    #    elozo lepesben jelzett (EAP-TLS/EAP-TTLS/PEAP mind ugyanazt a kulso
    #    TLS-alagutfelepitest hasznaljak, csak a tipusszam ter el).
    client_hello = build_client_hello_record()
    code, attrs = conv.send_eap(
        build_eap_peap_response(frame.eap_id, eap_type, flags=0, payload=client_hello), username=identity
    )
    if code == ACCESS_REJECT:
        raise RuntimeError("A szerver elutasitotta a ClientHello-t (Access-Reject).")

    # 3) A szerver ServerHello+Certificate+ServerHelloDone flight-jenek
    #    osszegyujtese - ez tobb EAP-fragmensre (M bit) is szethullhat,
    #    ilyenkor ures ACK-kal kell kernünk a kovetkezo darabot.
    tls_buffer = bytearray()
    while True:
        eap_bytes = get_eap_message(attrs)
        frame = parse_eap_peap(eap_bytes, expected_type=eap_type)

        if frame.eap_code == EAP_FAILURE:
            raise RuntimeError("A szerver EAP-Failure-t kuldott a TLS handshake kozben.")
        if frame.eap_code == EAP_SUCCESS:
            break

        tls_buffer.extend(frame.payload)

        if frame.flags & FLAG_MORE_FRAGMENTS:
            # ures ACK a kovetkezo fragmensert
            code, attrs = conv.send_eap(
                build_eap_peap_response(frame.eap_id, eap_type, flags=0, payload=b""), username=identity
            )
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
    parser.add_argument(
        "--source-ip",
        default=None,
        help="Forras IP cim, ahonnan a kereseket kuldjuk (tobb-cimu klienshez, "
             "ha a szerver policy csak egy adott forras cimrol fogad kereseket). "
             "Ha nincs megadva, az OS valasztja ki az utvonalazas alapjan.",
    )
    parser.add_argument(
        "--nas-ip",
        default=None,
        help="A NAS-IP-Address attributumhoz kuldott cim. Ha nincs megadva, "
             "es van --source-ip, akkor azt hasznaljuk; egyebkent 127.0.0.1.",
    )
    parser.add_argument("--timeout", type=float, default=5.0, help="UDP valasz timeout masodpercben")
    args = parser.parse_args()

    nas_ip = args.nas_ip or args.source_ip or "127.0.0.1"

    try:
        certs = probe_certificate(
            args.server, args.port, args.secret, args.identity, nas_ip, args.timeout,
            source_ip=args.source_ip,
        )
    except (TimeoutError, RuntimeError, ValueError) as e:
        sys.exit(f"HIBA: {e}")

    print_certificates(certs)


if __name__ == "__main__":
    main()
