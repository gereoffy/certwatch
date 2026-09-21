# certwatch - SSL certificate expiry notification

Queries SSL certificate of listed sites, prints days left before expiry and the Issuer name.


Supported protocols:
- any implicit ssl protocols (https, imaps, smtps, pop3s, ldaps, ftps etc)
- smtp starttls (smtp 25, submission 587)
- imap starttls (143)
- pop3 stls (110)
- ftp auth tls (21)
- ldap starttls (389)
- radius EAP-PEAP / EAP-TTLS (1812)


A list entry is either a URI or the classic `host:port` pair:

    https://www.example.hu          smtp://mail.example.hu:2525
    imap://mail.example.hu          ftp://files.example.hu:1337
    ldap://dc.example.local         radius://eduroam@example.hu
    www.example.hu:443

With an explicit `protocol://` the port is optional (the protocol's standard
port is used), and - more importantly - the protocol, so the right STARTTLS
dialogue is used even on an unusual port. Without a protocol the port decides,
the way it always did (25/587 smtp, 143 imap, 110 pop3, 21 ftp, 389 ldap,
1812 radius, ...); a port that is not in the table, or a bare host name (443),
means plain implicit TLS. A line that cannot be parsed is reported as
`BAD ENTRY` instead of killing the run.


If the normal (verified) connection fails - expired certificate, private or
self-signed CA, missing intermediate, hostname mismatch - the host is probed
again with verification disabled (CERT_NONE, no hostname check, relaxed
ciphers, TLS capped at 1.2 so the Certificate message stays in cleartext), and
the report contains the whole received chain: subject, SAN, issuer, validity
with days left, serial, CA / self-signed flags, plus whether the hostname
matches. The days-left value then comes from the unverified leaf, so an already
expired certificate still gets a real (negative) day count and sorts to the top
of the report.


RADIUS entries look like `radius://identity@my-realm.com`: the left side is the EAP
outer identity (it does not have to be a real user - the server sends its
certificate during the TLS handshake, before any password is checked!),
and all such queries go to the proxy configured at the top of certwatch.py
(RADIUS_SERVER / RADIUS_SECRET). Only the outer tunnel is built: identity,
EAP method negotiation (PEAP, or Nak to TTLS), then the TLS handshake until
the certificate arrives - no inner authentication and no password is ever sent.
Since the identity is not a hostname, for these entries only the chain is
verified, not the name. (For a full RADIUS conversation see radprobe.py.)


Only the Python standard library is needed (the certificates are parsed from
DER by the built-in reader in certwatch.py).


Usage:

./certwatch [emailaddress]  
(if email address given, results will be sent to email instead of stdout)

