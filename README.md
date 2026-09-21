# certwatch - SSL certificate expiry notification

Queries SSL certificate of listed sites, prints days left before expiry and the Issuer name.


Supported protocols:
- any implicit ssl protocols (https, imaps, smtps etc)
- smtp starttls (25/587)
- imap starttls (143)
- ftp auth tls (21)


If the normal (verified) connection fails - expired certificate, private or
self-signed CA, missing intermediate, hostname mismatch - the host is probed
again with verification disabled (CERT_NONE, no hostname check, relaxed
ciphers, TLS capped at 1.2 so the Certificate message stays in cleartext), and
the report contains the whole received chain: subject, SAN, issuer, validity
with days left, serial, CA / self-signed flags, plus whether the hostname
matches. The days-left value then comes from the unverified leaf, so an already
expired certificate still gets a real (negative) day count and sorts to the top
of the report.

Only the Python standard library is needed (the certificates are parsed from
DER by the built-in reader in certwatch.py).


Usage:

./certwatch [emailaddress]  
(if email address given, results will be sent to email instead of stdout)

