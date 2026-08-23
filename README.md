# certwatch - SSL certificate expiry notification

Queries SSL certificate of listed sites, prints days left before expiry and the Issuer name.


Supported protocols:
- any implicit ssl protocols (https, imaps, smtps etc)
- smtp starttls (25/587)
- imap starttls (143)
- ftp auth tls (21)


Usage:

./certwatch [emailaddress]  
(if email address given, results will be sent to email instead of stdout)

# radius_peap_cert_probe - Radius SSL cert checker

easy way to query EAP-TLS/TTLS/PEAP radius server certificates! written by Claude.AI (free edition, Sonnet 5)

Usage: ./radius_peap_cert_probe.py --server IP --secret "psk" --identity username
