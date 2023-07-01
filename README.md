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
