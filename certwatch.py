#! /usr/bin/python3

import sys
import ssl
import socket
import datetime
import subprocess
#import traceback

def test_cert(host,port):
        try:
#            print(f"\nChecking certifcate for server {host} port {port}")
            with socket.create_connection((host, port)) as sock:
                def get():
                    ret=sock.recv(1024)
#                    print(ret)
                def send(s,welc=True):
                    if welc: get()  # read welcome msg
                    sock.sendall(s) # send cmd
                    get()           # read reply
                if port=="25" or port=="587": # smtp starttls
                    send(b"EHLO FIXME.to.myhostname.hu\r\n")
                    send(b"STARTTLS\r\n",False)
                if port=="143": # imap starttls
                    send(b"1 STARTTLS\r\n")
                if port=="21": # ftp starttls
                    send(b"AUTH TLS\r\n")
                context = ssl.create_default_context()
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    certificate = ssock.getpeercert()
                certExpires = datetime.datetime.strptime(
                    certificate["notAfter"], "%b %d %H:%M:%S %Y %Z"
                )
#                print(certificate.keys())
                try:
                    ca=certificate["issuer"]
                    # ((('countryName', 'NL'),), (('organizationName', 'GEANT Vereniging'),), (('commonName', 'GEANT OV RSA CA 4'),))
                    ca=ca[1][0][1]
                except:
                    ca="???"
#                for cc in ca: print(cc[0][0])
#                help(ca)
                daysToExpiration = (certExpires - datetime.datetime.now()).days
#                print(f"Expires on: {certExpires} in {daysToExpiration} days")
                return daysToExpiration,str(certExpires)+"  "+str(ca)
        except Exception as e:
            #traceback.print_exc()
            #print( traceback.format_exception_only() )
#            print(e)
            return -1,str(e)

##check  certificate expiration
data=[]
for ip in open("certwatch.txt","rt"):
    i=ip.split("#")[0].strip()
    if not i: continue # skip empty lines / comments
    host, port = i.split(":")
    d,e=test_cert(host,port)
#    print("%3d  [%s:%s]  "%(d,host,port),e)
#    print(("%3d  %s:%s "%(d,host,port)).ljust(32),e)
    x=(d,e,host,port)
    data.append(x)

data.sort()

reply="From: Cert-watch <root@FIXME.to.myhostname.hu>\nSubject: cert-watcher status\n\n"
for d,e,host,port in data:
    reply+=("%3d  %s:%s "%(d,host,port)).ljust(32)+str(e)+"\n"

if len(sys.argv)>1:
    subprocess.run(["/usr/sbin/sendmail"]+sys.argv[1:],input=reply.encode("us-ascii",errors="ignore"))
else:
    print(reply)

