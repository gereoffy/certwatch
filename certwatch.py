#! /usr/bin/python3

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
                    send(b"EHLO arp.interoot.hu\r\n")
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
                daysToExpiration = (certExpires - datetime.datetime.now()).days
#                print(f"Expires on: {certExpires} in {daysToExpiration} days")
                return daysToExpiration,certExpires
        except Exception as e:
            #traceback.print_exc()
            #print( traceback.format_exception_only() )
#            print(e)
            return -1,str(e)

##check  certificate expiration
data=[]
for ip in open("/root/certwatch.txt","rt"):
    i=ip.split("#")[0].strip()
    if not i: continue # skip empty lines / comments
    host, port = i.split(":")
    d,e=test_cert(host,port)
#    print("%3d  [%s:%s]  "%(d,host,port),e)
    print(("%3d  %s:%s "%(d,host,port)).ljust(32),e)
    x=(d,e,host,port)
    data.append(x)

data.sort()

reply="From: ARP Cert-watch <root@cloud.mshw.hu>\nSubject: ARP cert-watcher status\n\n"
for d,e,host,port in data:
    reply+=("%3d  %s:%s "%(d,host,port)).ljust(32)+str(e)+"\n"

#subprocess.run(["/usr/sbin/sendmail","log@interoot.hu"],input=reply.encode("us-ascii",errors="ignore"))

