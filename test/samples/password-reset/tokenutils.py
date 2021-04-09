#!/usr/bin/env python3

'''
Sample library to create tokens vulnerable to padding oracle attacks

Copyright (C) 2016-2017 Blindspot Security LLC
Author: Timothy D. Morgan

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Lesser General Public License, version 3,
 as published by the Free Software Foundation.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import time
import json

from Crypto.Cipher import AES
from Crypto import Random

from bletchley.buffertools import pkcs7PadBuffer,stripPKCS7Pad
from bletchley.blobtools import encodeChain,decodeChain


key = Random.new().read(32) # Never breaking AES256!!!


def encodeToken(ciphertext):
    return encodeChain(['base64/rfc3548','percent/upper'], ciphertext)


def decodeToken(token):
    return decodeChain(['percent/upper','base64/rfc3548'], token)


def _encrypt(plaintext):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = iv + cipher.encrypt(pkcs7PadBuffer(plaintext.encode('utf-8'), AES.block_size))

    return encodeToken(ciphertext)


def _decrypt(token):
    plaintext = None
    ciphertext = decodeToken(token)
    iv = ciphertext[0:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = stripPKCS7Pad(cipher.decrypt(ciphertext[AES.block_size:]), AES.block_size)
    if plaintext == None:
        raise Exception('Padding Error')
    
    return plaintext


def generateResetToken(user):
    seven_days = 7*24*60*60
    reset_info = {'user':user,'expires':int(time.time()+seven_days)}
    return _encrypt(json.dumps(reset_info)).decode('utf-8')


def validateResetToken(token):
    try:
        plaintext = _decrypt(token)
    except Exception as e:
        return (False, 'Reset Token Corrupt!')

    try:
        decoded = plaintext.decode('utf-8')
    except Exception as e:
        return (False, 'Bad Token!')

    try:
        reset_info = json.loads(decoded)
    except Exception as e:
        return (False, 'Parse Error!')

    if reset_info.get('expires', 0) < int(time.time()):
        return (False, 'Token Expired!')
    
    return (True, reset_info)


if __name__ == "__main__":
    token = generateResetToken('bob')
    print(token)
    print(validateResetToken(token))
