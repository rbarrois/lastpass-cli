#!/usr/bin/env python
# -*- coding: utf-8 -*-


import argparse
import base64
import Crypto
import json
import lastpass.fetcher
import requests
import os


PWD_LENGTH = 32


class LastPassException(Exception):
    pass


def get_pubkey(username, session):
    data = {
        'getpubkey': 1,
        'uid': json.dumps({username: {'type': '', 'id': ''}}),
    }
    ret = requests.get('https://lastpass.com/share.php', params=data, cookies={'PHPSESSID': session.id})
    values = ret.json()
    if not values['success']:
        raise LastPassException()
    return {
        'username': values['username0'],
        'uid': values['uid0'],
        'pubkey': base64.b16decode(values['pubkey0']),
    }


def get_meta(username, folder_name, pubkey, iterations=5000):
    newusername = '%s-%s' % (username, folder_name)
    name = folder_name
    password = os.urandom(PWD_LENGTH)
    sharekey_bytes = Crypto.Protocol.KDF.PBKDF2(
        password=password,
        salt=newusername.encode('ascii'),
        count=iterations,
        hashAlgo=Crypto.Hash.SHA256.SHA256Hash,
    )
    sharekey_hex = base64.b16encode(sharekey_bytes)
    newhash_bytes = Crypto.Protocol.KDF.PBKDF2(
        password=sharekey_bytes,
        salt=password,
        count=iterations,
        hashAlgo=Crypto.Hash.SHA256.SHA256Hash,
    )
    newhash_hex = base64.b16encode(newhash_bytes)




def main():
    uname = 'raphael.barrois@polyconseil.fr'
    pwd = ''
    multifactor = '504140'
    session = lastpass.fetcher.login(uname, pwd, multifactor_password=multifactor)
    print(get_pubkey(uname, session))


if __name__ == '__main__':
    main()
