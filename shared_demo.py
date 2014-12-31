#!/usr/bin/env python
# -*- coding: utf-8 -*-


import argparse
import base64
import Crypto
import Crypto.Cipher.PKCS1_OAEP
import datetime
import getpass
import json
import lastpass.fetcher
import requests
import os
import pprint


PWD_LENGTH = 32


class LastPassException(Exception):
    pass


def pkcs7_padding(in_bytes):
    missing = 16 - (len(in_bytes) % 16)
    extra = chr(missing) * missing
    return in_bytes + extra.encode('ascii')


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


def get_meta(username, folder_name, pubkey_bytes, iterations=5000):
    newusername = '%s-%s' % (username, folder_name)
    # name is the plaintext name of the folder being added
    name = folder_name

    # To go from nothing to your hash and sharekey you should do the following.
    # newusername is the creators username, followed by hyphen, followed by the shared folders plaintext name

    # 1) Generate a random password.
    password = os.urandom(PWD_LENGTH)
    # 2) Generate the sharekey. PBKDF2-SHA256() where the "password" and "salt" are the randmly generated password and newusername. 
    # The default # of iterations is 5000.
    sharekey_bytes = Crypto.Protocol.KDF.PBKDF2(
        password=password,
        salt=newusername.encode('ascii'),
        count=iterations,
        #hashAlgo=Crypto.Hash.SHA256.SHA256Hash,
    )
    # The result should be hexadecimal.
    sharekey_hex = base64.b16encode(sharekey_bytes)
    # 3) Generate your newhash. This is PBKDF2-SHA256 usually using default of 5000 iterations. The salt is your randomly generated password, 
    # the "password" is your newly generated key.
    newhash_bytes = Crypto.Protocol.KDF.PBKDF2(
        password=sharekey_bytes,
        salt=password,
        count=iterations,
        #hashAlgo=Crypto.Hash.SHA256.SHA256Hash,
    )
    newhash_hex = base64.b16encode(newhash_bytes)

    # Before uploading, RSA encrypt the sharekey and ensure it is hexencoded.
    rsa_key = Crypto.PublicKey.RSA.importKey(pubkey_bytes)
    rsa_cipher = Crypto.Cipher.PKCS1_OAEP.new(rsa_key)
    encrypted_sharekey_bytes = rsa_cipher.encrypt(sharekey_hex)
    encrypted_sharekey_hex = base64.b16encode(encrypted_sharekey_bytes)

    # Sharename is the ciphertext name of the folder being added, encrypted with the sharekey
    sharename_iv = Crypto.Random.new().read(Crypto.Cipher.AES.block_size)
    sharename_cipher = Crypto.Cipher.AES.new(sharekey_bytes, Crypto.Cipher.AES.MODE_CBC, sharename_iv)
    encrypted_sharename_bytes = sharename_cipher.encrypt(pkcs7_padding(name.encode('ascii')))
    encrypted_sharename = '!%s|%s' % (base64.b64encode(sharename_iv), base64.b64encode(encrypted_sharename_bytes))


    return {
        'newusername': newusername,
        'name': name,
        'sharekey': encrypted_sharekey_hex,
        'newhash': newhash_hex,
        'sharename': encrypted_sharename,
    }


def create_folder(meta, session):
    data = {
        'id': 0,
        'newusername': meta['newusername'],
        'name': meta['name'],
        'sharekey': meta['sharekey'],
        'sharename': meta['sharename'],
        'newhash': meta['newhash'],
        'token': session.extra['token'],
        'wxsessid': session.id,
        'xmlr': 1,
    }
    ret = requests.post('https://lastpass.com/share.php', params=data, cookies={'PHPSESSID': session.id})
    print(ret)
    print(ret.content)


def main():
    uname = 'raphael.barrois@polyconseil.fr'
    folder_name = 'lastpass-cli-%s' % datetime.datetime.now().strftime('%Y%m%d%H%M')
    pwd = getpass.getpass(prompt="Password:")
    multifactor = getpass.getpass(prompt="2Factor code:")
    session = lastpass.fetcher.login(uname, pwd, multifactor_password=multifactor)
    pubkey_data = get_pubkey(uname, session)
    meta = get_meta(pubkey_data['username'], folder_name, pubkey_data['pubkey'])
    pprint.pprint(meta)



if __name__ == '__main__':
    main()
