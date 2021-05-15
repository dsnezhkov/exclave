import os
import sys
import json
import base64

from io import StringIO

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2

import hexdump
import uuid

import cherrypy
from cherrypy.process.plugins import PIDFile

config = {
    "symkey": {
        "key": bytes(),
        "len": 0,
        "mac": bytes()
    }
}


def do_payload():
    print("SymKey generated:")
    hexdump.hexdump(config["symkey"]["key"])
    print("SymKey len: ", config["symkey"]["len"])

    test_string = """
    Where does it come from?
    """
    print("Length of plain payload is: ", len(test_string))

    nonce = b'\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C'
    b64cipher = str(base64.b64encode(config["symkey"]["key"]), 'utf-8')
    cipher = AES.new(key=config["symkey"]["key"],
                     mode=AES.MODE_GCM,
                     nonce=nonce)

    encryptedData, tag = cipher.encrypt_and_digest(test_string.encode('utf-8'))
    print("Length of encrypted payload is: ", len(encryptedData))
    print("Tag is: {0} len: {1}".format(tag, len(tag)))

    tagB64 = str(base64.b64encode(tag), 'utf-8')
    encryptedDataB64 = str(base64.b64encode(encryptedData), 'utf-8')
    response = {
      "payload": encryptedDataB64,
      "len": len(encryptedData),
      "mac": tagB64
    }
    return response


def do_symkey(data):
    public_key = json.loads(data)
    exp = base64.b64decode(public_key["exp"])
    mod = base64.b64decode(public_key["mod"])

    print("Extracting mod and exp")
    n = int.from_bytes(mod, byteorder="little")
    e = int.from_bytes(exp, byteorder="little")
    key_params = (n, e)

    print("Constructing RSA key")
    pub_key = RSA.construct(key_params)

    print("Exporting public key to PEM")
    pub_key_pem = pub_key.exportKey().decode('ascii')
    pem_fpath = "keys/sgxRSApub.pem"
    export_pk_pem(pem_fpath, pub_key_pem)

    print("Creating AES Symmetric Key from token")
    salt = get_random_bytes(16)  # AES-GCM-128
    token = str(uuid.uuid4())

    symkey = PBKDF2(token, salt, dkLen=16)
    print("SymKey generated:")
    hexdump.hexdump(symkey)
    print("SymKey len: ", len(symkey))
    config["symkey"]["key"] = symkey
    config["symkey"]["len"] = len(symkey)

    print("Encrypting SymKey with RSA Pub Key")
    cipher = PKCS1_OAEP.new(pub_key, SHA256)
    ciphertext = cipher.encrypt(symkey)

    print("RSA Ciphertext of symkey:")
    hexdump.hexdump(ciphertext)
    print("RSA Ciphertext len: ", len(ciphertext))

    print("B64 encoding ciphertext")
    b64cipher = str(base64.b64encode(ciphertext), 'utf-8')
    response = {
        "key": b64cipher,
        "len": len(ciphertext)
    }
    return response


class SGXServer(object):
    exposedViewPaths = {}

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def symkey(self):
        jdata = json.dumps(cherrypy.request.json)
        eResponse = do_symkey(jdata)
        return eResponse

    @cherrypy.expose
    @cherrypy.tools.json_out()
    def payload(self):
        eResponse = do_payload()
        return eResponse


def export_pk_pem(path, pubkey):
    with open(path, "w") as f:
        f.write(pubkey)


if __name__ == '__main__':
    cherrypy.config.update((os.path.join(os.curdir, "server.conf")))

    app = SGXServer()

    # Daemonizer(cherrypy.engine).subscribe()
    PIDFile(cherrypy.engine, 'sgx.pid').subscribe()

    cherrypy.tree.mount(app, '/', config=os.path.join(
        os.curdir, "apps", "sgx.conf"))

    cherrypy.engine.start()
    cherrypy.engine.block()
