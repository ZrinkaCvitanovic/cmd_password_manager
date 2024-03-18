import hashlib
import json
import time
import sys
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Protocol.KDF import PBKDF2

salt = b'verylongsaltthatithinkissufficientforalabexcercise'  # Salt for key derivation
iterations = 100000  # Number of iterations for key derivation
key_length = 32  # AES key length (256 bits)

class PasswordManager:
    def __init__(self, password_file, master_password):
        self.password_file = password_file
        self.master_password_hash = hashlib.sha256( master_password.encode() ).digest()
        self.iv_length = 16
        self.aes_key = PBKDF2( self.master_password_hash, salt, dkLen=key_length, count=iterations )

    def encrypt_data(self, data):
        iv = get_random_bytes( 16 )
        cipher = AES.new( self.aes_key, AES.MODE_CBC, iv )
        padded_data = pad( data.encode(), AES.block_size )
        encrypted_data = cipher.encrypt( padded_data )
        encoded_data = base64.b64encode( iv + encrypted_data )
        return encoded_data

    def decrypt_data(self, encoded_data):
        decoded_data = base64.b64decode( encoded_data )
        iv = decoded_data[:AES.block_size]
        cipher = AES.new( self.aes_key, AES.MODE_CBC, iv )
        decrypted_data = cipher.decrypt( decoded_data[AES.block_size:] )
        unpadded_data = unpad( decrypted_data, AES.block_size )
        decrypted_text = unpadded_data.decode()
        return decrypted_text

    def put(self, service, password):
        hashed_service = hashlib.sha256( service.encode() ).digest()
        with open( self.password_file.name, "rb" ) as file:
            lines = file.readlines()
        encrypted_data = self.encrypt_data(password)
        with open(self.password_file.name, "ab") as file:
            file.write( hashed_service + b" : " + encrypted_data + b"\n" )

        print(f"Password for {service} added successfully.")

    def get(self, service):
        hashed_service = hashlib.sha256( service.encode() ).digest()
        plaintext_pass = None
        with open( self.password_file.name, "rb" ) as file:
            lines = file.readlines()
            for line in lines:
                current_service, encrypted_pass = line.strip().split( b" : " )
                if current_service == hashed_service:
                    try:
                        plaintext_pass = self.decrypt_data( encrypted_pass )
                    except ValueError as ve:
                        print("You have entered the wrong master password when logging in. Exit and try again!")
                        return
            if plaintext_pass is not None:
                print( f"Password for {service}: {plaintext_pass}" )
            else:
                print( f"No password found for {service}." )

    def verify_master_password(self, input_password):
        input_password_hash = hashlib.sha256( input_password.encode() ).digest()
        return input_password_hash == self.master_password_hash


def main():
    password_manager = None
    if sys.argv[1] == "init":
        master_password = sys.argv[2]
        name = input( "Enter a database you wish to access (leave empty to create a new database with default name): " )
        if name == "":
            current = time.strftime( "%Y%m%d-%H%M%S" )
            password_file = open( "passwords" + current + ".enc",
                                  "w" )  # zato da svaki password file dobije jedinstveni id
        else:
            password_file = open( name, "a" )
        password_manager = PasswordManager( password_file, master_password )
    while True:
        command = input().strip().split()
        if command[0] == "exit":
            print("leaving...")
            break
        if len( command ) > 1 and password_manager is not None:
            input_password = command[1]
            if not password_manager.verify_master_password( input_password ):
                print( "Invalid master password" )
                continue
            if command[0] == "put":
                password_manager.put( command[2], command[3] )
            elif command[0] == "get":
                password_manager.get( command[2] )
            else:
                print( "Invalid command." )
        else:
            print( "Invalid command." )


if __name__ == "__main__":
    main()