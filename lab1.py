import hashlib
import json
import time
import sys
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad


#pip install pycryptodome
class PasswordManager:
    def __init__(self, password_file, master_password):
        self.password_file = password_file
        self.master_password_hash = hashlib.sha256( master_password.encode() ).digest()
        self.iv_length = 16

    def encrypt_data(self, input_password, data):
        hashed_password = hashlib.sha256( input_password.encode() ).digest()
       # iv = get_random_bytes( 16 )
        cipher = AES.new( hashed_password, AES.MODE_CBC )
        padded_data = pad( data.encode(), AES.block_size )
        #encrypted_data = iv + cipher.encrypt( padded_data )
        encrypted_data = cipher.encrypt( padded_data )
        return encrypted_data

    """def decrypt_data(self, password, encrypted_data):
        encrypted_text = base64.b64decode(encrypted_data)
        hashed_password = hashlib.sha256( password.encode() ).digest()
        #iv = encrypted_data[:16]  # Extract IV from the first 16 bytes
        #iv_bytes = iv.encode( 'utf-8' )  # Convert IV to bytes
        #cipher = AES.new( hashed_password, AES.MODE_CBC, iv_bytes )
        cipher = AES.new( hashed_password, AES.MODE_CBC)
        #encrypted_message = encrypted_data[16:]
        decrypted_message = cipher.decrypt( encrypted_text )
        unpadded_text = unpad( decrypted_text, AES.block_size )  # Unpad and decode the decrypted data
        return unpadded_data """

    def decrypt_data(self, password, encrypted_data):
        encrypted_text = base64.b64decode( encrypted_data )
        hashed_password = hashlib.sha256( password.encode() ).digest()
        cipher = AES.new( hashed_password, AES.MODE_CBC, encrypted_text[:16] )
        decrypted_text = cipher.decrypt( encrypted_text[16:] )
        unpadded_text = unpad( decrypted_text, AES.block_size )
        decrypted_data = unpadded_text.decode()
        return decrypted_data

    def put(self, input_pass, service, password):
        print("put")
        with open(self.password_file.name, 'r') as f:
            encrypted_data = f.read()

        if encrypted_data:
            passwords = self.decrypt_data(input_pass, encrypted_data)
        else:
            passwords = {}

        encoded_password = base64.b64encode(self.encrypt_data(input_pass, password))
        passwords[service] = encoded_password.decode()

        with open(self.password_file.name, 'w') as f:
            f.write(json.dumps(passwords))
            print(f"Password for {service} added successfully.")

    def get(self, input_pass, service):
        print( "get" )
        with open( self.password_file.name, 'r' ) as f:
            encrypted_data = f.read()

        if encrypted_data:
            passwords = self.decrypt_data( input_pass,encrypted_data)
            if service in passwords:
                decoded_password = base64.b64decode(passwords[service])
                print( f"Password for {service}: {decoded_password.decode()}" )
            else:
                print( f"No password found for {service}." )
        else:
            print( "Password file is empty." )
    def verify_master_password(self, input_password):
        input_password_hash = hashlib.sha256( input_password.encode() ).digest()
        return input_password_hash == self.master_password_hash


def main():
    password_manager = None
    if sys.argv[1] == "init":
        master_password = sys.argv[2]
        current = time.strftime( "%Y%m%d-%H%M%S" )
        password_file = open( "passwords" + current + ".enc", "w" )  # zato da svaki password file dobije jedinstveni id
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
                password_manager.put( command[1], command[2], command[3] )
            elif command[0] == "get":
                password_manager.get( command[1], command[2] )
        else:
            print( "Invalid command." )


if __name__ == "__main__":
    main()
