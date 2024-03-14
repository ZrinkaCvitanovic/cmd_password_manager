import hashlib
import base64
import json
import os
import sys


class PasswordManager:
    def __init__(self, password_file, master_password):
        self.password_file = password_file
        self.master_password_hash = hashlib.sha256( master_password.encode() ).digest()
        self.iv_length = 16

    def encrypt(self, password, data):
        hashed_password = hashlib.sha256( password.encode() ).digest()
        encrypted_data = bytes( [data[i] ^ hashed_password[i % len( hashed_password )] for i in range( len( data ) )] )
        encoded_data = base64.b64encode( encrypted_data )
        return encoded_data

    def decrypt(self, password, encoded_data):
        hashed_password = hashlib.sha256( password.encode() ).digest()
        encrypted_data = base64.b64decode( encoded_data )
        decrypted_data = bytes(
            [encrypted_data[i] ^ hashed_password[i % len( hashed_password )] for i in range( len( encrypted_data ) )] )
        return decrypted_data

    def put(self, input_pass, service, password):
        print("put")
        with open(self.password_file, 'r') as f:
            encrypted_data = f.read()

        if encrypted_data:
            passwords = json.loads(self.decrypt(input_pass, encrypted_data))
        else:
            passwords = {}

        passwords[service] = self.encrypt(input_pass, password)

        with open(self.password_file, 'w') as f:
            f.write(json.dumps(passwords))
            print(f"Password for {service} added successfully.")

    def get(self, input_pass, service):
        print( "get" )
        with open( self.password_file, 'r' ) as f:
            encrypted_data = f.read()

        if encrypted_data:
            passwords = json.loads( self.decrypt( input_pass, encrypted_data ) )
            if service in passwords:
                print( f"Password for {service}: {passwords[service]}" )
            else:
                print( f"No password found for {service}." )
        else:
            print( "Password file is empty." )
    def verify_master_password(self, input_password):
        input_password_hash = hashlib.sha256( input_password.encode() ).digest()
        return input_password_hash == self.master_password_hash


def main():
    if sys.argv[1] == "init":
        master_password = sys.argv[2]
        password_file = open( "passwords.enc", "w" )
        password_manager = PasswordManager( password_file, master_password )

        while True:
            command = input().strip().split()
            if command[0] == "exit":
                print("leaving...")
                break
            if len( command ) > 1:
                input_password = command[1]
                if not password_manager.verify_master_password( input_password ):
                    print( "Invalid master password" )
                    continue
                if len( command ) == 4 and command[0] == "put":
                    password_manager.put( command[1], command[2], command[3] )
                elif len( command ) == 3 and command[0] == "get":
                    password_manager.get( command[1], command[2] )
            else:
                print( "Invalid command." )
    else:
        print( "Database not initialized! Use 'init' command to create a database." )


if __name__ == "__main__":
    main()
