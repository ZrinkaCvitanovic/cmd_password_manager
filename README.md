# Password_Manager

This is a simplified version of a password manager tool used from command line.   

## Usage
initialising a database:  
**python main.py init [master password]**  

After this step you are prompted to enter the name of a database or leave empty if you wish to use the default name (timestamp of creation). Custom names are useful if you wish to use a database multiple times. 

adding a new password:  
**put [master password] [service] [password you wish to store]**  

retrieving a password:  
**get [master password] [service]**

Every time data is fetched or added, a master password must be provided in order to ensure that a legitimate user is accessing a database. Make sure your master password is not prone to guessing. 

## Requirements
You need to install **pycryptodome** library in your virtual environment:  
pip3 install pycryptodome 

## Explanation  
Passwords and services are stored in an encrypted file. Encryption is performed using AES encryption and CBC mode. For encrypting each entry an initialisation vector of 16 random bytes is used along with the master password that is provided from every user input. This method also makes sure that the length of a password is not obvious from the length of an encrypted entry. Furthermore, even if two passwords are the same, their encrypted entries are completely different. This is also a pivotal security requirement in today's systems. 

The master password must not be stored anywhere because once that password is cracked, the entire database in compromised. That is why user needs to enter master password for every interaction with the databse. Therefore, _verify_master_password()_ does not check whether the password is correct, but only checks whether the entered password matches the one entered at the initialisation of a database. Its purpose is only to enchance user experience, it is not here for security reasons.

If a user enter the wrong password at the initialisation and tries to read data using the same wrong password, the passwords won't be readable. The master password is used for generating an encryption key and the same key is used for decrypting the data. If a user enters the wrong password, the newly generated key won't be able to encrypt data. 

For additional privacy, names of services whose passwords are being stored are not written in plaintext, but in sha-256 hashes with salt. Even though salt is hardcoded here, that is bad practice. Salt should be randomly generated and stored in a database in plaintext.  

A downside of using AES CBC without HMAC is that there is no integrity check for each entry. However, this repo is only a demonstration of how passwords managers work.  
 


