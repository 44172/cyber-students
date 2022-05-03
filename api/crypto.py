from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes

def encrypt_aes_256(plaintext, key):
    print("encrypt_aes_256")
    key_bytes = bytes(key, "utf-8")
    aes_cipher = Cipher(algorithms.AES(key_bytes),
                        modes.CBC(bytearray(16)),
                        backend=default_backend())
    aes_encryptor = aes_cipher.encryptor()
    padder = padding.PKCS7(256).padder()

    plaintext_bytes = bytes(plaintext, "utf-8")
    padded_bytes = padder.update(plaintext_bytes) + padder.finalize()
    ciphertext_bytes = aes_encryptor.update(padded_bytes) + aes_encryptor.finalize()
    ciphertext = ciphertext_bytes.hex()

    print("ciphertext is: " + ciphertext)
    print("plaintext is: " + plaintext)
    return ciphertext

def decrypt_aes_256(ciphertext, key):
    print("decrypt_aes_256")
    key_bytes = bytes(key, "utf-8")
    aes_cipher = Cipher(algorithms.AES(key_bytes),
                        modes.CBC(bytearray(16)),
                        backend=default_backend())
    aes_decryptor = aes_cipher.decryptor()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()

    padded_bytes = aes_decryptor.update(ciphertext) + aes_decryptor.finalize()
    plaintext_bytes = unpadder.update(padded_bytes) + unpadder.finalize()
    plaintext = str(plaintext_bytes, "utf-8")
    print("ciphertext is: " + ciphertext)
    print("plaintext is: " + plaintext)
    return plaintext




def hash_password(password, salt):
    #digest = hashes.Hash(hashes.SHA256())
    kdf = Scrypt(salt=salt, length=32, n=2 ** 14, r=8, p=1)
    password_bytes = bytes(password, "utf-8")
    hashed_password = kdf.derive(password_bytes)
    #digest.update(password_bytes)
    #password_hash_bytes = digest.finalize()
    #password_hash = str(password_hash_bytes, "utf-8")
    print("hash is" + str(hashed_password.hex()))
    #store Salt in row of data base
    #Store hashed password in row of database
    print("Salt is :" + str(salt.hex()))
    hashed_password = {"hashed_password": hashed_password.hex(), "salt": salt.hex()}

    return hashed_password


def verify_hash(password, hashed_password):
    #digest = hashes.Hash(hashes.SHA256())
    password_bytes = bytes(password, "utf-8")
    hashed_password = kdf.derive(password_bytes)
    #digest.update(password_bytes)
    #password_hash = digest.finalize()

    print("hash is" + hashed_password)
    return hashed_password


def valid_login(userdata, password_attempt):
    hashed_password_attempt = hash_password(password_attempt, bytes.fromhex(userdata['saltkey']))
    if userdata['password'] == hashed_password_attempt['hashed_password']:
        valid_cred = True
        print("Valid login")
    else:
        valid_cred = False
        print("Invalid login")

    return  valid_cred


#password = input("Please enter your password: ")
#password_bytes = bytes(password, "utf-8")
