"""
Midbar
Distributed under the MIT License
© Copyright Maxim Bortnikov 2023
For more information please visit
https://sourceforge.net/projects/midbar/
https://github.com/Northstrix/Midbar
Required libraries:
https://github.com/Northstrix/AES_in_CBC_mode_for_microcontrollers
https://github.com/ulwanski/sha512
https://github.com/Bodmer/TFT_eSPI
https://github.com/intrbiz/arduino-crypto
https://github.com/techpaul/PS2KeyAdvanced
https://github.com/techpaul/PS2KeyMap
https://github.com/mobizt/Firebase-ESP32
"""
import hashlib
iterations = 20451

def mbedtls_pkcs5_pbkdf2_hmac(password, salt, iterations, keylen):
    """
    Implementation of mbedtls_pkcs5_pbkdf2_hmac with SHA256 in Python.
    
    Args:
        password (bytes): The password to derive the key from.
        salt (bytes): The salt value.
        iterations (int): The number of iterations.
        keylen (int): The desired length of the derived key.
    
    Returns:
        bytes: The derived key.
    """
    dk = hashlib.pbkdf2_hmac('sha256', password, salt, iterations, dklen=keylen)
    return dk

# Example usage:
password = b"12345"
string_salt = 'db2cbc75e27434c5cb1cc8b4d8dbfe90'
salt = bytes.fromhex(string_salt)

keylen = 96

derived_key = mbedtls_pkcs5_pbkdf2_hmac(password, salt, iterations, keylen)
print("Derived Key:", derived_key.hex())