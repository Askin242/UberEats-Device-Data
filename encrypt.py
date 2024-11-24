import base64
import json

def encrypt_data(data, key):
    json_str = json.dumps(data)
    
    key_length = len(key)
    encrypted_chars = [
        chr(ord(char) ^ key[i % key_length]) 
        for i, char in enumerate(json_str)
    ]
    xor_encrypted = ''.join(encrypted_chars)
    
    return base64.b64encode(xor_encrypted.encode('utf-8')).decode('utf-8')

xor_key = [89, 231, 225, 55]

data = {'sid': 'bbc661585c424072'}

encrypted_data = encrypt_data(data, xor_key)
print("Données chiffrées :", encrypted_data)
