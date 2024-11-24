import base64
import json

def decrypt_data(encoded_data, key):
    base64_decoded = base64.b64decode(encoded_data).decode('utf-8')

    key_length = len(key)
    decrypted_chars = [
        chr(ord(char) ^ key[i % key_length]) 
        for i, char in enumerate(base64_decoded)
    ]
    decrypted_str = ''.join(decrypted_chars)

    return json.loads(decrypted_str)

xor_key = [89, 231, 225, 55]

encoded_data = "IsOFwpJePcOFw5sXe8KFwoNUb8ORw5ACYcOSwoIDa8OTw5EAa8OFwpw="

decrypted_data = decrypt_data(encoded_data, xor_key)
print("Result: ", decrypted_data)
