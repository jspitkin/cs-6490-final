from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from socket import *

SERVER_NAME = ''
SERVER_PORT = 12001


def read_key(path):
    with open(path, 'rb') as f:
        key = f.read(32)
    return key


def encrypt_text(plaintext, key):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + tag + ciphertext


def decrypt_text(ciphertext, key):
    nonce = ciphertext[0:16]
    tag = ciphertext[16:32]
    ciphertext = ciphertext[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        plaintext
    except ValueError:
        print("Key incorrect or message corrupted")
    return plaintext


client_socket = socket(AF_INET, SOCK_STREAM)
client_socket.connect((SERVER_NAME, SERVER_PORT))

key = read_key('aes-key.bin')
client_socket.send(encrypt_text(b"http://jakepitkin.me", key))
buffer = b""
while(1):
    try:
        client_socket.settimeout(1)
        response = client_socket.recv(1024)
        buffer = buffer + response
    except:
        break

print('From Server: ', decrypt_text(buffer, key).decode())
with open('output.html', 'w') as f:
    f.write(decrypt_text(buffer, key).decode())
client_socket.close()
