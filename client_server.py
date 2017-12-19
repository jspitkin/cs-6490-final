"""
    Network Security CS6490
    Fall 2017 - Final Project
    CryptoChrome Server
"""

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from socket import *
import requests
import math

CLIENT_PORT = 12001
SERVER_PORT = 12000


def main():
    key = read_key('aes-key.bin')
    serv_sock = socket(AF_INET, SOCK_STREAM)
    serv_sock.bind(('', CLIENT_PORT))
    serv_sock.listen(1)

    while 1:
        conn_sock, addr = serv_sock.accept()
        packet = conn_sock.recv(1024)
        if 'CONNECT' in packet.decode():
            continue
        elif 'GET' in packet.decode():
            if len(packet.split()) < 1:
                continue
            url = packet.split()[1]
            #encrypted_url = encrypt_text(url, key)
            sock = socket(AF_INET, SOCK_STREAM)
            sock.connect(('', SERVER_PORT))
            sock.send(url)
            encrypted_response = receive(sock)
            response = decrypt_text(encrypted_response, key)
            send_response(response, conn_sock)




def receive(socket):
    buffer = b""
    while(1):
        try:
            socket.settimeout(1)
            response = socket.recv(1024)
            buffer = buffer + response
        except socket.Timeouterror:
            break
    return buffer


def send_response(response, socket):
    packet_count = math.ceil(len(resonse) / 1024)
    packet_num = 0
    start = 0
    end = 1023
    while packet_num < packet_count:
        socket.send(response[start:end])
        start = start + 1024
        end = end + 1024


def make_http_request(url):
    response = requests.get(url)
    return response.content


def generate_key(path):
    key = get_random_bytes(32)
    with open('path', 'wb') as f:
        f.write(key)


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
        return ""
    return plaintext


if __name__ == "__main__":
    main()
