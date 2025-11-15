from cryptography.fernet import Fernet, InvalidToken
from Crypto.Cipher import AES, ChaCha20
from Crypto.Random import get_random_bytes
from constants import *
import os

# --- GENEROWANIE KLUCZA ---
def generate_key(algo: str, key_length_name: str = None):
    if algo == "Fernet (AES-128)":
        key = Fernet.generate_key()
        return key, key.decode('utf-8')
    else:
        key_size = KEY_LENGTH_MAP[key_length_name]
        key = get_random_bytes(key_size)
        return key, key.hex()

# --- ZAPIS KLUCZA NA PULPICIE ---
def save_key_to_desktop(key_str: str, folder_name: str, algo_tag: str) -> str:
    desktop = os.path.join(os.path.expanduser('~'), 'Desktop')
    filename = f"{folder_name}_{algo_tag}_klucz.txt"
    path = os.path.join(desktop, filename)
    with open(path, "w", encoding='utf-8') as f:
        f.write(key_str)
    return path

# --- SZYFROWANIE ---
def encrypt_fernet(data: bytes, key: bytes) -> bytes:
    fernet = Fernet(key)
    return FERNET_TAG + fernet.encrypt(data)

def encrypt_aes_gcm(data: bytes, key: bytes) -> bytes:
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return AESGCM_TAG + nonce + tag + ciphertext

def encrypt_chacha20_poly1305(data: bytes, key: bytes) -> bytes:
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return CHACHA_TAG + nonce + tag + ciphertext

# --- ODSZYFROWANIE ---
def decrypt_fernet(encrypted_data: bytes, key: bytes) -> bytes:
    data = encrypted_data[TAG_LEN:]
    fernet = Fernet(key)
    return fernet.decrypt(data)

def decrypt_aes_gcm(encrypted_data: bytes, key: bytes) -> bytes:
    nonce = encrypted_data[TAG_LEN: TAG_LEN + NONCE_SIZE]
    tag = encrypted_data[TAG_LEN + NONCE_SIZE: TAG_LEN + NONCE_SIZE + TAG_SIZE]
    ciphertext = encrypted_data[TAG_LEN + NONCE_SIZE + TAG_SIZE:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def decrypt_chacha20_poly1305(encrypted_data: bytes, key: bytes) -> bytes:
    nonce = encrypted_data[TAG_LEN: TAG_LEN + NONCE_SIZE]
    tag = encrypted_data[TAG_LEN + NONCE_SIZE: TAG_LEN + NONCE_SIZE + TAG_SIZE]
    ciphertext = encrypted_data[TAG_LEN + NONCE_SIZE + TAG_SIZE:]
    cipher = ChaCha20.new(key=key, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

# --- AUTOMATYCZNE ODSZYFROWANIE PO TAGU ---
def decrypt_auto(file_data: bytes, key_str: str):
    tag = file_data[:TAG_LEN]
    if tag == FERNET_TAG:
        key = key_str.encode()
        return decrypt_fernet(file_data, key), "Fernet"
    elif tag == AESGCM_TAG:
        key = bytes.fromhex(key_str)
        return decrypt_aes_gcm(file_data, key), "AES-GCM"
    elif tag == CHACHA_TAG:
        key = bytes.fromhex(key_str)
        return decrypt_chacha20_poly1305(file_data, key), "ChaCha20-Poly1305"
    else:
        raise ValueError("Nieznany tag algorytmu")