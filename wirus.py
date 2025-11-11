import os
import time
import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet, InvalidToken

# Importy dla nowych algorytmów
try:
    from Crypto.Cipher import AES, ChaCha20
    from Crypto.Random import get_random_bytes
    from Crypto.Hash import SHA256
    from Crypto.Protocol.KDF import PBKDF2
except ImportError:
    # Wymagane, jeśli PyCryptodome nie jest zainstalowane
    messagebox.showerror("Błąd",
                         "Brak wymaganej biblioteki. Zainstaluj 'pycryptodome' używając: pip install pycryptodome")
    AES = None
    ChaCha20 = None
    get_random_bytes = None
    PBKDF2 = None
    SHA256 = None

# Stałe
# KEY_SIZE zostało usunięte, będzie dynamiczne
SALT_SIZE = 16
NONCE_SIZE = 12  # Dla GCM i ChaCha20
TAG_SIZE = 16  # Dla GCM i Poly1305
CHUNK_SIZE = 64 * 1024  # Blok do odczytu/zapisu dla dużych plików

# Stały tag dla wszystkich algorytmów
FERNET_TAG = b'FERNET'
AESGCM_TAG = b'AESGCM'
CHACHA_TAG = b'CHACHA'
TAG_LEN = 6  # Wszystkie tagi mają teraz 6 bajtów


class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Szyfrator Wielu Algorytmów")
        self.geometry("700x600")  # Zmniejszono wysokość po usunięciu suwaka
        self.center_window()

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        # --- NOWOŚĆ: Mapowanie nazw długości klucza na bajty ---
        self.key_length_map = {
            "128 bitów (16 bajtów)": 16,
            "192 bity (24 bajty)": 24,
            "256 bitów (32 bajty)": 32
        }
        self.aes_key_options = list(self.key_length_map.keys())
        self.chacha_key_options = [self.aes_key_options[0], self.aes_key_options[2]]  # 128 i 256

        self.tab_view = ctk.CTkTabview(self, width=250)
        self.tab_view.grid(row=0, column=0, padx=20, pady=10, sticky="ew")

        self.tab_encrypt = self.tab_view.add("Szyfrowanie")
        self.tab_decrypt = self.tab_view.add("Odszyfrowanie")

        self.setup_encrypt_tab()
        self.setup_decrypt_tab()

        # konsola logow
        self.log_textbox = ctk.CTkTextbox(self, state="disabled", wrap="word")
        self.log_textbox.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")

        # Inicjalne wywołanie, aby ukryć pola klucza (bo domyślnie jest Fernet)
        self.update_encryption_fields(self.algo_options[0])

    def setup_encrypt_tab(self):
        """Tworzy widżety dla zakladki szyfrowania."""
        self.tab_encrypt.grid_columnconfigure(1, weight=1)

        # Wybór algorytmu
        label_algo = ctk.CTkLabel(self.tab_encrypt, text="Wybierz Algorytm Szyfrowania:")
        label_algo.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        self.algo_options = ["Fernet (AES-128)", "AES-GCM", "ChaCha20-Poly1305"]
        self.algo_combobox = ctk.CTkComboBox(self.tab_encrypt, values=self.algo_options,
                                             command=self.update_encryption_fields)
        self.algo_combobox.set(self.algo_options[0])
        self.algo_combobox.grid(row=0, column=1, columnspan=2, padx=10, pady=5, sticky="ew")

        # etykieta i pole na sciezke
        label_folder = ctk.CTkLabel(self.tab_encrypt, text="Wybierz folder:")
        label_folder.grid(row=1, column=0, padx=10, pady=5, sticky="w")

        # przycisk, ktory uruchamia szyfrowanie
        button_browse_folder = ctk.CTkButton(self.tab_encrypt, text="Wybierz folder i szyfruj...",
                                             command=self.select_folder_and_encrypt)
        button_browse_folder.grid(row=1, column=1, columnspan=2, padx=10, pady=5, sticky="ew")

        # --- ZMIANA: Usunięto suwak rund, dodano wybór długości klucza ---
        self.label_key_length = ctk.CTkLabel(self.tab_encrypt, text="Wybierz długość klucza:")
        self.label_key_length.grid(row=2, column=0, padx=10, pady=5, sticky="w")

        self.key_length_combobox = ctk.CTkComboBox(self.tab_encrypt, values=self.aes_key_options)
        self.key_length_combobox.grid(row=2, column=1, columnspan=2, padx=10, pady=5, sticky="ew")

        # Pole na wygenerowany klucz
        self.key_entry_display = ctk.CTkEntry(self.tab_encrypt,
                                              placeholder_text="Tutaj pojawi się wygenerowany klucz (base64 dla Fernet, hex dla pozostałych)...",
                                              state="readonly")
        self.key_entry_display.grid(row=3, column=0, columnspan=3, padx=10, pady=10, sticky="ew")

    def update_encryption_fields(self, choice):
        """Dostosowuje UI w zależności od wybranego algorytmu."""
        if choice == self.algo_options[0]:  # Fernet
            # Ukryj wybór długości klucza
            self.label_key_length.grid_remove()
            self.key_length_combobox.grid_remove()
            self.log("Wybrano Fernet. Używa stałego klucza AES-128 (256 bitów łącznie).")

        elif choice == self.algo_options[1]:  # AES-GCM
            # Pokaż wybór długości klucza dla AES
            self.label_key_length.grid()
            self.key_length_combobox.grid()
            self.key_length_combobox.configure(values=self.aes_key_options)
            self.key_length_combobox.set(self.aes_key_options[2])  # Domyślnie 256 bit
            self.log("Wybrano AES-GCM. Wybierz długość klucza.")

        elif choice == self.algo_options[2]:  # ChaCha20
            # Pokaż wybór długości klucza dla ChaCha20
            self.label_key_length.grid()
            self.key_length_combobox.grid()
            self.key_length_combobox.configure(values=self.chacha_key_options)
            self.key_length_combobox.set(self.chacha_key_options[1])  # Domyślnie 256 bit
            self.log("Wybrano ChaCha20-Poly1305. Wybierz długość klucza.")

    def setup_decrypt_tab(self):
        """Tworzy widżety dla zakladki odszyfrowywania."""
        self.tab_decrypt.grid_columnconfigure(1, weight=1)

        label_file = ctk.CTkLabel(self.tab_decrypt, text="Wybierz plik do odszyfrowania:")
        label_file.grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.entry_path_decrypt = ctk.CTkEntry(self.tab_decrypt, placeholder_text="Wybierz zaszyfrowany plik...")
        self.entry_path_decrypt.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        button_browse_file = ctk.CTkButton(self.tab_decrypt, text="Przeglądaj...", command=self.browse_file)
        button_browse_file.grid(row=0, column=2, padx=10, pady=10)

        label_key = ctk.CTkLabel(self.tab_decrypt, text="Wklej lub wczytaj klucz:")
        label_key.grid(row=1, column=0, padx=10, pady=10, sticky="w")
        self.key_entry_decrypt = ctk.CTkEntry(self.tab_decrypt,
                                              placeholder_text="Wprowadź klucz lub wczytaj z pliku...")
        self.key_entry_decrypt.grid(row=1, column=1, padx=10, pady=10, sticky="ew")
        button_browse_key = ctk.CTkButton(self.tab_decrypt, text="Przeglądaj...", command=self.browse_key_file)
        button_browse_key.grid(row=1, column=2, padx=10, pady=10)

        button_decrypt = ctk.CTkButton(self.tab_decrypt, text="ODSZYFRUJ PLIK", command=self.run_decryption)
        button_decrypt.grid(row=2, column=0, columnspan=3, padx=10, pady=10, sticky="ew")

    # --- USUNIĘTO update_strength_label ---

    def center_window(self):
        self.update_idletasks()
        width = self.winfo_width()
        height = self.winfo_height()
        x = (self.winfo_screenwidth() // 2) - (width // 2)
        y = (self.winfo_screenheight() // 2) - (height // 2)
        self.geometry(f'{width}x{height}+{x}+{y}')

    def log(self, message):
        self.log_textbox.configure(state="normal")
        self.log_textbox.insert("end", message + "\n")
        self.log_textbox.configure(state="disabled")
        self.log_textbox.see("end")

    def select_folder_and_encrypt(self):
        """Otwiera dialog wyboru folderu i od razu uruchamia szyfrowanie."""
        folder_path = filedialog.askdirectory()
        if folder_path:
            self.log(f"Wybrano folder: {folder_path}")
            self.run_encryption(folder_path)

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.entry_path_decrypt.delete(0, "end")
            self.entry_path_decrypt.insert(0, file_path)
            self.log(f"Wybrano plik: {file_path}")

    def browse_key_file(self):
        file_path = filedialog.askopenfilename(title="Wybierz plik z kluczem",
                                               filetypes=(("Pliki tekstowe", "*.txt"), ("Wszystkie pliki", "*.*")))
        if file_path:
            try:
                with open(file_path, "r", encoding='utf-8') as f:
                    key_content = f.read().strip()
                self.key_entry_decrypt.delete(0, "end")
                self.key_entry_decrypt.insert(0, key_content)
                self.log(f"Wczytano klucz z pliku: {file_path}")
            except Exception as e:
                self.log(f"BŁĄD: Nie odczytano klucza: {e}")
                messagebox.showerror("Błąd odczytu", f"Nie można odczytać pliku z kluczem.\n\nBłąd: {e}")

    def wczytaj_pliki_z_folderu(self, folder_path):
        files = []
        for item in os.listdir(folder_path):
            if item == os.path.basename(__file__):  # Ignoruj plik samego skryptu
                continue
            file_path = os.path.join(folder_path, item)
            if os.path.isfile(file_path):
                files.append(item)
        return files

    # --- Funkcje Szyfrowania dla różnych Algorytmów ---

    def encrypt_fernet(self, data, key):
        """Szyfrowanie za pomocą standardowego Fernet.
        Format: FERNET_TAG (6 bajtów) + Szyfrogram
        """
        # USUNIĘTO parametr 'rounds' i logikę wielorundowości
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(data)

        # Zwraca tylko tag i zaszyfrowane dane
        return FERNET_TAG + encrypted_data

    def encrypt_aes_gcm(self, data, key):
        """Szyfrowanie za pomocą AES-256 GCM.
        Format: AESGCM_TAG (6 bajtów) + Nonce (12) + Tag (16) + Szyfrogram
        """
        if AES is None: raise RuntimeError("Brak biblioteki PyCryptodome")

        nonce = get_random_bytes(NONCE_SIZE)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        return AESGCM_TAG + nonce + tag + ciphertext

    def encrypt_chacha20_poly1305(self, data, key):
        """Szyfrowanie za pomocą ChaCha20-Poly1305.
        Format: CHACHA_TAG (6 bajtów) + Nonce (12) + Tag (16) + Szyfrogram
        """
        if ChaCha20 is None: raise RuntimeError("Brak biblioteki PyCryptodome")

        nonce = get_random_bytes(NONCE_SIZE)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        return CHACHA_TAG + nonce + tag + ciphertext

    # --- Szyfrowanie Główne ---
    def run_encryption(self, folder_path):
        if not os.path.isdir(folder_path):
            messagebox.showerror("Błąd", "Podana ścieżka nie jest prawidłowym folderem!")
            return

        selected_algo = self.algo_combobox.get()
        key_length_str = ""  # Do logowania

        if selected_algo == self.algo_options[0]:  # Fernet
            key = Fernet.generate_key()
            key_str = key.decode('utf-8')
            algo_tag_display = "FERNET"
            key_length_str = "128-bit (AES)"
        else:  # AES lub ChaCha20
            # --- NOWA LOGIKA POBIERANIA DŁUGOŚCI KLUCZA ---
            selected_key_length_name = self.key_length_combobox.get()
            KEY_SIZE = self.key_length_map[selected_key_length_name]

            key = get_random_bytes(KEY_SIZE)
            key_str = key.hex()

            key_length_str = selected_key_length_name
            if selected_algo == self.algo_options[1]:
                algo_tag_display = "AESGCM"
            else:
                algo_tag_display = "CHACHA"

        self.log(
            f"\n--- Rozpoczynam szyfrowanie ({algo_tag_display}, Klucz: {key_length_str}) ---")

        self.key_entry_display.configure(state="normal")
        self.key_entry_display.delete(0, "end")
        self.key_entry_display.insert(0, key_str)
        self.key_entry_display.configure(state="readonly")

        try:
            folder_name = os.path.basename(os.path.normpath(folder_path))
            key_filename = f"{folder_name}_{algo_tag_display}_klucz.txt"

            desktop_path = os.path.join(os.path.expanduser('~'), 'Desktop')
            desktop_key_file_path = os.path.join(desktop_path, key_filename)

            with open(desktop_key_file_path, "w") as f:
                f.write(key_str)
            self.log(f"Zapisano klucz na pulpicie: {desktop_key_file_path}")
        except Exception as e:
            self.log(f"BŁĄD: Nie udało się zapisać klucza na pulpicie: {e}")

        files_to_process = self.wczytaj_pliki_z_folderu(folder_path)
        start_time = time.time()

        for file in files_to_process:
            file_path = os.path.join(folder_path, file)
            if file == key_filename:
                continue

            try:
                with open(file_path, "rb") as f_in:
                    data = f_in.read()

                if selected_algo == self.algo_options[0]:
                    encrypted_data = self.encrypt_fernet(data, key)  # Usunięto 'rounds'
                elif selected_algo == self.algo_options[1]:
                    encrypted_data = self.encrypt_aes_gcm(data, key)
                elif selected_algo == self.algo_options[2]:
                    encrypted_data = self.encrypt_chacha20_poly1305(data, key)
                else:
                    self.log(f"BŁĄD: Nieznany algorytm: {selected_algo}")
                    continue

                with open(file_path, "wb") as f_out:
                    f_out.write(encrypted_data)

                self.log(f"Zaszyfrowano: {file}")
            except Exception as e:
                self.log(f"BŁĄD przy szyfrowaniu {file}: {e}")

        total_time = time.time() - start_time
        self.log(f"--- Szyfrowanie zakończone w {total_time:.2f}s ---")
        messagebox.showinfo("Sukces", f"Zaszyfrowano {len(files_to_process)} plików!")

    # --- Funkcje Odszyfrowania dla różnych Algorytmów ---

    def decrypt_fernet(self, encrypted_data, key):
        """Odszyfrowanie za pomocą standardowego Fernet.
        Format: FERNET_TAG (6 bajtów) + Szyfrogram
        """
        # --- ZMIANA: Usunięto logikę czytania rund ---

        # Odszyfrowywane dane zaczynają się PO 6 bajtach tagu
        data_to_decrypt = encrypted_data[TAG_LEN:]

        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(data_to_decrypt)

        # Zwracamy 1, aby funkcja wywołująca wiedziała, że to była 1 runda
        return decrypted_data, 1

    def decrypt_aes_gcm(self, encrypted_data, key):
        """Odszyfrowanie za pomocą AES-GCM.
        Format: AESGCM_TAG (6 bajtów) + Nonce (12) + Tag (16) + Szyfrogram
        """
        if AES is None: raise RuntimeError("Brak biblioteki PyCryptodome")

        # Dane zaczynają się po 6-bajtowym tagu
        nonce = encrypted_data[TAG_LEN: TAG_LEN + NONCE_SIZE]
        tag = encrypted_data[TAG_LEN + NONCE_SIZE: TAG_LEN + NONCE_SIZE + TAG_SIZE]
        ciphertext = encrypted_data[TAG_LEN + NONCE_SIZE + TAG_SIZE:]

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data, 1

    def decrypt_chacha20_poly1305(self, encrypted_data, key):
        """Odszyfrowanie za pomocą ChaCha20-Poly1305.
        Format: CHACHA_TAG (6 bajtów) + Nonce (12) + Tag (16) + Szyfrogram
        """
        if ChaCha20 is None: raise RuntimeError("Brak biblioteki PyCryptodome")

        # Dane zaczynają się po 6-bajtowym tagu
        nonce = encrypted_data[TAG_LEN: TAG_LEN + NONCE_SIZE]
        tag = encrypted_data[TAG_LEN + NONCE_SIZE: TAG_LEN + NONCE_SIZE + TAG_SIZE]
        ciphertext = encrypted_data[TAG_LEN + NONCE_SIZE + TAG_SIZE:]

        cipher = ChaCha20.new(key=key, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data, 1

    # --- Odszyfrowanie Główne ---
    def run_decryption(self):
        file_path = self.entry_path_decrypt.get()
        key_str = self.key_entry_decrypt.get()

        if not os.path.isfile(file_path):
            messagebox.showerror("Błąd", "Podana ścieżka nie jest prawidłowym plikiem!")
            return
        if not key_str:
            messagebox.showerror("Błąd", "Klucz odszyfrowujący nie może być pusty!")
            return

        self.log("\n--- Rozpoczynam odszyfrowywanie pliku ---")

        try:
            # 1. Wczytanie zaszyfrowanych danych
            with open(file_path, "rb") as f_in:
                encrypted_data = f_in.read()

            if len(encrypted_data) < TAG_LEN + 1:  # Minimalna dlugosc: 6 bajtów tagu + dane
                raise ValueError("Plik jest za krótki/uszkodzony.")

            # 2. Identyfikacja algorytmu

            # --- ZMIANA: Wszystkie tagi są na początku pliku ---
            algo_tag_check = encrypted_data[0: TAG_LEN]

            algo_tag = None
            key = None

            if algo_tag_check == FERNET_TAG:
                # Jest to Fernet
                algo_tag = 'FERNET'
                key = key_str.encode('utf-8')
                decrypted_data, rounds = self.decrypt_fernet(encrypted_data, key)

            elif algo_tag_check == AESGCM_TAG:
                # Jest to AES
                algo_tag = 'AESGCM'
                key = bytes.fromhex(key_str)
                decrypted_data, rounds = self.decrypt_aes_gcm(encrypted_data, key)

            elif algo_tag_check == CHACHA_TAG:
                # Jest to ChaCha
                algo_tag = 'CHACHA'
                key = bytes.fromhex(key_str)
                decrypted_data, rounds = self.decrypt_chacha20_poly1305(encrypted_data, key)
            else:
                self.log(
                    f"BŁĄD: Nieznany lub uszkodzony plik. Nie rozpoznano znacznika algorytmu: {encrypted_data[:7]}")
                messagebox.showerror("Błąd odszyfrowywania",
                                     "Nieznany format pliku. Czy to jest plik zaszyfrowany przez ten program?")
                return

            self.log(
                f"Wykryto algorytm: {algo_tag}. Odszyfrowuję...")

            # 3. Zapisanie odszyfrowanych danych
            with open(file_path, "wb") as f_out:
                f_out.write(decrypted_data)

            self.log(f"Pomyślnie odszyfrowano plik: {os.path.basename(file_path)}")
            messagebox.showinfo("Sukces", "Plik został pomyślnie odszyfrowany!")

        except InvalidToken:
            self.log(
                "BŁĄD: Podany klucz lub tag jest nieprawidłowy dla tego pliku. Upewnij się, że używasz poprawnego klucza i plik nie jest uszkodzony.")
            messagebox.showerror("Błąd odszyfrowywania",
                                 "Nieprawidłowy klucz lub naruszenie integralności! Upewnij się, że klucz jest poprawny.")
        except Exception as e:
            self.log(f"Wystąpił nieoczekiwany błąd: {e}")
            messagebox.showerror("Błąd", f"Wystąpił błąd: {e}")


if __name__ == "__main__":
    app = App()
    app.mainloop()