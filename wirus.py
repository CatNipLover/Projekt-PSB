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
KEY_SIZE = 32  # 256 bitów dla AES i ChaCha20
SALT_SIZE = 16
NONCE_SIZE = 12  # Dla GCM i ChaCha20
TAG_SIZE = 16  # Dla GCM i Poly1305
CHUNK_SIZE = 64 * 1024  # Blok do odczytu/zapisu dla dużych plików

# Stały tag dla Fernet
FERNET_TAG = b'FERNET'
TAG_LEN = len(FERNET_TAG)  # 6 bajtów


class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Szyfrator Wielu Algorytmów")
        self.geometry("700x700")
        self.center_window()

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        self.tab_view = ctk.CTkTabview(self, width=250)
        self.tab_view.grid(row=0, column=0, padx=20, pady=10, sticky="ew")

        self.tab_encrypt = self.tab_view.add("Szyfrowanie")
        self.tab_decrypt = self.tab_view.add("Odszyfrowanie")

        self.setup_encrypt_tab()
        self.setup_decrypt_tab()

        # konsola logow
        self.log_textbox = ctk.CTkTextbox(self, state="disabled", wrap="word")
        self.log_textbox.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")

    def setup_encrypt_tab(self):
        """Tworzy widżety dla zakladki szyfrowania."""
        self.tab_encrypt.grid_columnconfigure(1, weight=1)

        # Wybór algorytmu
        label_algo = ctk.CTkLabel(self.tab_encrypt, text="Wybierz Algorytm Szyfrowania:")
        label_algo.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        self.algo_options = ["Fernet (domyślny)", "AES-256 GCM", "ChaCha20-Poly1305"]
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

        # interaktywny suwak 
        label_strength = ctk.CTkLabel(self.tab_encrypt, text="Rundy Szyfrowania (tylko Fernet):")
        label_strength.grid(row=2, column=0, padx=10, pady=5, sticky="w")

        self.strength_slider = ctk.CTkSlider(self.tab_encrypt, from_=1, to=3, number_of_steps=2,
                                             command=self.update_strength_label)
        self.strength_slider.grid(row=2, column=1, padx=10, pady=5, sticky="ew")

        self.strength_label_display = ctk.CTkLabel(self.tab_encrypt, text="", font=("Arial", 12, "bold"))
        self.strength_label_display.grid(row=2, column=2, padx=10, pady=5, sticky="w")

        self.strength_slider.set(1)
        self.update_strength_label(1)

        # Pole na wygenerowany klucz
        self.key_entry_display = ctk.CTkEntry(self.tab_encrypt,
                                              placeholder_text="Tutaj pojawi się wygenerowany klucz (base64 dla Fernet, hex dla pozostałych)...",
                                              state="readonly")
        self.key_entry_display.grid(row=3, column=0, columnspan=3, padx=10, pady=10, sticky="ew")

    def update_encryption_fields(self, choice):
        """Dostosowuje UI w zależności od wybranego algorytmu."""
        is_fernet = choice == self.algo_options[0]

        self.strength_slider.configure(state="normal" if is_fernet else "disabled")
        self.strength_label_display.configure(text_color="#2ECC71" if is_fernet else "#AAB7B8")
        self.update_strength_label(self.strength_slider.get())

        if not is_fernet:
            self.log("Uwaga: Algorytmy AES-GCM i ChaCha20-Poly1305 używają 1 rundy i klucza 256-bitowego.")

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

    # poziomy szyfrowania 
    def update_strength_label(self, value):
        """Aktualizuje etykietę siły szyfrowania na podstawie pozycji suwaka."""
        value = int(value)
        current_algo = self.algo_combobox.get()
        is_fernet = current_algo == self.algo_options[0]

        if is_fernet:
            if value == 1:
                text = "Poziom 1: Szybki (1 runda)"
                color = "#2ECC71"
            elif value == 2:
                text = "Poziom 2: Bezpieczny (3 rundy)"
                color = "#F39C12"
            else:
                text = "Poziom 3: Pancerny (5 rund)"
                color = "#E74C3C"
        else:
            text = "Tryb Nierundowy (1 runda)"
            color = "#AAB7B8"

        self.strength_label_display.configure(text=text, text_color=color)

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

    def encrypt_fernet(self, data, key, rounds):
        """Szyfrowanie za pomocą Fernet (wielorundowe).
        Format: Liczba_Rund (1 bajt) + FERNET_TAG (6 bajtów) + Szyfrogram
        """
        fernet = Fernet(key)
        encrypted_data = data
        for _ in range(rounds):
            encrypted_data = fernet.encrypt(encrypted_data)

        # 1 bajt rundy + 6 bajtów tagu
        return rounds.to_bytes(1, 'big') + FERNET_TAG + encrypted_data

    def encrypt_aes_gcm(self, data, key):
        """Szyfrowanie za pomocą AES-256 GCM (jednorundowe).
        Format: AESGCM_TAG (6 bajtów) + Nonce (12) + Tag (16) + Szyfrogram
        """
        if AES is None: raise RuntimeError("Brak biblioteki PyCryptodome")

        nonce = get_random_bytes(NONCE_SIZE)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        return b'AESGCM' + nonce + tag + ciphertext

    def encrypt_chacha20_poly1305(self, data, key):
        """Szyfrowanie za pomocą ChaCha20-Poly1305 (jednorundowe).
        Format: CHACHA_TAG (6 bajtów) + Nonce (12) + Tag (16) + Szyfrogram
        """
        if ChaCha20 is None: raise RuntimeError("Brak biblioteki PyCryptodome")

        nonce = get_random_bytes(NONCE_SIZE)
        cipher = ChaCha20.new(key=key, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        return b'CHACHA' + nonce + tag + ciphertext

    # --- Szyfrowanie Główne ---
    def run_encryption(self, folder_path):
        if not os.path.isdir(folder_path):
            messagebox.showerror("Błąd", "Podana ścieżka nie jest prawidłowym folderem!")
            return

        selected_algo = self.algo_combobox.get()
        rounds = 1

        if selected_algo == self.algo_options[0]:  # Fernet
            rounds_map = {1: 1, 2: 3, 3: 5}
            rounds = rounds_map[int(self.strength_slider.get())]
            key = Fernet.generate_key()
            key_str = key.decode('utf-8')
            algo_tag_display = "FERNET"
        else:  # AES lub ChaCha20
            key = get_random_bytes(KEY_SIZE)
            key_str = key.hex()
            algo_tag_display = selected_algo.split(' ')[0].strip()

        self.log(
            f"\n--- Rozpoczynam szyfrowanie ({algo_tag_display}, {rounds} {'runda' if rounds == 1 else 'rund'}) ---")

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
                    encrypted_data = self.encrypt_fernet(data, key, rounds)
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
        """Odszyfrowanie za pomocą Fernet (wielorundowe).
        Format: Liczba_Rund (1 bajt) + FERNET_TAG (6 bajtów) + Szyfrogram
        """
        # Odczyt pierwszej rundy (1 bajt)
        rounds = int.from_bytes(encrypted_data[:1], 'big')

        # Odszyfrowywane dane zaczynają się PO 1 bajcie rundy i 6 bajtach tagu
        data_to_decrypt = encrypted_data[1 + TAG_LEN:]

        fernet = Fernet(key)
        decrypted_data = data_to_decrypt
        for _ in range(rounds):
            decrypted_data = fernet.decrypt(decrypted_data)
        return decrypted_data, rounds

    def decrypt_aes_gcm(self, encrypted_data, key):
        """Odszyfrowanie za pomocą AES-256 GCM (jednorundowe)."""
        if AES is None: raise RuntimeError("Brak biblioteki PyCryptodome")

        # Tag jest zawsze 6 bajtów
        nonce = encrypted_data[TAG_LEN: TAG_LEN + NONCE_SIZE]
        tag = encrypted_data[TAG_LEN + NONCE_SIZE: TAG_LEN + NONCE_SIZE + TAG_SIZE]
        ciphertext = encrypted_data[TAG_LEN + NONCE_SIZE + TAG_SIZE:]

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data, 1

    def decrypt_chacha20_poly1305(self, encrypted_data, key):
        """Odszyfrowanie za pomocą ChaCha20-Poly1305 (jednorundowe)."""
        if ChaCha20 is None: raise RuntimeError("Brak biblioteki PyCryptodome")

        # Tag jest zawsze 6 bajtów
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

            if len(encrypted_data) < 1 + TAG_LEN:  # Minimalna dlugosc: 1 bajt rundy + 6 bajtów tagu
                raise ValueError("Plik jest za krótki/uszkodzony.")

            # 2. Identyfikacja algorytmu

            # W pierwszej kolejności sprawdzamy FERNECIE (ma 1 bajt rundy + 6 bajtów tagu)
            fernet_tag_check = encrypted_data[1: 1 + TAG_LEN]

            # Sprawdzamy AES/CHACHA (ma 6 bajtów tagu od początku)
            crypto_tag_check = encrypted_data[0: TAG_LEN]

            algo_tag = None
            key = None

            if fernet_tag_check == FERNET_TAG:
                # Jest to Fernet
                algo_tag = 'FERNET'
                key = key_str.encode('utf-8')
                decrypted_data, rounds = self.decrypt_fernet(encrypted_data, key)

            elif crypto_tag_check in (b'AESGCM', b'CHACHA'):
                # Jest to AES lub ChaCha
                algo_tag = crypto_tag_check.decode('utf-8')
                key = bytes.fromhex(key_str)

                if algo_tag == 'AESGCM':
                    decrypted_data, rounds = self.decrypt_aes_gcm(encrypted_data, key)
                else:  # CHACHA
                    decrypted_data, rounds = self.decrypt_chacha20_poly1305(encrypted_data, key)
            else:
                self.log(
                    f"BŁĄD: Nieznany lub uszkodzony plik. Nie rozpoznano znacznika algorytmu: {encrypted_data[:7]}")
                messagebox.showerror("Błąd odszyfrowywania",
                                     "Nieznany format pliku. Czy to jest plik zaszyfrowany przez ten program?")
                return

            self.log(
                f"Wykryto algorytm: {algo_tag}. Wykryto {rounds} {'rundę' if rounds == 1 else 'rund'} szyfrowania. Odszyfrowuję...")

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