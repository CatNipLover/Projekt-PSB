# main.py
import customtkinter as ctk
from tkinter import filedialog, messagebox
import os
import time
from constants import *
from crypto import *
from utils import center_window
from cryptography.fernet import InvalidToken


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Szyfrator Wielu Algorytmów")
        self.geometry("700x580")
        center_window(self, 700, 580)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")

        # Najpierw GUI – wszystko w setup_ui()
        self.setup_ui()

    def setup_ui(self):
        # --- TABY ---
        self.tab_view = ctk.CTkTabview(self)
        self.tab_view.grid(row=0, column=0, padx=20, pady=10, sticky="ew")

        tab_encrypt = self.tab_view.add("Szyfrowanie")
        tab_decrypt = self.tab_view.add("Odszyfrowanie")

        # --- SZYFROWANIE ---
        self.setup_encrypt_tab(tab_encrypt)
        self.setup_decrypt_tab(tab_decrypt)

        # --- LOGI – TWORZONE PRZED update_encryption_fields! ---
        self.log_box = ctk.CTkTextbox(self, state="disabled", wrap="word")
        self.log_box.grid(row=1, column=0, padx=20, pady=(0, 20), sticky="nsew")

        # --- Teraz bezpiecznie: ustawiamy domyślny algorytm ---
        self.update_encryption_fields(ALGO_OPTIONS[0])
        self.log("Aplikacja gotowa. Wybierz folder lub plik.")

    def setup_encrypt_tab(self, parent):
        parent.grid_columnconfigure(1, weight=1)

        # Algorytm
        ctk.CTkLabel(parent, text="Wybierz Algorytm Szyfrowania:").grid(
            row=0, column=0, padx=10, pady=5, sticky="w")
        self.algo_combo = ctk.CTkComboBox(parent, values=ALGO_OPTIONS,
                                          command=self.update_encryption_fields)
        self.algo_combo.set(ALGO_OPTIONS[0])
        self.algo_combo.grid(row=0, column=1, columnspan=2, padx=10, pady=5, sticky="ew")

        # Folder
        ctk.CTkButton(parent, text="Wybierz folder i szyfruj...",
                      command=self.select_folder_encrypt).grid(
            row=1, column=0, columnspan=3, padx=10, pady=5, sticky="ew")

        # Długość klucza (ukryte na start)
        self.key_length_label = ctk.CTkLabel(parent, text="Wybierz długość klucza:")
        self.key_length_combo = ctk.CTkComboBox(parent, values=AES_KEY_OPTIONS)

        # Klucz
        self.key_display = ctk.CTkEntry(parent, state="readonly",
                                        placeholder_text="Tutaj pojawi się wygenerowany klucz...")
        self.key_display.grid(row=3, column=0, columnspan=3, padx=10, pady=10, sticky="ew")

    def setup_decrypt_tab(self, parent):
        parent.grid_columnconfigure(1, weight=1)

        # Plik
        ctk.CTkLabel(parent, text="Wybierz plik do odszyfrowania:").grid(
            row=0, column=0, padx=10, pady=10, sticky="w")
        self.file_entry = ctk.CTkEntry(parent, placeholder_text="Wybierz zaszyfrowany plik...")
        self.file_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        ctk.CTkButton(parent, text="Przeglądaj...", command=self.browse_file).grid(
            row=0, column=2, padx=10, pady=10)

        # Klucz
        ctk.CTkLabel(parent, text="Wklej lub wczytaj klucz:").grid(
            row=1, column=0, padx=10, pady=10, sticky="w")
        self.key_entry = ctk.CTkEntry(parent, placeholder_text="Wprowadź klucz...")
        self.key_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")
        ctk.CTkButton(parent, text="Przeglądaj...", command=self.browse_key).grid(
            row=1, column=2, padx=10, pady=10)

        # Przycisk
        ctk.CTkButton(parent, text="ODSZYFRUJ PLIK", command=self.decrypt_file).grid(
            row=2, column=0, columnspan=3, padx=10, pady=10, sticky="ew")

    def update_encryption_fields(self, choice):
        if choice == ALGO_OPTIONS[0]:  # Fernet
            self.key_length_label.grid_remove()
            self.key_length_combo.grid_remove()
            self.log("Wybrano Fernet (AES-128). Klucz jest generowany automatycznie.")
        else:
            self.key_length_label.grid(row=2, column=0, padx=10, pady=5, sticky="w")
            self.key_length_combo.grid(row=2, column=1, columnspan=2, padx=10, pady=5, sticky="ew")
            if choice == ALGO_OPTIONS[1]:  # AES-GCM
                self.key_length_combo.configure(values=AES_KEY_OPTIONS)
                self.key_length_combo.set(AES_KEY_OPTIONS[2])  # 256 domyślnie
                self.log("Wybrano AES-GCM. Wybierz długość klucza.")
            else:  # ChaCha20
                self.key_length_combo.configure(values=CHACHA_KEY_OPTIONS)
                self.key_length_combo.set(CHACHA_KEY_OPTIONS[1])  # 256 domyślnie
                self.log("Wybrano ChaCha20-Poly1305. Wybierz długość klucza.")

    def log(self, msg):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", msg + "\n")
        self.log_box.configure(state="disabled")
        self.log_box.see("end")

    def select_folder_encrypt(self):
        folder = filedialog.askdirectory(title="Wybierz folder do zaszyfrowania")
        if folder:
            self.log(f"Wybrano folder: {folder}")
            self.encrypt_folder(folder)

    def encrypt_folder(self, folder_path):
        algo = self.algo_combo.get()
        folder_name = os.path.basename(os.path.normpath(folder_path))
        algo_tag = {
            "Fernet (AES-128)": "FERNET",
            "AES-GCM": "AESGCM",
            "ChaCha20-Poly1305": "CHACHA"
        }[algo]

        try:
            if algo == ALGO_OPTIONS[0]:
                key, key_str = generate_key(algo)
            else:
                key_length_name = self.key_length_combo.get()
                key, key_str = generate_key(algo, key_length_name)

            # Pokaż klucz
            self.key_display.configure(state="normal")
            self.key_display.delete(0, "end")
            self.key_display.insert(0, key_str)
            self.key_display.configure(state="readonly")

            # Zapisz klucz
            key_path = save_key_to_desktop(key_str, folder_name, algo_tag)
            self.log(f"Klucz zapisany: {key_path}")

            # Wybierz funkcję
            encrypt_func = {
                ALGO_OPTIONS[0]: encrypt_fernet,
                ALGO_OPTIONS[1]: encrypt_aes_gcm,
                ALGO_OPTIONS[2]: encrypt_chacha20_poly1305
            }[algo]

            # Pliki
            files = [
                os.path.join(folder_path, f) for f in os.listdir(folder_path)
                if os.path.isfile(os.path.join(folder_path, f)) and f != os.path.basename(__file__)
            ]

            start = time.time()
            for file_path in files:
                try:
                    with open(file_path, "rb") as f:
                        data = f.read()
                    encrypted = encrypt_func(data, key)
                    with open(file_path, "wb") as f:
                        f.write(encrypted)
                    self.log(f"Zaszyfrowano: {os.path.basename(file_path)}")
                except Exception as e:
                    self.log(f"BŁĄD ({os.path.basename(file_path)}): {e}")

            self.log(f"--- Szyfrowanie zakończone w {time.time() - start:.2f}s ---")
            messagebox.showinfo("Sukces", f"Zaszyfrowano {len(files)} plików!\nKlucz na pulpicie.")

        except Exception as e:
            self.log(f"BŁĄD: {e}")
            messagebox.showerror("Błąd", str(e))

    def browse_file(self):
        path = filedialog.askopenfilename(title="Wybierz zaszyfrowany plik")
        if path:
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, path)
            self.log(f"Wybrano plik: {path}")

    def browse_key(self):
        path = filedialog.askopenfilename(
            title="Wybierz plik z kluczem",
            filetypes=[("Pliki tekstowe", "*.txt"), ("Wszystkie pliki", "*.*")]
        )
        if path:
            try:
                with open(path, "r", encoding='utf-8') as f:
                    key = f.read().strip()
                self.key_entry.delete(0, "end")
                self.key_entry.insert(0, key)
                self.log(f"Wczytano klucz z: {path}")
            except Exception as e:
                self.log(f"Nie wczytano klucza: {e}")

    def decrypt_file(self):
        file_path = self.file_entry.get().strip()
        key_str = self.key_entry.get().strip()

        if not file_path or not os.path.isfile(file_path):
            messagebox.showerror("Błąd", "Wybierz prawidłowy plik!")
            return
        if not key_str:
            messagebox.showerror("Błąd", "Wprowadź klucz!")
            return

        self.log(f"Próba odszyfrowania: {os.path.basename(file_path)}")

        try:
            with open(file_path, "rb") as f:
                data = f.read()

            if len(data) < 6:
                raise ValueError("Plik za krótki – nie jest zaszyfrowany przez ten program.")

            decrypted, algo_name = decrypt_auto(data, key_str)

            with open(file_path, "wb") as f:
                f.write(decrypted)

            self.log(f"ODSZYFROWANO ({algo_name})")
            messagebox.showinfo("Sukces", f"Plik odszyfrowany!\nAlgorytm: {algo_name}")

        except InvalidToken:
            self.log("BŁĄD: Nieprawidłowy klucz!")
            messagebox.showerror("Błąd", "Nieprawidłowy klucz lub plik uszkodzony!")
        except Exception as e:
            self.log(f"Błąd: {e}")
            messagebox.showerror("Błąd", str(e))


if __name__ == "__main__":
    app = App()
    app.mainloop()