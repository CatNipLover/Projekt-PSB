
import os
import time
import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet, InvalidToken

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Symulator ataku ransomware")
        self.geometry("700x650")
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

        # gui 

    def setup_encrypt_tab(self):
        """Tworzy widzety dla zakladki szyfrowania."""
        self.tab_encrypt.grid_columnconfigure(1, weight=1)

        # etykieta i pole na sciezke
        label_folder = ctk.CTkLabel(self.tab_encrypt, text="Wybierz folder, aby rozpocząć szyfrowanie:")
        label_folder.grid(row=0, column=0, padx=10, pady=10, sticky="w")

        # przycisk, ktory uruchamia szyfrowanie
        button_browse_folder = ctk.CTkButton(self.tab_encrypt, text="Wybierz folder i szyfruj...",
                                             command=self.select_folder_and_encrypt)
        button_browse_folder.grid(row=0, column=1, columnspan=2, padx=10, pady=10, sticky="ew")

        # interaktywny suwak 
        label_strength = ctk.CTkLabel(self.tab_encrypt, text="Poziom szyfrowania:")
        label_strength.grid(row=1, column=0, padx=10, pady=10, sticky="w")

        self.strength_slider = ctk.CTkSlider(self.tab_encrypt, from_=1, to=3, number_of_steps=2,
                                             command=self.update_strength_label)
        self.strength_slider.grid(row=1, column=1, padx=10, pady=10, sticky="ew")

        self.strength_label_display = ctk.CTkLabel(self.tab_encrypt, text="", font=("Arial", 12, "bold"))
        self.strength_label_display.grid(row=1, column=2, padx=10, pady=10, sticky="w")

        self.strength_slider.set(1)
        self.update_strength_label(1)

        # pole na wygenerowany klucz
        self.key_entry_display = ctk.CTkEntry(self.tab_encrypt,
                                              placeholder_text="Tutaj pojawi się wygenerowany klucz...",
                                              state="readonly")
        self.key_entry_display.grid(row=2, column=0, columnspan=3, padx=10, pady=10, sticky="ew")

    def setup_decrypt_tab(self):
        """Tworzy widzety dla zakladki odszyfrowywania."""
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
        if value == 1:
            text = "Poziom 1: Szybki (1 runda)"
            color = "#2ECC71"
        elif value == 2:
            text = "Poziom 2: Bezpieczny (3 rundy)"
            color = "#F39C12"
        else:
            text = "Poziom 3: Pancerny (5 rund)"
            color = "#E74C3C"
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
        for file in os.listdir(folder_path):
            if file == os.path.basename(__file__):  # Ignoruj plik samego skryptu
                continue
            file_path = os.path.join(folder_path, file)
            if os.path.isfile(file_path):
                files.append(file)
        return files

    # szyfrowanie
    def run_encryption(self, folder_path):
        if not os.path.isdir(folder_path):
            messagebox.showerror("Błąd", "Podana ścieżka nie jest prawidłowym folderem!")
            return

        slider_value = self.strength_slider.get()
        rounds_map = {1: 1, 2: 3, 3: 5}
        rounds = rounds_map[int(slider_value)]

        self.log(f"\n--- Rozpoczynam szyfrowanie ({rounds} {'runda' if rounds == 1 else 'rund'}) ---")

        key = Fernet.generate_key()
        key_str = key.decode('utf-8')

        self.key_entry_display.configure(state="normal")
        self.key_entry_display.delete(0, "end")
        self.key_entry_display.insert(0, key_str)
        self.key_entry_display.configure(state="readonly")

        try:
            # stworzenie klucza 
            folder_name = os.path.basename(os.path.normpath(folder_path))
            key_filename = f"{folder_name}_klucz.txt"

            desktop_path = os.path.join(os.path.expanduser('~'), 'Desktop')
            desktop_key_file_path = os.path.join(desktop_path, key_filename)

            with open(desktop_key_file_path, "w") as f:
                f.write(key_str)
            self.log(f"Zapisano klucz na pulpicie: {desktop_key_file_path}")
        except Exception as e:
            self.log(f"BŁĄD: Nie udało się zapisać klucza na pulpicie: {e}")

        fernet = Fernet(key)
        files_to_process = self.wczytaj_pliki_z_folderu(folder_path)
        start_time = time.time()

        for file in files_to_process:
            # zabezpieczenie pliku z kluczem, aby nie zostal zaszyfrowany 
            if file == key_filename and os.path.dirname(folder_path) == os.path.join(os.path.expanduser('~'),
                                                                                     'Desktop'):
                continue

            file_path = os.path.join(folder_path, file)
            try:
                with open(file_path, "rb") as f_in:
                    data = f_in.read()

                encrypted_data = data
                for _ in range(rounds):
                    encrypted_data = fernet.encrypt(encrypted_data)

                with open(file_path, "wb") as f_out:
                    f_out.write(rounds.to_bytes(1, 'big'))
                    f_out.write(encrypted_data)

                self.log(f"Zaszyfrowano: {file}")
            except Exception as e:
                self.log(f"BŁĄD przy szyfrowaniu {file}: {e}")

        total_time = time.time() - start_time
        self.log(f"--- Szyfrowanie zakończone w {total_time:.2f}s ---")
        messagebox.showinfo("Sukces", f"Zaszyfrowano {len(files_to_process)} plików!")

    # odszyfrowywanie 
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
            key = key_str.encode('utf-8')
            fernet = Fernet(key)

            with open(file_path, "rb") as f_in:
                rounds = int.from_bytes(f_in.read(1), 'big')
                encrypted_data = f_in.read()

            self.log(f"Wykryto {rounds} {'rundę' if rounds == 1 else 'rund'} szyfrowania. Odszyfrowuję...")

            decrypted_data = encrypted_data
            for _ in range(rounds):
                decrypted_data = fernet.decrypt(decrypted_data)

            with open(file_path, "wb") as f_out:
                f_out.write(decrypted_data)

            self.log(f"Pomyślnie odszyfrowano plik: {os.path.basename(file_path)}")
            messagebox.showinfo("Sukces", "Plik został pomyślnie odszyfrowany!")

        except InvalidToken:
            self.log("BŁĄD: Podany klucz jest nieprawidłowy dla tego pliku.")
            messagebox.showerror("Błąd odszyfrowywania", "Nieprawidłowy klucz! Upewnij się, że jest poprawny.")
        except Exception as e:
            self.log(f"Wystąpił nieoczekiwany błąd: {e}")
            messagebox.showerror("Błąd", f"Wystąpił błąd: {e}")


if __name__ == "__main__":
    app = App()
    app.mainloop()

