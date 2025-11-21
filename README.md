# 🔐 Symulator ataku ransomware

## 🎓 Projekt na zaliczenie przedmiotu *Projektowanie systemów bezpieczeństwa*

**Autorzy:** Maciej Gilecki, Paweł Górski, Mateusz Gałda  
**Kierunek:** Inżynieria i analiza danych  
**Prowadzący:** dr inż. Mariusz Nycz  

---

## 📘 Opis projektu

Celem projektu jest stworzenie aplikacji edukacyjnej, która w bezpieczny i kontrolowany sposób symuluje działanie ataku ransomware. Program umożliwia:

- szyfrowanie plików w wybranym folderze,
- testowanie trzech różnych algorytmów szyfrowania,
- generowanie klucza szyfrującego i zapisywanie go na pulpicie,
- odszyfrowywanie zaszyfrowanych plików,
- poznanie mechanizmów typowych dla działania ransomware.

Aplikacja korzysta z języka **Python** oraz nowoczesnego interfejsu graficznego opartego o `customtkinter`.

---

## 🧩 Funkcjonalności

### 🔒 Szyfrowanie

- Szyfrowanie wszystkich plików w wybranym folderze  
- Obsługa trzech algorytmów:
  - **Fernet (AES-128)**
  - **AES-GCM**
  - **ChaCha20-Poly1305**
- Do każdego pliku dodawany jest tag algorytmu, dzięki czemu możliwe jest automatyczne rozpoznanie metody przy odszyfrowaniu.

### 🔑 Klucze szyfrujące

- Automatyczne generowanie poprawnych kluczy zgodnych z wybranym algorytmem
- Zapis klucza szyfrującego na pulpicie użytkownika

### 🔓 Odszyfrowywanie

- Automatyczna detekcja użytego algorytmu szyfrowania na podstawie tagu (`decrypt_auto`)
- Wsparcie dla wszystkich trzech algorytmów szyfrowania

### 🖥️ Interfejs graficzny

- Nowoczesny interfejs oparty o `customtkinter`
- Dwie zakładki: **Szyfrowanie** oraz **Odszyfrowanie**
- Wbudowana konsola logów prezentująca przebieg operacji

---

## 🔧 Obsługiwane algorytmy szyfrowania

| Algorytm                  | Możliwe długości kluczy |
|---------------------------|--------------------------|
| **Fernet (AES-128)**     | 256 bit (32 bajty)       |
| **AES-GCM**              | 128 / 192 / 256 bit      |
| **ChaCha20-Poly1305**    | 256 bit (32 bajty)       |

Każdy plik zaszyfrowany algorytmem AES-GCM lub ChaCha20-Poly1305 zawiera:

- 6 bajtów tagu algorytmu  
- 12 bajtów nonce  
- 16 bajtów tagu integralności  
- ciphertext  

---

## ⚙️ Technologie

| Biblioteka               | Zastosowanie |
|--------------------------|--------------|
| **Python 3.8+**          | Główny język programu |
| **customtkinter**        | Interfejs graficzny |
| **tkinter**              | Okna dialogowe |
| **cryptography (Fernet)**| Szyfrowanie AES-128 |
| **PyCryptodome**         | Implementacja AES-GCM i ChaCha20 |
| **os, time**             | Operacje systemowe i pomiar czasu |

---

## 🖥️ Wymagania systemowe

- Python **3.8 lub nowszy**
- System: Windows / macOS / Linux
- Wymagane biblioteki:

```bash
pip install customtkinter cryptography pycryptodome
```

## ⚠️ Informacje bezpieczeństwa

- Program jest **wyłącznie symulatorem edukacyjnym**.  
- Nie powinien być używany do jakichkolwiek nielegalnych celów.  
- Szyfruje tylko pliki w folderze **wybranym przez użytkownika**.  
- Zaleca się wykonywanie operacji na **kopiach zapasowych danych**.
