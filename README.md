# 🔐 Symulator ataku ransomware

❗ PROJEKT WYŁĄCZNIE EDUKACYJNY ❗  
Ten projekt został stworzony **jedynie na potrzeby zaliczenia przedmiotu**  
*Projektowanie systemów bezpieczeństwa* na studiach.  
**Kod nie może być wykorzystywany w celach komercyjnych, produkcyjnych ani do żadnych działań niezgodnych z prawem.**

📄 Licencja: MIT  
Możesz czytać, uruchamiać i uczyć się na tym kodzie – wystarczy zachować informacje o autorach i licencji (szczegóły w pliku `LICENSE`).

## 🎓 Projekt na zaliczenie przedmiotu *Projektowanie systemów bezpieczeństwa*
**Autorzy:** Maciej Gilecki, Paweł Górski, Mateusz Gałda  
**Kierunek:** Inżynieria i analiza danych  
**Prowadzący:** dr inż. Mariusz Nycz  
**Rok akademicki:** 2025/2026  

---
## 📘 Opis projektu
Celem projektu jest stworzenie aplikacji edukacyjnej, która w bezpieczny i kontrolowany sposób symuluje atak ransomware. Program pozwala:
- 🔒 szyfrować pliki w wybranym folderze,
- testować trzy różne algorytmy szyfrowania,
- generować i zapisywać klucz na pulpicie,
- 🔓 odszyfrowywać zaszyfrowane pliki,
- zrozumieć mechanizmy działania prawdziwego ransomware.

Aplikacja napisana w **Pythonie** z nowoczesnym GUI dzięki `customtkinter`.

---
## 🧩 Funkcjonalności
### 🔒 Szyfrowanie
- szyfrowanie wszystkich plików w wybranym folderze
- trzy algorytmy: **Fernet (AES-128)** • **AES-GCM** • **ChaCha20-Poly1305**
- automatyczny tag algorytmu w każdym pliku

### 🔑 Klucze
- automatyczne generowanie poprawnego klucza
- zapis klucza na pulpicie użytkownika

### 🔓 Odszyfrowywanie
- tryb automatyczny – sam rozpoznaje algorytm
- pełne wsparcie dla wszystkich trzech metod

### 🖥️ Interfejs
- nowoczesny wygląd (`customtkinter`)
- dwie zakładki: Szyfrowanie ↔ Odszyfrowanie
- wbudowana konsola logów

---
## 🔧 Obsługiwane algorytmy
| Algorytm                  | Długość klucza                  |
|---------------------------|----------------------------------|
| **Fernet (AES-128)**      | 256 bit (32 bajty)              |
| **AES-GCM**               | 128 / 192 / 256 bit             |
| **ChaCha20-Poly1305**     | 256 bit (32 bajty)              |

---
## ⚙️ Użyte technologie
- Python 3.8+
- customtkinter • tkinter
- cryptography • PyCryptodome
- standardowe moduły Pythona

---
## ⚠️ WAŻNE – BEZPIECZEŃSTWO
- To tylko **symulator edukacyjny**  
- Zawsze pracuj na **kopiach danych**  
- Autorzy nie ponoszą odpowiedzialności za niewłaściwe użycie
---
## 🛠️ Instalacja i wymagania

**Wymagania:**
- Python 3.8 lub nowszy
- System: Windows / macOS / Linux

**Wymagane biblioteki – zainstaluj jedną komendą:**
```bash
pip install customtkinter cryptography pycryptodome
```
Lub uruchomić plik main.exe

---
**© 2025 Maciej Gilecki, Paweł Górski, Mateusz Gałda**  
Projekt studencki • Licencja MIT • Wyłącznie cele edukacyjne 🚀
