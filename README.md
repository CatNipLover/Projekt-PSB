# 🔐 Symulator ataku ransomware

## 🎓 Projekt na zaliczenie przedmiotu projektowanie systemów bezpieczeństwa

**Autorzy:** *Maciej Gilecki, Paweł Górski, Matuesz Gałda*  
**Kierunek:** Inżynieria i analiza danych  
**Przedmiot:** Projektowanie systemów bezpieczeństwa  
**Prowadzący:** *dr inż. Mariusz Nycz*  

---

## 📘 Opis projektu

Celem projektu było przeprowadzenie symulacja ataku ransomware w celu zrozumienia zagrożeń, mechanizmów szyfrujących i reakcji obronnych (np. backupów)
Program został napisany w języku **Python** z wykorzystaniem bibliotek:

- `customtkinter` – do stworzenia nowoczesnego interfejsu graficznego (GUI),
- `cryptography` (moduł `Fernet`) – do bezpiecznego szyfrowania danych.

Aplikacja umożliwia użytkownikowi wybór folderu do symulacji ataku (szyfrowania plików), ustalenie poziomu szyfrowania, a następnie automatyczne zapisanie klucza szyfrującego na pulpicie. W kolejnej zakładce można odszyfrować wybrane pliki za pomocą zapisanego klucza.

---

## 🧩 Funkcjonalności

✅ Szyfrowanie plików w wybranym folderze  
✅ Wybór poziomu zabezpieczeń:
- Poziom 1 – **Szybki (1 runda)**
- Poziom 2 – **Bezpieczny (3 rundy)**
- Poziom 3 – **Pancerny (5 rund)**

✅ Automatyczne generowanie i zapisywanie klucza szyfrującego (`.txt`)  
✅ Odszyfrowywanie plików przy użyciu zapisanego klucza  
✅ Wbudowana **konsola logów** z informacjami o przebiegu operacji  
✅ Intuicyjny interfejs graficzny oparty na kartach (*Szyfrowanie / Odszyfrowanie*)

---

## ⚙️ Technologie

|     Biblioteki     |                Zastosowanie                  |
|--------------------|----------------------------------------------|
| **Python 3.8+** | Główny język programowania                      |
| **customtkinter** | Tworzenie nowoczesnego interfejsu graficznego |
| **cryptography** | Algorytmy szyfrowania symetrycznego (Fernet)   |
| **tkinter** | Obsługa okien dialogowych i komunikatów             |
| **os, time** | Operacje systemowe i pomiar czasu                  |

---

## 🖥️ Wymagania systemowe

- Python 3.8 lub nowszy  
- System: Windows / macOS / Linux  
- Zainstalowane biblioteki:

- Instalacja wymagancyh bibliotek
```bash
pip install customtkinter cryptography
```
