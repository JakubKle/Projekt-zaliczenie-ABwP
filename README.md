# Projekt-zaliczenie-ABwP
Projekt – zaliczenie ćwiczeń, ABwP – Aspekty bezpieczeństwa w programowaniu, semestr V

## **Opis aplikacji**
Aplikacja pokazuje:
1. **Zastosowanie szyfrowania AES** do zabezpieczania danych (np. haseł).
2. **Podatność na atak SQL Injection** oraz sposób zabezpieczenia przed nim.

Aplikacja składa się z interfejsu graficznego, który umożliwia:
- Logowanie za pomocą dwóch trybów:
  - **Niezabezpieczone logowanie** (pokazuje podatność na SQL Injection).
  - **Zabezpieczone logowanie** (zastosowanie Prepared Statements).
- Demonstrację szyfrowania i deszyfrowania haseł z wykorzystaniem algorytmu AES.

---

## **Technologie użyte w aplikacji**

### 1. **AES (Advanced Encryption Standard)**
- Algorytm szyfrowania symetrycznego używany do ochrony danych.
- Tryb: **CBC (Cipher Block Chaining)**.
- Padding: **PKCS7**, aby dane pasowały do długości bloków.
- Sól (salt) i wektor inicjalizujący (IV) są generowane losowo.

### 2. **SQL Injection**
- Pokaz podatności:
  - Manipulacja zapytaniem SQL, aby uzyskać nieautoryzowany dostęp.
- Zabezpieczenie:
  - Zastosowanie Prepared Statements w zapytaniach SQL, które uniemożliwiają manipulację kodem SQL.

### 3. **SQLite**
- Baza danych używana do przechowywania użytkowników i zaszyfrowanych haseł.

### 4. **Tkinter**
- Biblioteka GUI (Graphical User Interface) dla języka Python, używana do stworzenia interfejsu użytkownika.

---

## **Funkcjonalności aplikacji**

1. **Logowanie niezabezpieczone**
   - Wrażliwe na atak SQL Injection.
   - Użytkownik może wprowadzić manipulowane dane, np.: `admin' OR '1'='1`, aby uzyskać nieautoryzowany dostęp.

2. **Logowanie zabezpieczone**
   - Wykorzystuje Prepared Statements, co zapobiega atakom SQL Injection.
   - Hasło jest szyfrowane i przechowywane w bazie danych, a podczas logowania jest odszyfrowywane i porównywane z wprowadzonym przez użytkownika.

3. **Szyfrowanie i deszyfrowanie**
   - Hasła użytkowników są szyfrowane algorytmem AES przed zapisaniem w bazie danych.
   - Odszyfrowywanie haseł następuje podczas logowania w celu porównania ich z wprowadzonymi danymi.

---

## **Struktura projektu**

- `users.db` - Baza danych SQLite, zawiera tabelę `users` z użytkownikami, ich zaszyfrowanymi hasłami, solą i wektorem.
- Główne funkcje:
  - **Szyfrowanie i deszyfrowanie:**
    - `encrypt_text(text, password)` - Szyfruje dane tekstowe.
    - `decrypt_text(encrypted_text, password, salt, iv)` - Odszyfrowuje dane.
  - **Logowanie:**
    - `insecure_login(username, password)` - Niezabezpieczone logowanie podatne na SQL Injection.
    - `secure_login(username, password)` - Zabezpieczone logowanie z wykorzystaniem Prepared Statements.
  - **Tworzenie bazy danych:**
    - `create_database()` - Tworzy bazę danych i dodaje przykładowego użytkownika.

---

## **Instrukcja uruchomienia**

### 1. Wymagania
- Python wersja 3.6 lub nowsza.
- Biblioteka `cryptography` (`pip install cryptography`).

### 2. Uruchamianie aplikacji
- Uruchom aplikację:
   ```bash
   python <nazwa_pliku>.py
   ```

### 3. Dane do testów
- **Poprawne dane logowania:**
  - Nazwa użytkownika: `admin`
  - Hasło: `1234`
- **Przykład SQL Injection:**
  - Nazwa użytkownika: `admin' OR '1'='1`
  - Hasło: dowolny tekst.

---

## **Problemy i ich rozwiązania**

1. **Problem:** Dane binarne w bazie były trudne do odczytania.
   - **Rozwiązanie:** Przechowywanie danych w formacie Base64, co ułatwia zapis i odczyt.

2. **Problem:** SQL Injection umożliwiał nieautoryzowany dostęp.
   - **Rozwiązanie:** Wprowadzenie Prepared Statements, które eliminują możliwość manipulacji kodem SQL.

---

## **Przykłady działania**

1. **SQL Injection:**
   - Wprowadzenie: `admin' OR '1'='1`
   - Wynik: „Zalogowano jako admin” (dla niezabezpieczonego logowania).

2. **Zabezpieczone logowanie:**
   - Wprowadzenie: `admin` / `1234`
   - Wynik: „Zalogowano jako admin”.
   - Wprowadzenie: `admin' OR '1'='1`
   - Wynik: „Nieprawidłowa nazwa użytkownika lub hasło”.

3. **Nieprawidłowe logowanie:**
   - Wprowadzenie: `admin` / `złe hasło`
   - Wynik: „Nieprawidłowe dane logowania”.

---

Jakub Klepacz
