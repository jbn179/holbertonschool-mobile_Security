# Rapport — Tâche 2 : Cryptographie Android — Interception et Déchiffrement

## Objectif

Extraire un flag caché dans une application Android (`app-release-task2.apk`) qui utilise un chiffrement XOR basé sur un calcul Fibonacci. Aucun serveur distant n'est impliqué — le chiffrement est entièrement local.

---

## Étape 1 — Analyse statique du bytecode Java

Décompilation de l'APK avec `jadx` :

```bash
jadx ~/Desktop/app-release-task2.apk -d ~/Desktop/task2_jadx
```

Fichiers pertinents identifiés :
- `com/holberton/task3/MainActivityKt.java` — contient toute la logique de déchiffrement
- `com/holberton/task3/MainActivity.java` — simple lanceur d'interface

---

## Étape 2 — Analyse de l'algorithme

Trois fonctions clés dans `MainActivityKt.java` :

### `performslowDecryption()`
```java
public static final String performslowDecryption() {
    byte[] decoded = Base64.getDecoder().decode(
        "cVZaW1dDQllZTFdRW1xeUlBbX21CWFtHalRZXUJFRFhNX1ZcbllGQ15cUUNSRFpcVks="
    );
    return xorDecrypt(new String(decoded, UTF_8), String.valueOf(slowRecursive(150)));
}
```

### `slowRecursive(int n)` — Fibonacci récursif naïf
```java
public static final long slowRecursive(int i) {
    return i <= 1 ? i : slowRecursive(i - 1) + slowRecursive(i - 2);
}
```
Calcule `Fibonacci(150)` de façon volontairement lente (d'où le nom).

### `xorDecrypt(String encryptedFlag, String key)` — XOR caractère par caractère
```java
// Pour chaque caractère i : result[i] = key[i % key.length()] XOR encrypted[i]
```

---

## Étape 3 — Déchiffrement

Réimplémentation en Python (sans exécuter l'application) :

```python
import base64

def fib(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a

key = str(fib(150))
# fib(150) = 9969216677189303386214405760200

encrypted = base64.b64decode(
    "cVZaW1dDQllZTFdRW1xeUlBbX21CWFtHalRZXUJFRFhNX1ZcbllGQ15cUUNSRFpcVks="
).decode('utf-8')

flag = "".join(chr(ord(key[i % len(key)]) ^ ord(c)) for i, c in enumerate(encrypted))
print(flag)
```

---

## Résultat

**Flag :** `Holberton{fibonacci_slow_computation_optimization}`

---

## Observations de sécurité

- La clé de chiffrement est entièrement dérivable à partir du code source — aucun secret externe.
- `slowRecursive` est une implémentation Fibonacci récursive naïve en O(2^n), utilisée intentionnellement pour ralentir l'analyse dynamique.
- Le flag est chiffré en XOR avec une clé dériviste du résultat de `fib(150)` converti en string — facilement cassable par analyse statique.

---

## Résumé des outils utilisés

| Outil | Usage |
|-------|-------|
| `jadx` | Décompilation du bytecode Java |
| `python3` | Réimplémentation de l'algorithme et déchiffrement |
