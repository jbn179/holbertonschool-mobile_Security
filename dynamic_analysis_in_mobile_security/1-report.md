# Rapport — Tâche 1 : Hooking de Fonctions Natives Android

## Objectif

Extraire un flag caché dans le code natif (JNI) d'une application Android (`task1_d.apk`) sans exécuter l'application, en combinant analyse statique du bytecode Java et du binaire natif.

---

## Étape 1 — Analyse statique du bytecode Java

Décompilation de l'APK avec `jadx` :

```bash
jadx ~/Desktop/task1_d.apk -d ~/Desktop/task1_jadx
```

Lecture de `MainActivity.java` : l'application déclare une méthode native et charge la librairie `libnative-lib.so` :

```java
public final native String getSecretMessage();

static {
    System.loadLibrary("native-lib");
}
```

La méthode `getSecretMessage()` est implémentée en C dans la librairie native. Elle n'est jamais affichée dans l'interface, ce qui confirme qu'il faut analyser le binaire directement.

---

## Étape 2 — Identification de la librairie native

Extraction des librairies avec `apktool` :

```bash
apktool d ~/Desktop/task1_d.apk -o ~/Desktop/task1_out
find ~/Desktop/task1_out -name "*.so"
```

Librairies trouvées pour les architectures : `x86_64`, `arm64-v8a`, `x86`, `armeabi-v7a`.

Vérification des symboles exportés :

```bash
nm -D ~/Desktop/task1_out/lib/x86_64/libnative-lib.so | grep -i "secret\|jni"
```

Résultat :
```
0000000000000860 T Java_com_holberton_task2_1d_MainActivity_getSecretMessage
```

---

## Étape 3 — Analyse du désassemblage

```bash
objdump -d ~/Desktop/task1_out/lib/x86_64/libnative-lib.so | grep -A 80 "getSecretMessage"
```

L'algorithme dans `getSecretMessage` :

1. Copie **49 octets** (0x31) depuis la section `.rodata` à l'offset `0x5f0`
2. Pour chaque octet à l'index `i` : `char[i] = char[i] - lit(i % 10)`
3. Passe la chaîne déchiffrée à la JVM via `NewStringUTF`

La fonction `lit(n)` calcule le **n-ème nombre de Fibonacci** de façon itérative :

```
lit(0..9) = [0, 1, 1, 2, 3, 5, 8, 13, 21, 34]
```

---

## Étape 4 — Extraction des données chiffrées

```bash
readelf -x .rodata ~/Desktop/task1_out/lib/x86_64/libnative-lib.so
```

Bytes bruts à `0x5f0` :
```
48 70 6d 64 68 77 7c 7c 83 9d 6e 62 75 6b 79 6a
67 75 84 91 6b 6a 6f 69 62 6e 7b 6c 83 91 5f 65
6a 68 69 6a 7a 72 83 96 5f 62 75 61 64 71 74 8a 00
```

---

## Étape 5 — Déchiffrement

Réimplémentation de l'algorithme en Python :

```python
def fib(n):
    if n <= 1:
        return n
    a, b = 0, 1
    for _ in range(2, n+1):
        a, b = b, a+b
    return b

fibs = [fib(i) for i in range(10)]

raw = [72, 112, 109, 100, 104, 119, 124, 124, 131, 157,
       110, 98, 117, 107, 121, 106, 103, 117, 132, 145,
       107, 106, 111, 105, 98, 110, 123, 108, 131, 145,
       95, 101, 106, 104, 105, 106, 122, 114, 131, 150,
       95, 98, 117, 97, 100, 113, 116, 138, 0]

result = ""
for i, b in enumerate(raw):
    if b == 0:
        break
    result += chr(b - fibs[i % 10])

print(result)
```

---

## Résultat

**Flag :** `Holberton{native_hooking_is_no_different_at_all}`

---

## Résumé des outils utilisés

| Outil | Usage |
|-------|-------|
| `jadx` | Décompilation du bytecode Java |
| `apktool` | Extraction des librairies natives |
| `nm` / `readelf` | Analyse des symboles et sections du `.so` |
| `objdump` | Désassemblage de la fonction native |
| `python3` | Réimplémentation de l'algorithme et déchiffrement |
