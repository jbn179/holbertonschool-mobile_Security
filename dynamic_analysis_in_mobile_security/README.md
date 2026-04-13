# Analyse Dynamique en Sécurité Mobile

## Note méthodologique — Analyse statique vs dynamique

Ce projet est présenté comme un exercice d'**analyse dynamique** (Frida, Objection, ADB, interception réseau). En pratique, l'ensemble des flags a été obtenu par **analyse statique pure**, sans exécuter les applications ni utiliser d'émulateur.

### Pourquoi l'analyse statique a suffi

| Tâche | Raison pour laquelle le dynamique n'était pas nécessaire |
|-------|----------------------------------------------------------|
| Tâche 0 | Algorithme entièrement lisible dans le bytecode Java décompilé — bruteforce de seed reproductible localement |
| Tâche 1 | Fonction native désassemblée avec `objdump` — données chiffrées extraites de `.rodata` |
| Tâche 2 | Clé et données hardcodées dans le bytecode — algorithme reproductible en Python |
| Tâche 3 | Fonction cachée non appelée mais entièrement visible après décompilation |

### Quand l'analyse dynamique devient nécessaire

L'analyse dynamique (Frida, Objection) aurait été indispensable dans les cas suivants :
- Clés dérivées à l'exécution depuis l'environnement (IMEI, timestamp, serveur distant)
- Code obfusqué ou packé résistant à la décompilation
- Logique dans du code natif non lisible statiquement (ex: OLLVM)
- Certificate pinning ou root detection à contourner
- Données chiffrées échangées avec un serveur réel

### Conclusion

Les applications de ce projet embarquent toute leur logique dans le binaire sans protection robuste. L'analyse statique avec `jadx`, `objdump`, et `readelf` s'est révélée suffisante et plus rapide que l'approche dynamique. Dans un contexte réel, les deux approches sont complémentaires.

---

## Tâche 0 — Sécurité d'Application Android

**APK :** `task0_d.apk`

### Approche

Analyse statique avec `jadx` pour lire `MainActivity.java`.

L'application stocke un tableau d'octets obfusqués (`obfuscatedFlagData`) et effectue un XOR de chaque octet avec `java.util.Random(seed).nextInt(256)` pour générer une chaîne. Le bouton de l'interface appelle `generateString(0)` mais la bonne seed qui révèle le flag est trouvée par bruteforce.

Constantes extraites de `ComposerKt` :
- `providerKey = 201` (index 15 et 18 du tableau)
- `providerValuesKey = 203` (index 21)

### Résolution

Réimplémentation du LCG de `java.util.Random` en Python, puis bruteforce des seeds 0 à 1000 :

```python
def java_random_next(seed, bits):
    seed = (seed * 0x5DEECE66D + 0xB) & ((1 << 48) - 1)
    return seed, seed >> (48 - bits)

def java_random_nextint(seed, bound):
    seed, val = java_random_next(seed, 31)
    return seed, (val * bound) >> 31

def java_init_seed(seed):
    return (seed ^ 0x5DEECE66D) & ((1 << 48) - 1)
```

La seed **837** produit le flag.

**Flag :** `Holberton{Good_job_finishing_your_first_dynamic_exercise}`

---

## Tâche 1 — Hooking de Fonctions Natives Android

**APK :** `task1_d.apk`

### Approche

Analyse statique avec `jadx` + `objdump` sur la librairie native `libnative-lib.so`.

`MainActivity.java` déclare une méthode native `getSecretMessage()` jamais affichée dans l'interface. Le flag est chiffré dans la section `.rodata` du `.so` et déchiffré à l'exécution par la fonction JNI `Java_com_holberton_task2_1d_MainActivity_getSecretMessage`.

Algorithme identifié par désassemblage :
- Copie 49 octets depuis `.rodata` (offset `0x5f0`)
- Pour chaque octet `i` : `char[i] = obf[i] - lit(i % 10)`
- `lit(n)` calcule le **n-ème nombre de Fibonacci** : `[0, 1, 1, 2, 3, 5, 8, 13, 21, 34]`

### Résolution

Réimplémentation en Python et déchiffrement statique (sans émulateur ni Frida) :

```python
fibs = [0, 1, 1, 2, 3, 5, 8, 13, 21, 34]
raw = [72,112,109,100,104,119,124,124,131,157,110,98,117,107,121,106,
       103,117,132,145,107,106,111,105,98,110,123,108,131,145,95,101,
       106,104,105,106,122,114,131,150,95,98,117,97,100,113,116,138,0]

flag = "".join(chr(b - fibs[i % 10]) for i, b in enumerate(raw) if b != 0)
```

**Flag :** `Holberton{native_hooking_is_no_different_at_all}`

Rapport complet : [1-report.md](1-report.md)

---

## Tâche 2 — Cryptographie Android : Interception et Déchiffrement

**APK :** `app-release-task2.apk`

### Approche

Analyse statique avec `jadx`. Aucun serveur distant — le chiffrement est entièrement local dans `MainActivityKt.java`.

L'algorithme :
1. Décode une chaîne Base64 hardcodée
2. Calcule `Fibonacci(150)` via une fonction récursive naïve intentionnellement lente
3. XOR caractère par caractère avec la clé = `str(fib(150))`

### Résolution

```python
import base64

def fib(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a

key = str(fib(150))
encrypted = base64.b64decode(
    "cVZaW1dDQllZTFdRW1xeUlBbX21CWFtHalRZXUJFRFhNX1ZcbllGQ15cUUNSRFpcVks="
).decode('utf-8')
flag = "".join(chr(ord(key[i % len(key)]) ^ ord(c)) for i, c in enumerate(encrypted))
```

**Flag :** `Holberton{fibonacci_slow_computation_optimization}`

Rapport complet : [2-report.md](2-report.md)

---

## Tâche 3 — Révélation de Fonctions Cachées Android

**APK :** `task3_d.apk`

### Approche

Analyse statique avec `jadx`. La fonction de déchiffrement `aBcDeFgHiJkLmNoPqRsTuVwXyZ123456` est privée, statique, au nom obfusqué, et **jamais appelée** dans le flux normal de l'app.

L'algorithme pour chaque octet à l'index `i` :
1. XOR avec 19
2. Rotation droite de 2 bits
3. Soustraction de `index * 3`
4. Multiplication modulaire par 183

### Résolution

```python
import base64

data = base64.b64decode(
    "8CP4zSyn62t78lwwc383rxcgtv/UiMv3Pw+Mfw12LzXvorIpBypNK/oB7XvWNV0oWfoX"
)
flag_chars = []
for index, value in enumerate(b & 0xFF for b in data):
    temp  = value ^ 19
    temp2 = (((temp >> 2) | (temp << 6)) & 255) - (index * 3)
    temp2 = temp2 % 256
    if temp2 < 0:
        temp2 += 256
    flag_chars.append(chr((temp2 * 183) % 256))
print("".join(flag_chars))
```

**Flag :** `Holberton{calling_uncalled_functions_is_now_known!}`

Rapport complet : [3-report.md](3-report.md)
