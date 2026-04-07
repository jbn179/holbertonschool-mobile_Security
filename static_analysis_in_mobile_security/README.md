# Static Analysis in Mobile Security

Documentation des méthodes, outils et commandes utilisés pour chaque tâche d'analyse statique d'APK Android.

---

## Tâche 0 — Android App Security

**Objectif :** Retrouver un flag caché dans l'APK `mobile-task0.apk` par analyse statique uniquement (sans exécuter l'application).

### Outils utilisés

| Outil | Rôle |
|---|---|
| `apktool` | Extraction et décompilation du bytecode Smali |
| `jadx` | Décompilation en Java lisible |

### Méthodologie

#### 1. Extraction de l'APK avec apktool

```bash
apktool d mobile-task0.apk -o APK0_extracted
```

L'APK est un fichier ZIP. apktool extrait le contenu et décompile les fichiers `.dex` en bytecode Smali lisible. Le résultat contient plusieurs dossiers `smali_classes*`, les ressources XML, le `AndroidManifest.xml`, etc.

#### 2. Décompilation en Java avec jadx

```bash
jadx ~/Desktop/mobile-task0.apk -d ~/Desktop/APK0_jadx
```

jadx convertit le bytecode Dalvik en code Java lisible, ce qui facilite la compréhension de la logique applicative. Des erreurs de décompilation (39 ici) sont normales et dues à l'obfuscation.

#### 3. Localisation du code applicatif

On identifie d'abord le package de l'application parmi les librairies tierces :

```bash
find ~/Desktop/APK0_extracted/ -name "*.smali" -path "*/holberton/*"
```

Le code métier se trouve dans `smali_classes4/com/holberton/task1/`, notamment :
- `MainActivityKt.smali` — logique principale
- `MainActivityKt$FlagChallenge*.smali` — logique de vérification du flag

#### 4. Analyse du code décompilé

Le fichier `APK0_jadx/sources/com/holberton/task1/MainActivityKt.java` révèle la construction du flag :

```java
final String correctFlag =
    hexToAscii("486f6c626572746f6e7b")
    + xorDeobfuscate(xorObfuscate(listOf(71,111,111,100,95), 42), 42)
    + xorDeobfuscate(xorObfuscate(listOf(106,111,98), 42), 42)
    + "_on_your_"
    + hexToAscii("6669727374")
    + "_static_analysis_"
    + hexToAscii("6578657263697365")
    + "}";
```

#### 5. Reconstruction du flag

Deux techniques d'obfuscation sont utilisées :

**Hex → ASCII** : conversion simple de chaînes hexadécimales.
```
486f6c626572746f6e7b  →  Holberton{
6669727374            →  first
6578657263697365      →  exercise
```

**XOR double** : `xorObfuscate` puis `xorDeobfuscate` avec la même clé (42) — les deux opérations s'annulent, révélant les valeurs ASCII originales.
```
[71,111,111,100,95]  →  Good_
[106,111,98]         →  job
```

### Flag

```
Holberton{Good_job_on_your_first_static_analysis_exercise}
```

---

## Tâche 1 — Communication Between Device and Backend

**Objectif :** Analyser comment l'application envoie des informations du device à un serveur backend via HTTP POST, et retrouver le domaine obfusqué utilisé comme cible.

### Outils utilisés

| Outil | Rôle |
|---|---|
| `apktool` | Extraction et décompilation du bytecode Smali |
| `jadx` | Décompilation en Java lisible |
| `python3` | Décodage manuel du domaine obfusqué |

### Méthodologie

#### 1. Extraction et décompilation

```bash
apktool d ~/Desktop/mobile_task1.apk -o ~/Desktop/APK1_extracted
jadx ~/Desktop/mobile_task1.apk -d ~/Desktop/APK1_jadx
```

#### 2. Localisation du code applicatif

```bash
find ~/Desktop/APK1_extracted/ -name "*.smali" -path "*/holberton/*"
```

Le code métier se trouve dans `smali_classes4/com/holberton/task2/`, notamment `MainActivity.smali`.

#### 3. Analyse du code décompilé

Le fichier `APK1_jadx/sources/com/holberton/task2/MainActivity.java` révèle la chaîne de déobfuscation du domaine dans la méthode `xkfrj8932` :

```java
private final void xkfrj8932(Function0<Unit> onComplete, Function1<? super String, Unit> onError) {
    String step1 = abcd1234("DmVhMT9gLJyhpl5upzHhMTShM2Ilo3Im"); // ROT13
    String domain = uvwxyz7890(step1);                             // Base64 decode
    String url = "https://" + domain;
    sendDataToDomain(url, vgh12shj(), onComplete, onError);
}
```

Deux méthodes d'obfuscation en cascade :
- `abcd1234` → **ROT13** (identifié via les constantes `+'\r'` = +13 et `-'\r'` = -13 dans le Smali)
- `uvwxyz7890` → **Base64 decode**

Les données envoyées (`vgh12shj`) sont les infos du device en JSON via OkHttp :
```json
{
  "device_model": "...",
  "device_manufacturer": "...",
  "android_version": "...",
  "sdk_version": "..."
}
```

#### 4. Décodage du domaine

```python
import base64

s = 'DmVhMT9gLJyhpl5upzHhMTShM2Ilo3Im'

# Étape 1 — ROT13
rot13 = s.maketrans(
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
    'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
)
step1 = s.translate(rot13)
# → QzIuZG9tYWlucy5hcmUuZGFuZ2Vyb3Vz

# Étape 2 — Base64 decode
domain = base64.b64decode(step1).decode()
# → C2.domains.are.dangerous
```

#### 5. Risque de sécurité identifié

L'application communique avec un domaine de type **C2 (Command & Control)**, pattern caractéristique des malwares qui exfiltrent des données device vers un serveur distant. Le domaine est doublement obfusqué (ROT13 + Base64) pour éviter sa détection par analyse statique naïve.

### Flag

```
Holberton{C2.domains.are.dangerous}
```

---

## Tâche 2 — Reverse Engineering & Optimization Challenges

**Objectif :** Analyser un APK utilisant Fibonacci récursif comme clé de déchiffrement XOR, reconstruire le flag sans exécuter l'application.

### Outils utilisés

| Outil | Rôle |
|---|---|
| `apktool` | Extraction et décompilation du bytecode Smali |
| `jadx` | Décompilation en Java lisible |
| `python3` | Calcul de Fibonacci(150) et déchiffrement XOR |

### Méthodologie

#### 1. Extraction et décompilation

```bash
apktool d ~/Desktop/mobile-task2.apk -o ~/Desktop/APK2_extracted
jadx ~/Desktop/mobile-task2.apk -d ~/Desktop/APK2_jadx
```

#### 2. Localisation du code applicatif

```bash
find ~/Desktop/APK2_extracted/ -name "*.smali" -path "*/holberton/*"
```

Le code métier se trouve dans `smali/com/holberton/task3/`, notamment `MainActivityKt.smali` avec la classe `FibonacciDecryptionScreen`.

#### 3. Analyse du code décompilé

Le fichier `APK2_jadx/sources/com/holberton/task3/MainActivityKt.java` révèle la logique de déchiffrement :

```java
public static final String performslowDecryption() {
    byte[] decoded = Base64.getDecoder().decode(
        "cVZaW1dDQllZTFdRW1xeUlBbX21CWFtHalRZXUJFRFhNX1ZcbllGQ15cUUNSRFpcVks="
    );
    return xorDecrypt(new String(decoded, Charsets.UTF_8), String.valueOf(slowRecursive(150)));
}

public static final long slowRecursive(int i) {
    return i <= 1 ? i : slowRecursive(i - 1) + slowRecursive(i - 2);
}
```

**Problème de performance intentionnel :** `slowRecursive` est une implémentation naïve de Fibonacci en O(2^n). Pour n=150, le nombre d'appels récursifs est astronomique — l'app se fige intentionnellement.

**Solution :** Remplacer par une version itérative O(n) pour calculer Fibonacci(150) instantanément.

#### 4. Déchiffrement du flag

```python
import base64

# Version itérative O(n) au lieu de récursive O(2^n)
def fib(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a

fib150 = fib(150)
# → 9969216677189303386214405760200

key = str(fib150)

# Base64 decode du flag chiffré
encrypted = base64.b64decode(
    "cVZaW1dDQllZTFdRW1xeUlBbX21CWFtHalRZXUJFRFhNX1ZcbllGQ15cUUNSRFpcVks="
).decode('utf-8')

# XOR decrypt avec la clé Fibonacci
result = ''.join(chr(ord(key[i % len(key)]) ^ ord(c)) for i, c in enumerate(encrypted))
```

#### 5. Concept d'optimisation identifié

| Approche | Complexité | Fibonacci(150) |
|---|---|---|
| `slowRecursive` (récursif naïf) | O(2^n) | Impossible en temps réel |
| Version itérative | O(n) | Instantané |
| Mémoïsation | O(n) | Instantané |

### Flag

```
Holberton{fibonacci_slow_computation_optimization}
```

---
## Tâche 3 — Reverse Engineering & Native Libraries (JNI)

**Objectif :** Analyser un APK utilisant une bibliothèque native (`.so`) via JNI pour valider une clé et déchiffrer un flag XOR.

### Outils utilisés

| Outil | Rôle |
|---|---|
| `apktool` | Extraction de l'APK |
| `jadx` | Décompilation Java |
| `Ghidra` | Décompilation et analyse de la lib native x86_64 |
| `objdump` | Dump assembleur de la lib native |
| `python3` | Résolution des contraintes et déchiffrement XOR |

### Méthodologie

#### 1. Extraction et décompilation

```bash
apktool d ~/Desktop/mobile_task3.apk -o ~/Desktop/APK3_extracted
jadx ~/Desktop/mobile_task3.apk -d ~/Desktop/APK3_jadx
```

#### 2. Analyse du code Java

Le fichier `MainActivity.java` révèle la logique :

```java
private final String encryptedFlag = "BTYzMTAiMT0xKAssIg08MD4aOC1UOAhVRgUJSmZfBzEAHREDBDA7DzQMAwoAW1RBAh06Ig==";

public final native boolean validateUserInput(String key); // appel natif

// Déchiffrement XOR byte par byte
public final String xorDecrypt(String encrypted, String key) {
    byte[] decoded = Base64.decode(encrypted, 0);
    for (int i = 0; i < decoded.length; i++) {
        decryptedChar = decoded[i] ^ key.charAt(i % key.length());
    }
}
```

La clé est validée par la lib native `libtask4native.so`. Si valide, le flag est déchiffré par XOR.

#### 3. Analyse de la bibliothèque native avec Ghidra

On charge `lib/x86_64/libtask4native.so` dans Ghidra et on analyse `validateUserInput`. Le décompilé révèle :

- La clé doit faire exactement **52 caractères** (`0x34`)
- Chaque char est converti en `long` via `FUN_00101060` (simple cast)
- **20 équations mathématiques** valident la clé

#### 4. Résolution des équations

Les équations principales (v[n] = ord(key[n])) :

```python
# Eq1:  (v[2]+v[1]*v[0]+0x2a2bcd)*0x2054 == 0x556bd6714
# Eq2:  (v[0]+(v[4]*v[3]-v[5])*0x33f-0xc1)//2 == 0x2c3886
# Eq4:  v[2]+(v[12]+v[11]*v[10]-v[13])*7 == 0x7edd
# Eq5:  v[5]+(v[18]+v[16]-v[17])*(v[15]+v[14]) == 0x3d2c
# Eq6:  v[9]*v[4]+v[20]*3*v[19] == 0x521c
# Eq7:  (v[10]+v[7]*v[3]-v[1])*3 == 0x4f86
# Eq9:  (v[8]+v[11]*v[5]-v[19])*6 == 0x7da0
# Eq16: v[21]+v[22]*v[23]-v[24]+v[25] == 0x1527
# Eq17: (v[26]+v[27])*7-v[28]*3+v[29] == 0x401
# Eq18: v[30]*v[31]+v[32]-v[33]+v[34]*5 == 0x2ba5
# Eq19: (v[35]+v[36]-v[37]*v[38])%0x3039 == 0xdc5
# Eq20: sum(v[39..51]) == 0x4af
```

Un solver Python brute-force sur les caractères ASCII imprimables trouve la clé unique satisfaisant toutes les contraintes.

#### 5. Déchiffrement du flag

```python
import base64

enc = base64.b64decode("BTYzMTAiMT0xKAssIg08MD4aOC1UOAhVRgUJSmZfBzEAHREDBDA7DzQMAwoAW1RBAh06Ig==")
key = "MY_SUPER_SECURE_KEY_1ge45ql890anbdefg__jkmmn_555kk__"
flag = ''.join(chr(b ^ ord(key[i % len(key)])) for i, b in enumerate(enc))
# -> Holberton{Now_you_are_master_of_bytecode_and_native}
```

### Flag

```
Holberton{Now_you_are_master_of_bytecode_and_native}
```

---
