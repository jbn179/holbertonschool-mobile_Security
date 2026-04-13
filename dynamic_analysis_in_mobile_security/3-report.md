# Rapport — Tâche 3 : Révélation de Fonctions Cachées Android

## Objectif

Extraire un flag caché dans une application Android (`task3_d.apk`) dont la fonction de déchiffrement n'est jamais appelée lors de l'exécution normale de l'application.

---

## Étape 1 — Analyse statique du bytecode Java

Décompilation de l'APK avec `jadx` :

```bash
jadx ~/Desktop/task3_d.apk -d ~/Desktop/task3_jadx
```

Recherche des fonctions liées au flag :

```bash
grep -r "hidden\|secret\|flag\|decrypt\|encode\|Holberton" \
    ~/Desktop/task3_jadx/sources/com --include="*.java" -l
```

Fichier pertinent identifié : `com/holberton/task4_d/MainActivityKt.java`

---

## Étape 2 — Identification de la fonction cachée

Dans `MainActivityKt.java`, une méthode privée au nom intentionnellement obfusqué est présente :

```java
private static final void aBcDeFgHiJkLmNoPqRsTuVwXyZ123456(Function1<? super String, Unit> function1)
```

Cette fonction **n'est jamais invoquée** dans le flux normal de l'application. L'interface affiche uniquement :

> "Hmm it seems the interesting function is never called."

---

## Étape 3 — Analyse de l'algorithme de déchiffrement

La fonction effectue les opérations suivantes :

1. **Décode** une chaîne Base64 hardcodée :
   ```
   8CP4zSyn62t78lwwc383rxcgtv/UiMv3Pw+Mfw12LzXvorIpBypNK/oB7XvWNV0oWfoX
   ```

2. Pour chaque octet à l'index `i`, applique trois transformations successives :
   ```java
   int temp  = value ^ 19;                              // XOR avec 19
   int temp2 = (((temp >> 2) | (temp << 6)) & 255)      // rotation droite 2 bits
               - (index * 3);                            // soustraction position
   temp2 = temp2 % 256;
   if (temp2 < 0) temp2 += 256;
   char c = (char) ((temp2 * 183) % 256);               // multiplication modulaire
   ```

3. Concatène les caractères résultants pour former le flag.

---

## Étape 4 — Réimplémentation et déchiffrement

Reproduction exacte de l'algorithme en Python (sans exécuter l'application) :

```python
import base64

data = base64.b64decode(
    "8CP4zSyn62t78lwwc383rxcgtv/UiMv3Pw+Mfw12LzXvorIpBypNK/oB7XvWNV0oWfoX"
)
decoded_bytes = [b & 0xFF for b in data]

flag_chars = []
for index, value in enumerate(decoded_bytes):
    temp  = value ^ 19
    temp2 = (((temp >> 2) | (temp << 6)) & 255) - (index * 3)
    temp2 = temp2 % 256
    if temp2 < 0:
        temp2 += 256
    flag_chars.append(chr((temp2 * 183) % 256))

print("".join(flag_chars))
```

---

## Résultat

**Flag :** `Holberton{calling_uncalled_functions_is_now_known!}`

---

## Observations de sécurité

- La fonction cachée est **privée et statique** — non accessible via l'interface, mais entièrement visible après décompilation.
- Le nom obfusqué (`aBcDeFgHiJkLmNoPqRsTuVwXyZ123456`) est une technique de dissimulation superficielle, inefficace contre l'analyse statique.
- Toute la logique de déchiffrement est embarquée dans le binaire — aucun secret externe n'est nécessaire pour reconstituer le flag.

---

## Résumé des outils utilisés

| Outil | Usage |
|-------|-------|
| `jadx` | Décompilation du bytecode Java |
| `python3` | Réimplémentation de l'algorithme et déchiffrement |
