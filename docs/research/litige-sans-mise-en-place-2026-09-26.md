# Le litige sans mise en place : X25519 et le hachage prouvés avec Longfellow

| | |
| --- | --- |
| Date | 2026-09-26 |
| Nature | Note de recherche. Elle poursuit la note [litige X25519](litige-x25519-2026-09-26.md) (section 4). Elle prouve avec Longfellow (sumcheck et Ligero), sans mise en place, la moitié X25519 d'un litige dans son corps et son hachage dans GF(2^128). Elle étalonne la machine contre les mesures publiées sur Pixel 9, et chiffre la partie réseau euclidien par un repère : la vérification ML-DSA-65 de Longfellow. Rien de tout cela ne fait partie du profil `city-g/v0.4`. |
| Question | Sans mise en place, que coûte le litige, et que coûterait-il sur un téléphone ? |
| Compagnons | [`dispute-zk/longfellow/`](dispute-zk/longfellow/) : le circuit X25519, son témoin, leurs tests et bancs d'essai contre OpenSSL et la RFC 7748, la chaîne de permutations Keccak, et le correctif qui les ajoute à Longfellow. |
| Auteur | Claude Code (assistant IA d'Anthropic), à la demande du mainteneur. Les mesures viennent d'une machine virtuelle à 4 vCPU (Intel Xeon à 2,10 GHz), étalonnée contre les mesures de Longfellow sur Pixel 9. Aucun téléphone n'a été mesuré. Une relecture cryptographique humaine reste nécessaire. |

## 0. Résumé

1. **X25519 sans mise en place.**
   - La moitié X25519 se prouve en 65 ms et se vérifie en 48 ms. La preuve fait 158 Ko et tient en un seul message, que tout le monde peut vérifier.
   - Avec Diet Mac'n'Cheese, la même moitié envoyait 23 Mo en 178 vols (note [litige X25519](litige-x25519-2026-09-26.md)). C'est 140 fois moins d'octets.
2. **Le hachage.** Les 26 permutations Keccak-f du litige se prouvent dans GF(2^128) en 0,69 s et se vérifient en 0,27 s ; la preuve fait 552 Ko.
3. **Le téléphone, par étalonnage.**
   - Sur cette machine, l'ECDSA de Longfellow se prouve en 52 ms et se vérifie en 30 ms. L'article de Longfellow mesure 53,3 et 33,5 ms sur un Pixel 9.
   - Les temps de cette note sont donc proches de ceux d'un Pixel 9. C'est un étalonnage, pas une mesure sur téléphone.
4. **La partie réseau devient le poste principal.**
   - Son repère, la vérification d'une signature ML-DSA-65 dans Longfellow, se prouve en 3,2 s et se vérifie en 1,85 s ; la preuve fait 790 Ko.
   - Le circuit de ML-KEM reste à écrire. X25519, qui dominait avec les VOLE, devient ici le plus petit poste.
5. **Le litige entier, projeté** : de l'ordre de 1,5 Mo et de 2 à 4 s sur un Pixel 9, en un seul message vérifiable par tous. Avec les VOLE, il fallait 25 Mo et près de 190 vols.

## 1. X25519 dans son corps, sans mise en place

### 1.1 Le circuit

Il reprend l'énoncé de la note [litige X25519](litige-x25519-2026-09-26.md) (section 1) :
- à partir des 256 bits de `sk_X`, il vérifie `pk_X = X25519(sk_X, 9)` contre la clé publique ;
- il rend `ss_X = X25519(sk_X, ct_X)` en 255 bits canoniques pour le combineur.

Longfellow prouve des circuits en couches par sumcheck, et engage le témoin par Ligero. Le circuit est écrit comme celui de sa vérification ECDSA :
- **L'état après chaque étape est un témoin**, pour les deux échelles de Montgomery. Chaque étape se vérifie donc seule, et le circuit n'a que 9 couches.
- **Les bits d'échange** `k_{t+1} ⊕ k_t` se calculent dans le corps, une multiplication chacun.
- **L'inverse final** est un indice, avec ses trois contrôles, comme dans la relation de Diet Mac'n'Cheese.
- **Les bits de `ss_X`** sont comparés à `p` par le comparateur de Longfellow, pour être canoniques.

Le circuit compte 2 555 entrées, dont `pk_X` et `u` publics, et 35 511 termes.

**Le corps.** Ni F_{2^255−19} ni son extension quadratique n'ont de grande racine 2^k-ième de l'unité : la plus grande puissance de 2 qui divise `p − 1` est 4, et celle qui divise `p² − 1` est 8. Le code de Reed-Solomon passe donc par la convolution CRT de Longfellow, comme pour secp256k1.

### 1.2 Les vérifications

- **Le témoin** concorde avec OpenSSL sur 20 clés tirées au hasard, et avec la RFC 7748 (section 6.1).
- **Le circuit**, évalué en clair :
  - accepte les témoins honnêtes, y compris pour `u = 0`, où `z` est nul et `ss_X` aussi ;
  - rejette un bit du scalaire inversé, un bit de `ss_X` inversé, un état faux, une valeur qui n'est pas un bit, et une autre clé publique.
- **La preuve** : un témoin dont le dernier bit de `ss_X` est inversé ne donne aucune preuve valide.

### 1.3 Ce qu'elle ne fixe pas seule

Prise seule, la moitié X25519 ne fixe `sk_X` que par `pk_X`, c'est-à-dire modulo `ℓ` et au signe près. Pour un `ct_X` hors du sous-groupe d'ordre `ℓ`, deux scalaires bridés pourraient donner deux `ss_X` différents.

Deux choses règlent ce cas :
- l'énoncé complet lie `sk_X` à la graine par Keccak, avec la clé ML-KEM qui doit correspondre à `pk_M` ;
- le contrôle public de la note [litige X25519](litige-x25519-2026-09-26.md) (section 3.3) accuse le committer de tout `ct_X` hors de ce sous-groupe, sans preuve.

## 2. Le hachage dans GF(2^128)

La chaîne enchaîne 26 permutations Keccak-f[1600], le nombre que compte le litige, avec le circuit SHA-3 de Longfellow. Ce circuit prend l'état tous les 6 tours comme témoin : la profondeur reste de 9 couches, quelle que soit la longueur de la chaîne.

| Chaîne | Entrées | Termes | Preuve | Prouveur | Vérifieur |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 permutation | 8 001 | 1 186 043 | 128 936 o | 34 ms | 11 ms |
| 26 permutations | 168 001 | 30 716 943 | 565 064 o | 0,69 s | 0,27 s |

- Dans GF(2^128), le ou exclusif est une addition, donc gratuit. Seul le `χ` de Keccak multiplie.
- Un témoin faux dans le dernier état donne une preuve rejetée.
- Les 4 compressions BLAKE3 et le bloc ChaCha20 du litige manquent. Ils ne comptent que pour 5 % des portes AND dans le décompte d'emp-zk.

## 3. La partie réseau, par un repère

Le circuit de ML-KEM-768 n'est pas écrit pour Longfellow. Son repère est la vérification d'une signature ML-DSA-65, que Longfellow fournit :

| Preuve | Corps | Couches | Termes | Preuve | Prouveur | Vérifieur |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| Vérification ML-DSA-65 | F_{8380417^6} | 39 | 8 009 000 | 808 696 o | 3,2 s | 1,85 s |

- **Le même genre de calcul.** Elle multiplie par une matrice publique dans le domaine de la NTT, vérifie des NTT et des arrondis, et hache avec SHAKE256, comme la décapsulation et le rechiffrement de ML-KEM.
- **Un corps où l'arithmétique modulo `q` est native** : une extension de degré 6 du corps de ML-DSA, où `q = 8 380 417`. Pour ML-KEM, `q = 3 329` demanderait une extension de degré 11 ou 12 pour 128 bits. L'autre voie est F_{2^255−19}, avec un contrôle d'intervalle par réduction : 26 108 réductions en tout.
- **La conséquence.** Dans ce système, la partie réseau coûterait plus que le hachage et X25519 réunis. Avec emp-zk, c'était l'inverse : sur des bits, elle prenait 1,2 Mo et une demi-seconde, et X25519 était hors de portée.

## 4. Le téléphone, par étalonnage

Longfellow publie ses mesures ECDSA sur plusieurs appareils. Le même banc d'essai, sur cette machine :

| Machine | Prouveur ECDSA | Vérifieur ECDSA |
| --- | ---: | ---: |
| Cette machine virtuelle (Xeon à 2,10 GHz) | 52 ms | 30 ms |
| Pixel 9 (Tensor G4), mesuré par Longfellow | 53,3 ms | 33,5 ms |
| iPhone 15 Plus (A16), mesuré par Longfellow | 30,7 ms | 20,8 ms |
| Xeon Platinum 8581C, mesuré par Longfellow | 38,4 ms | 24,9 ms |

- **Les temps de cette note sont donc proches de ceux d'un Pixel 9**, pour ce code, et environ 0,6 fois ceux-là sur un iPhone 15 Plus.
- **Réserve** : l'article a mesuré une version antérieure du code, et un autre circuit peut se comporter autrement. C'est un étalonnage, pas une mesure sur téléphone.
- **Le réseau.** Une preuve est un seul message. Sur la 4G émulée de la note précédente, à 10 Mbit/s montants, 158 Ko partent en 0,13 s et 1,5 Mo en 1,2 s, plus un aller-retour.

## 5. Les deux voies, comparées

| | Avec VOLE (emp-zk et Diet Mac'n'Cheese) | Sans mise en place (Longfellow) |
| --- | --- | --- |
| Moitié X25519 | 23 Mo, 178 vols, 2,7 s en local | 158 Ko, 65 ms, vérifiée en 48 ms |
| Hachage (26 Keccak-f) | Compris dans les 2 Mo d'emp-zk, 0,3 s | 552 Ko, 0,69 s, vérifié en 0,27 s |
| Partie réseau | 1,2 Mo sur des bits, une demi-seconde | À écrire ; repère ML-DSA-65 : 3,2 s et 790 Ko |
| Mise en place | 21 Mo, avant la première porte | Aucune |
| Échanges | Près de 190 vols | Un message |
| Qui vérifie | Le serveur seul | Tout le monde |
| Sécurité statistique | 40 bits pour les conversions de Diet Mac'n'Cheese | Environ 109 bits, selon Longfellow |

- **Une voie mixte** existe : emp-zk pour le hachage et la partie réseau, Longfellow pour X25519. Il faudrait alors lier `sk_X` et `ss_X` entre deux systèmes de preuve qui ne partagent aucun engagement, ce que cette note ne résout pas.
- **Dans Longfellow**, les deux corps se lient par un MAC dans GF(2^128) sur chaque valeur partagée, comme le fait sa présentation mdoc entre SHA-256 et ECDSA. Il faudrait lier ici `sk_X`, `ss_X` et les entrées de ML-KEM.

## 6. Où en est le problème 2

| Problème | État | Ce qui reste |
| --- | --- | --- |
| 2. Preuves de litige | Sans mise en place : X25519 en 158 Ko et 65 ms, le hachage en 552 Ko et 0,69 s, temps proches d'un Pixel 9 par étalonnage | La partie réseau de ML-KEM dans son corps ; les liens entre corps ; puis le litige entier, mesuré sur un vrai téléphone |

L'ordre des problèmes ouverts ne change pas :
1. la preuve de l'arbre ;
2. le litige entier sans mise en place ;
3. la spécification du profil candidat.

## 7. Reproduire

- **Construire** Longfellow avec le correctif et le répertoire de [`dispute-zk/longfellow/`](dispute-zk/longfellow/), comme l'indique [`dispute-zk/README.md`](dispute-zk/README.md).
- **X25519** : `x25519_circuit_test` lance les tests et imprime la taille du circuit et de la preuve ; `--benchmark_filter=BM_` mesure le prouveur, le vérifieur et le témoin.
- **Le hachage** : `keccak_chain_test`, de même, pour 1 et 26 permutations.
- **Les repères** : `verify_test --benchmark_filter=BM_ECDSAZK` pour l'étalonnage, `ml_dsa_circuit_test` pour ML-DSA-65.

## 8. Sources

* M. Frigo, a. shelat, [Anonymous credentials from ECDSA](https://eprint.iacr.org/2024/2010), 2024 ; la bibliothèque [longfellow-zk](https://github.com/google/longfellow-zk), et sa spécification [libzk](https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/) à l'IETF.
* A. Langley, M. Hamburg, S. Turner, [RFC 7748 : Elliptic Curves for Security](https://www.rfc-editor.org/rfc/rfc7748), 2016.
* NIST, [FIPS 204, Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final), 2024.
* M. Barbosa et al., [X-Wing: The Hybrid KEM You've Been Looking For](https://eprint.iacr.org/2024/039), 2024.
* Notes précédentes : [litige X25519](litige-x25519-2026-09-26.md), [preuves et mesures](preuves-et-mesures-2026-09-26.md), [problèmes ouverts](problemes-ouverts-2026-09-26.md).
