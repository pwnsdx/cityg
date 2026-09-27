# Le litige entier, sans mise en place, dans un seul corps

| | |
| --- | --- |
| Date | 2026-09-26 |
| Nature | Note de recherche. Elle poursuit la note [litige sans mise en place](litige-sans-mise-en-place-2026-09-26.md). Elle écrit la partie réseau de ML-KEM-768 pour Longfellow, révise l'énoncé du litige, et prouve l'énoncé entier de la branche 1 dans le corps de X25519 : ML-KEM, X25519, le hachage, `ExpandLabel` et ChaCha20. Rien de tout cela ne fait partie du profil `city-g/v0.4`. |
| Question | Que coûte le litige entier sans mise en place, et à quel énoncé ? |
| Compagnons | [`dispute-zk/longfellow/`](dispute-zk/longfellow/) : une référence ML-KEM-768 et X-Wing, les circuits et témoins du réseau, du litige entier et de sa fin (BLAKE3 et ChaCha20), leurs tests et bancs d'essai. [`bench/src/bin/wrap_vector.rs`](bench/src/bin/wrap_vector.rs) : un wrap produit par `cityg-core`, qui sert de vecteur de test. |
| Auteur | Claude Code (assistant IA d'Anthropic), à la demande du mainteneur. Les mesures viennent de la machine virtuelle de la note précédente (4 vCPU, Intel Xeon à 2,10 GHz), étalonnée contre les mesures de Longfellow sur Pixel 9. Aucun téléphone n'a été mesuré. Une relecture cryptographique humaine reste nécessaire. |

## 0. Résumé

1. **Le litige courant tient en 573 Ko.**
   - Son énoncé : « le wrap ne s'ouvre pas ». La preuve se calcule en 1,49 s et se vérifie en 0,97 s, sur une machine que l'étalonnage de la note précédente place au niveau d'un Pixel 9.
   - Elle ne demande aucune mise en place et tient en un message, que tout le monde peut vérifier.
   - Avec les VOLE, le même litige coûtait 25 Mo et près de 190 vols. La note précédente projetait 1,5 Mo et 2 à 4 s.
2. **La partie réseau coûte de 109 000 à 184 000 termes, au lieu de 1,57 million pour ses seuls produits denses.**
   - Chaque relation de ML-KEM devient une identité entre polynômes, vérifiée en un point que le vérifieur tire après l'engagement du témoin.
   - Il faut que ce point vienne après l'engagement : un témoin forgé pour un point connu d'avance passe en ce point et échoue ailleurs.
3. **L'énoncé change, et le hachage passe de 26 permutations Keccak à 2.**
   - La graine du membre sort de l'énoncé : la clé publique suffit à lier la clé ML-KEM. Une borne sur sa norme empêche un membre de choisir une clé qui échoue plus souvent.
   - Le rechiffrement de Fujisaki-Okamoto sort de l'énoncé courant. Un second énoncé, « le rechiffrement diffère », condamne l'auteur d'un chiffré invalide sans révéler où il diffère.
4. **L'énoncé de la branche 1 est complet.**
   - `ExpandLabel` (BLAKE3) et le premier bloc de ChaCha20 sont dans le circuit.
   - La preuve révèle la clé Poly1305 du wrap, et non son secret. Le vérifieur calcule l'étiquette lui-même.
   - C'est vérifié sur un vrai wrap de `cityg-core` : sa version altérée est condamnée, l'originale ne l'est pas.
5. **Ce qui reste :**
   - la branche 2 ;
   - le taux d'échec du déchiffrement pour une clé de norme bornée ;
   - un vrai téléphone ;
   - une relecture humaine.

   Depuis (note [les deux branches](litige-deux-branches-2026-09-27.md)) : la branche 2 est prouvée, en 787 Ko et 3,72 s. Le taux d'échec est calculé, et il corrige la section 1.2 : la borne est désormais posée sur `|s|²` et `|e|²` séparément. La mémoire est mesurée avec le circuit sérialisé.

## 1. L'énoncé, révisé

### 1.1 Trois énoncés

```text
public  : pk_t = (ek, pk_X), ct = (c, ct_X), context, sealed
témoin  : (s, e) et sk_X ; la graine X-Wing n'y est plus
commun  : t = A s + e (mod q), s et e petits, |s|² + |e|² ≤ 2047   (la clé ML-KEM)
          m' = Compress_1(v' − sᵀ u')                                (le déchiffrement)
          (K, r') = G(m' ‖ H(ek))

« le wrap ne s'ouvre pas »
          pk_X = X25519(sk_X, 9), ss_X = X25519(sk_X, ct_X)
          ss = SHA3-256(K ‖ ss_X ‖ ct_X ‖ pk_X ‖ label)
          k, n = ExpandLabel(ss, "wrap key" | "wrap nonce", context)
          révèle P = ChaCha20(k, n, 0)[0..32], la clé Poly1305 du wrap ;
          le vérifieur constate que Poly1305(P, context, sealed) n'est pas l'étiquette de sealed

« le rechiffrement diffère »
          (y, e1, e2) = CBD(PRF(r', 0..6))
          Compress(Aᵀ y + e1, tᵀ y + e2 + 1665 m') diffère de c en un coefficient, que la preuve tait
```

Un troisième énoncé, « la décapsulation entière », sert de repère : c'est le premier, avec en plus le rechiffrement, qui doit redonner `c`. C'est la décapsulation de FIPS 203 quand le rechiffrement réussit.

### 1.2 Pourquoi la graine peut sortir

- **La clé ML-KEM est liée.**
  - Deux clés courtes `(s, e)` et `(s', e')` qui donnent le même `t` diffèrent d'un vecteur court du noyau de `[A | I]`. Le circuit borne chaque coefficient dans `[−4, 3]`, donc la différence dans `[−7, 7]`.
  - Il y a 15^1536 ≈ 2^6001 tels vecteurs. Pour une matrice aléatoire, chacun est dans le noyau avec une probabilité de l'ordre de `q^−768 ≈ 2^−8986`.
  - `A` sort de SHAKE128 : le membre ne peut pas le choisir, et en essayer d'autres ne l'aide pas. La clé est donc unique, sauf avec une probabilité de l'ordre de `2^−2985`.
- **`sk_X` est lié par `pk_X`**, et le contrôle public de la note [litige X25519](litige-x25519-2026-09-26.md) (section 3.3) fixe `ss_X`.
- **Le secret de rejet implicite `z` ne sert plus** : section 1.3.
- **La norme est bornée**, parce qu'un membre choisit sa clé.
  - Sans cette borne, une clé aux coefficients plus grands augmenterait le taux d'échec du déchiffrement. Un échec fait différer le rechiffrement : le membre pourrait alors accuser un committer honnête.
  - Une clé honnête a `|s|² + |e|² ≈ 1536`, avec un écart type de 48 ; la borne 2047 est à plus de dix écarts types.
  - Sous la borne, dans le modèle habituel de l'erreur de déchiffrement, sa variance croît d'au plus 28 %, quand toute la norme va dans `s` : 7 454 au lieu de 5 818.
  - Le taux d'échec honnête de ML-KEM-768 est `2^−164,8` ([FIPS 203](https://csrc.nist.gov/pubs/fips/203/final)). Une estimation gaussienne le portait vers `2^−129` pour la pire clé admise.
  - **Corrigé depuis** (note [les deux branches](litige-deux-branches-2026-09-27.md), section 2). Calculé exactement, comme le font les scripts de Kyber, le taux de la pire clé sous cette borne est `2^−98,9`. L'estimation mettait à l'échelle la variance totale, surtout faite d'un arrondi borné qui ne pèse pas dans la queue. Le circuit borne désormais `|s|²` et `|e|²` par 1 100 chacun : la pire clé admise échoue avec `2^−121,2`.

### 1.3 Pourquoi le rechiffrement sort de l'énoncé courant

- **Sûreté.**
  - Pour un chiffré honnête, le rechiffrement réussit, et `K = G(m' ‖ h)` est le secret de l'encapsulation, sauf échec du déchiffrement.
  - L'énoncé « le wrap ne s'ouvre pas » ne peut donc pas condamner un committer honnête, même sans contrôler le rechiffrement.
- **Complétude.**
  - Si le rechiffrement échoue, FIPS 203 rend le secret de rejet `J(z ‖ c)`. Le wrap peut alors ne pas s'ouvrir pour le membre, tout en s'ouvrant avec `K`.
  - Un committer malveillant y arrive en retouchant un chiffré honnête : un bit de `c2` laisse `m'` intact et fait échouer le rechiffrement.
  - Le membre prouve alors l'autre énoncé, « le rechiffrement diffère ». Il condamne à lui seul, puisque aucun chiffré honnête ne le vérifie, sauf échec du déchiffrement.
- **Ce qui fuit : le choix de l'énoncé**, qui dit si le rechiffrement a réussi.
  - Un adversaire IND-CCA l'apprend déjà de l'oracle de décapsulation.
  - Pour un chiffré qu'il a formé honnêtement, il compare la sortie à `K`. Pour un autre chiffré, le rechiffrement échoue toujours.
- **Ce qui ne doit pas fuir : l'indice du coefficient qui diffère.**
  - Après une retouche, seul le coefficient retouché diffère si `m'` n'a pas changé ; presque tous diffèrent sinon.
  - L'indice dirait donc si le déchiffrement a changé : c'est un oracle de vérification du clair. Sous une forme à plusieurs valeurs, un tel oracle retrouve la clé de Kyber en 78 requêtes et une réduction de réseau de `2^32` opérations ([Shao, Liu et Zhou, 2023](https://eprint.iacr.org/2023/887)).
  - Le circuit choisit le coefficient par un vecteur un-parmi-n secret, et montre qu'il diffère par un inverse.

### 1.4 Le hachage, de 26 permutations à 2

| Permutations Keccak-f | Énoncé d'emp-zk | « le wrap ne s'ouvre pas » | « le rechiffrement diffère » |
| --- | ---: | ---: | ---: |
| Clé depuis la graine | 8 | 0 | 0 |
| `G(m' ‖ h)` | 1 | 1 | 1 |
| `PRF(r', 0..6)`, le bruit du rechiffrement | 7 | 0 | 7 |
| `J(z ‖ c)`, le rejet implicite | 9 | 0 | 0 |
| Le combineur de X-Wing | 1 | 1 | 0 |
| Total | 26 | 2 | 8 |

## 2. La partie réseau, en un point

### 2.1 Le principe

- **Des identités entières.** Les relations de ML-KEM s'écrivent dans le domaine normal, avec `A = NTT⁻¹(Â)` et `t = NTT⁻¹(t̂)` publics. Chacune est une identité entre polynômes de degré au plus 510, à petits coefficients entiers, par exemple `Σⱼ Aᵢⱼ sⱼ + eᵢ − tᵢ = q Qᵢ + (X^256 + 1) Hᵢ`, où `Qᵢ` porte les quotients par `q`.
- **Ce que fournit le prouveur**, pour chaque coefficient : le quotient par `q` (12 bits), et pour une compression le décalage dans son intervalle. Pour chaque relation, il fournit la moitié haute `Hᵢ` du produit, sans borne.
- **Les compressions.**
  - Les entiers `x` tels que `Compress_d(x mod q) = c` forment un intervalle de largeur `w`, qui fait le tour de `q` seulement pour `c = 0`.
  - Le décalage tient en `m` bits, dont le plus fort pèse `w − 2^(m−1)` : 2 bits pour `Compress_10`, 8 pour `Compress_4`, 11 pour `Compress_1`.
- **Le point.**
  - Le circuit vérifie chaque identité en un point `ρ` que le vérifieur tire du transcript après l'engagement Ligero du témoin.
  - Longfellow le permet : sa présentation mdoc tire ainsi la clé de son MAC. Les évaluations publiques (`Aᵢⱼ(ρ)`, `tᵢ(ρ)`, les intervalles) deviennent des entrées publiques.
- **Pourquoi c'est sain.**
  - Une identité fausse passe en un point aléatoire avec probabilité au plus `510/p ≈ 2^−246`.
  - Hors de `H`, tous les coefficients sont bornés par leurs bits, sous `2^25`, et `X^256 + 1` est unitaire. Une identité dans `F_p[X]` en est donc une dans `Z[X]` : `H` est la vraie moitié haute, et la relation tient modulo `q`.

### 2.2 Le coût

| Partie réseau | Termes | Entrées | Preuve seule |
| --- | ---: | ---: | ---: |
| Produits négacycliques denses de toutes les relations, estimés à la note précédente | ~1 570 000 | | |
| Clé et déchiffrement, en un point | 108 916 | 28 442 | 332 588 o |
| Clé, déchiffrement et rechiffrement égal au chiffré, en un point | 184 232 | 46 362 | 411 948 o |

- Pour les mêmes relations, les termes baissent d'un facteur 8 à 9. Les quotients dominent désormais : 12 bits par coefficient, soit 12 288 bits pour la clé et le déchiffrement.
- Les entrées comptent les 7 168 bits de PRF de ce banc d'essai, qui dans le litige viennent de Keccak.

## 3. Le hachage et la fin de l'énoncé, dans le même corps

- **Un seul corps.**
  - La note précédente prouvait Keccak dans GF(2^128), où le ou exclusif est gratuit.
  - Mais lier les deux corps coûte environ 1 500 termes par bit, avec un MAC comme celui de la présentation mdoc de Longfellow.
  - Tout est donc dans `F_{2^255−19}`, où le ou exclusif coûte une multiplication.
- **Keccak-f dans `F_{2^255−19}`** : 532 756 termes et 8 001 entrées par permutation. Elle se prouve en 347 ms et se vérifie en 200 ms, pour une preuve de 290 668 o. La profondeur est de 38 couches, avec l'état tous les 6 tours comme témoin.
- **`ExpandLabel` et ChaCha20.**
  - Chaque addition modulo `2^32` prend en témoin les 32 bits de la somme et sa retenue. La somme des mots empaquetés est linéaire dans `F_p`.
  - BLAKE3 et ChaCha20 sont écrits une fois, sur deux moteurs : l'un calcule en clair et enregistre le témoin, l'autre le vérifie dans le circuit.
  - Les mots que seuls des ou exclusifs changent (`b` et `d`) sont pris en témoin après chaque tour. Sans cela, la profondeur passe de 38 à 60, et les copies entre couches ajoutent 0,84 million de termes.
  - Leur coût, mesuré en retirant cette fin de l'énoncé : 50 312 éléments de témoin et 550 447 termes.
- **La clé Poly1305 révélée, pas le secret.** Révéler `ss` ferait du membre un oracle de décapsulation : un serveur qui recopie le `ct` d'un wrap honnête dans un faux wrap obtiendrait le secret du wrap honnête. La clé Poly1305 ne dit rien du flot qui chiffre le secret.

## 4. Les mesures

### 4.1 Les trois énoncés

Rate 1/7 et 132 requêtes, environ 109 bits de sécurité statistique selon Longfellow. Temps moyens de trois exécutions, sur un cœur :

| Énoncé | Keccak-f | Entrées (publiques) | Termes | Preuve | Prouveur | Vérifieur |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Le wrap ne s'ouvre pas | 2 | 87 844 (1 181) | 1 716 241 | 586 284 o | 1,49 s | 0,97 s |
| Le rechiffrement diffère | 8 | 100 398 (1 555) | 4 161 071 | 629 324 o | 2,56 s | 1,55 s |
| La décapsulation entière (repère) | 9 | 150 564 (2 209) | 5 227 015 | 753 836 o | 3,39 s | 2,01 s |

Depuis (note [les deux branches](litige-deux-branches-2026-09-27.md), section 1.3) : avec la seconde borne de norme, chaque énoncé gagne 11 entrées et 47 termes, et les temps restent dans le bruit de ceux-ci. La branche 2 s'y ajoute.

- **Le témoin se calcule en 2 ms.**
- **Ce qui coûte, pour le premier énoncé.**
  - Chez le prouveur, l'engagement Ligero prend 0,73 s, le sumcheck 0,55 s, la preuve Ligero 0,14 s.
  - Chez le vérifieur, le sumcheck prend 0,3 s et Ligero 0,66 s environ.
  - Ligero est en `F_{2^255−19}`, sans racine de l'unité, donc par convolution CRT. Son coût suit la taille du témoin.
  - Allonger ou raccourcir les lignes de Ligero ne l'aide pas. De 4 096 à 32 768 éléments par ligne, le vérifieur prend de 0,92 à 1,16 s. La preuve est la plus petite avec le défaut, 16 384, et atteint 1,3 Mo avec 4 096.
- **La mémoire.**
  - Le circuit ne dépend pas du litige : il se compile une fois, en 2,5 s et 419 Mo pour le premier énoncé, et se livre sérialisé, comme les circuits mdoc de Longfellow.
  - Circuit chargé, le prouveur culmine à 315 Mo et le vérifieur à 289 Mo.
  - Pour les deux autres énoncés, il faut 585 à 740 Mo.
  - **Corrigé depuis** (note [les deux branches](litige-deux-branches-2026-09-27.md), section 4) : ces pics comptaient le tas que le compilateur laisse au processus. Chargé sérialisé par un processus neuf, le circuit du premier énoncé occupe 20 Mo, et son prouveur culmine à 104 Mo.
- **Sur un téléphone.** Par l'étalonnage de la note précédente, ces temps sont proches de ceux d'un Pixel 9, et environ 0,6 fois ceux-là sur un iPhone 15 Plus. Sur la 4G émulée, 573 Ko montent en 0,47 s, plus un aller-retour.

### 4.2 Les voies comparées

| | Avec VOLE (emp-zk et Diet Mac'n'Cheese) | Longfellow, deux corps (note précédente) | Longfellow, un corps (cette note) |
| --- | --- | --- | --- |
| Énoncé | Complet : 26 Keccak-f, le réseau, X25519, BLAKE3 et ChaCha20 | X25519 et le hachage, sans le réseau ni le lien entre les corps | Complet pour la branche 1, avec 2 Keccak-f |
| Octets | 25 Mo | 158 + 552 Ko | 573 Ko |
| Temps | 4 s en local, 23 s sur la 4G émulée | 0,76 s à prouver, 0,32 s à vérifier | 1,49 s à prouver, 0,97 s à vérifier, et 0,47 s d'envoi sur la 4G émulée |
| Échanges | Près de 190 vols | Deux messages | Un message |
| Qui vérifie | Le serveur seul | Tout le monde | Tout le monde |

## 5. Les vérifications

- **La référence X-Wing** concorde avec les trois vecteurs du brouillon X-Wing livrés avec la crate `x-wing` : clé publique et chiffré par leur empreinte SHA3-256, et secret partagé.
- **Le wrap** concorde avec un wrap produit par `cityg-core` ([`wrap_vector.rs`](bench/src/bin/wrap_vector.rs)) : contexte, entrée d'`ExpandLabel`, clé, nonce et `sealed`. Le scellement est refait par OpenSSL, et la clé Poly1305 comparée au flot ChaCha20 d'OpenSSL.
- **La partie réseau, évaluée en clair.**
  - Elle accepte les témoins honnêtes de six instances en des points aléatoires.
  - Elle rejette un bit de `s`, de la marge de la norme, d'un quotient, de `m'`, d'un décalage ou de la sortie PRF, une moitié haute décalée de 1, et un autre chiffré.
  - Un chiffré retouché passe l'énoncé « le rechiffrement diffère ». Il échoue si le coefficient choisi concorde, ou contre le chiffré honnête.
- **Le litige entier.**
  - Chaque preuve se vérifie, et échoue contre l'énoncé d'une autre instance.
  - Un bit faux dans `sk_X`, dans l'état final de `G` ou du combineur, dans `s` ou dans une retenue de ChaCha20 ne donne aucune preuve.
  - Le wrap de `cityg-core` altéré d'un bit est condamné par l'étiquette que calcule le vérifieur ; l'original ne l'est pas.

## 6. Ce qui reste

- **La branche 2**, « le wrap s'ouvre sur un mauvais secret ». Faite depuis (note [les deux branches](litige-deux-branches-2026-09-27.md)), sans Poly1305.
  - Il faut ouvrir le wrap dans le circuit : Poly1305 modulo `2^130 − 5`, et un bloc de ChaCha20 de plus.
  - Il faut aussi dériver la clé de nœud du secret : `ExpandLabel`, puis une génération X-Wing. Celle-ci coûte une permutation SHAKE256, `G`, six PRF, le produit par la matrice publique de `pk_v` quand son `ρ` concorde, et une échelle X25519.
  - Ce serait de l'ordre de la décapsulation entière, soit 4 à 5 millions de termes.
- **Le taux d'échec du déchiffrement** pour la pire clé de norme bornée, calculé exactement. Fait depuis : `2^−98,9` sous cette borne, `2^−121,2` sous les deux bornes qui la remplacent.
- **Un vrai téléphone**, avec le circuit sérialisé.
- **Le contrôle public de `ct_X`**, codé chez le vérifieur. Il est décrit, pas écrit. Codé depuis, avec celui de `pk_v`.
- **Des leviers.**
  - Longfellow tourne ici sur un cœur.
  - Un partage en deux corps reste à chiffrer : Keccak, `ExpandLabel` et ChaCha20 dans GF(2^128), liés par MAC à `m'` et `ss_X`, soit 511 bits.
- **Une relecture cryptographique humaine**, en particulier de la section 1.

## 7. Où en est le problème 2

| Problème | État | Ce qui reste |
| --- | --- | --- |
| 2. Preuves de litige | L'énoncé entier de la branche 1, sans mise en place : 573 Ko, 1,49 s pour prouver, 0,97 s pour vérifier, sur une machine au rythme d'un Pixel 9. Le chiffré invalide se condamne à part, en 615 Ko. | La branche 2 ; le taux d'échec sous la borne de norme ; un vrai téléphone ; une relecture |

Depuis (note [les deux branches](litige-deux-branches-2026-09-27.md)) : la branche 2 tient en 787 Ko et 3,72 s, le taux d'échec est calculé, et le prouveur tient en 104 à 251 Mo avec le circuit sérialisé. Restent un vrai téléphone, une branche 2 allégée pour le cas courant, et une relecture.

L'ordre des problèmes ouverts ne change pas :
1. la preuve de l'arbre ;
2. le litige ;
3. la spécification du profil candidat.

## 8. Reproduire

- **Construire** Longfellow avec le correctif et le répertoire [`dispute-zk/longfellow/`](dispute-zk/longfellow/), comme l'indique [`dispute-zk/README.md`](dispute-zk/README.md), cible `dispute_test`.
- **Les tests** : `dispute_test` vérifie les références, la partie réseau, les trois énoncés et le wrap altéré, et imprime la taille de chaque circuit et de chaque preuve.
- **Les temps** : `dispute_test --gtest_filter=-* --benchmark_filter=BM_Dispute`.
- **Les longueurs de ligne et la mémoire** : `DISPUTE_MODE=0 dispute_test --gtest_also_run_disabled_tests --gtest_filter='Dispute.DISABLED_*'`.
- **Le vecteur de wrap** : `cargo run --release --manifest-path docs/research/bench/Cargo.toml --bin wrap_vector`.

## 9. Sources

* NIST, [FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final), 2024 ; R. Avanzi et al., [CRYSTALS-Kyber, spécification du 3e tour](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210131.pdf), 2021, table 1 : taux d'échec `2^−164` pour Kyber768.
* M. Barbosa et al., [X-Wing: The Hybrid KEM You've Been Looking For](https://eprint.iacr.org/2024/039), 2024 ; le [brouillon X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) à l'IETF.
* D. Hofheinz, K. Hövelmanns, E. Kiltz, [A Modular Analysis of the Fujisaki-Okamoto Transformation](https://eprint.iacr.org/2017/604), TCC 2017.
* M. Shao, Y. Liu, Y. Zhou, [Pairwise and Parallel: Enhancing the Key Mismatch Attacks on Kyber and Beyond](https://eprint.iacr.org/2023/887), 2023.
* M. Frigo, a. shelat, [Anonymous credentials from ECDSA](https://eprint.iacr.org/2024/2010), 2024 ; la bibliothèque [longfellow-zk](https://github.com/google/longfellow-zk).
* S. Ames, C. Hazay, Y. Ishai, M. Venkitasubramaniam, [Ligero: Lightweight Sublinear Arguments Without a Trusted Setup](https://eprint.iacr.org/2022/1608), CCS 2017.
* J. O'Connor et al., [la spécification de BLAKE3](https://github.com/BLAKE3-team/BLAKE3-specs) ; Y. Nir, A. Langley, [RFC 8439 : ChaCha20 and Poly1305 for IETF Protocols](https://www.rfc-editor.org/rfc/rfc8439), 2018.
* Notes précédentes : [litige sans mise en place](litige-sans-mise-en-place-2026-09-26.md), [litige X25519](litige-x25519-2026-09-26.md), [preuves et mesures](preuves-et-mesures-2026-09-26.md), [problèmes ouverts](problemes-ouverts-2026-09-26.md).
