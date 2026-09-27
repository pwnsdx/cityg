# Les deux branches du litige

| | |
| --- | --- |
| Date | 2026-09-27 |
| Nature | Note de recherche. Elle poursuit la note [litige entier](litige-entier-2026-09-26.md). Elle prouve la branche 2 du litige, « le wrap s'ouvre sur un mauvais secret », avec un énoncé court pour le cas courant. Elle calcule exactement le taux d'échec du déchiffrement sous la borne de norme, et corrige l'estimation de la note précédente. Elle code les contrôles publics du vérifieur, et mesure la mémoire avec le circuit sérialisé. Rien de tout cela ne fait partie du profil `city-g/v0.4`. |
| Question | Que coûte la branche 2, et que vaut la borne de norme ? |
| Compagnons | [`dispute-zk/longfellow/`](dispute-zk/longfellow/) : les circuits, témoins, tests et bancs d'essai des cinq énoncés, et le contrôle public de `ct_X` ([`x25519_check.h`](dispute-zk/longfellow/x25519_check.h)). [`dispute-zk/decryption_failure.py`](dispute-zk/decryption_failure.py) : le taux d'échec exact. [`bench/src/bin/wrap_vector.rs`](bench/src/bin/wrap_vector.rs) : un wrap de `cityg-core` et la clé de nœud de son secret. |
| Auteur | Claude Code (assistant IA d'Anthropic), à la demande du mainteneur. Les mesures viennent de la machine virtuelle des notes précédentes (4 vCPU, Intel Xeon à 2,10 GHz). Ce jour-là, elle fait tourner le banc ECDSA de Longfellow en 55 et 34 ms, contre 53,3 et 33,5 ms sur Pixel 9. Aucun téléphone n'a été mesuré. Une relecture cryptographique humaine reste nécessaire. |

## 0. Résumé

1. **La branche 2 tient en 787 Ko.**
   - Son énoncé : « le wrap s'ouvre sur un secret dont la clé de nœud n'est pas `pk_v` ». La preuve se calcule en 3,72 s et se vérifie en 2,26 s, sur une machine au rythme d'un Pixel 9.
   - Le circuit ouvre le secret scellé avec le deuxième bloc de ChaCha20, puis dérive sa clé de nœud : `ExpandLabel`, SHAKE256, `G`, six PRF, une identité de réseau avec la matrice publique de `pk_v`, une échelle X25519. Il montre enfin que cette clé diffère de `pk_v`, à une place qu'il tait.
   - Il ne vérifie pas l'étiquette et ne révèle pas la clé Poly1305 : si l'étiquette est fausse, le wrap ne s'ouvre pas, et c'est la branche 1. L'énoncé condamne dans les deux cas.
   - Sur un wrap de `cityg-core`, le témoin retrouve la clé de nœud que calcule `cityg-core`. Si `pk_v` est faux dans sa graine, dans `t` ou dans `pk_X`, le committer est condamné ; avec le vrai `pk_v`, il ne l'est pas.
   - Dans le cas courant, où le committer a scellé un autre secret que celui de `pk_v`, un énoncé court suffit : 635 Ko, et un peu plus de la moitié du temps de l'énoncé complet.
2. **La borne de norme était trop lâche.**
   - Calculé exactement, comme le font les scripts de Kyber, le taux d'échec de la pire clé sous `|s|² + |e|² ≤ 2047` est `2^−98,9`, et non `2^−129` comme l'estimait la note précédente.
   - Le circuit borne désormais `|s|²` et `|e|²` séparément, par 1 100 chacun. La pire clé admise échoue alors avec une probabilité `2^−121,2` par chiffré, et une clé honnête sort de la borne avec une probabilité `2^−62,9`.
3. **La mémoire était surestimée.**
   - Sérialisé, le circuit pèse de 563 Ko à 1,44 Mo une fois compressé. Chargé par un processus qui ne l'a pas compilé, il occupe de 20 à 41 Mo.
   - Le prouveur culmine alors à 104 Mo pour la branche 1 et à 251 Mo pour la branche 2, 143 Mo avec l'énoncé court. La note précédente comptait de 315 à 740 Mo, en y incluant le tas que le compilateur laisse au processus.
4. **Les contrôles publics sont codés.** Le vérifieur contrôle que `ct_X` est dans le sous-groupe d'ordre premier et que `pk_v` est encodé canoniquement. Sinon, il condamne sans preuve.
5. **Ce qui reste :**
   - un vrai téléphone ;
   - une relecture humaine.

## 1. La branche 2

### 1.1 L'énoncé

La note [problèmes ouverts](problemes-ouverts-2026-09-26.md) (section 2.1) pose la branche 2 : le wrap s'ouvre et rend `s`, mais `KemKey(s, "tree node key").pk ≠ pk_v`. Dans `cityg-core`, cette clé est `X-Wing.KeyGen(ExpandLabel(s, "tree node key", [], 32))`.

```text
public  : pk_t = (ek, pk_X), ct = (c, ct_X), context, sealed[0..32],
          pk_v = (t̂_v, ρ_v, pk_X,v), la clé que le committer a publiée pour v
témoin  : (s, e) et sk_X, comme pour la branche 1
commun  : comme la branche 1 jusqu'à k, n = ExpandLabel(ss, "wrap key" | "wrap nonce", context)

« le wrap s'ouvre sur un mauvais secret »
          s_w = sealed[0..32] ⊕ ChaCha20(k, n, 1)[0..32]            (le secret scellé)
          graine = ExpandLabel(s_w, "tree node key", [], 32)
          d ‖ z ‖ sk_X' = SHAKE256(graine, 96)
          ρ' ‖ σ' = G(d ‖ 3) ; s' = CBD(PRF(σ', 0..2)), e' = CBD(PRF(σ', 3..5))
          t' = A_v s' + e' (mod q), avec A_v = NTT⁻¹(Expand(ρ_v)) public
          pk_X' = X25519(sk_X', 9)
          (ρ', t', pk_X') ≠ (ρ_v, NTT⁻¹(t̂_v), pk_X,v), en une place que la preuve tait
```

### 1.2 Pourquoi c'est sain

- **L'étiquette n'est pas vérifiée.**
  - Si l'étiquette de `sealed` est bonne, le wrap s'ouvre sur `s_w` : c'est la branche 2. Sinon, il ne s'ouvre pas : c'est la branche 1. Dans les deux cas, le committer est en faute.
  - L'énoncé n'a donc pas besoin de la clé Poly1305, ni de la révéler : le circuit calcule le bloc 1 de ChaCha20, et non le bloc 0.
  - Pour un committer honnête, le wrap s'ouvre sur le secret dont la clé de nœud est `pk_v`, et l'énoncé est faux. Seul un échec du déchiffrement le rendrait vrai, comme pour la branche 1 (section 2).
- **La matrice de `pk_v` suffit.**
  - Le circuit ne dérive pas la matrice `A' = Expand(ρ')` de la clé du secret : son échantillonnage par rejet coûte 27 permutations SHAKE128 en moyenne (note [problèmes ouverts](problemes-ouverts-2026-09-26.md), section 2.2).
  - Il prend `A_v`, que le vérifieur dérive de `ρ_v`, et prouve l'identité `t' = A_v s' + e'` en un point tiré après l'engagement, comme les autres identités de réseau.
  - Si `ρ' ≠ ρ_v`, les deux clés diffèrent déjà par `ρ`, quel que soit le `t'` obtenu. Si `ρ' = ρ_v`, `A_v` est la matrice de la clé du secret, et `t'` est son vrai `t`. Une différence prouvée est donc toujours une vraie différence.
- **La place qui diffère reste cachée.**
  - La révéler dirait quelque chose de la clé d'un secret que le vérifieur ne doit pas connaître.
  - Le circuit la choisit donc par un vecteur un-parmi-1 025 secret : 256 bits de `ρ`, 768 coefficients de `t`, puis `pk_X`. Il montre que la différence à cette place a un inverse, pour environ 2 000 multiplications.
- **Le vérifieur contrôle `pk_v`.**
  - Les coefficients de `t̂_v` doivent être sous `q`, comme le contrôle de module de FIPS 203, et `pk_X,v` sous `2^255 − 19`.
  - Aucune génération de clé ne donne un autre encodage : un `pk_v` qui échoue à ce contrôle condamne le committer sans preuve.
  - Pour un `pk_v` canonique, comparer `t'` à `NTT⁻¹(t̂_v)` revient à comparer les encodages, car la NTT est une bijection de `Z_q^256`.
- **Le transcript absorbe tout l'énoncé**, y compris `sealed` et `pk_v`, avant de tirer le point : `A_v` entre dans une identité vérifiée en ce point. Le banc d'essai hache `pk_t`, `ct`, `context`, `sealed` et `pk_v`.

### 1.3 Son coût

| Permutations Keccak-f | Énoncé d'emp-zk, branche 2 | Branche 1 | Branche 2 |
| --- | ---: | ---: | ---: |
| Clé du membre depuis sa graine | 8 | 0 | 0 |
| `G(m' ‖ h)` | 1 | 1 | 1 |
| Rechiffrement et rejet implicite | 16 | 0 | 0 |
| Le combineur de X-Wing | 1 | 1 | 1 |
| Clé de nœud : `SHAKE256(graine)`, `G(d ‖ 3)`, six PRF | 8 | 0 | 8 |
| Total | 34 | 2 | 10 |

- **Le reste de l'énoncé.** Cinq compressions BLAKE3 au lieu de quatre, un bloc ChaCha20, et une troisième échelle X25519. Poly1305 n'y entre pas, alors que la note [problèmes ouverts](problemes-ouverts-2026-09-26.md) le comptait.
- **Les quatre énoncés**, avec Longfellow et les paramètres des notes précédentes : rate 1/7, 132 requêtes, environ 109 bits de sécurité statistique. Temps moyens de trois exécutions, sur un cœur :

| Énoncé | Keccak-f | Échelles X25519 | Entrées (publiques) | Termes | Preuve | Prouveur | Vérifieur |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Branche 1 : le wrap ne s'ouvre pas | 2 | 2 | 87 855 (1 181) | 1 716 288 | 587 116 o | 1,41 s | 0,99 s |
| Branche 2 : il s'ouvre sur un mauvais secret | 10 | 3 | 171 133 (2 463) | 5 922 950 | 805 484 o | 3,72 s | 2,26 s |
| Le rechiffrement diffère | 8 | 0 | 100 409 (1 555) | 4 161 118 | 628 908 o | 2,53 s | 1,52 s |
| La décapsulation entière (repère) | 9 | 2 | 150 575 (2 209) | 5 227 062 | 753 292 o | 3,23 s | 1,98 s |

- **Keccak fait environ 90 % des termes de la branche 2.**
  - Une permutation seule en compte 532 756 ; la branche 2 en ajoute 4,21 millions à la branche 1.
  - La note précédente l'estimait à 4 à 5 millions de termes ; il y en a 5,9 millions.
- **La preuve ne croît que de 37 %** par rapport à la branche 1, quand les termes triplent : la taille de Ligero croît moins vite que le témoin. Sur la 4G émulée des notes précédentes, 10 Mbit/s en montée, 787 Ko montent en 0,64 s.
- **Le témoin se calcule en 3,3 ms**, contre 1,9 ms pour la branche 1.
- **Les trois autres énoncés** gagnent 11 entrées et 47 termes, pour la seconde borne de norme (section 2). Leurs temps restent dans le bruit de ceux de la note précédente.

### 1.4 L'énoncé court, pour le cas courant

- **Le cas courant.**
  - Un committer qui scelle un autre secret que celui de `pk_v` donne une clé `pk'` dont la graine de matrice `ρ'` diffère de `ρ_v`, sauf avec une probabilité `2^−256`.
  - Un `pk_v` forgé à partir de la bonne clé, mais avec une autre clé X25519, donne `pk_X' ≠ pk_X,v`.
- **Ce qu'il garde et ce qu'il laisse.**
  - L'énoncé court s'arrête à `G(d ‖ 3)` et à l'échelle de `pk_X'`. Sa sélection cachée porte sur 257 places : les 256 bits de `ρ'`, puis `pk_X'`.
  - Il laisse les six PRF, l'identité `t' = A_v s' + e'`, les 768 coefficients de `t_v` et les neuf évaluations de `A_v`.
  - L'échelle ne coûte qu'environ 18 000 termes : la moitié X25519 du litige, qui en a deux, en compte 35 511. La garder couvre le second cas pour presque rien.
- **Ce qu'il dit de plus** : que les clés diffèrent en `ρ` ou en `pk_X`. `pk'` est la clé publique qu'un committer honnête aurait publiée ; ce qu'on en apprend ne touche pas au secret.
- **Quel énoncé prouver.** Le membre calcule tout en clair, puis prouve le premier cas qui s'applique :
  1. le rechiffrement échoue : « le rechiffrement diffère » ;
  2. l'étiquette est fausse : la branche 1 ;
  3. `ρ'` ou `pk_X'` diffère de `pk_v` : la branche 2 courte ;
  4. `t'` diffère : la branche 2 complète.

  Sinon, le wrap est bon.
- **Son coût**, mesuré dans une même session contre l'énoncé complet. Dans cette session, la machine fait tourner le banc ECDSA de Longfellow en 52,4 et 31,5 ms, un peu plus vite que pour la section 1.3 (55 et 34 ms) :

| Énoncé | Keccak-f | Entrées (publiques) | Termes | Preuve | Prouveur | Vérifieur |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Branche 2 complète | 10 | 171 133 (2 463) | 5 922 950 | 805 484 o | 3,46 s | 2,08 s |
| Branche 2 courte | 4 | 111 991 (1 686) | 2 873 383 | 650 444 o | 1,86 s | 1,19 s |

- **Moitié moins de termes, 54 % du temps à prouver, 57 % à vérifier.** La preuve de 635 Ko monte en 0,52 s sur la 4G émulée.
- **Le témoin se calcule en 2,4 ms**, contre 3,1 ms pour l'énoncé complet dans la même session.

## 2. Le taux d'échec du déchiffrement, calculé

### 2.1 La méthode

- **Le modèle** est celui des scripts de l'équipe Kyber ([security-estimates](https://github.com/pq-crystals/security-estimates)).
  - Pour un coefficient du message, l'erreur de déchiffrement est `eᵀ r + e2 + Δv − sᵀ (e1 + Δu)`.
  - `r`, `e1` et `e2` suivent CBD_2. `Δu` et `Δv` sont les erreurs d'arrondi de `Compress_10` et `Compress_4` d'une valeur uniforme. Tout est indépendant.
  - Un coefficient échoue au-delà de `q/4` en valeur absolue ; un chiffré échoue si l'un de ses 256 coefficients échoue, par la borne de l'union.
- **Pour une clé fixée**, la loi d'un coefficient ne dépend que du nombre de coefficients de `s`, et de `e`, de chaque valeur absolue.
- **Le calcul.**
  - [`decryption_failure.py`](dispute-zk/decryption_failure.py) convole les lois exactes en flottants, directement et non par FFT, pour garder la précision des queues.
  - Il garde la fenêtre `[−3000, 3000]`. La masse qui en sort compte comme un échec : chaque taux est un majorant.
  - Il cherche la pire clé par descente locale, depuis des clés qui dépensent toute la borne.
- **Le contrôle.** Pour les clés honnêtes en moyenne, le script trouve `2^−165,2`, contre `2^−164,8` dans FIPS 203. Une clé honnête typique (384 coefficients ±1 et 96 de ±2 dans `s` comme dans `e`, norme 1 536) échoue avec `2^−175,0`.

### 2.2 Les résultats

| Borne | Une clé honnête la dépasse | Pire clé admise | Son taux d'échec |
| --- | ---: | --- | ---: |
| `\|s\|² + \|e\|² ≤ 2047` (note précédente) | `2^−77,0` | `s` : 339 coefficients ±1 et 427 de ±2 ; `e = 0` | `2^−98,9` |
| `\|s\|² ≤ 1024` et `\|e\|² ≤ 1024` | `2^−39,6` | 680 de ±1 et 86 de ±2, dans `s` comme dans `e` | `2^−130,3` |
| `\|s\|² ≤ 1100` et `\|e\|² ≤ 1100` (le circuit) | `2^−62,9` | 656 de ±1 et 111 de ±2, dans `s` comme dans `e` | `2^−121,2` |
| Coefficients dans `[−4, 3]`, sans borne | 0 | tous à −4 | `2^−7,3` |

- **Pourquoi l'estimation se trompait.**
  - La note précédente mettait à l'échelle l'exposant du taux honnête par la variance totale de l'erreur, qui ne croît que de 28 %.
  - Mais cette variance est surtout celle de `Δv`, bornée, qui ne fait pas la queue. La partie `sᵀ (e1 + Δu)` la fait : pour la pire clé, son écart type croît de 63 %.
- **Pourquoi deux bornes.**
  - `s` multiplie `e1 + Δu`, de variance 1,92, quand `e` multiplie `r`, de variance 1. La pire clé met donc toute la norme dans `s`.
  - Une borne par partie l'en empêche. À 1 100, elle laisse `2^−62,9` de chances qu'une clé honnête la dépasse : le membre ne pourrait alors pas prouver de litige avec cette clé.
- **Ce que vaut `2^−121,2`.**
  - Le membre choisit sa clé, pas les chiffrés : le committer encapsule avec un aléa frais.
  - Sur `2^40` chiffrés vers une même clé, la chance d'un seul échec reste sous `2^−81`. Un échec permettrait au membre de condamner un committer honnête, par l'une ou l'autre branche.
- **L'unicité de la clé tient toujours** : elle ne dépend que de l'intervalle `[−4, 3]` des coefficients (note [litige entier](litige-entier-2026-09-26.md), section 1.2).
- **Le coût** : une marge de 11 bits de plus, soit 11 entrées et 47 termes.

## 3. Les contrôles publics

- **`ct_X`** ([`x25519_check.h`](dispute-zk/longfellow/x25519_check.h)).
  - Le vérifieur demande un encodage canonique (sous `2^255 − 19`) et `u ≠ 0`.
  - Puis il lance l'échelle de RFC 7748 avec le scalaire `ℓ`, l'ordre du sous-groupe premier, sans le brider. Elle finit sur `z = 0` exactement quand `ℓ P = O`.
  - Tout autre `ct_X` condamne le committer sans preuve (note [litige X25519](litige-x25519-2026-09-26.md), section 3.3).
  - Testé : vingt `ct_X` honnêtes calculés par OpenSSL passent. Les points d'ordre 2, 4 et 8, un point d'ordre mixte, un point de la tordue et un encodage non canonique échouent.
- **`pk_v`**, pour la branche 2 : coefficients de `t̂_v` sous `q`, et `pk_X,v` sous `2^255 − 19` (section 1.2).
- **Leur coût** : une échelle de 255 pas et un réencodage, calculés par le vérifieur, hors de la preuve.

## 4. La mémoire, circuit sérialisé

Le circuit ne dépend pas du litige : il se compile une fois, chez qui construit l'application, et se livre sérialisé, comme les circuits mdoc de Longfellow. Le test `Dispute.DISABLED_Serialized` écrit chaque circuit avec `CircuitWriter`, compressé par zstd au niveau 16 comme les circuits mdoc. Un second processus le lit, le décompresse, vérifie son identifiant, puis prouve et vérifie.

| Énoncé | Circuit sérialisé | Compressé | Chargement | Circuit chargé | Prouveur | Vérifieur |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Branche 1 | 20 605 926 o | 576 978 o | 0,21 s | 20 Mo | 104 Mo | 50 Mo |
| Branche 2 | 71 086 190 o | 1 506 552 o | 0,72 s | 41 Mo | 251 Mo | 90 Mo |
| Branche 2 courte | 34 491 354 o | 873 600 o | 0,34 s | 26 Mo | 143 Mo | 70 Mo |
| Le rechiffrement diffère | 49 936 046 o | 1 001 097 o | 0,52 s | 32 Mo | 172 Mo | 57 Mo |
| La décapsulation entière | 62 735 246 o | 1 337 812 o | 0,64 s | 38 Mo | 228 Mo | 119 Mo |

- **Les colonnes.** « Circuit chargé » est la mémoire résidente après chargement et calcul du témoin. Prouveur et vérifieur sont des pics, mesurés chacun depuis son début. Le chargement monte brièvement à 38 Mo pour la branche 1 et à 107 Mo pour la branche 2.
- **La correction.**
  - La note précédente mesurait dans le processus qui venait de compiler le circuit. Son tas restait au processus, d'où 315 Mo pour le prouveur de la branche 1, et 585 à 740 Mo pour les autres énoncés.
  - La compilation elle-même culmine à 420 Mo pour la branche 1, à 685 Mo pour la branche 2 courte et à 1 360 Mo pour la complète.
- **Pour un téléphone**, il faudrait donc de l'ordre de 100 à 250 Mo. Les quatre circuits qu'un membre peut avoir à prouver pèsent 3,8 Mo compressés, livrés avec l'application.

## 5. Les vérifications

- **La branche 2 sur le wrap de `cityg-core`.**
  - Le témoin ouvre le secret du vecteur, et la clé de nœud qu'il en dérive concorde avec celle de `cityg-core` : début de `t`, `ρ` et `pk_X`, que [`wrap_vector.rs`](bench/src/bin/wrap_vector.rs) imprime désormais.
  - Un `pk_v` pris d'un autre secret, ou faux d'un coefficient de `t̂`, ou faux dans `pk_X`, donne une preuve qui se vérifie. La place choisie tombe dans la bonne partie : `ρ`, `t` ou `pk_X`.
  - Le vrai `pk_v` n'a pas de témoin. Forcée sur une place où les clés concordent, la preuve échoue.
  - Un `pk_v` non canonique est rejeté avant toute preuve.
  - L'énoncé court condamne un `pk_v` faux dans sa graine ou dans `pk_X`, à une place dans la bonne partie. Faux dans `t` seulement, il n'a pas de témoin : l'énoncé complet est nécessaire.
- **Chaque énoncé** se prouve, se vérifie, et échoue contre l'énoncé d'une autre instance.
- **Les vérifications de la note précédente** passent toujours : références X-Wing et `cityg-core`, partie réseau en clair, témoins faux, wrap altéré.

## 6. Ce qui reste

- **Un vrai téléphone.** Les circuits se chargent désormais en 0,2 à 0,7 s, et le prouveur tient en 104 à 251 Mo : c'est à mesurer sur un appareil.
- **La branche 2 allégée pour le cas courant** est faite (section 1.4) : 2,9 millions de termes au lieu de 5,9.
- **Des leviers.**
  - Longfellow n'a pas de parallélisme : il tourne ici sur un cœur. L'engagement Ligero, près de la moitié du temps du prouveur de la branche 1, encode pourtant ses lignes indépendamment les unes des autres.
  - Le partage en deux corps reste à chiffrer pour la branche 1, et ne paierait pas pour la branche 2. Les 6 144 bits de PRF de la clé de nœud devraient y passer au réseau : à environ 1 500 termes par bit, ce lien coûterait plus que Keccak.
- **Une relecture cryptographique humaine**, en particulier des sections 1.2 et 2.

## 7. Où en est le problème 2

| Problème | État | Ce qui reste |
| --- | --- | --- |
| 2. Preuves de litige | Les deux branches, sans mise en place, dans un seul corps. Branche 1 : 573 Ko, 1,41 s pour prouver, 0,99 s pour vérifier. Branche 2 : 787 Ko, 3,72 s et 2,26 s, et, dans le cas courant, 635 Ko et un peu plus de la moitié du temps. Temps d'une machine au rythme d'un Pixel 9 ; prouveur en 104 à 251 Mo avec le circuit sérialisé. Le chiffré invalide se condamne à part, en 614 Ko. Le taux d'échec de la pire clé admise est de `2^−121,2`. | Un vrai téléphone ; une relecture |

L'ordre des problèmes ouverts ne change pas :
1. la preuve de l'arbre ;
2. le litige ;
3. la spécification du profil candidat.

## 8. Reproduire

- **Construire** Longfellow avec le correctif et le répertoire [`dispute-zk/longfellow/`](dispute-zk/longfellow/), comme l'indique [`dispute-zk/README.md`](dispute-zk/README.md), cible `dispute_test`.
- **Les tests** : `dispute_test` vérifie les références, la partie réseau, les cinq énoncés, le wrap altéré et chaque place de la branche 2.
- **Les temps** : `dispute_test --gtest_filter=-* --benchmark_filter=BM_Dispute`. Les arguments 0 à 4 sont la branche 1, la décapsulation entière, le rechiffrement qui diffère, la branche 2 et sa version courte.
- **La mémoire** : `DISPUTE_STATEMENT=3 DISPUTE_CIRCUIT=/tmp/branche2.zst dispute_test --gtest_also_run_disabled_tests --gtest_filter=Dispute.DISABLED_Serialized`, deux fois. La première écrit le circuit, la seconde le charge et mesure.
- **Le taux d'échec** : `python3 docs/research/dispute-zk/decryption_failure.py`, avec numpy, en quelques minutes.
- **Le vecteur** : `cargo run --release --manifest-path docs/research/bench/Cargo.toml --bin wrap_vector`.

## 9. Sources

* NIST, [FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final), 2024 : taux d'échec `2^−164,8` pour ML-KEM-768, et contrôle de module de la clé d'encapsulation.
* R. Avanzi et al., [CRYSTALS-Kyber, spécification du 3e tour](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210131.pdf), 2021, table 1 ; les scripts [pq-crystals/security-estimates](https://github.com/pq-crystals/security-estimates), qui calculent ce taux.
* M. Barbosa et al., [X-Wing: The Hybrid KEM You've Been Looking For](https://eprint.iacr.org/2024/039), 2024 ; le [brouillon X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/) à l'IETF.
* A. Langley, M. Hamburg, S. Turner, [RFC 7748 : Elliptic Curves for Security](https://www.rfc-editor.org/rfc/rfc7748), 2016 ; Y. Nir, A. Langley, [RFC 8439 : ChaCha20 and Poly1305 for IETF Protocols](https://www.rfc-editor.org/rfc/rfc8439), 2018.
* M. Frigo, a. shelat, [Anonymous credentials from ECDSA](https://eprint.iacr.org/2024/2010), 2024 ; la bibliothèque [longfellow-zk](https://github.com/google/longfellow-zk), dont les circuits mdoc se livrent sérialisés et compressés par zstd.
* Notes précédentes : [litige entier](litige-entier-2026-09-26.md), [litige sans mise en place](litige-sans-mise-en-place-2026-09-26.md), [litige X25519](litige-x25519-2026-09-26.md), [problèmes ouverts](problemes-ouverts-2026-09-26.md).
