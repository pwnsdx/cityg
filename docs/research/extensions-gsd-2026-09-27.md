# Les extensions du jeu GSD et l'invariant de cohérence, écrits en entier

| | |
| --- | --- |
| Date | 2026-09-27 |
| Nature | Note de recherche. Elle écrit en entier ce que la note [l'argument adaptatif](argument-adaptatif-2026-09-27.md) laissait en esquisse (sa section 8, points 1 et 2) : le jeu GSD étendu, son théorème et sa preuve dans les deux cas de l'événement `E`, et l'invariant de cohérence sur les formats réels du profil v0.4 et de l'étape 1 du [brouillon v0.5](../specs-v0.5-draft.md). En l'écrivant, elle a trouvé une faille de l'étape 1, corrigée dans le code et la spécification. |
| Question | Le théorème GSD tient-il avec les deux oracles que City-G ajoute, sans programmer l'oracle aléatoire ? Et le graphe que construit la réduction est-il bien celui que suppose le prédicat, pour tous les objets qu'un membre traite ? |
| Compagnons | [`safety_predicate.py`](safety_predicate.py) : 34 traces, dont trois bifurcations, et la condition « une clé `SEnc` par clair ». [`open_problems_sim.py`](open_problems_sim.py), rapport 6 : la perte avec un sommet par encapsulation. Tests `a_relay_element_opens_only_under_the_transcript_of_its_window` (`crates/cityg-core/tests/islands.rs`) et `two_branches_of_a_fork_seal_under_different_keys` (`src/top.rs`). |
| Auteur | Claude Code (assistant IA d'Anthropic), à la demande du mainteneur. Une relecture cryptographique humaine reste nécessaire. |

## 0. Résumé

1. **Un choix de modélisation.** Chaque encapsulation devient un sommet, et une enveloppe est une encapsulation suivie d'un scellement symétrique : `Enc = Encap ; SEnc`.
   - Sans cela, la réduction ne sait pas simuler un membre qui ouvre une encapsulation honnête dans un autre format. City-G le permet : la clé de feuille sert aux enveloppes et aux welcomes de saut.
   - Le jeu n'a alors que quatre sortes d'arêtes : `Encap`, `SEnc`, `Hash`, `Join-Hash`. L'`Enc` d'Alwen, Jost et Mularczyk en est un cas particulier.
   - Le coût : environ deux bits sur la perte (section 6).
2. **Le théorème** (section 3) : pour `N` sommets et `m` requêtes à l'oracle,
   `Avantage ≤ 2N² · (ε_KEM + ε_AE) + m N / 2^(λ−1)`.
   - `ε_KEM` est l'avantage IND-CCA contre X-Wing, `ε_AE` celui contre ChaCha20-Poly1305 à usage unique, déchiffrements compris.
   - L'oracle aléatoire est observé, jamais programmé (section 4.5).
3. **La preuve, dans les deux cas** (section 4).
   - Si `E` est improbable, on plante un défi sur une arête qui entre dans le sommet défié.
   - Si `E` est probable, on devine le premier sommet dont la graine est interrogée, puis une de ses arêtes entrantes, et on guette la requête.
   - Chaque cas perd `N²`. La réduction joue contre deux challengers à la fois, KEM et AE, et n'emploie le défi que de celui dont l'arête plantée a besoin.
4. **L'invariant de cohérence** (section 5) est écrit opération par opération, pour tous les objets du profil et de l'étape 1 : paquets entiers et d'îlot, commits, sceaux, entrants, welcomes, entrées, relais, éléments plats, rafraîchissements.
5. **Ce que l'écriture a trouvé.** Une condition du théorème était fausse dans l'étape 1 : « une clé `SEnc` scelle un seul clair ».
   - Les branches d'une bifurcation partagent l'époque et les îlots qu'aucune ne re-keye. Leurs relais scellaient deux racines différentes sous la même clé et le même nonce.
   - Le XOR des deux éléments est le XOR des deux racines. Un membre qu'une branche retire lit alors, avec le DS, l'époque qui le retire.
   - Le contexte d'un élément de relais lie désormais le hachage de transcript intérimaire de l'époque, qui couvre le sceau et le tag (commits `c23e566` puis `d9cf566`). Lier le seul sceau ne suffisait pas.
6. **La perte recomptée** : pour un million de membres pendant dix ans, `N ≈ 2^34` et `2N² ≈ 2^69`. Il reste 123 bits à ML-KEM-768, au lieu de 125.

## 1. Pourquoi réécrire le jeu

Le jeu d'Alwen, Jost et Mularczyk ([Crypto 2022](https://eprint.iacr.org/2020/1327), figure 20) a un chiffrement à clé publique `Enc` et son déchiffrement `Dec`. La note précédente y ajoutait deux oracles, `Encap` et `SEnc`, sans écrire leurs règles. Les écrire fait apparaître deux difficultés.

**Une encapsulation honnête rouverte dans un autre format.**
- Une clé X-Wing de City-G sert parfois à deux formats. La clé de feuille d'un membre reçoit les enveloppes du niveau 1 et l'encapsulation de feuille d'un welcome de saut.
- Le DS peut donc prendre la partie KEM `ct` d'une enveloppe honnête vers la feuille de M et la mettre dans un welcome de saut adressé à M. M décapsule et obtient la clé KEM `K` de l'enveloppe. Il en dérive une clé de welcome, et l'AEAD du welcome échoue : le DS ne connaît pas `K`.
- La réduction `B` doit simuler ce pas. Avec `Enc` et `Dec` seuls, elle n'a aucun nom pour `K` : ce n'est pas une graine du jeu.
- Un oracle qui décapsulerait `ct` et rendrait `K` serait pire : `B` apprendrait la clé de l'enveloppe, donc le secret qu'elle porte, et gagnerait trivialement.
- **Solution** : faire de `K` un sommet. `B` a alors un nom pour la valeur que M calcule, et le jeu répond à sa place.

**Un défi qu'un déchiffrement trahit.**
- Supposons que l'adversaire défie un sommet dont la graine est la clé `K` d'une encapsulation `ct`. Il fabrique un chiffré symétrique sous une clé dérivée de la réponse, puis demande qu'on déchiffre `(ct, ce chiffré)`.
- Le déchiffrement réussit si la réponse est la vraie graine, et échoue sinon. L'adversaire gagne à coup sûr.
- **Solution** : interdire les déchiffrements qui réutilisent une encapsulation honnête pour sa clé, et ceux sous la clé du sommet défié.

## 2. Le jeu GSD+

### 2.1 Les primitives

- **KEM** : X-Wing, IND-CCA si ML-KEM-768 ou X25519 l'est.
- **AE** : ChaCha20-Poly1305. Sa clé et son nonce viennent de l'oracle : `k ‖ n := Hash(s, lbl)`. Chaque clé scelle un seul clair.
- **Hash** : BLAKE3, modélisé par un oracle aléatoire. `λ = 256`.

### 2.2 L'état et les oracles

Chaque sommet `u` porte une graine `s_u`, d'abord indéfinie (`⊥`). Sa paire de clés, quand il en faut une, est `KEM.kg(Hash(s_u, "node"))`. Le jeu tient :
- l'ensemble des arêtes étiquetées ;
- `Kem(u)` : les encapsulations honnêtes sous la clé de `u` ;
- `Clé(u, lbl)` : le clair scellé sous la clé `SEnc` de `(u, lbl)`, s'il y en a un ;
- `Corr` : les sommets corrompus ;
- `Dech` : les sommets sous lesquels un déchiffrement a été demandé.

```text
Encap(u, v)         req s_v = ⊥ et v sans arête entrante
                    (ct, K) ← KEM.encaps(pk_u) ; s_v := K
                    arête u → v (encap) ; Kem(u) += ct ; rend (pk_u, ct)
SEnc(u, v, lbl)     req Clé(u, lbl) ∈ {⊥, v}
                    si s_v = ⊥ : s_v ← aléa ; k ‖ n := Hash(s_u, lbl)
                    c := AE.enc(k, n, lbl, s_v) ; Clé(u, lbl) := v
                    arête u → v (senc) ; rend c
Hash(u, v, lbl)     req s_v = ⊥, et (u, lbl) jamais utilisé ; s_v := Hash(s_u, lbl)
Join-Hash(u, u', v, lbl)   de même, s_v := Hash(s_u, s_u', lbl) ; arête ET
Decap(u, ct)        req ct ∉ Kem(u) ; Dech += u ; rend KEM.decaps(sk_u, ct)
SDec(u, lbl, c)     req c n'est pas le chiffré de SEnc(u, ·, lbl) ; Dech += u
                    rend AE.dec(Hash(s_u, lbl), c)        (un clair, ou ⊥)
Corr(u)             Corr += u ; rend s_u
Chal(u*)            une fois ; rend s_u* si b = 0, un aléa sinon
```

Un sommet `Encap` n'a que son arête `Encap` : aucune autre ne peut entrer en lui.

**Exposition.** `gsd-exp(u)` est vrai si `u ∈ Corr`, ou s'il existe une arête vers `u` dont toutes les sources sont exposées. Une arête `Encap`, `SEnc` ou `Hash` a une source ; une arête `Join-Hash` en a deux.

**Victoire.** L'adversaire gagne si `b' = b` et si, à la fin :
- le graphe est acyclique ;
- `u*` est un puits ;
- `u*` n'est pas exposé ;
- `u* ∉ Dech`.

### 2.3 Ce que chaque restriction empêche

| Restriction | Ce qu'elle empêche |
| --- | --- |
| `Decap(u, ct)` exige `ct ∉ Kem(u)` | rendre la clé KEM d'une encapsulation honnête, donc ce qu'elle protège (section 1) |
| `u* ∉ Dech` | tester la réponse du défi par un déchiffrement sous une clé qu'elle donne (section 1) |
| un seul clair par `(u, lbl)` | la clé et le nonce sont déterministes : deux clairs sous eux, c'est un masque jetable employé deux fois ([RFC 8439, section 4](https://www.rfc-editor.org/rfc/rfc8439#section-4) : « the XOR of the plaintexts is equal to the XOR of the ciphertexts ») |
| `Hash(u, ·, lbl)` une fois par `(u, lbl)` | deux sommets pour une même valeur ; comme chez Alwen, Jost et Mularczyk |

`Enc` et `Dec` d'Alwen, Jost et Mularczyk en sont des cas particuliers :
- `Enc(u, v, ctx)` est `Encap(u, k)` pour un sommet `k` neuf, puis `SEnc(k, v, ("wrap", ctx))`. C'est la construction KEM-DEM de [Cramer et Shoup](https://eprint.iacr.org/2001/108), rendue visible dans le graphe.
- `Dec(u, (ct, d), ctx)` devient :
  - `Decap(u, ct)` puis le déchiffrement de `d` sous la clé obtenue, si `ct ∉ Kem(u)` ;
  - sinon `SDec(k, ("wrap", ctx), d)`, où `k` est le sommet de `ct`.

L'exposition se transmet de même : `v` est exposé par cette paire d'arêtes exactement quand `u` l'est.

## 3. Le théorème

**Théorème.** Soit `A` un adversaire contre GSD+ qui crée au plus `N` sommets, fait au plus `m` requêtes à l'oracle et au plus `q` requêtes `SDec`. Alors, dans le modèle de l'oracle aléatoire observable et non programmable :

```text
Avantage(A) ≤ 2N² · (ε_KEM + ε_AE(q)) + m N / 2^(λ−1)
```

- `ε_KEM` est l'avantage IND-CCA d'un adversaire contre X-Wing, pour un défi.
- `ε_AE(q)` est celui d'un adversaire contre ChaCha20-Poly1305, sous une clé aléatoire : un chiffrement gauche-ou-droite et `q` déchiffrements.

La forme est celle du théorème 3 de [Tainted TreeKEM](https://eprint.iacr.org/2019/1489) : `2N²ε + mN/2^(λ−1)`. La section 4 suit sa preuve, lemmes 4 à 6 et corollaires 1 et 2, en l'adaptant aux nouvelles arêtes.

## 4. La preuve

### 4.1 L'événement E

**E** : l'adversaire interroge l'oracle sur une entrée qui contient la graine `s_w` d'un sommet `w ≠ u*` non exposé au moment de la requête.

- Les graines comprennent les clés KEM des sommets `Encap`.
- Une requête qui dérive une clé `SEnc`, `Hash(s_u, lbl)`, contient `s_u` : elle compte.

Soit `ε` l'avantage de `A`, et `ε_E = (Pr[E | b = 0] + Pr[E | b = 1]) / 2`. Deux cas, comme chez Tainted TreeKEM.

### 4.2 Trois faits, tant que E n'arrive pas

- **F1.** Pour un sommet `u` non exposé, les valeurs `Hash(s_u, lbl)` sont uniformes et indépendantes de la vue de `A`. Seuls les objets que le jeu en tire lui en disent quelque chose : la clé publique de `u` et les chiffrés `SEnc` sous `u`.
- **F2.** Un sommet `Hash` ou `Join-Hash` dont un parent n'est pas exposé a une graine uniforme, indépendante de la vue de `A`. Pour `Join-Hash`, il suffit qu'un des deux parents ne le soit pas.
- **F3.** Une incohérence entre une valeur et l'oracle, en un point que personne n'interroge, ne se voit pas. Les réductions n'en introduisent qu'en de tels points.

### 4.3 Premier cas : ε_E < ε/2

On arrête le jeu dès que `E` arrive, en comptant cela comme la sortie 1. L'avantage dans ce jeu arrêté, GSD+\*, reste au moins `ε/2`, par le calcul du lemme 4 de Tainted TreeKEM.

**Un défi sans arête chiffrée.** Si `u*` n'a pour arêtes entrantes que des `Hash` ou des `Join-Hash`, l'avantage dans GSD+\* est nul, par F2.
- La graine de `u*` est un tirage de l'oracle en un point que `A` n'interroge pas, et `u*` est un puits : rien n'en est tiré.
- C'est le cas de City-G, dont le défi est `msg_n = Hash(epoch_n, "msg")`. Tout l'avantage d'un adversaire contre City-G passe donc par `E` : c'est le second cas qui compte.

**Un défi derrière une arête `Encap`.** C'est alors sa seule arête entrante. La réduction devine `u*`, puis la source `u°` de cette arête, chacune parmi `N` sommets.
- Elle reçoit du challenger KEM `(pk*, ct*, K_β)` : `K_0` est la vraie clé de `ct*`, `K_1` un aléa.
- Elle pose `pk_u° := pk*` dès que la clé de `u°` est créée. La requête `Encap(u°, u*)` rend `ct*`, et `s_u* := K_β`. Elle répond au défi par `K_β`.
- **Si β = 0**, c'est exactement GSD+\*₀.
- **Si β = 1**, la réponse est indépendante de `ct*`, et rien d'autre ne dépend de la vraie clé, puisque `u*` est un puits : c'est GSD+\*₁. `Decap(u°, ct*)` est interdit, et `SDec` sous `u*` aussi.
- **Le reste.** `Decap(u°, ct)` pour les autres `ct` passe par l'oracle de décapsulation du challenger. Les encapsulations vers `u°`, la réduction les fait elle-même sous `pk*`.
- **La graine de `u°`.** La réduction lui donne un aléa, sans lien avec `pk*`. Le vérifier demanderait d'interroger `s_u°`. Or `u°` est parent d'un sommet non exposé, donc non exposé lui-même : ce serait `E` (F3).

**Un défi derrière des arêtes `SEnc`.** Ce sont les hybrides de Tainted TreeKEM. `G_i` scelle `s'` au lieu de `s_u*` sur les `i` premières arêtes `SEnc` qui entrent dans `u*`, dans l'ordre des requêtes.
- La réduction du lemme 6 devine `u*` et la source `u°` d'une arête, chacune parmi `N`. Elle scelle `s_0` sur les arêtes vers `u*` antérieures à celle de `u°`, et `s_1` sur les suivantes.
- Sur celle de `u°`, d'étiquette `lbl°`, elle remplace `Hash(s_u°, lbl°)` par la clé cachée du challenger AE, et demande le chiffrement gauche-ou-droite de `(s_0, s_1)`. Elle répond au défi par `s_0`.
- Les `SDec(u°, lbl°, c)` passent par l'oracle de déchiffrement du challenger.
- La condition « un seul clair par `(u°, lbl°)` » garantit que cette clé ne scelle rien d'autre. Sans elle, il faudrait sceller d'autres clairs sous le même nonce, ce que la sécurité de l'AE ne couvre pas.
- Une éventuelle arête `Hash` vers `u*` est ignorée, comme chez Alwen, Jost et Mularczyk : la vérifier demanderait d'interroger la graine de son parent, non exposé (F3).
- Les termes du télescopage se compensent, sauf les deux extrêmes, comme dans la preuve du lemme 6. La réduction perd `N²` et non `N² · degré`.

**Les deux challengers.**
- La réduction ne sait pas d'avance si l'arête plantée sera `Encap` ou `SEnc`. Elle joue donc contre les deux challengers et n'emploie le défi que de l'un.
- Avant ce défi, la vue de `A` ne dépend pas du bit, et le choix du challenger non plus. Son avantage est donc au plus `ε_KEM + ε_AE`, chaque terme par une réduction qui simule l'autre challenger elle-même.

**Bilan du premier cas** : `ε/2 ≤ N² · (ε_KEM + ε_AE)`.

### 4.4 Second cas : ε_E ≥ ε/2

C'est le cas que la note précédente n'avait qu'esquissé. Soit `v°` le sommet dont la graine déclenche `E` la première fois.

**Où peut être `v°`.**
- Une source sans arête entrante : sa graine n'apparaît nulle part. `A` l'interroge avec probabilité au plus `m/2^λ`.
- Un sommet à arêtes `Hash` ou `Join-Hash` seulement : de même par F2. Son parent non exposé n'a pas été interrogé, sinon `E` serait arrivé plus tôt.
- Un sommet `Encap`, ou un sommet avec au moins une arête `SEnc`. Ce sont les cas où `A` a cassé une primitive.

**La réduction.**
1. Elle devine `v°` parmi `N` sommets.
2. **Les usages de `v°` passent par un remplaçant.** Sa paire de clés, ses fils `Hash` et `Join-Hash`, ses clés `SEnc` sont tirés d'un sommet `N + 1` jamais exposé, au lieu de `v°`. C'est le sommet spécial du lemme 5.
   - L'incohérence ne se voit qu'en interrogeant `s_v°`, et c'est justement la requête que la réduction guette.
   - Les `SDec` et `Decap` sous `v°` sont simulés avec `N + 1`. Sous l'une comme sous l'autre graine, `A` ne sait pas fabriquer de chiffré valide sans l'interroger.
3. **Si `v°` est un sommet `Encap`**, elle devine sa source `u°`, parmi `N`.
   - Elle y place `pk*`, rend `ct*` pour l'arête vers `v°`, et guette dans les requêtes de `A` la valeur `K_β`.
   - Si `A` interroge `K_β`, elle répond « réel ».
   - Si `β = 0`, la vue de `A` est celle du jeu jusqu'à cette requête, qui arrive avec la probabilité que `E` arrive d'abord en `v°`.
   - Si `β = 1`, rien n'emploie `K_1` : `A` l'interroge avec probabilité au plus `m/2^λ`.
4. **Si `v°` a des arêtes `SEnc`**, elle mène le télescopage du premier cas sur ces arêtes. Les premières scellent `s_0`, les suivantes `s_1`, et la réduction guette `s_0`.
   - Quand toutes scellent `s_0`, la vue est celle du jeu.
   - Quand toutes scellent `s_1`, `s_0` est indépendant de la vue.
   - Le corollaire 2 de Tainted TreeKEM donne la perte `N` pour la source devinée.
5. **Elle s'arrête** si `v°` devient exposé, par corruption de `v°` ou d'un parent : `E` ne peut plus arriver en `v°` au sens de sa définition. Elle s'arrête aussi dès qu'une de ses devinettes se révèle fausse.

**Bilan du second cas.** Comme au lemme 5 et au corollaire 2 : `ε_E ≤ N² · (ε_KEM + ε_AE) + N m / 2^λ`, donc `ε ≤ 2N² · (ε_KEM + ε_AE) + m N / 2^(λ−1)`.

Les deux cas donnent le théorème.

### 4.5 L'oracle n'est jamais programmé

Les réductions ne fixent aucune valeur de l'oracle. Elles transmettent les requêtes de `A` telles quelles, et n'interrogent elles-mêmes que des points dont elles connaissent la graine. Elles emploient quatre valeurs incohérentes avec l'oracle :

| Remplacement | Où | Pourquoi personne ne le voit |
| --- | --- | --- |
| `Hash(s_u°, lbl°)` par la clé du challenger AE | premier cas, arête `SEnc` | `u°` n'est pas exposé ; l'interroger est `E` |
| la paire de clés de `u°` par `pk*` | arêtes `Encap` | idem |
| la graine d'un sommet défié ou guetté par `s_0`, `s_1` ou `K_β` | les deux cas | l'arête `Hash` éventuelle vers lui ne se vérifie qu'en interrogeant son parent : `E` plus tôt |
| les usages de `v°` par ceux de `N + 1` | second cas | les vérifier, c'est interroger `s_v°`, la requête guettée |

C'est ce qu'Alwen, Jost et Mularczyk affirment pour leurs oracles (« we believe this is not necessary »). Avec `SEnc` aussi, la réduction n'a qu'à ne pas interroger l'oracle au point remplacé.

### 4.6 Ce que la preuve suppose, et ne donne pas

- **Un défi.** Plusieurs défis se ramènent à un seul par un hybride, qui multiplie la perte par leur nombre, comme l'indique Tainted TreeKEM.
- **Un nonce par clé.** ChaCha20-Poly1305 est employé avec un nonce dérivé de la clé. C'est sûr pour un seul clair, et c'est pourquoi la condition « un seul clair par `(u, lbl)` » est une condition du théorème, non un détail.
- **X-Wing est IND-CCA.** Le théorème ne distingue pas ses deux moitiés (section 6).

## 5. L'invariant de cohérence, en entier

Le lemme combinatoire de la note précédente repose sur un invariant : le graphe que `B` construit en simulant City-G est celui que suppose le prédicat. Voici l'invariant écrit en entier, sur les formats réels.

### 5.1 Ce que B tient

- Les clés de signature de tous les participants honnêtes : ce ne sont pas des secrets du jeu.
- Des **noms** : pour chaque secret honnête qu'elle ne connaît pas, le sommet qui le porte.
- Des **valeurs** : ce que `A` lui a donné, ce que ses propres tirages ont fixé, ce que `Corr`, `Decap` et `SDec` lui ont rendu, et ce qu'elle en a dérivé.

Une valeur connue de `B` est connue de l'adversaire du jeu GSD+ : c'est ce qui compte pour le théorème. Ce n'est pas toujours une valeur que `A` connaît, par exemple la clé d'une encapsulation que `A` a altérée.

### 5.2 L'énoncé

**Invariant.** À chaque pas de la simulation :
- **(I1)** tout secret que tient un participant honnête est (a) la graine d'un sommet du graphe de `B`, ou (b) une valeur que `B` connaît ;
- **(I2)** toute arête créée pour un participant honnête suit la structure du protocole :
  - `Encap` vers la clé d'un sommet prise dans une vue vérifiée : l'arbre vérifié contre l'en-tête, une requête signée, l'en-tête ou le point de contrôle qui ancre un entrant ;
  - `SEnc` sous un de ses propres secrets ;
  - `Hash` et `Join-Hash` de ses propres secrets ;
- **(I3)** une clé `SEnc` `(u, lbl)` d'un participant honnête scelle un seul clair ;
- **(I4)** `B` corrompt exactement les sommets que nomment les fuites du prédicat, plus les clairs qu'un participant honnête chiffre vers une clé qui n'est celle d'aucun sommet. Le prédicat expose ces derniers aussi : c'est sa règle de l'enveloppe, avec une clé fuitée.

### 5.3 Les opérations

Chaque ligne dit ce que fait `B` quand un participant honnête exécute l'opération, et pourquoi l'invariant tient après.

| Opération (spécification) | Ce que fait B | Pourquoi l'invariant tient |
| --- | --- | --- |
| **Tirer** : clés de feuille et d'init, aléa d'un tirage frais (v0.4 §7.1) et coins d'une encapsulation (brouillon 3.3) | une source ; corrompue si l'adversaire fixe l'aléa | (I1a) ; un tirage frais est `Hash(Join-Hash(couverture, r))`, les coins d'une encapsulation `Hash(Join-Hash(couverture, r'), ctx)` : ils restent secrets tant que la couverture l'est, même si `r` et `r'` sont corrompus (correction ci-dessous) |
| **Commit de quartier** (§12.4) | secrets frais et chaînés par `Join-Hash` et `Hash` ; pour chaque cible, `Encap` vers la clé de la vue vérifiée, puis `SEnc` | une cible dont la clé vient de l'adversaire, feuille ou nœud publié par un committer corrompu, n'est pas un sommet. `B` corrompt le clair et chiffre elle-même (I4). La règle des taches re-keye ces nœuds au retrait du committer |
| **Sceau avec ville** (§12.5) | comme un commit, puis le calendrier : `Hash` de la racine, `Join-Hash` avec son `init_n−1`, `Hash` pour chaque secret d'époque, `Hash` puis `Corr` pour le tag | (I1) ; si son `init_n−1` est une valeur (b), `B` crée pour elle une source corrompue avant le `Join-Hash` |
| **Sceau sans ville** (§12.5, brouillon 2.7) | le scelleur suit le commit de quartier le long de son chemin : comme « suivre » ; un suiveur d'îlot se rafraîchit d'abord | voir ces lignes |
| **Sceau d'entrant** (§12.7) | `Encap` vers la clé externe de l'époque `n − 1`, prise de l'en-tête vérifié : c'est le sommet `Hash(epoch_n−1, "external")` ; puis `Join-Hash` avec `commit_n` ; re-key de tout son chemin | si `epoch_n−1` est exposé, l'init externe l'est par l'arête `Encap`, sans `Corr` ; c'est la règle du prédicat |
| **Suivre, paquet entier** (§12.2) | chaque pas `Wrap`, d'encapsulation `ct` vers la clé de son nœud `u` : (i) chiffré honnête entier : `B` a le nom du clair ; (ii) `ct ∈ Kem(u)` avec un autre contexte ou une autre partie symétrique : `SDec(k, ctx, d)` sur le sommet `k` de `ct` ; (iii) `ct ∉ Kem(u)` : `Decap`, puis `B` déchiffre elle-même. `Chain` : `Hash` du nom ou de la valeur de l'étage inférieur | (i) donne (a) ; (ii) et (iii) donnent ⊥ ou une valeur que `B` connaît, (b) ; un `Chain` d'un nom retrouve le sommet du committer, puisque `Hash` est déterministe et appelé une fois par `(u, lbl)` |
| **Suivre, paquet d'îlot** (brouillon 2.6) | les pas jusqu'à la racine d'îlot, comme ci-dessus ; puis le sommet : l'élément de relais par `SDec(s_j, ctx, c)`, ou le nom de la racine si c'est le chiffré honnête ; l'élément plat comme un `Wrap` ; le rafraîchissement comme des `Wrap` et des `Chain` | (I1) ; accepter : section 5.4 |
| **Rafraîchissement seul** (brouillon 2.5) | la même marche, puis la comparaison avec la racine gardée | un nom n'est égal qu'à lui-même : une racine de nom `r_n` n'est retrouvée que par des pas honnêtes ; sinon le membre rejette et ne change rien (modèle `refresh_checked.pv`) |
| **Relais** (brouillon 2.3) | `SEnc(s_j, r_n, ctx)` avec `ctx` qui lie `interim_transcript_hash_n` | (I3), section 5.5. Si `s_j` est une valeur (b), `r_n` aussi : chaque pas depuis une valeur connue passe par un chiffré vers une clé connue de l'adversaire, que `B` a simulé après `Corr` de son clair (I4) |
| **Élément plat** (brouillon 2.4) | `Encap` vers la clé de la racine d'îlot, prise dans l'état vérifié, puis `SEnc` | une clé de l'adversaire : `Corr(r_n)`. Le prédicat l'exposait déjà, puisque le détenteur de la clé d'une racine d'îlot ouvre les enveloppes du chemin au-dessus d'elle. Une clé non vérifiée casserait (I2) : attaque `flat_unchecked.pv` |
| **Welcome d'entrée** (§11) | `Encap` vers la clé d'init de la requête signée, puis `SEnc(k, joiner_n, ctx)` | clé d'init de l'adversaire : `Corr(joiner_n)`, et le prédicat expose l'époque au joiner qu'il contrôle |
| **Welcome de saut** (§11) | deux `Encap`, vers la clé d'init de la requête et vers la clé de feuille de l'arbre vérifié, un `Join-Hash`, puis `SEnc` | clé d'init de l'adversaire (clé d'appareil volée) : une source corrompue dans le `Join-Hash`, qui reste secret tant que la feuille l'est. C'est le correctif du saut, `catch_up_stolen_key.pv` |
| **Entrer** : joiner, ré-entrée, saut (§12.9, §12.10) | ouvrir le welcome : nom si honnête, sinon `Decap` et `SDec` ; reprendre le chemin des derniers pas, comme « suivre » ; vérifier chaque secret contre la clé publique de l'arbre où il entre | une valeur (b) dont la clé égalerait celle d'un sommet serait une collision de `KemKey` ; le membre rejette |
| **Mettre à jour, retirer** (§12.6, §14.6) | une source neuve ; le retrait ne tire rien, la fenêtre qui l'applique re-keye | (I1) |
| **Effacer** (§12.4, §9) | `B` oublie les noms effacés | `CorrompreÉtat` ne corrompt que ce que l'état garde (I4) |

**Correction : les coins des encapsulations.** Dans une première version, la ligne « Tirer » ne couvrait que le secret frais. Or la v0.4 prend les coins de chaque encapsulation X-Wing au générateur (§7.2), et chaque secret frais part dans une enveloppe : si l'adversaire fixe l'aléa, il recalcule l'encapsulation et ouvre l'enveloppe. L'arête `Encap` n'est plus alors l'arête honnête du jeu, et la couverture ne protège rien. De plus, la couverture de la v0.4, `init_n−1`, est connue du membre que la fenêtre retire. Le brouillon v0.5 (section 3.3) couvre donc aussi les coins, par la graine de feuille de l'appareil. Tant que cette graine est secrète, les coins sont une sortie de l'oracle jamais demandée : des coins honnêtes pour le challenger. Si la graine et l'aléa sont tous deux corrompus, `B` corrompt le clair (I4). Le modèle symbolique le vérifie : [`task_hedge.pv`](../formal/task_hedge.pv) est prouvé, [`task_hedge_coins.pv`](../formal/task_hedge_coins.pv) et [`task_hedge_init.pv`](../formal/task_hedge_init.pv) donnent l'attaque.

### 5.4 Accepter une époque

**Lemme.** Un membre honnête accepte l'époque `n` avec la racine `r` et l'init `i` seulement si :
- `(r, i)` est la vraie paire `(r_n, init_n−1)` d'une branche, deux sommets ;
- ou `B` connaît `r` et `i`, et donc l'époque entière.

**Preuve.**
- Le tag publié est le fils corrompu `Hash(confirm_n, transcript)` du vrai sommet `confirm_n` de sa branche.
- Le membre calcule `confirm` depuis `Join-Hash(i, Hash(r))`. Si `r` ou `i` n'est pas le vrai, c'est un autre sommet, ou une valeur connue.
- L'égalité des tags est alors une collision de l'oracle, de probabilité au plus `q²/2^256`. Sinon, `B`, et avec elle l'adversaire, connaît toute la chaîne.
- Le second cas est la bifurcation par un initié (spécification, section 2.3), que le prédicat compte comme exposée.

Pour l'étape 1, la racine d'un suiveur d'îlot vient d'un élément de relais, d'un élément plat ou d'un rafraîchissement. Elle passe par le même tag. Le lemme vaut tel quel.

### 5.5 Ce que l'écriture a trouvé : (I3) et les bifurcations

La note précédente affirmait (section 4) : « Chaque clé scelle un seul clair : le contexte lie l'époque et l'îlot pour un relais ». C'est faux sous une bifurcation.

**La configuration.**
- Le DS montre la fenêtre `n` en deux branches, et aucune ne re-keye l'îlot `i`. Le secret `s_i` de sa racine est donc le même dans les deux.
- Il nomme un relais de l'îlot dans chaque branche. Les deux relais, honnêtes, scellent la racine de leur branche sous `ExpandLabel(s_i, "relay key", [gid, n, c, i])`, avec le même nonce.
- Le XOR des deux éléments est le XOR des deux racines (RFC 8439, section 4).

**Deux façons d'obtenir deux branches.**
1. **Deux sceaux.** Le DS confie la fenêtre à deux scelleurs honnêtes, avec deux contenus : la branche A retire M, la branche B le garde. M, membre de B, connaît la racine de B.
2. **Un seul sceau, deux tags.** M connaît `init_n−1`, puisqu'il était membre de l'époque `n − 1`. Avec le DS, il mène un membre honnête, qui ne vérifie que le tag, vers une racine de son choix, sous le vrai en-tête de sceau.
   - Il fabrique pour cela les pas ou le rafraîchissement du membre, et le tag qui va avec.
   - Si ce membre est le relais de l'îlot `i`, il scelle la racine de M sous la même clé que le relais de la vraie branche. Lier le seul sceau ne sépare pas ces deux branches.

**Dans les deux cas**, M apprend la vraie racine `r_n` de la branche qui le retire. Avec `init_n−1` et le contexte public, il en tire l'époque `n`. C'est une rupture de la sécurité après retrait, contre un membre retiré et le DS, que la v0.4 n'avait pas.

**Le correctif.**
- Le contexte d'un élément de relais lie `interim_transcript_hash_n`, qui couvre le sceau et le tag. Le membre le calcule depuis son paquet avant d'ouvrir l'élément.
- Deux membres qui ont accepté le même hachage intérimaire tiennent la même racine : sinon les tags coïncideraient, ce qui est une collision.
- Chaque clé scelle donc un seul clair, et un élément d'une branche ne s'ouvre pas dans une autre.
- Commits `c23e566` (le sceau) puis `d9cf566` (le transcript) ; brouillon v0.5, section 2.3 ; décision E-15.

**Les preuves.**
- `two_branches_of_a_fork_seal_under_different_keys` (unitaire) : deux branches scellent sous des flux de clé différents.
- `a_relay_element_opens_only_under_the_transcript_of_its_window` (scénario) : sous un autre tag, l'élément ne s'ouvre pas, et l'erreur est celle de l'élément de relais, non celle du tag.
- [`safety_predicate.py`](safety_predicate.py) exprime la réutilisation d'un nonce par une règle `XOR`, qu'aucun oracle GSD n'a : deux clairs sous une même clé et un même contexte se donnent l'un l'autre.

| Trace | Prédicat | Graphe GSD |
| --- | --- | --- |
| bifurcation, relais lié au transcript | sûre | valide |
| bifurcation, relais lié au sceau seul | exposée | non : une clé `SEnc` scelle deux clairs |
| bifurcation, relais lié à l'époque seule | exposée | non : de même |

**Pourquoi les modèles ne l'avaient pas vu.**
- Dans ProVerif, le chiffrement symétrique n'a pas de nonce : deux clairs sous une clé ne se trahissent pas.
- Le modèle CryptoVerif `relay.ocv` scelle un seul clair par fenêtre, par construction.
- Seule l'écriture de la condition (I3), clé par clé, sur les formats réels, fait apparaître le cas.

Les autres clés symétriques déterministes de City-G tiennent (I3).
- Les enveloppes et les welcomes tirent leur clé d'une encapsulation fraîche : une par clair.
- Le tag est un MAC, sans nonce.
- Toute clé de ce genre que les étapes 2 et 3 ajouteront devra être vérifiée de même : les clés de données d'émetteur du plan de messages, par exemple.

### 5.6 Le lemme combinatoire, conclu

Avec (I1) à (I4) :
- les arêtes du graphe de `B` vers de vrais secrets sont celles de la structure du protocole, sur lesquelles raisonne le prédicat ;
- les sommets créés par des pas faux, ou pour des valeurs connues, ne mènent à aucun vrai secret ;
- les corruptions de `B` sont les fuites du prédicat, plus des clairs que le prédicat expose aussi.

Donc `gsd-exp(msg_n)` dans le graphe de `B` implique que le prédicat expose l'époque `n`. Par contraposée, une époque sûre donne un défi valide, et le théorème de la section 3 s'applique à `B`.

La simulation ajoute ses propres erreurs :
- les collisions du tag, au plus `q²/2^256` ;
- les chiffrés qu'un membre ouvre sous une clé que `B` ne peut pas demander au jeu, déjà comptés dans `ε_AE`.

## 6. La perte, recomptée

Chaque enveloppe, welcome et élément plat ajoute maintenant un sommet `Encap`. [`open_problems_sim.py`](open_problems_sim.py), rapport 6, compte :
- une enveloppe par nœud re-keyé, vers son fils non chaîné ;
- deux sous un tirage frais ;
- un welcome par entrée.

| Membres | Fenêtres | Durée | Secrets | Encapsulations | Sommets `N` | Perte `2N²` | Bits restants, ML-KEM-768 |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2^20 | 5 min | 1 an | 2^29,6 | 2^29,4 | 2^30,5 | 2^62 | 130 |
| 2^20 | 5 min | 10 ans | 2^32,9 | 2^32,7 | 2^33,8 | 2^69 | 123 |
| 2^20 | 60 s | 10 ans | 2^33,2 | 2^33,0 | 2^34,1 | 2^69 | 123 |
| 2^24 | 5 min | 10 ans | 2^36,9 | 2^36,7 | 2^37,8 | 2^77 | 115 |

- Les encapsulations sont presque aussi nombreuses que les secrets. `N` double, et la perte prend deux bits.
- La somme `ε_KEM + ε_AE` remplace le `2ε_CCA + ε_AE` de la composition KEM-DEM de la note précédente. La décomposition fait passer la composition dans le graphe.
- Comme avant, les bits restants retranchent la perte à 192 bits pour ML-KEM-768 (catégorie 3 du NIST).

## 7. Ce qui reste

1. **Mécaniser.**
   - Le théorème, dans EasyCrypt ou SSProve. Le télescopage du lemme 6 et le double challenger sont les parties délicates.
   - L'invariant, dans DY\*, comme [Wallez, Protzenko et Bhargavan](https://eprint.iacr.org/2025/410) l'ont fait pour TreeKEM. La table de la section 5.3 en donne les cas.
2. **Une perte plus fine pour X-Wing**, par la technique d'[Azari et Ellison](https://eprint.iacr.org/2024/1878) sur la moitié X25519. Et plusieurs défis.
3. **Vérifier (I3) à chaque nouvelle clé déterministe**, dans les étapes 2 et 3. La [fiche de revue de sécurité](../security-review-checklist.md) le demande désormais : toute clé AEAD tirée d'un secret et d'un contexte doit sceller un seul clair, y compris entre les branches d'une bifurcation.

## 8. Reproductibilité

- `python3 docs/research/safety_predicate.py` : 34 traces, leur accord avec les modèles, et les conditions GSD. Deux traces ne sont pas des graphes GSD, comme attendu : les relais de bifurcation liés à l'époque ou au seul sceau.
- `python3 docs/research/open_problems_sim.py` : le rapport 6 donne la perte avec un sommet par encapsulation.
- `cargo test -p cityg-core --test islands a_relay_element_opens_only_under_the_transcript_of_its_window`, et les tests unitaires de `crates/cityg-core/src/top.rs`.

## 9. Sources

Chaque énoncé cité a été relu dans le texte.

* J. Alwen, D. Jost, M. Mularczyk, [On the Insider Security of MLS](https://eprint.iacr.org/2020/1327), Crypto 2022 : le jeu GSD modifié (figure 20), le théorème 6 et sa preuve (annexe D.2), réductions (1) et (2), et la remarque sur l'oracle non programmable.
* J. Alwen, M. Capretto, M. Cueto, C. Kamath, K. Klein, I. Markov, G. Pascual-Perez, K. Pietrzak, M. Walter, M. Yeo, [Keep the Dirt: Tainted TreeKEM, Adaptively and Actively Secure Continuous Group Key Agreement](https://eprint.iacr.org/2019/1489), IEEE S&P 2021 : théorème 3, lemmes 4 à 6 et corollaires 1 et 2 (annexe C), l'événement `E` et le sommet `N + 1`.
* J. Alwen, B. Auerbach, M. Cueto Noval, K. Klein, G. Pascual-Perez, K. Pietrzak, M. Walter, [CoCoA: Concurrent Continuous Group Key Agreement](https://eprint.iacr.org/2022/251), Eurocrypt 2022 : lemme 2, définition 10 (traitement faible), lemmes 4 et 5.
* R. Cramer, V. Shoup, [Design and Analysis of Practical Public-Key Encryption Schemes Secure against Adaptive Chosen Ciphertext Attack](https://eprint.iacr.org/2001/108), SIAM J. Comput. 33(1), 2003 : la composition KEM-DEM.
* Y. Nir, A. Langley, [ChaCha20 and Poly1305 for IETF Protocols](https://www.rfc-editor.org/rfc/rfc8439), RFC 8439, section 4 : les conséquences d'un nonce répété.
* K. Azari, A. Ellison, [Tighter Provable Security for TreeKEM](https://eprint.iacr.org/2024/1878), ACNS 2025.
* T. Wallez, J. Protzenko, K. Bhargavan, [TreeKEM: A Modular Machine-Checked Symbolic Security Analysis of Group Key Agreement in Messaging Layer Security](https://eprint.iacr.org/2025/410), IEEE S&P 2025.
* Notes précédentes : [l'argument adaptatif](argument-adaptatif-2026-09-27.md), [la preuve de l'arbre](preuve-arbre-2026-09-26.md) ; le [brouillon de spécification v0.5](../specs-v0.5-draft.md) et la [spécification v0.4](../specs.md).
