# Preuves et mesures : le litige mesuré, une faille du saut, le plan de preuve de l'arbre

| | |
| --- | --- |
| Date | 2026-09-26 |
| Nature | Note de recherche. Elle poursuit la note [problèmes ouverts](problemes-ouverts-2026-09-26.md) dans l'ordre de sa section 7. Elle mesure la preuve de litige, ajoute l'authentification au modèle calculatoire, trouve dans la v0.4 une faille du saut sous clé d'appareil volée et la corrige, écrit le plan de preuve de l'arbre sous corruptions adaptatives et recommande une dérivation de clés. Le correctif du saut est depuis appliqué à la v0.4 : spécification (section 11), modèle symbolique et code. |
| Question | Que coûte vraiment un litige, que peut-on prouver de plus, et que faut-il pour prouver l'arbre entier ? |
| Compagnons | [`dispute-zk/`](dispute-zk/README.md) : le prouveur du litige, en C++ avec emp-zk. [`formal-computational/`](formal-computational/README.md) : 21 modèles CryptoVerif, dont 7 nouveaux. [`formal-parity/`](formal-parity/README.md) : 34 scénarios ProVerif, dont 2 nouveaux. [`open_problems_sim.py`](open_problems_sim.py) : rapport 4. |
| Auteur | Claude Code (assistant IA d'Anthropic), à la demande du mainteneur. Les mesures viennent d'une machine virtuelle à 4 vCPU, prouveur et vérifieur sur la même machine ; les preuves calculatoires portent sur des configurations fixées. Une relecture cryptographique humaine reste nécessaire. |

## 0. Résumé

1. **Hors X25519, un litige se prouve en moins d'une seconde et 2 Mo.** Mesures faites avec emp-zk, par QuickSilver sur des bits authentifiés :
   - le hachage de l'énoncé (26 Keccak-f, 4 BLAKE3, 1 bloc ChaCha20) : 1,05 million de portes AND, 0,3 s ;
   - l'arithmétique de ML-KEM-768, sur des bits : 8,7 millions de portes ;
   - les deux ensemble : 9,7 millions de portes, 0,85 s et 1,98 Mo, dont 0,65 Mo de mise en place.
   - La moitié X25519 coûterait en bits 150 Mo et 90 s. Il lui faut une preuve dans son propre corps, soit environ 0,2 Mo plus une mise en place.
   - L'estimation de la note précédente, 0,4 Mo, supposait chaque partie dans son corps. L'écart vient de ML-KEM prouvé en bits et de la mise en place.
2. **L'authentification entre dans le modèle calculatoire.**
   - Un relais menteur est trahi par le tag, même s'il connaît toutes les clés de la chaîne. Il suffit que BLAKE3 résiste aux collisions (`relay_tag.ocv`).
   - Avec trois témoins sur quatre, un témoin allié au serveur ne suffit pas à faire bifurquer le groupe (`witness_quorum.ocv`).
   - Les trois contrôles échouent, comme prévu.
3. **Une faille de la v0.4 : le saut sous une clé d'appareil volée.**
   - Le voleur a la clé d'appareil d'un membre, pas son état. À chaque fenêtre, il demande un saut avec une clé d'init à lui et reçoit l'époque. Un saut ne change pas l'arbre : personne ne le voit, et les mises à jour du membre ne l'arrêtent pas (`catch_up_device_key.pv`).
   - La spécification ne promet rien contre ce voleur. Mais la réparation qu'elle prévoit, retirer l'appareil, suppose qu'on remarque le vol.
   - C'est l'équivalent, dans City-G, de ce qu'[ETK (Eurocrypt 2026)](https://eprint.iacr.org/2025/229) montre sur les opérations externes de MLS.
   - **Correctif** : le welcome d'un saut est aussi encapsulé vers la clé de feuille du membre, que le membre qui saute détient toujours. Il coûte 1 120 octets par saut. Les deux modèles le prouvent (`catch_up_leaf_bound.pv`, `catch_up_leaf_bound.ocv`).
   - Avec lui, la clé d'appareil seule ne donne plus accès aux époques sans changer la feuille du membre. Le membre est alors exclu et s'en aperçoit.
   - La v0.4 l'a adopté depuis (section 3.6).
4. **Le plan de preuve de l'arbre.**
   - Dans le modèle standard, la perte des preuves connues est `Q^log n`, soit 2^600 pour un million de membres et 2^30 opérations. La borne ne garantit plus rien, et aucune réduction qui ne rembobine pas l'adversaire ne peut être polynomiale ([Kamath et al.](https://eprint.iacr.org/2021/059)).
   - Avec des oracles aléatoires, TTKEM perd `(Qn)^2` : 100 bits sur les 192 de ML-KEM-768, il en reste 92. ETK prouve MLS de la même façon. C'est donc la voie retenue.
   - Le plan tient en quatre points :
     - un jeu à fenêtres ;
     - son prédicat de sûreté, tiré du graphe des taches ;
     - la preuve hybride de TTKEM, étendue à ce que City-G ajoute ;
     - les initiés, tenus par les audits et les litiges.
   - Les 21 modèles CryptoVerif en sont les lemmes, fenêtre par fenêtre.
5. **BLAKE3 ou HKDF.**
   - Dans une preuve par oracles aléatoires, le choix ne change rien. Il compte pour les lemmes du modèle standard, qui demandent une PRF double.
   - HMAC en est une, c'est prouvé, pour des clés de longueur fixe comme celles de City-G. BLAKE3 n'a aucune analyse.
   - Recommandation pour le prochain profil : passer `Extract` seul en HKDF-Extract avec SHA-384, comme la suite MLS la plus proche.
6. **Ce qui reste** :
   - écrire la preuve de l'arbre ;
   - prouver X25519 dans son corps, puis mesurer sur téléphone ;
   - la spécification du profil candidat.

## 1. Le litige, mesuré

### 1.1 Ce qui est prouvé

Un membre qui ne peut pas ouvrir une enveloppe prouve au serveur, sans révéler sa clé, que l'enveloppe ne s'ouvre pas. C'est la branche 1 de la note [problèmes ouverts](problemes-ouverts-2026-09-26.md), section 2.1.

Le prouveur [`dispute-zk/dispute_zk.cpp`](dispute-zk/dispute_zk.cpp) la mesure avec [emp-zk](https://github.com/emp-toolkit/emp-zk), la bibliothèque des auteurs de QuickSilver. La preuve est interactive et son vérifieur désigné est le serveur.

- **Le hachage** comprend :
  - les 26 permutations Keccak de la génération de clé X-Wing depuis la graine, et de la décapsulation ;
  - les 4 compressions BLAKE3 des deux `ExpandLabel` qui donnent la clé et le nonce AEAD ;
  - un seul bloc ChaCha20, au lieu de deux.
- **La clé Poly1305 est révélée.** Le bloc 0 de ChaCha20 donne la clé Poly1305 de l'enveloppe, et le prouveur la révèle. Le serveur calcule lui-même le tag sur le chiffré public et constate qu'il ne correspond pas.
  - Cette clé ne sert qu'une fois. Elle ne dit rien du flux de chiffrement ni de la clé ChaCha20.
  - L'enveloppe est déjà mauvaise, et son contexte ne resservira pas.
  - Le déchiffrement et les 9 multiplications modulo 2^130 − 5 sortent de la preuve.
- **L'arithmétique de ML-KEM-768** est prouvée sur des bits, en trois parties :
  - la clé secrète contre la clé publique, `A s + e = t`, où `A` est public ;
  - le déchiffrement `m'` ;
  - le rechiffrement de la transformation de Fujisaki-Okamoto, comparé au chiffré.

  Chaque produit a un facteur public. Le prouveur fournit chaque réduction modulo `q`, et le circuit la vérifie.
- **X25519** est évalué par une multiplication modulo 2^255 − 19 sur des bits. Les deux échelles de Montgomery en demandent 6 140.
- **Les vérifications.** Chaque circuit est comparé à une implémentation en clair sur sa première instance, et chaque preuve se termine par le verdict du vérifieur.
- **Les parties sont mesurées côte à côte.** L'énoncé complet relie les sorties Keccak aux entrées secrètes de la partie réseau, et les sorties BLAKE3 à la clé ChaCha20. Ces liaisons n'ajoutent aucune porte AND.

### 1.2 Les mesures

Intel Xeon à 2,10 GHz, 4 vCPU, prouveur et vérifieur sur la même machine :

| Preuve | Portes AND | Envoyé par le prouveur | Envoyé par le vérifieur | Temps |
| --- | ---: | ---: | ---: | ---: |
| Mise en place seule | 0 | 146 309 o | 501 728 o | 0,18 s |
| Hachage | 1 050 480 | 289 733 o | 501 728 o | 0,26 à 0,31 s |
| Hachage et ML-KEM | 9 724 459 | 1 473 733 o | 501 728 o | 0,82 à 0,89 s |
| Une multiplication modulo 2^255 − 19 | 198 651 | 24,8 Ko (pente) | | 14 ms (pente) |

- Au-delà de la mise en place, une preuve coûte 1,06 bit par porte AND, à 14 à 17 millions de portes par seconde.
- La partie ML-KEM compte 8 673 979 portes : 26 108 produits réduits modulo `q` et 38 912 additions.
- Le backend arithmétique d'emp-zk travaille dans F_{2^61−1}. Une multiplication y coûte 8 octets et 0,15 µs, après une mise en place de 32,9 Mo.

### 1.3 Ce que cela change

- **L'estimation de la note précédente** (0,4 Mo) comptait chaque partie dans son corps :
  - ML-KEM dans F_q, où son arithmétique à facteurs publics est linéaire, donc gratuite ;
  - X25519 dans son corps premier.

  emp-zk n'offre que les bits et F_{2^61−1}. La partie ML-KEM passe donc en bits (1,2 Mo), et la mise en place ajoute 0,65 Mo. Le hachage, lui, correspond à l'estimation : un bit par porte.
- **X25519 en bits** coûterait 1,2 milliard de portes, soit environ 150 Mo et 90 s : hors de portée d'un téléphone.
  - Dans une preuve à base de VOLE sur F_{2^255−19}, QuickSilver envoie un élément du corps par multiplication : 6 140 × 32 octets, environ 0,2 Mo.
  - S'y ajoute une mise en place à dimensionner pour si peu de multiplications. Celle d'emp-zk pour F_{2^61−1}, faite pour des millions, envoie 32,9 Mo.
- **ML-KEM dans F_q** ramènerait sa partie de 1,2 Mo à presque rien. Il faudrait en échange convertir les bits secrets en éléments de F_q : les échantillons, 4 bits par coefficient, et les arrondis. Les conversions de [Mystique](https://eprint.iacr.org/2021/730) s'en chargent.
- **Au total**, avec les trois corps, on revient à l'estimation : environ 0,4 Mo, plus les mises en place.
  - Avec emp-zk tel quel et sans X25519, c'est déjà 2 Mo et moins d'une seconde.
  - Pour un événement rare, c'est à la portée d'un téléphone.

### 1.4 Deux raccourcis écartés

On pourrait éviter de prouver X25519 ou ML-KEM en révélant un morceau du secret partagé. Aucun des deux raccourcis ne tient.

- **Révéler `ss_X`, le secret X25519 de l'encapsulation**, avec une preuve d'égalité de logarithmes discrets.
  - Le membre devient alors un oracle Diffie-Hellman statique pour la clé du nœud.
  - Un adversaire recopie le `ct_X` d'une enveloppe honnête vers le même nœud dans une enveloppe fausse. Le membre qui la conteste lui livre la moitié X25519 du secret de l'enveloppe honnête.
  - Ce secret ne repose alors plus que sur ML-KEM, et l'hybride perd sa raison d'être.
- **Révéler `m'`, le message que rend le déchiffrement de ML-KEM.**
  - C'est un oracle de déchiffrement sur des chiffrés invalides.
  - Un tel oracle suffit à retrouver la clé secrète : c'est ce que la transformation de Fujisaki-Okamoto sert à empêcher.

Le litige économique avait été écarté pour la même raison (`wrap_dispute_replay.pv`) : ce qu'on révèle d'une décapsulation ne doit pas dépendre d'un chiffré choisi par l'adversaire.

### 1.5 Des juges pairs pour les nœuds internes

Tous les membres placés sous un nœud interne en détiennent la clé. Une enveloppe fausse vers ce nœud les bloque tous.

- Le serveur peut demander à un autre membre sous ce nœud de confirmer le litige, sans preuve.
- Cette confirmation ne vaut rien si les membres sous le nœud sont alliés, ni pour une enveloppe vers une feuille, qui n'a qu'un détenteur.
- Elle ne remplace donc pas la preuve. Elle la rend nécessaire seulement quand les pairs manquent ou se contredisent.

## 2. L'authentification dans le modèle calculatoire

La note précédente laissait l'authentification au modèle symbolique. Deux propriétés passent au modèle calculatoire, sous forme de correspondances d'événements : CryptoVerif prouve qu'un événement n'arrive qu'après un autre.

| Modèle | Ce qu'il vérifie | Verdict | Borne |
| --- | --- | --- | --- |
| `relay_tag` | Le relais d'un îlot connaît l'init de l'époque précédente et le vrai secret de fenêtre. Il donne au membre B un secret de son choix. B en dérive l'époque et ne l'accepte que si le tag correspond au tag scellé, reçu authentiquement. | Prouvé : B n'accepte que le vrai secret. | 6 · Pcr, la résistance aux collisions de chacune des six étapes de la chaîne |
| `relay_tag_unbound` | Un tag qui ne dépend pas du secret de fenêtre. | Non prouvé. | |
| `witness_quorum` | Points de contrôle contresignés par 3 témoins sur 4. Le serveur choisit ce que chaque témoin honnête signe, une fois par époque. Le témoin 4 lui donne sa clé. | Prouvé : deux membres qui acceptent un point de contrôle de l'époque acceptent le même. | 3 · Psign, une par témoin honnête (EUF-CMA) |
| `witness_quorum_two_dishonest` | Deux témoins malhonnêtes. | Non prouvé ; la bifurcation existe. | |
| `witness_quorum_two_of_four` | Un quorum de 2 sur 4. | Non prouvé ; la bifurcation existe. | |

- **Le relais menteur.** Le relais choisit son secret après avoir vu le vrai, avec des clés qu'il connaît toutes. Il est pris si aucune des six étapes n'a deux entrées de même image.
  - La preuve suppose BLAKE3 résistant aux collisions, une hypothèse un peu plus forte que la résistance aux secondes préimages qu'évoquait la note précédente.
  - C'est la contrepartie calculatoire de `ilot_relay.pv`.
- **Les témoins.** Le quorum `k = 2f + 1` sur `n = 3f + 1` de la note précédente est prouvé pour `f = 1`. Les contrôles montrent qu'un témoin malhonnête de plus, ou un quorum plus bas, suffit à faire bifurquer le groupe.
- **Ce qui reste symbolique** :
  - les signatures des sceaux, des admissions et des requêtes ;
  - le contenu d'un point de contrôle.

## 3. Le saut sous une clé d'appareil volée

### 3.1 Ce qu'ETK a montré pour MLS

[ETK (Cremers, Günsay, Wesselkamp et Zhao, Eurocrypt 2026)](https://eprint.iacr.org/2025/229) est la première analyse des opérations externes de MLS, commits et propositions externes. Elle montre qu'avec ces opérations, MLS guérit d'une compromission de l'état de session, mais pas de celle des secrets de long terme.

- Qui détient la clé de signature d'un membre peut, à tout moment, le remplacer dans le groupe par un commit externe (*resync*), même après que ses mises à jour ont guéri son état.
- ETK propose ETK^PSK : le membre qui revient injecte une PSK de reprise tirée d'une époque passée, qu'un adversaire sans son état n'a pas.
- ETK montre aussi que MLS n'atteint sa fonctionnalité qu'avec des signatures fortement infalsifiables (SUF-CMA). C'est le cas de ML-DSA-65, que la spécification suppose telle (section 2.3).

### 3.2 Le saut dans City-G

La v0.4 offre trois façons de revenir (spécification, section 12.10). Dans le *saut* :

1. le membre enregistre une `CatchUpRequest` signée de sa clé d'appareil, liée au transcript courant, avec une clé d'init à usage unique ;
2. la fenêtre suivante lui scelle un welcome : le joiner secret de l'époque, chiffré vers cette clé d'init (section 11) ;
3. le welcomer vérifie la signature, que le membre est bien dans l'arbre, et le transcript. Il prend la clé d'init dans la requête.

Supposons qu'un voleur détienne la clé d'appareil d'un membre, mais pas son état (l'adversaire A6). Il peut alors :

1. signer une `CatchUpRequest` au nom du membre, avec une clé d'init à lui ;
2. recevoir le welcome, donc le joiner secret, donc toute l'époque ;
3. recommencer à chaque fenêtre.

L'attaque a trois propriétés :

- **Elle est furtive.** Un saut n'est pas un changement (section 10.1). L'arbre ne bouge pas, le sceau ne mentionne pas le saut, et le membre, qui suit le groupe, ne voit rien.
- **Elle est durable.** Les mises à jour du membre changent sa clé de feuille, pas sa clé d'appareil ; elles n'arrêtent rien.
- **ProVerif la trouve** (`catch_up_device_key.pv`). Le contrôle de vivacité montre que le saut du vrai membre, lui, fonctionne toujours.

**La spécification n'est pas contredite.**
- Contre A6, elle ne promet ni confidentialité ni guérison « jusqu'au retrait de l'appareil » (section 2.2). Elle dit aussi que la clé d'appareil permet de signer des requêtes.
- Mais la réparation qu'elle prévoit, retirer l'appareil, suppose qu'on remarque le vol.
- Par une mise à jour ou une ré-entrée, le voleur change la feuille du membre. Le membre ne peut plus suivre le groupe et s'en aperçoit (section 12.2).
- Par le saut, en revanche, personne ne s'aperçoit jamais de rien.

### 3.3 Le correctif : lier le welcome du saut à la clé de feuille

Le membre qui saute garde sa clé de feuille (section 12.10). Il suffit donc que le welcome d'un saut en dépende :

```text
(ct,  ss)      := X-Wing.Encaps(init_key)            clé d'init, prise dans la requête
(ct2, ss_leaf) := X-Wing.Encaps(leaf_key)            clé de feuille, prise dans l'arbre
wk             := Extract(ss, ss_leaf)
sealed         := ChaCha20-Poly1305(ExpandLabel(wk, "welcome key", context, 32),
                                    ExpandLabel(wk, "welcome nonce", context, 12),
                                    aad = context, joiner_secret_n)
```

Le `context` inclut en plus `kem_pk_hash(leaf_key)`. Le welcomer prend la clé de feuille dans l'arbre, qu'il a vérifié contre son en-tête (section 12.3), jamais dans la requête.

- **La clé d'init garde la confidentialité persistante du welcome.** Si la clé de feuille fuit plus tard, le welcome reste fermé, car la clé d'init a été effacée. Cette garantie repose sur la PRF par le sel, comme aujourd'hui.
- **La clé de feuille lie le saut à l'état du membre.** Le voleur de la seule clé d'appareil ne l'a pas.
  - Cette garantie repose sur la PRF par l'entrée, la moitié de la PRF double que la spécification suppose déjà (section 3.3).
  - L'ordre des arguments est choisi pour que ce que garantit la v0.4 garde son hypothèse d'origine.
- **Coût.** Par saut, un chiffré X-Wing de plus (1 120 octets) et une encapsulation, environ 0,15 ms. Le membre fait une décapsulation de plus.
- **Preuves.**
  - ProVerif prouve que l'époque reste secrète, et que le saut du vrai membre fonctionne toujours (`catch_up_leaf_bound.pv`).
  - CryptoVerif prouve que le joiner secret reste secret, sous IND-CCA2, la PRF double, la PRF et l'AEAD (`catch_up_leaf_bound.ocv`). Avec la règle de la v0.4, il ne prouve rien (`catch_up_init_only.ocv`).
- **C'est l'idée d'ETK^PSK, sans PSK.** Le secret qui prouve l'appartenance passée est la clé de feuille : le membre l'a déjà, et ses mises à jour la renouvellent.

### 3.4 Ce que devient le voleur d'une clé d'appareil

| Ce que le voleur signe | Règle de la v0.4 | Avec le correctif |
| --- | --- | --- |
| Des sauts, avec ses propres clés d'init | chaque époque, sans laisser de trace | rien : il lui manque la clé de feuille |
| Une mise à jour vers une clé de feuille à lui, puis des sauts | chaque époque ; le membre, exclu, s'en aperçoit | pareil |
| Une ré-entrée | la place entière du membre ; le membre, exclu, s'en aperçoit | pareil |
| Le retrait du membre | le retrait, visible | pareil |
| Des admissions, si l'appareil est admin | des entrées, visibles dans le sceau | pareil |

Avec le correctif, une clé d'appareil seule ne donne plus accès à aucune époque sans changer la feuille du membre. Ce changement exclut le membre du groupe, et il s'en aperçoit.

Un DS allié au voleur peut aussi lui confier des tâches de committer. Le voleur tire alors des secrets de nœud, mais sans l'init de l'époque précédente il n'en tire pas l'époque : c'est la chaîne d'init (décision E-5).

Si le voleur a aussi l'état du membre (A5 et A6 ensemble) :
- il lit jusqu'à la prochaine mise à jour du membre ;
- pour continuer ensuite, il doit remplacer la feuille du membre, et cela se voit aussi.

La ligne A6 du tableau des garanties pourrait donc passer de « non, jusqu'au retrait de l'appareil » à : « non, mais après la prochaine mise à jour du membre, tout usage de la clé l'exclut du groupe, et il s'en aperçoit ».

### 3.5 La ré-entrée reste liée à la seule clé d'appareil

ETK^PSK lierait aussi la ré-entrée à un secret passé. Dans City-G, la ré-entrée sert au membre qui revient quand personne n'est en ligne : il scelle lui-même la fenêtre (section 12.7). Deux façons de la lier coûtent trop :

- **Une PSK d'une époque passée.** Tous les membres devraient garder les secrets de reprise de toutes les époques d'où quelqu'un peut revenir. Ceux entrés depuis ne pourraient plus suivre.
- **Une preuve de possession de la clé de feuille.** C'est une clé de KEM : il faudrait une signature de plus par feuille, ou une preuve à divulgation nulle.

Le gain ne justifie pas ce coût : une ré-entrée volée remplace la feuille du membre, qui s'en aperçoit. La règle à ajouter est côté client. Un membre qui trouve sa feuille changée par une requête qu'il n'a pas faite traite sa clé d'appareil comme volée et demande son retrait.

### 3.6 Le correctif, appliqué

Le mainteneur a donné son accord, et la v0.4 a changé en conséquence :

- **La spécification** :
  - section 11 : le welcome d'un saut, avec la seconde encapsulation et le nouveau contexte ; le welcome gagne un champ, nul pour les entrées et les ré-entrées ;
  - section 12.10 : le membre ouvre le welcome avec sa clé de feuille, l'actuelle ou celle en attente si une mise à jour à lui a été appliquée ;
  - section 2.2 : le paragraphe sur les clés d'appareil ;
  - section 12.2 : la règle du membre dont la feuille a changé sans lui.
- **Le modèle symbolique de la v0.4** (`docs/formal/`) : `catch_up_stolen_key.pv` (prouvé) et `catch_up_init_only.pv` (attaque, l'ancienne règle).
- **`cityg-core`** : le welcome des sauts, l'erreur `LEAF_TAKEN` du membre dont la feuille a changé sans lui, et quatre scénarios : le voleur qui demande un saut, le voleur qui change la feuille, le saut après une mise à jour appliquée en l'absence du membre, et le saut accueilli par un entrant.

## 4. Le plan de preuve de l'arbre

### 4.1 L'énoncé visé

Le jeu est une « CGKA à fenêtres », dans le style de TTKEM et d'ETK.

- L'adversaire est le DS (A2). Il décide quelles requêtes entrent dans quelle fenêtre, et qui committe, scelle, relaie ou accueille.
- Il corrompt à tout moment, au vu de tout ce qui précède, l'état (A5) ou la clé d'appareil (A6) des membres de son choix. Il peut aussi être membre (A3) ou retiré (A4).
- Il demande le secret d'une époque, qui lui est donné réel ou aléatoire.

Une époque est *sûre* si aucune corruption n'y mène dans le graphe des secrets. Ce graphe relie les secrets de nœud et l'init de l'époque précédente par :
- les taches ;
- les enveloppes ;
- les welcomes, y compris ceux des sauts, avec le correctif ;
- la chaîne d'init.

Les scénarios ProVerif et les modèles CryptoVerif vérifient ce prédicat sur des cas particuliers, un par un.

La forme visée de la borne, pour une époque sûre, `n` membres et `Q` opérations, avec BLAKE3 en oracle aléatoire interrogé `q` fois :

```text
Avantage ≤ (Q n)^2 · (ε_CCA(X-Wing) + ε_AEAD(ChaCha20-Poly1305)) + Q · ε_SUF-CMA(ML-DSA-65) + q^2 / 2^256
```

### 4.2 Pourquoi des oracles aléatoires

`open_problems_sim.py`, rapport 4. Une réduction qui perd un facteur `L` retire `log2 L` bits à la sécurité de la primitive : sur 192 pour ML-KEM-768 (catégorie 3 du NIST), sur 128 pour X25519. X-Wing tient si l'un des deux tient.

| Membres | Opérations | Perte, oracles aléatoires | Bits restants, ML-KEM-768 | Bits restants, X25519 | Perte, modèle standard |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 2^10 | 2^20 | 2^60 | 132 | 68 | 2^200 |
| 2^16 | 2^30 | 2^92 | 100 | 36 | 2^480 |
| 2^20 | 2^20 | 2^80 | 112 | 48 | 2^400 |
| 2^20 | 2^30 | 2^100 | 92 | 28 | 2^600 |

- **L'échelle.** Un million de membres avec un changement toutes les 0,1 s font environ 2^28 opérations par an.
- **Le modèle standard.** La perte `Q^log n` de TTKEM dépasse partout 2^192 : la borne ne dit rien.
  - Ce n'est pas un défaut de cette preuve-là. [Kamath, Klein, Pietrzak et Walter](https://eprint.iacr.org/2021/059) montrent que, sur les protocoles de type TreeKEM, toute réduction en boîte noire qui ne rembobine pas l'adversaire perd au moins `n^Ω(log log n)`.
- **Les oracles aléatoires.** La perte y est polynomiale : à un million de membres et 2^30 opérations, il reste 92 bits.
  - La moitié X25519 seule n'en garderait que 28. C'est une limite de la borne, pas une attaque.
  - ETK prouve MLS de la même façon : HKDF et le MAC y sont remplacés par un oracle aléatoire global.

### 4.3 Ce que fournit la littérature

| Mécanisme de City-G | Analyse à suivre | Ce qui manque |
| --- | --- | --- |
| Règle des taches ; secrets tirés hors de son chemin | [TTKEM (IEEE S&P 2021)](https://eprint.iacr.org/2019/1489) : corruptions adaptatives, serveur actif, perte `(Qn)^2` avec oracles aléatoires | plusieurs committers par fenêtre, et un scelleur |
| Calendrier de clés (init, joiner, époque, tag) | [Brzuska, Cornelissen et Kohbrok (IEEE S&P 2022)](https://eprint.iacr.org/2021/137) ; ETK | les clés d'arbre stables pendant des fenêtres (`fs_stable_keys`) |
| Fenêtre d'entrant (init externe, secret de commit constant) | ETK, pour les commits externes | la fenêtre scellée seule (`entrant_window`) |
| Saut | aucune : MLS n'a pas de saut | le lemme du correctif (`catch_up_leaf_bound`) |
| Îlots, relais, ville entretenue | aucune | les lemmes `relay`, `relay_tag` et `city_*` |
| Initiés : committers malveillants | [Alwen, Jost et Mularczyk (Crypto 2022)](https://eprint.iacr.org/2020/1327) ; ETK, avec initiés malveillants | la solidité des audits et des litiges |
| L'arbre non borné, symboliquement | [Wallez, Protzenko et Bhargavan (IEEE S&P 2025)](https://eprint.iacr.org/2025/410), TreeKEM dans DY* | une voie possible pour le prédicat de sûreté |

### 4.4 Ce qui est déjà mécanisé

Les 21 modèles CryptoVerif sont les lemmes d'une fenêtre, dans le modèle standard, avec leurs hypothèses exactes :

- **Confidentialité persistante avec des clés stables** : `fs_stable_keys`, sous la PRF par le sel.
- **Guérison et retrait** : `sticky_removal`, `city_maintained` et `city_sticky`, sous la PRF double.
- **Entrant** : `entrant_window`, sous IND-CCA2 et la PRF double.
- **Îlots** : `relay` (secret) et `relay_tag` (authentification, résistance aux collisions).
- **Générateur faible** : `weak_rng`.
- **Saut** : `catch_up_leaf_bound`.
- **Bifurcations** : `witness_quorum`.
- **Contrôles** : onze modèles, dont l'échec vérifie que chaque hypothèse sert.

Côté symbolique, 18 + 17 + 34 scénarios ProVerif instancient le prédicat de sûreté sur de petits arbres.

### 4.5 Ce qui reste à écrire

La note [preuve de l'arbre](preuve-arbre-2026-09-26.md) fait depuis le point 1, rend le prédicat exécutable, esquisse le point 2 pas à pas et ajoute les lemmes de la règle des taches et de la guérison. L'argument adaptatif du point 2 reste le gros du travail.


1. **Le jeu et le prédicat de sûreté.** On les calque sur le prédicat *can-traverse* d'ETK, en y ajoutant les taches, les fenêtres à plusieurs committers, les entrants et les sauts.
2. **La preuve hybride dans le modèle de l'oracle aléatoire.** On suit TTKEM : on range les secrets de nœud par ordre de création, on devine le chemin du défi, puis on remplace les secrets partagés des enveloppes un à un, sous IND-CCA2. Chaque lemme de la section 4.4 justifie un pas.
3. **L'authentification** repose sur trois hypothèses :
   - ML-DSA-65 SUF-CMA, pour les sceaux et les requêtes ;
   - la résistance aux collisions, pour le haché de l'arbre et le tag ;
   - le quorum, pour les témoins.
4. **Les initiés.** Il faut borner la probabilité qu'une entrée invalide échappe aux audits (`e^-AUDIT_K`), et prouver la solidité des preuves de litige.
5. **La vérification mécanique.** Les lemmes sont déjà dans CryptoVerif. L'argument sur l'arbre s'écrit à la main, ou dans un assistant de preuve (EasyCrypt, SSProve). Le prédicat peut aussi se vérifier symboliquement dans DY*, comme l'ont fait Wallez et al.

## 5. BLAKE3 ou HKDF

`Extract` sert trois fois dans la v0.4 :
- le joiner secret, une fois par fenêtre ;
- la couverture des secrets frais, une fois par nœud re-keyé ;
- l'init externe, dont le sel est `ZERO32`.

Ses entrées sont toujours des secrets de 32 octets. Trois options se présentent, selon ce qui fonde la PRF double :

| Option | Ce qui fonde la PRF double | Coût |
| --- | --- | --- |
| BLAKE3 (v0.4) | rien de publié ; l'argument est heuristique | aucun |
| HKDF-Extract (HMAC) | prouvé dans le modèle standard ([Backendal et al., Crypto 2023](https://eprint.iacr.org/2023/861)) si l'ensemble des clés est *faisable*, par exemple de longueur fixe au plus un bloc, sous des hypothèses sur la compression de SHA-2 ; c'est l'hypothèse des analyses de MLS | une fonction de hachage de plus dans la suite |
| KMAC256 (Keccak) | seulement dans le modèle de la permutation idéale, où l'argument des éponges à clé vaut aussi quand le secret suit un préfixe connu | aucune primitive de plus : X-Wing et ML-DSA emploient déjà Keccak |

Deux points décident :

- **La preuve de l'arbre ne distingue pas les options.** Elle se fait avec des oracles aléatoires (section 4.2), qui sont des PRF doubles.
- **Les lemmes, eux, les distinguent.** Dans le modèle standard, seule HMAC a une preuve. Les clés de City-G sont de longueur fixe et plus courtes qu'un bloc : elles sont faisables.

**Recommandation** pour le prochain profil :
- passer `Extract` seul en HKDF-Extract avec SHA-384, sortie tronquée à 32 octets, comme la suite MLS la plus proche (`MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44`) ;
- garder BLAKE3 pour `ExpandLabel`, `DeriveSecret`, le MAC et le haché, où il n'est qu'une PRF au sens habituel, ou résistant aux collisions.

Le coût reste de quelques microsecondes par fenêtre. La v0.4 garde BLAKE3 et l'hypothèse énoncée à la section 3.3. Le choix revient au mainteneur.

## 6. Où en sont les problèmes ouverts

| Problème | État | Ce qui reste |
| --- | --- | --- |
| 1. Preuve calculatoire | 21 modèles, dont l'authentification ; plan de preuve de l'arbre écrit ; voie de l'oracle aléatoire retenue | Écrire la preuve de l'arbre ; les initiés |
| 2. Preuves de litige | Mesuré : hors X25519, 2 Mo et moins d'une seconde | Prouver X25519 dans son corps ; mesurer sur téléphone |
| 3. Bifurcations | Quorum prouvé dans le modèle calculatoire | La confiance dans les témoins |
| 4. Standards | Recommandation : `Extract` en HKDF-SHA-384 | La décision du mainteneur ; FN-DSA final |
| 5. Cartes d'émetteur | Inchangé | Mesurer sur des traces |
| 6. Métadonnées | Ramené aux limites de MLS | Le transport |
| 7. Spécification et implémentation | Correctif du saut appliqué à la v0.4 | Le profil candidat, sur l'accord du mainteneur |

Le nouvel ordre :
1. la preuve de l'arbre ;
2. X25519 dans le litige ;
3. la spécification du profil candidat.

Le correctif du saut, qui venait en tête, est appliqué.

## 7. Modèles et reproductibilité

- **Le litige.** Construire emp-toolkit, puis le prouveur, comme l'indique [`dispute-zk/README.md`](dispute-zk/README.md). La mesure se lance avec `./dispute_zk 1 full & ./dispute_zk 2 full`, et les autres modes avec `setup`, `dispute`, `mlkem`, `x25519mul N` et `arith N`.
- **CryptoVerif.** `docs/research/formal-computational/run.sh [chemin/de/cryptoverif]` lance les 21 modèles en une vingtaine de secondes. La CI les lance aussi.
- **ProVerif.** `docs/research/formal-parity/run.sh` lance les 34 scénarios, dont `catch_up_device_key` (attaque) et `catch_up_leaf_bound` (prouvé). Le modèle de la v0.4, `docs/formal/`, reçoit depuis la même paire (18 scénarios) ; `formal-messages/` (17) est inchangé.
- **Le modèle de coût.** `python3 docs/research/open_problems_sim.py` produit les quatre rapports, dont celui de la section 4.2.

## 8. Sources

* J. Alwen et al., [Keep the Dirt: Tainted TreeKEM, Adaptively and Actively Secure Continuous Group Key Agreement](https://eprint.iacr.org/2019/1489), IEEE S&P 2021.
* C. Kamath, K. Klein, K. Pietrzak, M. Walter, [The Cost of Adaptivity in Security Games on Graphs](https://eprint.iacr.org/2021/059), TCC 2021.
* C. Cremers, E. Günsay, V. Wesselkamp, M. Zhao, [ETK: External-Operations TreeKEM and the Security of MLS in RFC 9420](https://eprint.iacr.org/2025/229), Eurocrypt 2026.
* C. Brzuska, E. Cornelissen, K. Kohbrok, [Security Analysis of the MLS Key Derivation](https://eprint.iacr.org/2021/137), IEEE S&P 2022.
* J. Alwen, D. Jost, M. Mularczyk, [On the Insider Security of MLS](https://eprint.iacr.org/2020/1327), Crypto 2022.
* T. Wallez, J. Protzenko, K. Bhargavan, [TreeKEM: A Modular Machine-Checked Symbolic Security Analysis of Group Key Agreement in Messaging Layer Security](https://eprint.iacr.org/2025/410), IEEE S&P 2025.
* M. Backendal, M. Bellare, F. Günther, M. Scarlata, [When Messages are Keys: Is HMAC a dual-PRF?](https://eprint.iacr.org/2023/861), Crypto 2023.
* M. Bellare, A. Lysyanskaya, [Symmetric and Dual PRFs from Standard Assumptions: A Generic Validation of a Prevailing Assumption](https://eprint.iacr.org/2015/1198), Journal of Cryptology, 2024.
* K. Yang, P. Sarkar, C. Weng, X. Wang, [QuickSilver: Efficient and Affordable Zero-Knowledge Proofs for Circuits and Polynomials over Any Field](https://eprint.iacr.org/2021/076), CCS 2021 ; la bibliothèque [emp-zk](https://github.com/emp-toolkit/emp-zk).
* C. Weng, K. Yang, X. Xie, J. Katz, X. Wang, [Mystique: Efficient Conversions for Zero-Knowledge Proofs with Applications to Machine Learning](https://eprint.iacr.org/2021/730), USENIX Security 2021.
* M. Barbosa et al., [X-Wing: The Hybrid KEM You've Been Looking For](https://eprint.iacr.org/2024/039), 2024.
* NIST, [FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final), 2024.
* B. Blanchet et al., [CryptoVerif](https://bblanche.gitlabpages.inria.fr/CryptoVerif/), version 2.13 ; [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/), version 2.05.
* Notes précédentes : [problèmes ouverts](problemes-ouverts-2026-09-26.md), [au-delà de 0.4](au-dela-0.4-2026-09-26.md), [îlots](ilots-2026-09-26.md), [parité MLS](parite-mls-2026-09-26.md).
