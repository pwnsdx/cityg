# La preuve de l'arbre : le jeu, le prédicat de sûreté et l'esquisse

| | |
| --- | --- |
| Date | 2026-09-26 |
| Nature | Note de recherche. Elle poursuit le plan de la note [preuves et mesures](preuves-et-mesures-2026-09-26.md) (section 4). Elle écrit le jeu de sécurité de City-G sous corruptions adaptatives et son prédicat de sûreté, rendu exécutable et vérifié contre les modèles formels. Elle esquisse ensuite la preuve avec des oracles aléatoires, pas à pas, avec le lemme mécanisé de chaque pas, et ajoute deux lemmes calculatoires : la règle des taches et la guérison par mise à jour. Ce n'est pas encore une preuve complète ; la section 6 dit ce qui manque. |
| Question | Que faut-il démontrer, exactement, pour que la sécurité de l'arbre entier soit prouvée, et qu'est-ce qui l'est déjà ? |
| Compagnons | [`safety_predicate.py`](safety_predicate.py) : le prédicat, sur 25 traces, avec pour chacune le verdict du modèle qu'elle reprend (`python3 docs/research/safety_predicate.py`). [`formal-computational/`](formal-computational/README.md) : 25 modèles CryptoVerif, dont 4 nouveaux. |
| Auteur | Claude Code (assistant IA d'Anthropic), à la demande du mainteneur. C'est une esquisse : le jeu et le prédicat sont précis, les pas de la preuve sont justifiés par des lemmes mécanisés sur des configurations fixées, mais l'argument adaptatif sur l'arbre entier reste à écrire. Une relecture cryptographique humaine reste nécessaire. |

## 0. Résumé

1. **Le jeu.** C'est une CGKA à fenêtres, dans le style de TTKEM et d'ETK.
   - L'adversaire est le DS : il choisit les fenêtres et les rôles, et livre ce qu'il veut à qui il veut.
   - Il corrompt, quand il veut et au vu de tout ce qui précède, l'état d'un membre ou sa clé d'appareil ; il peut fixer l'aléa d'un membre, et être membre lui-même.
   - Il demande le secret de message d'une époque, réel ou aléatoire.
2. **Le prédicat de sûreté.** Une époque est sûre si aucune fuite n'atteint son secret de message dans le graphe des secrets.
   - Sept règles décrivent ce que l'adversaire tire de ce qu'il a : les dérivations, `Extract`, les enveloppes, les deux sortes de welcomes, l'init externe, le tag.
   - [`safety_predicate.py`](safety_predicate.py) le calcule sur des traces. Sur 25 traces tirées des modèles formels (ProVerif et CryptoVerif) et d'un tableau de la note précédente, il rend chaque fois le verdict du modèle.
3. **Le théorème visé**, avec BLAKE3 en oracle aléatoire : un avantage d'au plus `(Qn)^2 · (ε_CCA + ε_AEAD) + Q · ε_SUF-CMA + q^2 / 2^256`, la perte de TTKEM.
4. **L'esquisse.** Quatre pas mènent du jeu réel à un jeu où le secret défié est un aléa indépendant :
   - l'authenticité, par les signatures et la résistance aux collisions ;
   - la devinette de TTKEM, source de la perte ;
   - les enveloppes et les welcomes vers des clés sûres, par IND-CCA2 et l'AEAD ;
   - les dérivations de secrets sûrs, par les oracles aléatoires, ou la PRF double dans le modèle standard.

   Chaque pas a son lemme mécanisé, fenêtre par fenêtre.
5. **Deux lemmes nouveaux dans CryptoVerif.** La règle des taches (`taint.ocv`) et la guérison par mise à jour (`post_compromise.ocv`) sont prouvées ; leurs contrôles échouent comme prévu. Ce sont les contreparties calculatoires de `taint.pv` et de `post_compromise.pv`.
6. **Ce qui manque** : l'argument adaptatif lui-même, écrit pour des fenêtres à plusieurs committers, des entrants et des sauts ; la solidité des audits et des litiges ; une vérification mécanique de bout en bout.

## 1. Le jeu : une CGKA à fenêtres

### 1.1 Ce que l'adversaire contrôle

Les adversaires sont ceux de la spécification (section 2.1), réunis en un seul :

- **Le DS (A2)** :
  - il décide quelles requêtes entrent dans quelle fenêtre, et qui committe, scelle, accueille et relaie ;
  - il livre ce qu'il veut, à qui il veut, quand il veut ;
  - il crée ses propres appareils, qui rejoignent un groupe ouvert.
- **Les corruptions, adaptatives** : à tout moment, et au vu de tout ce qui précède, il obtient :
  - l'état d'un membre (A5) ;
  - sa clé d'appareil (A6) ;
  - ou le contrôle d'un membre, qui dévie à sa guise (A3) et garde ce qu'il sait une fois retiré (A4).
- **L'aléa** : il peut fixer le prochain tirage d'un membre, comme un générateur cassé.

### 1.2 Les oracles

| Oracle | Effet |
| --- | --- |
| `Rejoindre(appareil, admission)` | un appareil honnête signe une demande d'entrée, que le DS reçoit |
| `Demander(membre, genre)` | un membre honnête signe une mise à jour, un saut, une ré-entrée ou un retrait |
| `Fenêtre(tâche)` | le DS ouvre une fenêtre ; les rôles honnêtes committent, scellent et accueillent, l'adversaire joue les autres |
| `Livrer(membre, paquet ou entrée)` | un membre honnête suit une fenêtre, ou un appareil entre, avec les vérifications de la spécification (sections 12.2 à 12.10) |
| `CorrompreÉtat(membre)` | l'adversaire reçoit l'état courant du membre (A5) |
| `CorrompreClé(membre)` | l'adversaire reçoit la clé d'appareil du membre (A6) |
| `Aléa(membre, r)` | le prochain tirage du membre vaut `r` |
| `Défi(n)` | une seule fois : le secret de message de l'époque `n`, ou un aléa, selon un bit caché |

### 1.3 Gagner

L'adversaire gagne s'il devine le bit, et si l'époque défiée est sûre au sens de la section 2, évaluée sur toute la partie. Corrompre plus tard un membre qui détient encore les secrets de l'époque défiée la rend non sûre : un tel adversaire ne compte pas.

L'authenticité est un but à part. Deux membres honnêtes qui acceptent l'époque `n` avec le même haché de transcript s'accordent sur l'arbre, le registre et le transcript, et aucun membre n'accepte une époque que ni un scelleur honnête ni un scelleur corrompu n'a faite. La preuve la prend comme premier pas (section 4).

## 2. Le graphe des secrets et le prédicat de sûreté

### 2.1 Les règles

Un secret est connu de l'adversaire s'il fuit, ou si une règle le déduit de secrets connus :

| Mécanisme | Règle | Ce qui empêche d'en tirer davantage |
| --- | --- | --- |
| Dérivations : `ExpandLabel`, `DeriveSecret`, paires de clés de nœud, chaînage d'un chemin, clé de relais, et l'époque vers ses secrets (`init`, `msg`, `confirm`, `external`) | `x ⇒ y` | PRF, ou oracle aléatoire |
| `Extract` : joiner secret, init externe, couverture des secrets frais, clé du welcome d'un saut | `a ∧ b ⇒ y` | PRF double, ou oracle aléatoire |
| Enveloppe vers le nœud `t` (X-Wing et ChaCha20-Poly1305) | clé de `t` ⇒ secret enveloppé | IND-CCA2 et AEAD |
| Welcome d'une entrée ou d'une ré-entrée | clé d'init ⇒ joiner secret | IND-CCA2 et AEAD |
| Welcome d'un saut | clé d'init ∧ clé de feuille ⇒ joiner secret | IND-CCA2, AEAD et PRF double |
| Init externe d'une fenêtre d'entrant | clé externe de `n − 1` ⇒ init externe de `n` | IND-CCA2 |
| Tag de confirmation | aucune règle : il ne livre aucun secret | PRF |

### 2.2 Les fuites

| Adversaire | Ce qui fuit |
| --- | --- |
| A5, état compromis au temps `T` | la clé de feuille, les clés en attente, les secrets de chemin, et les secrets d'époque que le membre n'a pas encore effacés |
| A3 et A4, membre malveillant ou retiré | tout ce qu'il sait ou tire, y compris les secrets de nœud qu'il tire comme committer : ses taches |
| A6, clé d'appareil volée | les clés que le voleur met dans ce qu'il signe : la clé de feuille d'une mise à jour ou d'une ré-entrée, la clé d'init d'un saut ou d'une ré-entrée |
| Générateur cassé | le tirage `r` ; le secret frais reste couvert par l'init (section 7.1 de la spécification) |
| Groupe ouvert | les clés d'un appareil du DS qui entre |

### 2.3 Le prédicat

**L'époque `n` est sûre** si son secret de message n'est pas dans la clôture des fuites par les règles, évaluée sur toute la partie.

Le prédicat distingue les mécanismes que les modèles distinguent :
- une enveloppe vers un nœud taché par un retiré expose le secret : c'est la règle des taches (E-4) ;
- une époque dérivée sans la chaîne d'init expose le passé : c'est la chaîne d'init (E-5) ;
- un welcome de saut vers la seule clé d'init donne l'époque au voleur d'une clé d'appareil : c'était la faille corrigée ;
- une fenêtre d'entrant dont le secret de commit est public expose l'époque si un retrait attend.

### 2.4 Exécutable, et vérifié

[`safety_predicate.py`](safety_predicate.py) décrit chaque mécanisme par une règle et calcule la clôture sur des traces. Chaque trace reprend un modèle formel, et le script vérifie que le prédicat rend son verdict :

| Traces | Prédicat | Modèles |
| --- | --- | --- |
| Taches, avec et sans la règle | sûre, exposée | `taint.pv`, `taint_without_rule.pv`, `taint.ocv`, `taint_without_rule.ocv` |
| Guérison, avec et sans mise à jour | sûre, exposée | `post_compromise.pv`, `post_compromise.ocv`, `post_compromise_without_update.ocv` |
| Confidentialité persistante, avec et sans chaîne d'init | sûre, exposée | `forward_secrecy.pv`, `fs_stable_keys.ocv` et leurs contrôles |
| Entrée : l'époque d'avant, l'époque entrée | sûre, exposée | `join.pv` |
| Entrant qui applique un retrait ; groupe ouvert | sûre ; exposée | `entrant_removal.pv` ; `open_group.pv` |
| Saut lié à la feuille ; à la seule clé d'init ; après une mise à jour volée | sûre ; exposée ; exposée | `catch_up_stolen_key.pv`, `catch_up_init_only.pv` et leurs contreparties ; le tableau 3.4 de la note précédente |
| Retrait collant, avec et sans collusion | sûre, exposée | `sticky_removal.ocv`, `sticky_removal_collude.ocv` |
| Entrant seul, sans et avec retrait en attente | sûre, exposée | `ilot_entrant_join.pv`, `entrant_window.ocv` et leurs contrôles |
| Générateur cassé, couvert et non couvert | sûre, exposée | `weak_rng.ocv`, `weak_rng_unhedged.ocv` |
| Relais, racine sûre et connue | sûre, exposée | `ilot_relay.pv`, `relay.ocv`, `relay_known_root.ocv` |
| Ville entretenue ; figée ; figée avec un seul retiré | sûre ; exposée ; sûre | les trois modèles de ville, symboliques et calculatoires |
| Lien d'historique, retiré qui revient | exposée | `history_link_rejoin.pv` |

Les 25 traces s'accordent avec leurs modèles, dont 24 formels ; la 25e reprend le tableau 3.4 de la note [preuves et mesures](preuves-et-mesures-2026-09-26.md).

Le prédicat est une saturation de clauses de Horn, ce que fait ProVerif en plus général. Son intérêt ici est d'être exactement celui de la preuve, sur les objets de City-G. Il fixe les trois points que le théorème doit citer : ce qui fuit, ce qui se déduit, et ce qui compte comme sûr.

## 3. Le théorème visé

**Hypothèses** :
- BLAKE3 en oracle aléatoire pour `H`, `Extract`, `ExpandLabel`, `DeriveSecret` et le MAC, séparés par leurs étiquettes ;
- X-Wing IND-CCA2, avec plusieurs utilisateurs et plusieurs défis ;
- ChaCha20-Poly1305 IND-CPA et INT-CTXT, chaque clé ne servant qu'une fois ;
- ML-DSA-65 fortement infalsifiable (SUF-CMA), comme ETK l'exige pour MLS et comme la spécification le suppose (section 2.3).

**Énoncé.** Pour tout adversaire qui fait `Q` opérations et `q` requêtes à l'oracle aléatoire, sur un groupe d'au plus `n` membres :

```text
Avantage ≤ (Q n)^2 · (ε_CCA(X-Wing) + ε_AEAD(ChaCha20-Poly1305)) + Q · ε_SUF-CMA(ML-DSA-65) + q^2 / 2^256
```

Le facteur `(Qn)^2` est la perte de TTKEM avec des oracles aléatoires. À un million de membres et `2^30` opérations, il retire 100 bits, et il en reste 92 à ML-KEM-768 (note [preuves et mesures](preuves-et-mesures-2026-09-26.md), section 4.2).

## 4. L'esquisse de la preuve

La preuve passe du jeu réel à un jeu où le secret défié est un aléa indépendant de tout ce que voit l'adversaire.

1. **Authenticité (G0 → G1).** On abandonne si l'adversaire :
   - falsifie une signature de requête, de commit, de sceau, d'admission ou de point de contrôle (SUF-CMA) ;
   - ou trouve une collision de `H` sur le haché de l'arbre, le transcript ou la chaîne du tag (résistance aux collisions).

   Après ce pas, chaque membre honnête voit un état public cohérent avec ce que les parties honnêtes ont fait et ce que les parties corrompues ont signé. Un committer, un scelleur ou un welcomer honnête prend les clés dans l'arbre qu'il a vérifié contre son en-tête (section 12.3). Il n'enveloppe donc vers une clé choisie par l'adversaire que si cette clé est dans les fuites.
   - Lemmes : `fabrication.pv`, `anchored_join.pv` et `external_checked.pv` (symboliques) ; `relay_tag.ocv` et `witness_quorum.ocv` (calculatoires).
2. **La devinette (G1 → G2).** Comme dans TTKEM :
   - la réduction devine l'époque défiée et, à chaque remplacement, la clé sûre où elle place le défi IND-CCA2 ;
   - les oracles aléatoires lui permettent de ne pas s'engager sur les dérivations de secrets qu'elle ignore, tant que l'adversaire ne les interroge pas.

   C'est la source de la perte `(Qn)^2`.
3. **Enveloppes et welcomes (G2 → G3).** Dans l'ordre de leur création, chaque enveloppe et chaque welcome vers une clé sûre devient le chiffrement d'un aléa indépendant.
   - Hypothèses : IND-CCA2 de X-Wing, puis l'AEAD, sous une clé que l'oracle aléatoire tire du secret partagé.
   - L'oracle de décapsulation correspond aux membres honnêtes, qui décapsulent ce que le DS leur livre.
   - Pour un welcome de saut, la clé de feuille sûre suffit, même si l'adversaire a choisi la clé d'init.
   - Lemmes : `city_maintained.ocv`, `relay.ocv`, `taint.ocv`, `post_compromise.ocv`, `catch_up_leaf_bound.ocv`.
4. **Dérivations (G3 → G4).** Chaque secret dérivé d'une entrée sûre devient un aléa indépendant : c'est l'oracle aléatoire. `Extract` donne un aléa dès qu'une de ses deux entrées est sûre ; dans le modèle standard, c'est la PRF double.
   - Lemmes : `fs_stable_keys.ocv` (moitié par le sel), `sticky_removal.ocv`, `entrant_window.ocv`, `weak_rng.ocv` et `catch_up_leaf_bound.ocv` (moitié par l'entrée).

Dans G4, le secret de message de l'époque défiée est un aléa que rien ne relie à la vue de l'adversaire : son avantage y est nul. Les pertes s'additionnent pour donner l'énoncé de la section 3.

## 5. Les lemmes, pas par pas

| Pas | Lemme | Modèles CryptoVerif | Hypothèses de la borne |
| --- | --- | --- | --- |
| 1 | Un relais ne fait pas accepter un autre secret de fenêtre | `relay_tag` | résistance aux collisions (6 termes) |
| 1 | Trois témoins sur quatre refusent la bifurcation | `witness_quorum` | EUF-CMA (3 termes) |
| 3 | Un retiré qui a taché un nœud ne lit pas l'époque suivante | `taint` (nouveau) | IND-CCA2 (5), AEAD (5), PRF (11), PRF double par l'entrée (1) |
| 3 | Un membre fuité guérit par sa mise à jour | `post_compromise` (nouveau) | IND-CCA2 (6), AEAD (6), PRF (12), PRF double par l'entrée (1) |
| 3 | La ville entretenue ; les relais | `city_maintained`, `city_sticky`, `relay` | IND-CCA2, AEAD, PRF ; PRF double pour la ville |
| 3, 4 | Un saut lié à la feuille, la clé d'appareil volée | `catch_up_leaf_bound` | IND-CCA2, AEAD, PRF, PRF double par l'entrée |
| 4 | Confidentialité persistante, clés d'arbre stables | `fs_stable_keys` | PRF par le sel, PRF |
| 4 | Retrait collant ; entrant seul | `sticky_removal`, `entrant_window` | PRF double, PRF, IND-CCA2 |
| 4 | Générateur cassé, couvert | `weak_rng` | PRF par le sel, PRF |

Les deux lemmes nouveaux reprennent les scénarios `taint.pv` et `post_compromise.pv` du modèle de la v0.4. Leurs contrôles retirent chacun le mécanisme en cause, et CryptoVerif ne prouve plus rien :
- `taint_without_rule.ocv` ne re-keye que le chemin du retiré ;
- `post_compromise_without_update.ocv` garde l'ancienne clé de feuille.

Dans les deux lemmes, l'adversaire connaît l'init de l'époque précédente. C'est donc la moitié de la PRF double « par l'entrée » qui guérit l'époque, comme le disait la note [problèmes ouverts](problemes-ouverts-2026-09-26.md) (section 1.2).

## 6. Ce qui manque encore

1. **L'argument adaptatif, écrit pour City-G.** TTKEM prouve un commit par époque. Il faut étendre sa comptabilité :
   - aux fenêtres, qui font plusieurs commits de quartier et un scellement par époque ;
   - aux fenêtres d'entrant et à leur init externe ;
   - aux sauts.

   Le prédicat est prêt et chaque pas a son lemme ; il reste l'hybride global, avec l'ordre des remplacements et la devinette. C'est un travail de la taille d'un article.
2. **Les initiés.** Pour la confidentialité, le prédicat compte déjà comme fuité tout ce qu'un committer ou un scelleur corrompu tire, et le pas 1 l'empêche de signer au nom d'un autre. Restent hors de la preuve :
   - la solidité des audits, où une entrée invalide échappe avec une probabilité d'environ `e^-AUDIT_K` (spécification, section 15) ;
   - celle des preuves de litige, qui désignent le fautif.
3. **Le plan de messages**, hors de la v0.4, n'est pas dans le jeu.
4. **La vérification mécanique de bout en bout.** Les lemmes le sont, fenêtre par fenêtre. L'argument sur l'arbre pourrait l'être dans EasyCrypt ou SSProve. Le prédicat, lui, pourrait être vérifié symboliquement sur des arbres non bornés dans DY*, comme [Wallez, Protzenko et Bhargavan](https://eprint.iacr.org/2025/410) l'ont fait pour TreeKEM.

## 7. Modèles et reproductibilité

- `python3 docs/research/safety_predicate.py` : le prédicat sur les 25 traces ; il sort en erreur si une trace contredit son modèle.
- `docs/research/formal-computational/run.sh [chemin/de/cryptoverif]` : les 25 modèles CryptoVerif, dont `taint`, `taint_without_rule`, `post_compromise` et `post_compromise_without_update`. La CI les lance.
- Les modèles ProVerif sont inchangés : 18, 17 et 34 scénarios.

## 8. Sources

* J. Alwen et al., [Keep the Dirt: Tainted TreeKEM, Adaptively and Actively Secure Continuous Group Key Agreement](https://eprint.iacr.org/2019/1489), IEEE S&P 2021.
* C. Cremers, E. Günsay, V. Wesselkamp, M. Zhao, [ETK: External-Operations TreeKEM and the Security of MLS in RFC 9420](https://eprint.iacr.org/2025/229), Eurocrypt 2026.
* C. Kamath, K. Klein, K. Pietrzak, M. Walter, [The Cost of Adaptivity in Security Games on Graphs](https://eprint.iacr.org/2021/059), TCC 2021.
* C. Brzuska, E. Cornelissen, K. Kohbrok, [Security Analysis of the MLS Key Derivation](https://eprint.iacr.org/2021/137), IEEE S&P 2022.
* J. Alwen, D. Jost, M. Mularczyk, [On the Insider Security of MLS](https://eprint.iacr.org/2020/1327), Crypto 2022.
* T. Wallez, J. Protzenko, K. Bhargavan, [TreeKEM: A Modular Machine-Checked Symbolic Security Analysis of Group Key Agreement in Messaging Layer Security](https://eprint.iacr.org/2025/410), IEEE S&P 2025.
* B. Blanchet et al., [CryptoVerif](https://bblanche.gitlabpages.inria.fr/CryptoVerif/), version 2.13 ; [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/), version 2.05.
* Notes précédentes : [preuves et mesures](preuves-et-mesures-2026-09-26.md), [problèmes ouverts](problemes-ouverts-2026-09-26.md), [au-delà de 0.4](au-dela-0.4-2026-09-26.md).
