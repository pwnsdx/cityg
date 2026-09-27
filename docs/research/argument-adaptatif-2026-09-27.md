# L'argument adaptatif : l'arbre de City-G ramené au jeu GSD

| | |
| --- | --- |
| Date | 2026-09-27 |
| Nature | Note de recherche. Elle poursuit la note [la preuve de l'arbre](preuve-arbre-2026-09-26.md), dont la section 6 laissait ouvert l'argument adaptatif. Elle ramène le jeu de City-G au jeu GSD modifié d'Alwen, Jost et Mularczyk, par la voie que CoCoA et ETK ont suivie pour des variantes de MLS, et elle compte la perte en secrets réellement tirés. Elle couvre les fenêtres à plusieurs committers, les fenêtres d'entrant, les sauts, et les relais, éléments plats et rafraîchissements de l'étape 1 du [brouillon v0.5](../specs-v0.5-draft.md). C'est une preuve esquissée : les deux extensions du jeu et l'invariant de cohérence restent à écrire en entier, puis à mécaniser (section 8). |
| Question | Comment passer des lemmes prouvés fenêtre par fenêtre à la sécurité de l'arbre entier, contre un adversaire qui corrompt au vu de tout ce qui précède, et que perd-on ? |
| Compagnons | [`safety_predicate.py`](safety_predicate.py) : 28 traces, dont 3 nouvelles pour l'étape 1, traduites en hypergraphes GSD dont le script vérifie les conditions du théorème (`python3 docs/research/safety_predicate.py`). [`open_problems_sim.py`](open_problems_sim.py), rapport 5 : la perte comptée en secrets. |
| Auteur | Claude Code (assistant IA d'Anthropic), à la demande du mainteneur. Une relecture cryptographique humaine reste nécessaire. |

## 0. Résumé

1. **La difficulté.** Un adversaire adaptatif choisit après coup les secrets qu'il corrompt.
   - Une réduction qui remplacerait les enveloppes une à une devrait deviner, à la création de chaque enveloppe, si elle finira dans le graphe du défi. La perte serait exponentielle.
   - Les preuves de TreeKEM passent par un jeu intermédiaire, la *décryption sélective généralisée* (GSD), qui concentre l'adaptativité dans un seul théorème.
2. **La voie.** Réduire City-G au jeu GSD modifié d'Alwen, Jost et Mularczyk ([Crypto 2022](https://eprint.iacr.org/2020/1327)), comme l'ont fait CoCoA pour des re-keys concurrents ([Eurocrypt 2022](https://eprint.iacr.org/2022/251)) et ETK pour les opérations externes de MLS ([Eurocrypt 2026](https://eprint.iacr.org/2025/229)).
   - Ce jeu a déjà deux choses dont City-G a besoin : un oracle de déchiffrement, puisque le DS livre des chiffrés de son choix, et des arêtes « ET », comme `Extract` à deux entrées.
   - Son théorème dit qu'IND-CCA et l'oracle aléatoire impliquent la sécurité GSD. Il reprend celui de Tainted TreeKEM, avec une perte `2N²` pour un graphe de `N` secrets.
3. **Ce que City-G ajoute au jeu** : deux oracles.
   - `Encap` sert à l'init externe et aux deux encapsulations du welcome d'un saut.
   - `SEnc` sert aux éléments de relais et au scellement du welcome d'un saut.
   - La section 4 esquisse pourquoi le théorème tient avec eux.
4. **Deux lemmes font la réduction.**
   - *Simulation* (section 5) : le jeu de City-G se joue avec les oracles GSD. Le tag est un fils de la clé de confirmation, que la réduction publie en le corrompant.
   - *Combinatoire* (section 6) : une époque sûre au sens du prédicat garde un secret de message non exposé dans le graphe GSD.
     - Il repose sur un invariant de cohérence : tout secret d'un participant honnête est un sommet du graphe, ou une valeur que l'adversaire connaît déjà.
     - Un membre qui ne tient que des valeurs connues ne passe pas le tag d'une époque honnête.
5. **Les mécanismes propres à City-G** ne demandent rien de plus au théorème : les fenêtres à plusieurs committers, les entrants, les sauts, les relais.
   - Le jeu GSD ignore qui crée les sommets, et chaque mécanisme devient un oracle (section 6.3).
   - [`safety_predicate.py`](safety_predicate.py) traduit ses 28 traces en hypergraphes GSD. Il vérifie qu'ils sont acycliques et que le défi est un puits.
6. **La perte, comptée en secrets.** Une fenêtre tire environ `D log₂(n/D)` secrets pour `D` changements, pas `n` par opération.
   - Pour un million de membres pendant dix ans, `N ≈ 2^33` et la perte vaut `2N² ≈ 2^67`.
   - Il reste 125 bits à ML-KEM-768, au lieu des 92 à 94 qu'annonçait la borne `(Qn)²` de la note précédente (section 7).
7. **Ce qui reste** (section 8) : écrire en entier les deux extensions et l'invariant, les mécaniser, et chercher une perte plus fine pour X-Wing.

## 1. Où en était la preuve

La note [la preuve de l'arbre](preuve-arbre-2026-09-26.md) a posé trois choses.
- Le jeu : une CGKA à fenêtres, où le DS est l'adversaire et corrompt au vu de tout ce qui précède.
- Le prédicat de sûreté : la clôture des fuites par sept règles.
- Le théorème visé, avec BLAKE3 en oracle aléatoire.

Elle a esquissé la preuve en quatre pas, chacun justifié par un lemme mécanisé sur une fenêtre fixée. Il lui manquait l'hybride global : dans quel ordre remplacer les enveloppes, et quoi deviner.

La difficulté est celle que décrivent Alwen, Jost et Mularczyk (annexe D.2) :
- pour montrer qu'un secret chiffré reste caché, on remplace d'abord les chiffrés des clés qui mènent à lui ;
- il ne faut remplacer que ceux-là : remplacer les autres se verrait en corrompant leurs clés ;
- or, face à un adversaire adaptatif, on ne sait pas, quand un chiffré est créé, s'il faudra le remplacer. Le deviner pour chaque chiffré coûte une perte exponentielle.

Deux voies sont connues.
- **Dans le modèle standard**, le cadre de devinette par morceaux de [Jafargholi et al. (Crypto 2017)](https://eprint.iacr.org/2017/515), avec un pavage de l'arbre.
  - La perte est quasi polynomiale : `5 n² Q^(log n + 2)` pour Tainted TreeKEM (théorème 2 de [l'article](https://eprint.iacr.org/2019/1489)).
  - [Kamath, Klein, Pietrzak et Walter (TCC 2021)](https://eprint.iacr.org/2021/059) montrent que les réductions qu'ils appellent *oblivious* ne peuvent guère faire mieux sur ces jeux de graphes.
- **Dans le modèle de l'oracle aléatoire**, la perte est polynomiale.
  - Les graines passent par l'oracle avant de devenir des clés. Tant que l'adversaire n'interroge pas l'oracle sur une graine sûre, il joue en fait sur un graphe de profondeur 1 (Tainted TreeKEM, section 3.5).
  - La réduction ne devine alors que le nœud du défi et la source d'une de ses arêtes.

Le théorème visé par la note précédente est dans le modèle de l'oracle aléatoire. C'est donc la seconde voie.

## 2. Le jeu GSD modifié

Le jeu d'Alwen, Jost et Mularczyk (figure 20) tient un hypergraphe orienté.
- Chaque sommet `u` porte une graine aléatoire `s_u`. Sa paire de clés est `PKE.kg(Hash(s_u, "node"))`.
- L'adversaire dispose de six oracles :

| Oracle | Effet | Pour ITK, et pour City-G |
| --- | --- | --- |
| `Enc(u, v)` | arête `u → v` ; chiffré de `s_v` sous la clé publique de `u` | une enveloppe, un welcome, un élément plat |
| `Dec(u, c)` | déchiffre `c` sous la clé de `u`, si `c` n'est pas un chiffré de `Enc` pour `u` | un membre qui ouvre ce que le DS lui livre |
| `Hash(u, v, lbl)` | `s_v := Hash(s_u, lbl)`, une fois par paire `(u, lbl)` | les dérivations : chemin, calendrier de clés |
| `Join-Hash(u, u', v, lbl)` | `s_v := Hash(s_u, s_u', lbl)` | `Extract` : le joiner secret, les secrets frais couverts par l'init |
| `Corr(u)` | donne `s_u` | les fuites |
| `Chal(u*)` | `s_u*` ou un aléa, une seule fois | le défi |

Un sommet est **exposé** (`gsd-exp`) s'il est corrompu, ou si une arête arrive à lui dont toutes les sources sont exposées. L'adversaire gagne s'il devine le bit et si trois conditions tiennent : le graphe est acyclique, `u*` est un puits, et `u*` n'est pas exposé.

**Le théorème.**
- *Tainted TreeKEM, théorème 3.* Si le PKE est IND-CPA et `Hash` un oracle aléatoire, le jeu sans `Dec`, `Hash` ni `Join-Hash` est sûr à `2N²·ε + mN/2^(λ−1)` près. `N` est le nombre de sommets, `m` le nombre de requêtes à l'oracle, `λ` la longueur des graines.
- *Alwen, Jost et Mularczyk, théorème 6.* Ils étendent la réduction à `Dec`, `Hash` et `Join-Hash`, sous IND-CCA et avec un oracle observable mais non programmable, sans redire la perte. La réduction étant la même, elle garde la forme `2N²`.

**Où sont l'ordre des remplacements et la devinette.** La preuve distingue selon l'événement `E` : l'adversaire interroge l'oracle sur une graine qu'il ne connaît pas trivialement.
- *Si `E` est improbable*, la réduction devine le défi `u*` et la source `v` d'une arête `Enc` vers lui, d'où le facteur `N²`.
  - Elle place la clé du défi IND-CCA en `v` et le chiffré du défi sur l'arête.
  - Des hybrides traitent une à une les arêtes qui entrent dans `u*`.
- *Si `E` est probable*, elle devine le sommet dont la graine sera interrogée la première. Elle le défie dès qu'il est défini, et reconnaît la requête.

Tout ce que la section 6 de la note précédente demandait est là, prouvé une fois pour toutes. Il reste à montrer que City-G est une partie de ce jeu.

## 3. Le graphe GSD de City-G

| Secret de City-G | Sommet et arêtes entrantes | Qui les crée |
| --- | --- | --- |
| Clé de feuille, clé d'init d'une requête | une source | l'appareil |
| Secret de nœud chaîné (section 7.1) | `Hash(fils, "tree path")` | committer ou scelleur |
| Secret de nœud frais | `Hash(Join-Hash(couverture, r), "fresh node")` : `r` est une source, corrompue si l'adversaire fixe l'aléa, et la couverture est l'init de l'époque ou l'init externe | committer, scelleur ou entrant |
| Enveloppe de `s_v` vers le fils `t` | `Enc(t, v)` | committer ou scelleur |
| Racine `r_n` | le secret du nœud racine | scelleur (ville) ou committer (sans ville) |
| `commit_n`, puis le calendrier de clés | `Hash` depuis `r_n`, puis `Join-Hash(init_n−1, commit_n)` pour le joiner secret, puis `Hash` pour `epoch`, `init`, `msg`, `confirm`, `external` | chaque membre |
| Tag de confirmation | `Hash(confirm_n, transcript)`, puis `Corr` : le tag est public | le scelleur |
| Init externe d'une fenêtre d'entrant | `Encap(external_n−1)` | l'entrant |
| Welcome d'une entrée ou d'une ré-entrée | `Enc(clé d'init, joiner_n)` | le welcomer |
| Welcome d'un saut | `Encap(clé d'init) → a`, `Encap(clé de feuille) → b`, `Join-Hash(a, b) → w`, puis `SEnc(w, joiner_n)` | le welcomer |
| Élément de relais (brouillon v0.5, 2.3) | `SEnc(s_j, r_n)`, le libellé portant le groupe, l'époque et l'îlot | le relais |
| Élément plat (2.4) | `Enc(racine de l'îlot j, r_n)` | un membre de l'époque |
| Rafraîchissement (2.5) | aucune arête nouvelle : le membre rouvre des enveloppes existantes | – |
| Secret de message `msg_n` | `Hash(epoch_n, "msg")` : le défi | – |

Les clés de feuille, d'init et externes ont la forme du jeu : une clé de nœud est `KemKey(s, "tree node key")`, une clé tirée directement a la distribution de `kg(Hash(s))` pour un `s` uniforme, et la corrompre en donne moins que `s`.

Les fuites du jeu (note précédente, section 2.2) deviennent des `Corr`.
- *L'état d'un membre compromis* : ses clés de feuille et en attente, les secrets de son chemin, les secrets d'époque qu'il n'a pas effacés.
- *Pour un committer*, en plus : les secrets frais qu'il a tirés et pas encore effacés.
- *La clé d'appareil volée* : les clés que le voleur met dans ses requêtes, qui sont des sources corrompues.

**Les conditions du théorème.**
- *Acyclique.* On range les sommets par époque de création, puis par étape : sources, niveaux de l'arbre dans l'ordre, racine, calendrier de clés.
  - Toute arête monte dans cet ordre. Une enveloppe va d'un fils à son parent, l'init de l'époque `n − 1` sert à la fenêtre `n`, et un welcome ou un élément de sommet va d'une clé plus ancienne ou plus basse vers le joiner secret ou la racine.
  - Le script le vérifie sur les 28 traces.
- *Le défi est un puits.* En v0.4, `msg_n` n'a pas de descendant, puisque le plan de messages n'est pas spécifié. L'étape 3 déplacera le défi vers les secrets qui en dérivent.
- *`Hash` déterministe*, une fois par paire `(sommet, libellé)`.
  - Le secret nouveau d'un nœud est chaîné au plus une fois : il n'a qu'un parent, et un parent ne chaîne que d'un fils re-keyé dans la même fenêtre.
  - Une fenêtre qui ne re-keye rien garde `r_n−1`, donc `commit_n−1`. La réduction réutilise alors le sommet au lieu d'interroger deux fois.
  - Les libellés des relais, des welcomes et du calendrier de clés portent l'époque ou la requête.

## 4. Deux oracles de plus

City-G emploie deux formes que le jeu d'Alwen, Jost et Mularczyk n'a pas :

```text
Encap(u) → v      s_v := Hash(ss) pour une encapsulation X-Wing vers la clé de u ; le chiffré est donné
SEnc(u, v, lbl)   AEAD(k, s_v) avec k := Hash(s_u, lbl), clé à usage unique (ChaCha20-Poly1305) ;
                  Dec s'étend aux chiffrés de l'adversaire sous une telle clé
```

**Pourquoi le théorème tient (esquisse).** Seule la réduction du cas où `E` est improbable plante un défi sur une arête ; elle change selon la nature de l'arête devinée.
- **Arête `Enc`.** C'est le cas du théorème. Pour une enveloppe, le PKE est l'hybride KEM-DEM de X-Wing et de ChaCha20-Poly1305. Il est IND-CCA à `2ε_CCA(X-Wing) + ε_DEM` près : c'est le théorème de composition de [Cramer et Shoup (SIAM J. Comput. 2003)](https://eprint.iacr.org/2001/108).
- **Arête `Encap`.** La réduction plante le défi IND-CCA du KEM : un chiffré et un secret partagé, réel ou aléatoire. Le sommet reçoit `Hash(K*)`, et les décapsulations des membres sous cette clé passent par l'oracle du défi. La forme de la perte ne change pas.
- **Arête `SEnc`.** Tant que `E` n'arrive pas, `s_u` n'est pas interrogé, donc `k = Hash(s_u, lbl)` est une clé uniforme que l'adversaire ne voit jamais.
  - La réduction y plante un défi de confidentialité de l'AEAD, pour un seul chiffré.
  - Les déchiffrements par des membres, sous cette clé, de chiffrés fabriqués par l'adversaire reçoivent un refus. C'est faux au plus avec la probabilité d'intégrité des chiffrés, `q_dec · ε_INT`.
  - Chaque clé scelle un seul clair : le contexte lie l'époque et l'îlot pour un relais, la requête et les clés pour un welcome.
- **Le cas où `E` est probable** ne plante rien sur les arêtes. Les nouvelles arêtes n'y changent que la liste des requêtes à l'oracle à surveiller.

La borne devient, pour `N` secrets :

```text
Avantage GSD ≤ 2N² · (2ε_CCA(X-Wing) + ε_AE(ChaCha20-Poly1305)) + q_dec · ε_INT + m N / 2^(λ−1)
```

avec `λ = 256`. Le terme en `m` est négligeable : même pour `m = 2^64` et `N = 2^40`, il vaut `2^-151`.

## 5. Le lemme de simulation

La réduction `B`, un adversaire GSD, joue le jeu de City-G contre `A` :
- **Ce qu'elle tient.** Toutes les clés de signature, qui ne sont pas des secrets GSD. La table de l'oracle pour ce qu'elle sait calculer. Une *poignée* pour chaque secret qu'elle ignore : le nom d'un sommet.
- **Les pas honnêtes** deviennent les requêtes de la section 3.
  - Les clés publiques viennent des réponses du jeu, qui donne celle d'un sommet dès qu'il est la source d'une arête. `B` publie, comme City-G, la clé de chaque nœud et de chaque feuille.
  - Une clé à publier plus tôt, celle d'une feuille ou d'une init d'une requête, s'obtient par une requête `Hash` vers un sommet muet, que personne n'utilise. Le défi `msg_n` n'a pas de clé.
- **Un membre ouvre un chiffré.**
  - Si c'est le chiffré créé pour cette clé, `B` connaît la poignée du clair.
  - Sinon, elle appelle `Dec`. Le clair est une valeur, que la section 6.2 range parmi celles que l'adversaire connaît, ou le pas échoue.
- **Le tag.** Le scelleur honnête publie `Hash(confirm_n, transcript)` : `B` fait la requête `Hash` et corrompt le sommet obtenu. Un membre vérifie un tag reçu par la même requête, avec un nouveau libellé si le transcript diffère, et compare.
- **Les corruptions.**
  - `CorrompreÉtat` corrompt chaque poignée de l'état. Les effacements prévus par la spécification décident de ce qui y est : les secrets frais jusqu'à l'envoi du commit, les secrets d'époque jusqu'à l'époque suivante.
  - `CorrompreClé` remet la clé de signature ; les clés que le voleur met ensuite dans ses requêtes sont des valeurs de l'adversaire.
  - `Aléa` fait créer à `B` la source suivante, qu'elle corrompt aussitôt.
- **Le défi.** `Défi(n)` devient `Chal(msg_n)`.
- **L'ordre des pas.** L'authenticité, pas 1 de la note précédente, vient d'abord. Après lui, un membre honnête n'accepte que des objets signés qu'il a vérifiés, ou des étapes de chemin dont le tag confirme le résultat.

## 6. Le lemme combinatoire

**Lemme.** Si l'époque `n` est sûre au sens du prédicat, `gsd-exp(msg_n)` est faux dans le graphe de `B`.

### 6.1 Les mêmes règles

Chaque règle du prédicat (note précédente, section 2.1) est la condition `gsd-exp` d'un oracle :

| Règle | Oracle |
| --- | --- |
| dérivation | `Hash` |
| `Extract` | `Join-Hash` |
| enveloppe | `Enc` |
| init externe | `Encap` |
| relais | `SEnc` |
| welcome d'un saut | deux `Encap`, un `Join-Hash` et un `SEnc` |

Chaque fuite est un `Corr`. [`safety_predicate.py`](safety_predicate.py) attache désormais son oracle à chaque règle. Il vérifie sur les 28 traces que la traduction garde le verdict, puisque c'est la même clôture, et que les hypergraphes remplissent les conditions du théorème :

```text
28 traces, 28 agree with their models
as GSD hypergraphs: all acyclic, each challenge a sink; oracles used: Enc, Encap, Hash, Join-Hash, SEnc
```

Trois traces reprennent l'étape 1 :

| Trace | Prédicat | Source |
| --- | --- | --- |
| retrait dans un îlot, éléments plats | sûre | `ilot_removal.pv` |
| retrait, îlot non re-keyé | exposée | `ilot_removal_unrekeyed.pv` |
| retrait, élément de relais et rafraîchissement | sûre | test `a_removed_member_opens_no_top_of_the_window_that_removes_it` |

Cela ne suffit pas : le prédicat raisonne sur la structure que le protocole prévoit, et `B` construit son graphe à partir de ce que font réellement les participants, sous un DS hostile. Il faut que l'un soit l'autre.

### 6.2 L'invariant de cohérence

C'est la contrepartie du lemme 2 de CoCoA : dans CoCoA, toute clé de l'état d'un membre vient d'une mise à jour qu'il a au moins faiblement traitée.

**Invariant.** À tout instant :
- *(a) ou (b).* Tout secret que tient un participant honnête est soit (a) la graine d'un sommet du graphe de `B`, soit (b) une valeur que l'adversaire connaît : il l'a fournie, ou elle se déduit de valeurs qu'il connaît.
- *(c)* Un participant honnête ne crée une arête vers un sommet que là où la structure du protocole la met : sous la clé d'un sommet de sa vue vérifiée de l'arbre, d'une requête vérifiée, ou d'un secret qu'il a dérivé lui-même.

**Esquisse, par récurrence sur les opérations.**
- **Tirer** crée une source : (a).
- **Ouvrir** une enveloppe, un welcome, un élément de relais ou plat, ou une encapsulation.
  - Si le chiffré est celui qu'un participant honnête a créé pour cette clé, le clair est une graine : (a).
  - Sinon, l'AEAD ne s'ouvre que si l'adversaire a scellé sous une clé qu'il connaît : il connaît alors le clair, (b). Sans cela, le pas échoue et le membre ne change rien.
  - Un chiffré retouché ne change rien : IND-CCA et le rejet implicite de ML-KEM rendent sa décapsulation indépendante des clairs honnêtes. L'AEAD échoue ensuite, à la probabilité d'intégrité près.
- **Dériver.**
  - Des graines seules donnent une graine, (a). C'est parfois un sommet que personne d'autre n'utilise : `B` le crée à la demande.
  - Des valeurs connues seules donnent une valeur connue, (b).
  - Un mélange passe par une source corrompue que `B` crée pour la valeur connue : (a).
- **Accepter une époque.** Il faut que le tag calculé soit le tag publié. Celui-ci est le fils corrompu du vrai sommet `confirm_n`.
  - Un membre dont la racine n'est pas le vrai `r_n`, ou dont l'init n'est pas le vrai `init_n−1`, calcule un autre sommet. L'égalité n'arrive qu'à une collision de l'oracle près, `q²/2^256`.
  - Il n'accepte donc que le vrai `r_n`, ou une époque que l'adversaire connaît entièrement, parce qu'il en connaît la racine et l'init. C'est la bifurcation par un initié de la spécification (section 2.3), que le prédicat compte comme exposée.
- **Créer des arêtes, (c).**
  - Un committer ou un scelleur enveloppe vers les clés de sa vue de l'arbre, vérifiée contre son en-tête (v0.4 §12.3). Chaque clé y est celle d'un sommet : si un participant de l'adversaire l'a publiée, ce sommet est corrompu, et le prédicat dit la même chose.
  - Un welcomer scelle vers la clé d'init d'une requête signée, et, pour un saut, vers la clé de feuille de l'arbre vérifié.
  - Un faiseur d'éléments plats prend les clés des racines d'îlot dans un état vérifié (brouillon v0.5, section 2.4). Sans cette vérification, il scellerait `r_n` vers une clé choisie par le DS.
  - Un relais scelle `r_n` sous son `s_j`. Si son `s_j` était une valeur connue (b), son `r_n` le serait aussi : il l'a tiré de `s_j` par les pas de son chemin. Un pas depuis une valeur connue ne donne jamais le vrai secret, sauf par un chiffré honnête vers une clé tirée de cette valeur, et aucun participant honnête ne chiffre vers une clé hors de l'arbre vérifié.

**Conclusion.** Les seules arêtes du graphe de `B` vers de vrais secrets sont celles que la structure du protocole prévoit, et ce sont celles sur lesquelles raisonne le prédicat. Les autres sommets, créés par des pas faux, ne mènent à aucun vrai secret. Les corruptions de `B` sont exactement les fuites du prédicat. D'où le lemme.

### 6.3 Ce que chaque mécanisme demande

- **Fenêtres à plusieurs committers.** Le jeu GSD ne sait pas qui crée les sommets : les commits de quartier d'une même fenêtre sont des requêtes, dans l'ordre du jeu.
  - La règle des taches n'a pas besoin d'arête : un committer garde les secrets frais qu'il a tirés jusqu'à leur effacement, et sa corruption les expose.
  - La fenêtre qui le retire crée de nouveaux sommets pour ces nœuds. La clôture montre que les anciens ne mènent pas à l'époque suivante : c'est la trace « taint ».
- **Fenêtres d'entrant.**
  - L'init externe est une arête `Encap` depuis `external_n−1`, que connaît tout membre de l'époque `n − 1`, y compris celui dont le retrait attend. Ce sont les traces « lone entrant » et « entrant with a removal ».
  - Un entrant que le DS contrôle, dans un groupe ouvert, est un participant corrompu : ses sommets sont corrompus.
  - ETK a montré qu'avec les opérations externes de MLS, un membre compromis peut revenir après la guérison. Dans City-G, le prédicat couvre l'init externe par une règle, et le saut lie son welcome à la clé de feuille : ce sont les traces « catch-up ».
- **Sauts.** Le welcome devient deux `Encap`, un `Join-Hash` et un `SEnc`. La reprise du chemin rouvre des enveloppes existantes. Avec une clé d'appareil volée, la clé d'init est une source de l'adversaire : le joiner secret reste sûr tant que la clé de feuille l'est.
- **Relais, éléments plats, rafraîchissements.** Ce sont `SEnc`, `Enc`, et aucune arête nouvelle.
  - Un suiveur d'îlot tient sa part de chemin et `r_n`, ce qui reste dans l'invariant.
  - Un élément de relais fourni par un relais hostile est une valeur connue, qui échoue au tag : c'est `ilot_relay.pv`.
- **Croissance de l'arbre.** Les nœuds `(k, 0)` re-keyés sont des sommets ordinaires.

## 7. La perte, comptée en secrets

Le théorème compte les sommets du graphe, c'est-à-dire les secrets que le protocole tire réellement.

**Ancienne borne.** La note précédente prenait la borne `(Qn)²` du théorème 4 de Tainted TreeKEM, qui majore `N` par `2nQ` : un commit peut re-keyer `n` nœuds.

**Ce qu'une fenêtre de City-G tire** ([`open_problems_sim.py`](open_problems_sim.py), rapport 5) :
- les nouveaux secrets de nœud, un par ancêtre d'une feuille changée, soit environ `D log₂(n/D)` plus le haut saturé ;
- deux sommets par tirage frais, l'aléa et l'`Extract` ;
- une clé de feuille par changement, et une clé d'init par entrée ;
- huit sommets du calendrier de clés.

Les éléments de relais et plats ajoutent des arêtes, pas des sommets.

Au taux de 1,7 changement par seconde et par million de membres :

| Membres | Fenêtres | Durée | Secrets `N` | Perte `2N²` | Bits restants, ML-KEM-768 | Bits restants, X25519 | Borne `(Qn)²`, `Q` changements |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 2^20 | 5 min | 1 an | 2^29,6 | 2^60 | 132 | 68 | 2^91 |
| 2^20 | 5 min | 10 ans | 2^32,9 | 2^67 | 125 | 61 | 2^98 |
| 2^20 | 5 min | 50 ans | 2^35,2 | 2^71 | 121 | 57 | 2^103 |
| 2^20 | 60 s | 10 ans | 2^33,2 | 2^67 | 125 | 61 | 2^98 |
| 2^24 | 5 min | 10 ans | 2^36,9 | 2^75 | 117 | 53 | 2^114 |

- **La composition KEM-DEM** double `ε_CCA(X-Wing)` dans la borne de la section 4 : un bit de moins que la colonne `2N²`.
- **Environ trente bits de gagnés** sur la borne précédente, parce que le re-key de City-G reste près de la borne inférieure.
  - [Azari et Ellison (ACNS 2025)](https://eprint.iacr.org/2024/1878) font la même observation pour TreeKEM : le théorème de Tainted TreeKEM y donne `O((c log u + p)²)` pour `c` commits et `p` propositions.
  - Comme dans la note précédente, les bits restants retranchent la perte à 192 bits pour ML-KEM-768 (catégorie 3 du NIST) et à 128 pour X25519.
- **X-Wing tient si l'une de ses moitiés tient.**
  - X25519 seul garderait de 53 à 68 bits. La garantie classique repose donc sur ML-KEM-768, et, face à un adversaire quantique, sur lui seul.
  - Azari et Ellison obtiennent pour DHIES une perte linéaire en `N`, grâce à l'auto-réductibilité aléatoire de Diffie-Hellman. La technique s'appliquerait en principe à la moitié X25519 d'X-Wing, ce qui n'est pas fait.
  - Nous ne connaissons pas de réduction aussi serrée pour ML-KEM sous plusieurs clés.
- **Dans le modèle standard**, la borne quasi polynomiale du théorème 2 de Tainted TreeKEM ne dit rien à ces tailles. Les bornes inférieures de Kamath et al. montrent qu'une réduction *oblivious* ne peut pas faire beaucoup mieux. L'oracle aléatoire reste la voie utile.

## 8. Ce qui reste

1. **Écrire en entier les extensions du théorème**, `Encap` et `SEnc`, y compris le cas où `E` est probable.
   - La section 4 suit la réduction de Tainted TreeKEM et d'Alwen, Jost et Mularczyk pas à pas, mais ce n'est qu'une esquisse.
   - Il faut aussi vérifier que l'oracle n'a pas besoin d'être programmable avec `SEnc`, comme ces auteurs le disent pour leurs oracles.
2. **Écrire l'invariant de cohérence en entier**, sur les formats réels : paquets entiers et d'îlot, entrées, éléments de relais et plats, rafraîchissements. CoCoA y consacre deux lemmes (4 et 5, le traitement faible) pour un serveur qui calcule des paquets individuels, ce que fait le DS de City-G.
3. **Mécaniser.**
   - La réduction au jeu GSD, dans EasyCrypt ou SSProve. Les lemmes par fenêtre le sont déjà dans CryptoVerif.
   - L'invariant, symboliquement sur des arbres non bornés, dans DY\*, comme l'ont fait [Wallez, Protzenko et Bhargavan](https://eprint.iacr.org/2025/410) pour TreeKEM.
4. **Une perte plus fine pour X-Wing**, par la technique d'Azari et Ellison sur la moitié X25519, et plusieurs défis.
5. **Hors du jeu**, comme avant :
   - l'intégrité face aux initiés, avec les audits et les litiges ;
   - le plan de messages, étape 3 ;
   - les bifurcations.

## 9. Reproductibilité

- `python3 docs/research/safety_predicate.py` : les 28 traces, leur accord avec les modèles, et les conditions GSD de chaque hypergraphe. Le script sort en erreur si une trace contredit son modèle, ou si un graphe a un cycle ou un défi qui n'est pas un puits.
- `python3 docs/research/open_problems_sim.py` : le rapport 5 donne la perte comptée en secrets.

## 10. Sources

Chaque énoncé cité a été relu dans l'article.

* J. Alwen, D. Jost, M. Mularczyk, [On the Insider Security of MLS](https://eprint.iacr.org/2020/1327), Crypto 2022 : le jeu GSD modifié (figure 20) et son théorème 6.
* J. Alwen, M. Capretto, M. Cueto, C. Kamath, K. Klein, I. Markov, G. Pascual-Perez, K. Pietrzak, M. Walter, M. Yeo, [Keep the Dirt: Tainted TreeKEM, Adaptively and Actively Secure Continuous Group Key Agreement](https://eprint.iacr.org/2019/1489), IEEE S&P 2021, pages 268 à 284 : théorèmes 2, 3 et 4. La version publiée nomme K. Klein en premier, l'eprint suit l'ordre alphabétique.
* J. Alwen, B. Auerbach, M. Cueto Noval, K. Klein, G. Pascual-Perez, K. Pietrzak, M. Walter, [CoCoA: Concurrent Continuous Group Key Agreement](https://eprint.iacr.org/2022/251), Eurocrypt 2022 : théorème 1 et lemme 2.
* C. Cremers, E. Günsay, V. Wesselkamp, M. Zhao, [ETK: External-Operations TreeKEM and the Security of MLS in RFC 9420](https://eprint.iacr.org/2025/229), Eurocrypt 2026 : théorème 1, jeu GSD avec déchiffrement (figure 9).
* K. Azari, A. Ellison, [Tighter Provable Security for TreeKEM](https://eprint.iacr.org/2024/1878), ACNS 2025.
* C. Kamath, K. Klein, K. Pietrzak, M. Walter, [The Cost of Adaptivity in Security Games on Graphs](https://eprint.iacr.org/2021/059), TCC 2021.
* Z. Jafargholi, C. Kamath, K. Klein, I. Komargodski, K. Pietrzak, D. Wichs, [Be Adaptive, Avoid Overcommitting](https://eprint.iacr.org/2017/515), Crypto 2017.
* R. Cramer, V. Shoup, [Design and Analysis of Practical Public-Key Encryption Schemes Secure against Adaptive Chosen Ciphertext Attack](https://eprint.iacr.org/2001/108), SIAM J. Comput. 33(1), 2003 : la composition KEM-DEM.
* T. Wallez, J. Protzenko, K. Bhargavan, [TreeKEM: A Modular Machine-Checked Symbolic Security Analysis of Group Key Agreement in Messaging Layer Security](https://eprint.iacr.org/2025/410), IEEE S&P 2025.
* Notes précédentes : [la preuve de l'arbre](preuve-arbre-2026-09-26.md), [preuves et mesures](preuves-et-mesures-2026-09-26.md), [problèmes ouverts](problemes-ouverts-2026-09-26.md), [au-delà de 0.4](au-dela-0.4-2026-09-26.md) ; le [brouillon de spécification v0.5](../specs-v0.5-draft.md).
