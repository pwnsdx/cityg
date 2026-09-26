# Les problèmes ouverts de l'au-delà de la v0.4 : premières résolutions

| | |
| --- | --- |
| Date | 2026-09-26 |
| Nature | Note de recherche. Elle reprend les problèmes ouverts de la note [au-delà de 0.4](au-dela-0.4-2026-09-26.md) (section 6), dans leur ordre, et en résout une partie : premières preuves calculatoires mécanisées, taille des preuves de litige, témoins contre les bifurcations, cache des cartes, métadonnées. Elle corrige aussi l'énoncé d'une hypothèse de la spécification (section 3.3). Rien d'autre n'est encore dans la spécification ni dans le code. |
| Question | Que peut-on résoudre dès maintenant des problèmes ouverts du profil candidat, et que reste-t-il ? |
| Compagnons | [`formal-computational/`](formal-computational/README.md) : 14 modèles CryptoVerif 2.13, lancés par `docs/research/formal-computational/run.sh` et par la CI. [`open_problems_sim.py`](open_problems_sim.py) : modèle de coût (`python3 docs/research/open_problems_sim.py`, quelques secondes). |
| Auteur | Claude Code (assistant IA d'Anthropic), à la demande du mainteneur. Les preuves calculatoires portent sur des configurations fixées et sur des hypothèses énoncées ; les coûts des preuves de litige sont des estimations à partir de coûts publiés. Une relecture cryptographique humaine reste nécessaire. |

## 0. Résumé

1. **Preuve calculatoire (problème 1) : les premières preuves mécanisées.** 14 modèles CryptoVerif, tous au verdict attendu : 7 propriétés prouvées et 7 contrôles, qui retirent chacun le mécanisme ou l'hypothèse dont la propriété dépend.
   - Prouvées dans le modèle calculatoire :
     - la confidentialité persistante avec des clés d'arbre stables ;
     - le retrait « collant » ;
     - la fenêtre qu'un entrant scelle seul ;
     - les relais et les éléments plats ;
     - la ville entretenue ;
     - la couverture des secrets frais contre un générateur faible.
   - Les trois modèles de la ville rendent les mêmes verdicts que leurs contreparties ProVerif.
   - Hypothèses : X-Wing IND-CCA2, BLAKE3 en mode à clé PRF, ChaCha20-Poly1305 IND-CPA et INT-CTXT, et `Extract` **PRF double**.
2. **Une hypothèse manquait à la spécification.** Elle ne demandait à `Extract` que d'être une PRF quand la clé est le sel.
   - Or la guérison après compromission, le retrait collant, la ville entretenue et l'init externe demandent aussi qu'`Extract` soit pseudo-aléatoire quand la clé est l'entrée et que le sel est connu. Sans cette hypothèse, CryptoVerif ne prouve rien (`sticky_removal_single_prf.ocv`).
   - TLS 1.3, KEMTLS, MLS et Noise font la même hypothèse sur HMAC, que [Backendal et al. (Crypto 2023)](https://eprint.iacr.org/2023/861) caractérisent ; personne ne l'a étudiée pour BLAKE3.
   - La spécification l'énonce désormais (section 3.3).
3. **Litiges (problème 2) : l'énoncé tient en 1,1 million de portes AND.** L'énoncé : la décapsulation X-Wing avec la bonne clé, puis la dérivation de la clé AEAD et l'ouverture ChaCha20-Poly1305, qui échoue.
   - Il compte 26 permutations Keccak, 4 compressions BLAKE3, 2 blocs ChaCha20 et 6 140 multiplications dans le corps de X25519.
   - La matrice de ML-KEM et toute son arithmétique sont publiques ou linéaires, donc hors de l'énoncé ou gratuites.
   - Le vérifieur naturel est le serveur. Une preuve à vérifieur désigné (QuickSilver) envoie environ 0,4 Mo.
   - Une preuve publique post-quantique (VOLE dans la tête) enverrait de 1,5 à 2,2 Mo pour sa partie booléenne.
   - À la portée d'un téléphone, pour un événement rare ; reste à l'implémenter et à mesurer.
4. **Bifurcations (problème 3) : des témoins.** Si 3 témoins sur 4 contresignent chaque fenêtre, le groupe tolère un témoin absent et un témoin allié au serveur.
   - Coût : 83 Ko par jour avec des signatures UOV, 575 Ko avec FN-DSA-512.
   - Si le quorum ne répond pas, le membre accepte la fenêtre au niveau de MLS, en le signalant : jamais moins que MLS.
5. **Standards (problème 4).** Le KEM de City-G est bien celui des suites hybrides de MLS. Le KEM multi-destinataires n'est plus nécessaire. Reste un choix pour le mainteneur : garder BLAKE3 avec l'hypothèse de PRF double désormais énoncée, ou prendre HKDF-SHA-384 comme les suites de MLS, dont l'hypothèse est étudiée.
6. **Cartes d'émetteur (problème 5).** Les cartes changent au plus toutes les semaines (`UPDATE_INTERVAL`), donc un lecteur peut les garder en cache.
   - Si 80 % de ses émetteurs du jour étaient déjà là, un lecteur de 10 000 messages paie 2,5 Mo par jour pour les émetteurs au lieu de 3,7.
   - Le plancher est celui des preuves d'appartenance, 1,7 Mo par jour.
7. **Métadonnées (problème 6).** Les tâches et les relais ne révèlent au serveur que la présence en ligne, qu'il voit déjà par les connexions, comme un DS de MLS. Ce qui reste relève du transport, hors du protocole.
8. **Ce qui reste** (section 7) :
   - la preuve calculatoire de l'arbre entier, sous corruptions adaptatives ;
   - la mesure des preuves de litige ;
   - la spécification et l'implémentation.

## 1. Preuve calculatoire

### 1.1 Ce qui est prouvé

[CryptoVerif](https://bblanche.gitlabpages.inria.fr/CryptoVerif/) prouve des propriétés dans le modèle calculatoire : chaque preuve est une suite de jeux, et la borne finale donne l'avantage de l'adversaire en fonction de celui contre chaque primitive. Les 14 modèles de [`formal-computational/`](formal-computational/README.md) suivent le calendrier de clés de la spécification (section 9) : `Extract`, `ExpandLabel`, `DeriveSecret`, le tag, l'init externe, les enveloppes (section 7.2) et les clés dérivées des secrets de nœud.

| Modèle | Ce qu'il vérifie | Verdict | Hypothèses de la borne |
| --- | --- | --- | --- |
| `fs_stable_keys` | Le membre A efface l'époque 1 ; l'adversaire connaît tous les secrets de commit, comme quand fuient des clés d'arbre restées les mêmes, et tout l'état de A à l'époque 3. | Prouvé : l'époque 2 reste secrète. | PRF (sel), PRF |
| `fs_stable_keys_without_init` | Sans chaîne d'init. | Non prouvé. | |
| `sticky_removal` | M, retiré par la fenêtre 2, connaît l'époque 1 ; le secret de la fenêtre 3 lui parvient. | Prouvé : l'époque 3 reste secrète. | PRF double, PRF |
| `sticky_removal_single_prf` | `Extract` seulement PRF par son sel. | Non prouvé. | |
| `sticky_removal_collude` | Un membre de l'époque 2, retiré ensuite, donne l'init de l'époque 2. | Non prouvé. | |
| `entrant_window` | Un entrant scelle seul : init externe vers la clé externe de l'époque 1, secret de commit constant ; l'adversaire fait décapsuler ses propres encapsulations. | Prouvé : l'époque 2 reste secrète. | IND-CCA2, PRF double, PRF |
| `entrant_window_removal_waiting` | Un retrait attend : l'adversaire connaît la clé externe. | Non prouvé. | |
| `relay` | Relais et élément plat portent le même secret de fenêtre, sous des clés tirées du secret de la racine de l'îlot avec des labels distincts. | Prouvé : le secret de fenêtre reste secret. | IND-CCA2, AEAD, PRF |
| `relay_known_root` | L'adversaire connaît la racine. | Non prouvé. | |
| `city_maintained` | La ville entretenue, avec de vraies enveloppes : deux retirés alliés au serveur. | Prouvé. | IND-CCA2, AEAD, PRF, PRF double |
| `city_stale` | La ville non re-keyée. | Non prouvé (attaque dans ProVerif). | |
| `city_sticky` | La ville non re-keyée, un seul retiré. | Prouvé. | IND-CCA2, AEAD, PRF, PRF double |
| `weak_rng` | Le générateur du committer est cassé ; ses secrets frais sont couverts par son init (spécification, section 7.1). | Prouvé : ils restent secrets pour un tiers. | PRF (sel), PRF |
| `weak_rng_unhedged` | Sans cette couverture. | Non prouvé. | |

- **Les contrôles** ne donnent pas d'attaque : « non prouvé » veut dire que CryptoVerif ne trouve pas de preuve. Chacun retire le mécanisme ou l'hypothèse dont la propriété dépend, et ProVerif montre l'attaque quand il y en a une.
- **Les enveloppes et les clés** sont celles de la spécification : KEM X-Wing, clé et nonce ChaCha20-Poly1305 tirés du secret partagé, paires de clés dérivées des secrets de nœud. CryptoVerif les enchaîne sans aide, en 9 secondes pour la ville.

### 1.2 L'hypothèse manquante : `Extract`, PRF double

`Extract(salt, ikm)` est BLAKE3 en mode à clé, avec le sel pour clé (spécification, section 3.3). La spécification disait seulement que ce mode est une PRF. Les modèles montrent que cela ne suffit pas :

- **PRF par le sel** : la confidentialité persistante (`fs_stable_keys`) et la couverture contre un générateur faible (`weak_rng`) n'ont besoin que de cela ;
- **PRF par l'entrée, le sel étant connu** : c'est ce qui fait qu'un secret frais guérit une init connue, et CryptoVerif en a besoin partout où cela arrive :
  - la guérison après compromission ;
  - le retrait collant ;
  - la ville entretenue, parce que le second retiré connaît l'init de l'époque 2 ;
  - l'init externe, dont le sel est `ZERO32`.

C'est la *PRF double* (dual PRF) :
- TLS 1.3, KEMTLS, MLS et Noise la supposent de HMAC ;
- [Backendal et al. (Crypto 2023)](https://eprint.iacr.org/2023/861) montrent que HMAC l'est exactement pour des ensembles de clés qu'ils appellent *faisables*, et que les usages de ces protocoles le sont ;
- [Bellare et Lysyanskaya (J. Cryptology 2024)](https://eprint.iacr.org/2015/1198) construisent des PRF doubles à partir d'hypothèses standard.

Aucune analyse n'existe pour BLAKE3 en mode à clé. L'hypothèse est plausible : la compression de BLAKE3 mélange le message comme une clé de chiffrement par bloc. Mais cet argument est heuristique.

La spécification énonce désormais l'hypothèse (section 3.3). Le choix entre BLAKE3 et HKDF est discuté en section 4.

### 1.3 Ce que la littérature couvre déjà

Trois points que la note au-delà de 0.4 disait sans équivalent dans les analyses de MLS en ont un :

- **Un secret de commit public.** MLS l'a aussi : un commit sans chemin prend un secret de commit nul ([RFC 9420, section 12.4.2](https://www.rfc-editor.org/rfc/rfc9420.html#section-12.4.2)). L'analyse du calendrier de clés de MLS par [Brzuska, Cornelissen et Kohbrok (IEEE S&P 2022)](https://eprint.iacr.org/2021/137) repose sur la même PRF double. `entrant_window` en est l'instance City-G.
- **Des clés d'arbre stables.** Dans MLS aussi, la clé d'un nœud reste la même tant qu'aucun commit ne la change. La confidentialité persistante vient alors de la chaîne d'init et de l'effacement ; `fs_stable_keys` le prouve pour City-G.
- **Des secrets tirés hors de son chemin, suivis par des taches.** C'est TTKEM, [Tainted TreeKEM (Alwen et al., IEEE S&P 2021)](https://eprint.iacr.org/2019/1489), dont vient la règle des taches de la v0.4 (décision E-4), et qui a des preuves contre un adversaire adaptatif.

Pour les primitives : X-Wing est IND-CCA si X25519 (Diffie-Hellman fort) ou ML-KEM-768 (avec SHA3-256 PRF) l'est ([Barbosa et al., 2024](https://eprint.iacr.org/2024/039)). La composition KEM puis AEAD des enveloppes est celle de HPKE, déjà analysée avec CryptoVerif ([Alwen et al., Eurocrypt 2021](https://eprint.iacr.org/2020/1499)).

### 1.4 Ce qui reste

- **L'arbre entier sous corruptions adaptatives.** Les modèles fixent quelques nœuds et quelques fenêtres. Un groupe réel, où l'adversaire choisit qui corrompre au vu des échanges, relève de la *décryption sélective généralisée* sur un arbre. Elle se réduit à la sécurité du chiffrement avec une perte quasi polynomiale ([Fuchsbauer, Jafargholi et Pietrzak, Crypto 2015](https://eprint.iacr.org/2016/389)) ; c'est la voie de TTKEM. Il reste à écrire cette preuve pour les îlots, la ville et les tâches. La note [preuves et mesures](preuves-et-mesures-2026-09-26.md) (section 4) en écrit le plan, avec des oracles aléatoires : à un million de membres, la perte quasi polynomiale ne laisse aucune garantie.
- **L'authentification** : sceaux, admissions, points de contrôle restent au modèle symbolique. Le relais et le quorum des témoins sont depuis prouvés dans le modèle calculatoire (note [preuves et mesures](preuves-et-mesures-2026-09-26.md), section 2).
- **Le relais menteur.** Dans le modèle symbolique, il est trahi par le tag. Dans le modèle calculatoire, il connaît les clés : il faut que la chaîne qui va du secret de fenêtre au tag résiste aux secondes préimages, ce que BLAKE3 donne, mais que les modèles ne vérifient pas. C'est depuis prouvé, sous la résistance aux collisions (`relay_tag.ocv`).

## 2. Les preuves de litige

### 2.1 L'énoncé

Un membre qui ne peut pas ouvrir l'enveloppe `Wrap = [v, t, ct, sealed]` prouve, sans révéler sa clé ni aucun secret :

```text
public  : pk_t (clé de t), ct, sealed, context (section 7.2), pk_v (nouvelle clé de v, publiée)
témoin  : la graine X-Wing de t
relation: pk_t = X-Wing.KeyGen(graine)
          ss   = X-Wing.Decaps(graine, ct)
          k, n = ExpandLabel(ss, "wrap key" | "wrap nonce", context)
          et soit   ChaCha20-Poly1305.Open(k, n, context, sealed) échoue           (branche 1)
             soit   il rend s, et KemKey(s, "tree node key").pk ≠ pk_v            (branche 2)
```

La branche 2 attrape un client qui scelle un secret bien formé, mais pas celui de la clé qu'il a publiée.

### 2.2 Sa taille

`open_problems_sim.py`, rapport 1 :

| Branche | Keccak-f | BLAKE3 | ChaCha20 | Portes AND | Multiplications mod 2^255 − 19 | Multiplications mod 2^130 − 5 | Bits à convertir |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 1, l'enveloppe ne s'ouvre pas | 26 | 4 | 2 | 1 082 271 | 6 140 | 9 | 29 693 |
| 2, elle s'ouvre sur un mauvais secret | 34 | 5 | 2 | 1 399 887 | 9 210 | 9 | 36 092 |

- **Keccak.** Il y en a 8 pour retrouver la clé depuis la graine, puis 18 pour la décapsulation :
  - `G(m' ‖ h)` : 1 ;
  - l'échantillonnage de `y`, `e1` et `e2` : 7 ;
  - `J(z ‖ c)` : 9 ;
  - le combineur de X-Wing : 1.

  Les comptes suivent les longueurs de FIPS 203 et de X-Wing.
- **Ce qui sort de l'énoncé.** La matrice `A` de ML-KEM vient de la graine publique `ρ` de la clé publique. Son échantillonnage par rejet, 27 permutations en moyenne (mesuré avec SHAKE128), reste hors de l'énoncé.
- **L'arithmétique des réseaux** a toujours un facteur public : `A`, `u`, `t`. Elle est donc linéaire, et gratuite dans les preuves à base de VOLE, qui s'engagent linéairement. Restent les arrondis de la compression, en bits.
- **X25519** coûte deux échelles de Montgomery, pour la clé et pour la décapsulation, et une troisième dans la branche 2 : dans le corps premier natif, 3 070 multiplications chacune.

### 2.3 Le vérifieur est le serveur

C'est le serveur qui attribue les tâches et qui exclut le fautif. Une preuve à *vérifieur désigné* suffit donc. Aucun membre n'a besoin de la vérifier : un serveur malveillant peut déjà refuser des tâches à qui il veut.

- **QuickSilver** ([Yang et al., CCS 2021](https://eprint.iacr.org/2021/076)) :
  - un élément de corps par porte non linéaire, quel que soit le corps, donc un bit par porte AND ;
  - zéro connaissance face à un vérifieur malveillant ;
  - interactif, ce qui convient à un litige entre un client et le serveur ;
  - les conversions entre bits et corps sont celles de [Mystique (Weng et al., USENIX Security 2021)](https://eprint.iacr.org/2021/730).

  En comptant un élément du corps cible par multiplication et par bit converti : **environ 0,4 Mo** pour la branche 1, **0,6 Mo** pour la branche 2, plus la mise en place des VOLE. Le calcul d'un million de portes est négligeable pour ce protocole, dont le coût publié est de l'ordre d'un dollar pour mille milliards de portes AND.
- **Une preuve publique post-quantique** : le VOLE dans la tête ([Baum et al., Crypto 2023](https://eprint.iacr.org/2023/996)), celui de FAEST, a une taille linéaire.
  - À 11 à 16 bits par porte AND, sa partie booléenne ferait **1,5 à 2,2 Mo** pour la branche 1.
  - Sa partie en corps premier, X25519, reste à chiffrer.
  - Elle servirait si d'autres que le serveur devaient vérifier : un auditeur, ou un membre qui conteste une exclusion.

Un litige coûte donc au plaignant ce que coûtent quelques fenêtres de suivi. Il est rare : un client fautif est exclu des tâches au premier litige.

### 2.4 Ce qui reste

Écrire l'énoncé dans une bibliothèque de preuves à base de VOLE, puis mesurer le temps sur un téléphone et la taille, y compris la mise en place. C'est fait, hors X25519, dans la note [preuves et mesures](preuves-et-mesures-2026-09-26.md) (section 1) : moins d'une seconde et 2 Mo. Chiffrer la partie X25519 d'une preuve publique. En attendant, les parades de la note [îlots](ilots-2026-09-26.md) (section 3) restent :
- le serveur réserve les tâches aux appareils présents depuis un certain temps ;
- il limite le débit des entrées.

## 3. Bifurcations : des témoins

Un membre qui vérifie le point de contrôle de chaque fenêtre refuse les bifurcations (`authorizer_follow.pv`). Mais un seul autorisateur fait dépendre le groupe de sa disponibilité.

- **Des témoins en quorum.** `n` témoins, dont l'autorisateur s'il le faut, signent chacun au plus un point de contrôle par époque, et un membre en exige `k`.
  - Une bifurcation demande deux points de contrôle d'une même époque avec `k` signatures chacun. Le serveur peut montrer l'un aux uns et l'autre aux autres ; `f` témoins malhonnêtes, qui signent les deux, y arrivent si `f ≥ 2k − n`.
  - Avec `n = 3f + 1` et `k = 2f + 1`, c'est impossible, et `f` témoins absents n'arrêtent pas le groupe : c'est le quorum des protocoles de consensus tolérants aux fautes byzantines.
- **Le coût** (rapport 2 ; signatures seules, fenêtres de 5 minutes) :

  | Témoins | Signatures par fenêtre | Tolère | ML-DSA-65 | FN-DSA-512 | UOV |
  | ---: | ---: | ---: | ---: | ---: | ---: |
  | 1 (l'autorisateur) | 1 | 0 | 953 Ko | 192 Ko | 28 Ko |
  | 4 | 3 | 1 | 2,9 Mo | 575 Ko | 83 Ko |
  | 7 | 5 | 2 | 4,8 Mo | 959 Ko | 138 Ko |

  UOV ajoute sa clé de 67 Ko, une fois par témoin. Comme dans la note au-delà de 0.4, la clé UOV d'un témoin ne sert qu'au suivi ; les entrants s'ancrent sur une signature ML-DSA ou FN-DSA.
- **La vivacité.** Si le quorum ne répond pas dans un délai, le membre accepte la fenêtre au niveau de MLS, par le tag et la signature du scelleur, et la marque comme non contresignée. S'il découvre plus tard deux points de contrôle contradictoires, il le signale. Le refus des bifurcations se dégrade en détection, jamais en dessous de MLS.
- **Les témoins** peuvent être des services indépendants, comme ceux de la transparence des certificats ; la RFC 9750 recommande d'ailleurs un mécanisme de transparence des clés (section 8.4.3.1).

## 4. Standards

- **Le KEM.** Le projet de suites post-quantiques de MLS prend les KEM hybrides du projet CFRG des KEM hybrides concrets, dont `MLKEM768-X25519` est dit identique à X-Wing : City-G et MLS partagent leur KEM.
- **Le KEM multi-destinataires** n'est plus nécessaire depuis la ville entretenue.
- **FN-DSA** attend sa norme finale ; les cartes peuvent être ML-DSA en attendant.
- **La dérivation de clés, un choix pour le mainteneur :**
  - garder BLAKE3, rapide, avec l'hypothèse de PRF double désormais énoncée ;
  - ou prendre HKDF-SHA-384, comme les suites de MLS : leur analyse et celle de HMAC en PRF double s'appliqueraient telles quelles.

  Le coût est négligeable dans les deux cas : un membre fait quelques dizaines de dérivations par fenêtre. La différence est la maturité de l'analyse, pas la vitesse.

## 5. Cartes d'émetteur

La note au-delà de 0.4 proposait de garder les cartes en cache. Leur rythme de changement décide du gain : une carte change avec la feuille, et un membre met à jour sa feuille au moins toutes les semaines (`UPDATE_INTERVAL`, spécification, section 16).

- **Le cache.** Un lecteur garde la partie carte des feuilles de ses émetteurs. Pour un émetteur déjà vu dont la carte n'a pas changé, il ne relit que le reste de la feuille, 122 octets, pour en recalculer le haché, et il revalide la carte contre l'époque du message (`card_revalidated.pv`).
- **Le gain** (rapport 3 ; lecteur de 10 000 messages par jour, 2 001 émetteurs par jour) :

  | Émetteurs revenus des jours précédents | Hits du cache | Cartes par jour | Émetteurs par jour, preuves comprises |
  | ---: | ---: | ---: | ---: |
  | 0 % | 0 % | 2,0 Mo | 3,7 Mo |
  | 50 % | 43 % | 1,3 Mo | 2,9 Mo |
  | 80 % | 69 % | 808 Ko | 2,5 Mo |
  | 95 % | 81 % | 578 Ko | 2,2 Mo |

- **Le plancher** est celui des preuves d'appartenance de chaque session, 1,7 Mo par jour, que le cache ne réduit pas : l'arbre change à chaque fenêtre. La journée de ce lecteur passe de 9,9 à 8,7 Mo si 80 % de ses émetteurs reviennent, pour 6,1 Mo de messages.
- **Changer les cartes moins souvent** que la feuille augmenterait le gain, mais retarderait la guérison de l'authentification. MLS n'impose pas non plus de changer la clé de signature. La note garde une carte liée à la feuille.

## 6. Métadonnées

La crainte de la note au-delà de 0.4 : en attribuant les tâches et les relais, le serveur verrait qui est en ligne. Il le voit déjà.

- **Ce que voit déjà un DS**, de City-G comme de MLS : les connexions de chaque appareil, leurs heures et leurs adresses, la taille et l'heure des messages. Il voit aussi l'appartenance, puisqu'il valide les requêtes, comme un DS de MLS qui voit les messages de gestion en clair (RFC 9750, section 6.4).
- **Ce que les tâches ajoutent** : que tel appareil, déjà connecté, a fait tel travail, et en combien de temps. Le serveur a choisi l'appareil ; il connaît déjà sa place dans l'arbre, puisqu'il l'y a mis.
- **Ce que les tâches ne révèlent pas** : qui envoie quel message (G2), puisque les données d'émetteur restent chiffrées.
- **Ce qui reste** relève du transport : cacher l'adresse et l'heure des connexions demande un transport anonyme, hors du protocole dans City-G comme dans MLS.

Le problème 6 se ramène donc aux limites de MLS (G12). Il sort de la liste des problèmes propres au profil candidat.

## 7. Où en sont les problèmes ouverts

| Problème de la note au-delà de 0.4 | État | Ce qui reste |
| --- | --- | --- |
| 1. Preuve calculatoire | Avancé : 7 propriétés prouvées dans le modèle calculatoire, hypothèse de PRF double identifiée et énoncée | L'arbre entier sous corruptions adaptatives ; l'authentification ; la seconde préimage du tag |
| 2. Preuves de litige | Chiffré : 1,1 million de portes AND, environ 0,4 Mo à vérifieur désigné | Implémenter, mesurer ; partie X25519 d'une preuve publique |
| 3. Bifurcations | Résolu en conception : témoins 3 sur 4, dégradation vers MLS | La confiance dans les témoins ; UOV reste un candidat |
| 4. Standards | Clarifié : KEM commun avec MLS, KEM multi-destinataires inutile | FN-DSA final ; BLAKE3 ou HKDF (décision) |
| 5. Cartes d'émetteur | Chiffré : cache, jusqu'à −40 % sur les émetteurs | Mesurer sur des traces le retour des émetteurs |
| 6. Métadonnées | Ramené aux limites de MLS | Le transport, hors du protocole |
| 7. Spécification et implémentation | Inchangé | L'accord du mainteneur |

Le nouvel ordre :
1. la preuve de l'arbre sous corruptions adaptatives ;
2. la mesure des litiges ;
3. le choix entre BLAKE3 et HKDF, qui conditionne la première ;
4. la spécification.

La note [preuves et mesures](preuves-et-mesures-2026-09-26.md) reprend cet ordre : elle mesure le litige, prouve l'authentification du relais et des témoins, écrit le plan de preuve de l'arbre et recommande HKDF pour `Extract`. Elle trouve aussi une faille du saut de la v0.4 sous clé d'appareil volée, et la corrige.

## 8. Modèles et reproductibilité

- `docs/research/formal-computational/run.sh [chemin/de/cryptoverif]` : les 14 modèles en une vingtaine de secondes. Le job des modèles formels de la CI construit CryptoVerif 2.13, somme de contrôle vérifiée, et les lance ; le script de CI locale les lance quand `cryptoverif` est installé.
- `python3 docs/research/open_problems_sim.py` : les trois rapports de cette note.
- Les modèles ProVerif restent inchangés : 16, 17 et 32 scénarios.

## 9. Sources

* B. Blanchet et al., [CryptoVerif](https://bblanche.gitlabpages.inria.fr/CryptoVerif/), version 2.13.
* M. Backendal, M. Bellare, F. Günther, M. Scarlata, [When Messages are Keys: Is HMAC a dual-PRF?](https://eprint.iacr.org/2023/861), Crypto 2023.
* M. Bellare, A. Lysyanskaya, [Symmetric and Dual PRFs from Standard Assumptions: A Generic Validation of a Prevailing Assumption](https://eprint.iacr.org/2015/1198), Journal of Cryptology, 2024.
* M. Backendal, S. Clermont, M. Fischlin, F. Günther, [Key Derivation Functions Without a Grain of Salt](https://eprint.iacr.org/2025/657), Eurocrypt 2025.
* C. Brzuska, E. Cornelissen, K. Kohbrok, [Security Analysis of the MLS Key Derivation](https://eprint.iacr.org/2021/137), IEEE S&P 2022.
* J. Alwen et al., [Keep the Dirt: Tainted TreeKEM, Adaptively and Actively Secure Continuous Group Key Agreement](https://eprint.iacr.org/2019/1489), IEEE S&P 2021.
* G. Fuchsbauer, Z. Jafargholi, K. Pietrzak, [A Quasipolynomial Reduction for Generalized Selective Decryption on Trees](https://eprint.iacr.org/2016/389), Crypto 2015.
* M. Barbosa et al., [X-Wing: The Hybrid KEM You've Been Looking For](https://eprint.iacr.org/2024/039), 2024.
* J. Alwen, B. Blanchet, E. Hauck, E. Kiltz, B. Lipp, D. Riepel, [Analysing the HPKE Standard](https://eprint.iacr.org/2020/1499), Eurocrypt 2021.
* K. Yang, P. Sarkar, C. Weng, X. Wang, [QuickSilver: Efficient and Affordable Zero-Knowledge Proofs for Circuits and Polynomials over Any Field](https://eprint.iacr.org/2021/076), CCS 2021.
* C. Weng, K. Yang, X. Xie, J. Katz, X. Wang, [Mystique: Efficient Conversions for Zero-Knowledge Proofs with Applications to Machine Learning](https://eprint.iacr.org/2021/730), USENIX Security 2021.
* C. Baum et al., [Publicly Verifiable Zero-Knowledge and Post-Quantum Signatures From VOLE-in-the-Head](https://eprint.iacr.org/2023/996), Crypto 2023.
* NIST, [FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard](https://csrc.nist.gov/pubs/fips/203/final), 2024.
* R. Barnes et al., [The Messaging Layer Security (MLS) Protocol](https://www.rfc-editor.org/rfc/rfc9420.html), RFC 9420, 2023 ; B. Beurdouche et al., [The Messaging Layer Security (MLS) Architecture](https://www.rfc-editor.org/rfc/rfc9750.html), RFC 9750, 2025.
* Notes précédentes : [au-delà de 0.4](au-dela-0.4-2026-09-26.md), [îlots](ilots-2026-09-26.md), [re-key par le serveur](rekey-serveur-2026-09-26.md), [parité MLS](parite-mls-2026-09-26.md), [plan de messages](plan-de-messages-2026-09-26.md).
