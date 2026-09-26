# Les garanties de MLS pour un million de membres

| | |
| --- | --- |
| Date | 2026-09-26 |
| Nature | Note de recherche. Elle fixe ce qu'il faut à City-G pour avoir les garanties de MLS ([RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html), [RFC 9750](https://www.rfc-editor.org/rfc/rfc9750.html)) dans des groupes d'un million de membres, avec des vagues d'entrées et de départs, et une appartenance que le service autorise. Elle révise la note [plan de messages](plan-de-messages-2026-09-26.md) : les lecteurs hors de l'arbre n'ont pas ces garanties et sortent du profil visé. La note [re-key par le serveur](rekey-serveur-2026-09-26.md) la complète : elle examine si le serveur pourrait re-keyer à la place des membres, et propose des litiges vérifiables contre les enveloppes fausses. Rien de ce qu'elle décrit n'est encore dans la spécification ni dans le code. |
| Question | Que faut-il changer à City-G pour qu'il ait les mêmes garanties que MLS, jusqu'à un million de membres, avec des entrées et des départs massifs, et où n'importe qui que le serveur autorise peut entrer ou sortir ? |
| Compagnons | [`parity_sim.py`](parity_sim.py) : modèle de coût (`python3 docs/research/parity_sim.py`, quelques secondes ; il réutilise [`rekey_sim.py`](rekey_sim.py) et [`msg_sim.py`](msg_sim.py)). [`formal-parity/`](formal-parity/README.md) : modèle ProVerif des mécanismes nouveaux (section 5). |
| Auteur | Claude Code (assistant IA d'Anthropic), à la demande du mainteneur. Le modèle symbolique couvre les choix clés ; il n'existe aucune preuve calculatoire. Une relecture cryptographique humaine reste nécessaire. |

Vocabulaire :
- la *parité* : les garanties de MLS, face aux mêmes adversaires ;
- l'*autorisateur* : le service qui décide qui peut entrer. Il signe les autorisations et un point de contrôle par fenêtre. Ce peut être le serveur qui fait office de DS, ou un service distinct ; la note recommande de les séparer ;
- un *retrait urgent* vient d'un admin ou de l'autorisateur, ou signale une compromission ; un *retrait ordinaire* est un départ volontaire ou une expulsion pour inactivité ;
- une *enveloppe* est, comme dans les notes précédentes, le secret d'un nœud chiffré vers un enfant (un *wrap* de la spécification) ;
- N est la taille du groupe, H = log2 N.

## 0. Résumé

1. **La v0.4 a déjà l'essentiel des garanties de MLS** : confidentialité des secrets de groupe, secret après retrait, confidentialité persistante, guérison après compromission, secret des entrants, accord sur les membres. Face au DS, elle a la même position que MLS : il ne lit ni ne forge, il peut retarder, supprimer ou faire bifurquer. Il lui manque quatre choses :
   - un plan de messages à la MLS, où le DS n'apprend pas qui a envoyé quoi ([RFC 9420, §16.3](https://www.rfc-editor.org/rfc/rfc9420.html#section-16.3)) ;
   - l'unicité des clés dans l'arbre ([§16.7](https://www.rfc-editor.org/rfc/rfc9420.html#section-16.7)) ;
   - un mode où le service autorise les entrées ([§16.11](https://www.rfc-editor.org/rfc/rfc9420.html#section-16.11), [RFC 9750, §6.4](https://www.rfc-editor.org/rfc/rfc9750.html#section-6.4)) ;
   - un moyen pour chaque membre de connaître l'appartenance ([RFC 9750, §8.4.3.1](https://www.rfc-editor.org/rfc/rfc9750.html#section-8.4.3.1)).
2. **La note du plan de messages allait trop loin.** Ses lecteurs hors de l'arbre, sa chaîne publique et la rétention des secrets par les gardiens n'ont pas les garanties de MLS. Un membre sans clé propre dans une structure de révocation ne peut pas, hors ligne, recevoir les époques qui suivent un retrait sans que le retiré les reçoive aussi (section 2.2). Ces mécanismes sortent du profil visé. Les cartes d'émetteur, les chaînes de rafale, les messages engageants et le journal scellé restent.
3. **Le profil proposé** (section 3) :
   - tout membre dans l'arbre, comme en v0.4 ;
   - un *mode autorisé* : l'autorisateur signe, par fenêtre, une racine de Merkle sur les entrées qu'il autorise et un point de contrôle de l'époque créée. Un entrant s'ancre sur ce point de contrôle, sans chaîne de sceaux. Un membre sort quand il veut ; un admin ou l'autorisateur peut le retirer ;
   - en option, chaque membre vérifie ce point de contrôle à chaque fenêtre qu'il suit. Si l'autorisateur est distinct du DS, l'admission devient alors déterministe comme dans MLS, et un initié allié au DS ne peut plus mener ce membre dans une époque inventée ; cela coûte 278 Ko par jour avec une signature FN-DSA et des fenêtres de 5 minutes ;
   - un plan de messages à la MLS : arbre de secrets, données d'émetteur chiffrées, carte d'émetteur dans la feuille, chaînes de rafale livrées à l'application seulement après vérification, engagement de clé, journal scellé ;
   - l'unicité des clés de feuille, des cartes et des appareils ;
   - un *journal des membres* : chaque sceau engage la liste des changements de sa fenêtre ;
   - des retraits urgents et ordinaires : la cadence des fenêtres règle le coût sans toucher aux garanties ;
   - un exporteur et un authentifiant d'époque, comme MLS.
4. **Chiffres** (2^20 membres, 1,7 changement par seconde ; `parity_sim.py`) :
   - suivre le groupe : 7,4 Mo par jour avec des fenêtres d'une minute, 2,0 Mo avec des fenêtres de 5 minutes, 1,1 Mo avec 10 minutes. La longueur des fenêtres est le délai d'un retrait ordinaire ; un retrait urgent ajoute une fenêtre de 1,4 Ko ;
   - la journée d'un membre qui lit 100 messages : 2,1 Mo avec des fenêtres de 5 minutes, contre 7,9 Mo pour un portage direct de la v0.4 ;
   - une vague de 100 000 entrées et 100 000 départs : 648 420 enveloppes en parallèle, 11,9 Ko par membre, 57 Ko par entrant au lieu de 327 Ko, et des autorisations de 54 Mo au lieu de 331 Mo ;
   - le retour après une absence : rejouer, et lire tout ce qui a été manqué, coûte 2,0 Mo par jour d'absence ; sauter coûte 32 Ko, sans les messages manqués.

   La parité se paie : un lecteur léger télécharge 2,1 Mo par jour au lieu des 329 Ko des lecteurs hors de l'arbre. C'est le prix du secret après retrait pour des membres hors ligne.
5. **Sécurité** : 10 scénarios ProVerif nouveaux, tous au verdict attendu.
   - Autorisations groupées, ancrage des entrants, et membres qui vérifient chaque point de contrôle : prouvés, et attaqués sans les signatures de l'autorisateur.
   - L'émetteur caché au DS : équivalence prouvée ; elle échoue, comme attendu, si l'émetteur passe en clair.
   - Les *liens d'historique*, qui auraient rendu le retour aussi économique qu'un saut : un retiré qui revient lit les époques où il n'était pas membre. Ils sont rejetés.
6. **Ce qui reste comme dans MLS** :
   - les bifurcations par le DS, détectables par comparaison hors bande, sauf pour un membre qui vérifie les points de contrôle d'un autorisateur distinct du DS : il les refuse ;
   - la fragmentation par un initié. Un scelleur hostile peut couper tout le groupe, comme un committer hostile dans MLS, et un committer de quartier son quartier. Mais chaque fenêtre donne ce pouvoir à plusieurs membres, un par quartier changé plus le scelleur, là où MLS le donne à un seul membre par époque ;
   - la compromission de l'autorisateur, qui fait entrer qui il veut, visiblement, comme un service d'authentification compromis.

## 1. La cible

### 1.1 Les garanties de MLS

MLS est pensé pour des groupes de dizaines de milliers de membres ([RFC 9750, §6](https://www.rfc-editor.org/rfc/rfc9750.html#section-6)). Ses garanties, et ce qu'il ne promet pas :

| # | Garantie ou limite de MLS | Source |
| --- | --- | --- |
| G1 | Seuls les membres d'une époque en lisent les messages : un retiré ne lit plus rien après son retrait, un entrant ne lit rien d'avant son entrée. | RFC 9420 §16.2 ; RFC 9750 §6.1 |
| G2 | Le DS n'apprend pas quel membre a envoyé un message chiffré. | RFC 9420 §16.3 |
| G3 | Chaque membre authentifie l'émetteur de chaque message (signature), et que le message vient d'un membre (AEAD). | RFC 9420 §16.5 ; RFC 9750 §8.2.1 |
| G4 | Confidentialité persistante, entre époques et dans une époque ; guérison après la mise à jour d'un membre compromis. | RFC 9420 §16.6 ; RFC 9750 §8.2.2 |
| G5 | Les clés de chiffrement et de signature de l'arbre sont toutes distinctes. | RFC 9420 §16.7 |
| G6 | Le matériel d'entrée ne sert qu'une fois. | RFC 9420 §16.8 |
| G7 | Le DS ne lit ni ne forge. Il peut retarder, supprimer, bloquer, choisir entre deux commits, et faire bifurquer le groupe, ce que seule une comparaison hors bande de l'authentifiant d'époque révèle. | RFC 9420 §16.9 ; RFC 9750 §5.2, §8.4.2 |
| G8 | Un service d'authentification compromis fait entrer qui il veut. | RFC 9420 §16.10 ; RFC 9750 §8.4.3 |
| G9 | Le DS ou les clients appliquent la politique d'accès, et les intermédiaires peuvent voir les messages de gestion pour l'appliquer. | RFC 9420 §16.11 ; RFC 9750 §6.4 |
| G10 | Tout membre sait qui est dans le groupe, et aucun membre n'entre ni ne sort sans que tous en soient informés. | RFC 9750 §6.1, §8.4.3.1 |
| G11 | Un membre hors ligne rattrape le groupe et lit ce qu'il a manqué. Les membres longtemps inactifs sont un risque pour G4, que les applications doivent borner par l'expulsion. | RFC 9750 §6.3, §8.2.2 ; RFC 9420 §16.6 |
| G12 | MLS ne promet pas : le déni, la confidentialité face au DS de l'identifiant du groupe, des époques et de leur fréquence (ni de l'appartenance si les messages de gestion passent en clair), la protection contre le rejeu d'un message par un initié dans son époque, la disponibilité, la résistance à la fragmentation par un initié. | RFC 9420 §16.4, §16.12 ; RFC 9750 §8.6 |

### 1.2 Les exigences d'échelle

- **R1.** Des groupes jusqu'à 2^20 membres, et au-delà : l'arbre de City-G va jusqu'à 2^24 feuilles.
- **R2.** Des vagues de 100 000 entrées et 100 000 départs, traitées en une fois.
- **R3.** N'importe qui que le service autorise peut entrer ; tout membre peut sortir.

## 2. Où en est City-G

### 2.1 Garantie par garantie

| # | v0.4 (spécification) | Plan de messages (note du 26) | Écart à combler |
| --- | --- | --- | --- |
| G1 | Oui : l'invariant de l'arbre, étendu aux committers par les taches ; secret après retrait dès la fenêtre qui l'applique ; secret des entrants par la chaîne d'init. | Non pour les lecteurs hors de l'arbre : rétention par les gardiens, ou lecture jusqu'à la rupture suivante. | Retirer les lecteurs hors de l'arbre (section 2.2). |
| G2 | Pas de plan de messages. | Non : l'émetteur est visible du DS, pour qu'il filtre. | Données d'émetteur chiffrées (section 3.3). |
| G3 | Signatures des requêtes, des commits et des sceaux. | Oui, par les cartes ; mais un message d'une rafale n'est authentifié que par le groupe tant que sa signature n'est pas arrivée. | Ne livrer un message qu'une fois sa signature vérifiée (section 3.3). |
| G4 | Oui : effacement par époque, chaîne d'init, taches pour la guérison. | Non : la rétention par les gardiens retarde la confidentialité persistante. | Arbre de secrets et journal scellé, sans rétention (section 3.3). |
| G5 | Non exigé. | Non exigé. | Unicité des clés de feuille, des cartes et des appareils (section 3.4). |
| G6 | Oui : clé d'init à usage unique, jeton d'admission à usage unique. | – | – |
| G7 | Oui, et le DS seul ne peut pas fabriquer d'époque pour un membre qui vérifie le tag (chaîne d'init). | Oui. | Authentifiant d'époque et points de contrôle (section 3.8). |
| G8 | Admins et invitations : leur compromission fait entrer qui elle veut. | – | Autorisateur (section 3.2). |
| G9 | Oui : le DS voit et vérifie toutes les requêtes. | – | Mode autorisé (section 3.2). |
| G10 | Accord par les hachés ; la liste des entrées d'une fenêtre se lit à partir des commits de quartier. | – | Journal des membres, compact et engagé par le sceau (section 3.5). |
| G11 | Oui en rejouant les fenêtres ; le saut rattrape sans lire le manqué ; expulsion des inactifs. | Les lecteurs dépendent d'un membre en ligne. | Garder le rejeu ; les liens d'historique sont rejetés (section 3.7). |
| G12 | Mêmes limites ; le DS voit l'appartenance, comme un DS de MLS qui voit les messages de gestion en clair. | Journal scellé : protège contre le rejeu et la suppression. | – |
| R1 | Oui : 2^24 feuilles. | – | – |
| R2 | Oui : une fenêtre par vague, des quartiers en parallèle. | – | Autorisations groupées (section 3.2). |
| R3 | Groupes fermés (admins) ou ouverts (tout appareil). | – | Mode autorisé ; départ volontaire déjà possible. |

La v0.4 fait sur un point mieux que MLS. Un membre y sort seul, par une requête signée ; dans MLS, un membre qui veut partir doit être retiré par un autre ([RFC 9750, §6.1](https://www.rfc-editor.org/rfc/rfc9750.html#section-6.1)).

### 2.2 Pourquoi les lecteurs hors de l'arbre n'ont pas la parité

Soit R un membre qui ne tient, en plus des données publiques, que des secrets partagés par le groupe, comme le secret de lecteur, et aucun secret qui lui soit propre dans une structure de révocation. Soit M un membre que la fenêtre `r` retire, et qui tenait les mêmes secrets de groupe que R à l'époque `r - 1`.

Leurs états ne diffèrent que par des secrets propres, que R n'a pas. Tout ce que R peut calculer après la fenêtre `r`, à partir de son état et des données publiques, M le peut donc aussi. Il ne reste que deux possibilités :
- **R interagit** avec une partie en ligne après la fenêtre `r`, qui lui sert l'époque : ce sont les lots de clés. Cette partie doit avoir gardé les secrets, ce qui affaiblit G4. Et R ne rattrape plus le groupe sans elle, ce qui affaiblit G11 ;
- **les données publiques suffisent** à calculer l'époque `r` : c'est la chaîne publique sans rupture. Alors M la calcule aussi, ce qui casse G1.

La parité exige donc que chaque membre tienne un secret propre dans une structure de révocation : une feuille dans un arbre. Exclure D membres parmi N coûte alors au moins de l'ordre de D·log(N/D) chiffrés ([Micciancio et Panjwani, Eurocrypt 2004](https://www.iacr.org/archive/eurocrypt2004/30270154/final.pdf)). Le re-key de City-G atteint cette borne à un facteur 1,1 à 1,3 près (note [grands-groupes](grands-groupes-2026-09-25.md), section 4.1).

Les lecteurs de la note du plan de messages tombent d'un côté ou de l'autre de l'alternative : lots et rétention, ou chaîne publique et ruptures. Les scénarios `reader_removed_with_root.pv`, `reader_removed_ratchet.pv` et `reader_link_no_break.pv` de [`formal-messages/`](formal-messages/README.md) en montrent les attaques. Les cartes, les rafales, les messages engageants et le journal scellé n'en dépendent pas.

## 3. Le profil proposé

### 3.1 Tout membre dans l'arbre

L'architecture de la v0.4 ne change pas : quartiers et ville, fenêtres, taches, chaîne d'init, sceaux par des entrants quand personne n'est en ligne, audits par échantillonnage. Chaque membre suit les fenêtres par un paquet qui porte son chemin, ou les rejoue à son retour.

### 3.2 Le mode autorisé

**Politique.** La politique de groupe gagne un troisième mode d'admission, *autorisé*, et la clé de l'autorisateur :

```text
GroupPolicy          := [..., admission_mode (0 fermé, 1 ouvert, 2 autorisé), authorizer_pk, ...]
AuthorizationBatch   := ["city-g/authorization-batch/v5", gid, epoch, root, count, signature]
AuthorizerCheckpoint := ["city-g/authorizer-checkpoint/v5", gid, epoch, interim, tree_hash,
                         registry_hash, confirmation_tag, external_pk_hash, signature]
```

**Entrées.** L'autorisateur signe, pour la fenêtre qui crée l'époque `n`, la racine de Merkle des hachés des requêtes d'entrée qu'il autorise. Une entrée est valide avec sa preuve d'inclusion dans une telle racine, et son jeton est le haché de la requête : elle n'entre qu'une fois. Le DS, les committers et les auditeurs vérifient la preuve (`batch_authorization.pv` ; sans la signature de la racine, le DS fait entrer ses propres appareils : `batch_authorization_unsigned.pv`). Pour 100 000 entrées, il y a une signature au lieu de 100 000, et 544 octets de preuve par entrée au lieu de 3,3 Ko.

**Points de contrôle.** Après chaque fenêtre, l'autorisateur signe le point de contrôle de l'époque créée, confirmation tag compris. Un entrant qui fait confiance à la clé de l'autorisateur vérifie ce seul point de contrôle et le joiner secret de son welcome, sans chaîne de sceaux (`authorizer_anchor.pv`). Il ne vérifie donc plus de 30 liens de sceaux en moyenne. Si l'autorisateur ne répond pas, l'entrant revient à la chaîne de sceaux depuis le dernier point de contrôle.

**Vérifier chaque point de contrôle (option).** Avant de signer, l'autorisateur vérifie la fenêtre : il tient l'état public du groupe, compare la liste des changements (section 3.5) à ses autorisations, et recalcule le registre et le haché de l'arbre. Il ne signe qu'un point de contrôle par époque.
- Un membre qui suit le groupe peut exiger ce point de contrôle avant d'accepter une fenêtre. Il gagne deux choses sur la v0.4 :
  - aucune entrée non autorisée ne passe, même avec la complicité du DS et d'un committer : c'est l'admission déterministe de MLS, où chaque membre valide chaque ajout ;
  - un initié allié au DS ne peut plus le mener dans une époque inventée, puisque l'autorisateur ne l'a pas signée (`authorizer_follow.pv` ; sans cette vérification, c'est la bifurcation de la v0.4 : `authorizer_follow_unchecked.pv`). MLS ne l'empêche pas.
- Il paie en vivacité, puisque sans point de contrôle il attend, et en octets : un point de contrôle par fenêtre, soit 1,0 Mo par jour avec une signature ML-DSA-65 et des fenêtres de 5 minutes, ou 278 Ko avec FN-DSA-512.
- Cela suppose un autorisateur distinct du DS. Confondu avec lui, il signe ce qu'il veut, et la vérification n'apporte plus que ce qu'apporte MLS.

**Sorties.** Un membre sort par sa propre requête, à tout moment. Un admin ou l'autorisateur peut retirer un membre : ses retraits sont groupés de la même façon et sont urgents (section 3.6).

**Confiance.** L'autorisateur a la place du service d'authentification de MLS (G8). S'il est compromis, il fait entrer qui il veut, mais chaque entrée reste visible : elle est engagée par le sceau et listée dans le journal des membres (section 3.5). La note recommande que l'autorisateur soit un service distinct du DS, sa clé dans un module matériel. Le DS seul ne peut alors ni faire entrer un appareil ni mener un entrant dans une époque fabriquée. Si c'est le même serveur, il peut autoriser ses propres appareils, visiblement, comme le prévoit l'exigence R3.

### 3.3 Un plan de messages à la MLS

**Calendrier.** Du `msg_secret_n` de la v0.4 dérivent quatre secrets, comme dans MLS :

```text
sender_data_secret_n, encryption_secret_n, exporter_secret_n, epoch_authenticator_n
    := DeriveSecret(msg_secret_n, "sender data" | "encryption" | "exporter" | "authenticator")
```

- `encryption_secret_n` est la racine d'un arbre de secrets sur les feuilles (2^24 positions, 8,1 µs mesurés par chaîne d'émetteur). Chaque émetteur y a sa chaîne, dont les clés s'effacent après usage : c'est la confidentialité persistante dans l'époque (G4).
- L'arbre efface ses nœuds à mesure que les chaînes sont dérivées.

**Message.**

```text
Message     := [gid, epoch, encrypted_sender_data, ciphertext, commitment]
sender_data := [leaf, generation, reuse_guard]             (chiffrées comme dans MLS, clé et nonce
                                                            tirés de sender_data_secret_n et d'un
                                                            échantillon du chiffré)
content     := [application_data, first_generation, signature or null, padding]
signature   := Card.Sign([gid, epoch, leaf, first_generation, chain_g])
chain_g     := H_L("msg-chain", [chain_g-1, H(content_g sans signature)])
commitment  := H_L("msg-commit", [key_g, nonce_g, H(ciphertext)])
```

- **L'émetteur est caché.** Il est chiffré avec la signature, que le DS ne voit pas. Le DS ne sait pas qui a envoyé (G2 ; équivalence prouvée par `sender_hidden.pv`, qui échoue quand l'émetteur passe en clair : `sender_visible.pv`). Le DS ne filtre donc plus les messages par la carte : il authentifie la connexion et limite les débits, comme MLS le prévoit (§16.11).
- **Les rafales sont livrées après vérification.** Une signature couvre la chaîne de la rafale. Un client ne livre un message à l'application qu'une fois sa signature vérifiée : G3 tient, au prix d'un délai d'au plus `T_AUTH` pour les messages d'une rafale (`burst_chain.pv`).
- **Le journal scellé.** Le sceau suivant engage la racine des messages de l'époque (note du plan de messages, section 3.5). Il en découle la cohérence du transcript, la détection des suppressions, et la protection contre le rejeu dans l'époque, que MLS ne donne pas (G12). Un message arrivé après la clôture de son époque est refusé, et son émetteur le rechiffre.
- **L'engagement de clé.** Il rend les signalements vérifiables (franking).

### 3.4 Cartes dans la feuille, unicité des clés

```text
LeafNode := [device_id, since, encryption_key, card, admission_hash, updated]
card     := [algorithm, public_key]
```

- **La feuille porte la carte.** Elle porte aussi `device_id` au lieu de la clé d'appareil : les requêtes signées portent la clé, que l'on vérifie contre `device_id`. Une feuille pèse ainsi 2,2 Ko au lieu de 4,1 Ko avec une carte FN-DSA-512.
- **La carte change à chaque mise à jour de la feuille**, ce qui donne la guérison de l'authentification (G4).
- **Unicité (G5).** Le DS, les committers et les auditeurs rejettent une feuille dont la clé de chiffrement ou la carte existe déjà dans l'arbre. Le registre tient pour cela une carte de Merkle creuse des hachés de clés, comme il le fait des appareils. Sans cette règle, un membre qui copie la carte d'un autre rend ses messages attribuables à deux feuilles.

### 3.5 Le journal des membres

Chaque sceau engage la racine de la liste compacte des changements de sa fenêtre : genre, feuille, `device_id`, préfixe du haché de la carte, 48 octets par changement.
- Un membre peut télécharger la liste d'une fenêtre et la vérifier : c'est ce que MLS impose à chaque membre, et que City-G laisse à la demande (G10).
- Voir tous les changements coûte 7,1 Mo par jour à 1,7 changement par seconde. Une preuve d'appartenance d'un appareil coûte 640 octets.
- Suivant la recommandation de la RFC 9750 (§8.4.3.1), un client montre les changements, ou tient un journal que l'utilisateur peut examiner quand ils sont trop nombreux.

### 3.6 Retraits urgents et ordinaires

La v0.4 ferme une fenêtre au plus `WINDOW_REMOVAL` (5 s) après un retrait, et un membre n'envoie pas tant qu'un retrait attend depuis plus longtemps. Avec un million de membres qui partent sans cesse, cette règle ferait une fenêtre toutes les 5 secondes : 44 Mo par jour et par membre à 1,7 changement par seconde (30 Mo avec des fenêtres de 10 s). Le profil distingue donc deux sortes de retraits :

- **urgents** (un admin, l'autorisateur, une compromission signalée) : fenêtre sous `WINDOW_REMOVAL`, et la règle d'envoi s'applique ;
- **ordinaires** (départs volontaires, expulsions pour inactivité) et mises à jour : la fenêtre planifiée suivante, `WINDOW_ORDINARY`, que l'on fixe à 5 minutes pour un groupe d'un million.

MLS ne borne pas le délai d'un retrait : il vaut jusqu'au commit suivant. Le secret après retrait est acquis dès la fenêtre qui applique le retrait, dans les deux cas. Ce qui change, c'est le coût : 2,0 Mo par jour avec des fenêtres de 5 minutes, au lieu de 7,4 Mo avec des fenêtres d'une minute. Un retrait urgent ajoute une fenêtre de 1,4 Ko.

### 3.7 Retour après une absence

- **Rejouer** chaque fenêtre manquée : le membre lit tout ce qu'il a manqué, comme dans MLS (G11). Cela coûte le suivi qu'il n'a pas fait : 2,0 Mo par jour d'absence avec des fenêtres de 5 minutes.
- **Sauter** au présent : 32 Ko, sans les époques manquées, comme la ré-initialisation de MLS après une perte d'état (RFC 9750, §6.6).
- **Les liens d'historique sont rejetés.** On a cherché à faire lire le manqué au prix d'un saut. Chaque sceau aurait porté le commit secret de l'époque précédente, chiffré sous une clé tirée du sien. Un membre de retour aurait remonté la chaîne depuis le présent, et recalculé chaque époque manquée avec sa dernière init. La chaîne d'init protège bien des membres retirés (`history_link.pv`). Mais un retiré qui revient tient encore son init d'avant son retrait : les liens lui donnent les époques où il n'était pas membre (`history_link_rejoin.pv`). Les liens ne distinguent pas un membre revenu d'une absence d'un ancien membre qui revient. Seul le chemin du membre dans l'arbre les distingue, et c'est ce que coûte le rejeu.

### 3.8 Exporteur, authentifiant d'époque et bifurcations

- `exporter_secret_n` sert les usages de l'application, comme l'exporteur de MLS.
- `epoch_authenticator_n` se compare hors bande pour détecter une bifurcation, comme dans MLS (RFC 9750, §5.2).
- Les points de contrôle de l'autorisateur et les témoins de la note du plan de messages (section 3.6) rendent cette comparaison automatique.

### 3.9 Ce que la parité ne change pas

- **Bifurcations.** Comme dans MLS, le DS peut faire bifurquer le groupe. Avec l'aide d'un membre de l'époque précédente, il peut mener un membre qui ne vérifie que le tag dans une époque de son choix (spécification, section 2.3). Un membre qui vérifie les points de contrôle d'un autorisateur distinct du DS refuse cette époque (section 3.2).
- **Fragmentation par un initié** (RFC 9420, §16.12). Dans MLS, le committer chiffre un secret de son chemin vers chaque sous-arbre voisin (§7.5) : chaque autre membre reçoit un chiffré de lui. Un committer hostile peut donc couper n'importe quelle partie du groupe, jusqu'au groupe entier. Dans City-G :
  - un committer de quartier ne chiffre que vers les membres de son quartier, dont il re-keye les chemins : il peut couper au plus ce quartier (4 096 membres avec `L = 12`), et les entrants dont il scelle les welcomes ;
  - le scelleur re-keye la ville jusqu'à la racine et calcule le tag de confirmation que chaque membre vérifie : un tag faux, ou un chiffré faux près de la racine, coupe tout le groupe, comme un committer MLS ;
  - un entrant qui scelle seul une fenêtre tient les deux rôles, comme un membre qui entre par un commit externe dans MLS.

  La portée d'un rôle n'est donc pas plus large que dans MLS. Ce qui l'est, c'est le nombre de membres qui reçoivent un rôle à chaque fenêtre : jusqu'à un committer par quartier changé, plus le scelleur. La parade reste celle de MLS, des rapports d'échec (spécification, section 19), que la note [re-key par le serveur](rekey-serveur-2026-09-26.md) rend vérifiables (section 3.4) ; le DS peut aussi confier le sceau à des membres de confiance, les gardiens admis d'un groupe public par exemple.
- **Métadonnées.** Le DS voit l'appartenance, puisqu'il valide les requêtes ; c'est la position d'un DS de MLS qui voit les messages de gestion en clair (RFC 9750, §6.4).

### 3.10 Ce qui sort du profil

Les lecteurs hors de l'arbre, les lots de clés, la chaîne publique, les ruptures et la rétention par les gardiens (note du plan de messages, sections 3.1 et 3.8) n'ont pas la parité (section 2.2). Une application qui accepterait une révocation de lecture retardée pourrait les employer, en le déclarant. Ils ne font pas partie du profil à parité.

## 4. Chiffres

`python3 docs/research/parity_sim.py`, groupe de 2^20 membres, quartiers de 2^12, suite de la spécification (X-Wing, ML-DSA-65), cartes FN-DSA-512.

### 4.1 Suivre le groupe

Par membre et par jour :

| Changements par seconde | Fenêtre (délai d'un retrait ordinaire) | Enveloppes par fenêtre | Par jour |
| ---: | ---: | ---: | ---: |
| 0,1 | 60 s | 1,7 | 3,2 Mo |
| 0,1 | 5 min | 3,2 | 1,1 Mo |
| 0,1 | 10 min | 3,8 | 0,7 Mo |
| 1,7 | 60 s | 4,2 | 7,4 Mo |
| 1,7 | 5 min | 5,6 | 2,0 Mo |
| 1,7 | 10 min | 6,2 | 1,1 Mo |
| 12 | 60 s | 5,9 | 10,3 Mo |
| 12 | 5 min | 7,1 | 2,4 Mo |
| 12 | 10 min | 7,6 | 1,3 Mo |

Un retrait urgent ajoute une fenêtre de quelques changements, 1,4 Ko ; cinquante par jour ajoutent 69 Ko. Vérifier le point de contrôle de l'autorisateur à chaque fenêtre ajoute 5,2 Mo par jour avec des fenêtres d'une minute et une signature ML-DSA-65, 1,0 Mo avec des fenêtres de 5 minutes, et 278 Ko avec une signature FN-DSA-512. Avec une suite de niveau I (ML-KEM-512 avec X25519, comme les suites à 128 bits de MLS), une enveloppe pèse 848 octets au lieu de 1 168, et le suivi baisse d'environ 27 % : 1,4 Mo par jour au lieu de 2,0 Mo avec des fenêtres de 5 minutes.

### 4.2 La journée d'un membre

1,7 changement par seconde, dix sessions, un émetteur pour cinq messages lus, tous nouveaux chaque jour. Le portage direct signe chaque message avec la clé d'appareil ML-DSA-65, avec des fenêtres d'une minute.

| Messages lus | Fenêtre | Suivi | Messages | Émetteurs | Total | Portage direct |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 60 s | 7,4 Mo | 61 Ko | 83 Ko | 7,6 Mo | 7,9 Mo |
| 100 | 5 min | 2,0 Mo | 61 Ko | 83 Ko | 2,1 Mo | 7,9 Mo |
| 1 000 | 60 s | 7,4 Mo | 609 Ko | 658 Ko | 8,7 Mo | 11,8 Mo |
| 1 000 | 5 min | 2,0 Mo | 609 Ko | 658 Ko | 3,2 Mo | 11,8 Mo |
| 10 000 | 60 s | 7,4 Mo | 6,1 Mo | 6,1 Mo | 19,6 Mo | 50,6 Mo |
| 10 000 | 5 min | 2,0 Mo | 6,1 Mo | 6,1 Mo | 14,1 Mo | 50,6 Mo |

Le suivi domine pour qui lit peu, les messages et les clés d'émetteurs pour qui lit beaucoup. Les lecteurs hors de l'arbre de la note précédente payaient 329 Ko pour 100 messages : l'écart, de 1,8 Mo par jour, est le prix de la parité.

### 4.3 Une vague de 100 000 entrées et 100 000 départs

- Commits : 648 420 enveloppes, 1,4 Go en tout, répartis entre les quartiers ; le plus chargé fait 6,0 Mo.
- Chaque membre : 10 enveloppes en moyenne, 11,9 Ko pour cette fenêtre.
- Chaque entrant : 57 Ko, ancré sur le point de contrôle de l'autorisateur ; 327 Ko avec un point de contrôle horaire et 30 liens de sceaux en moyenne. Pour tous les entrants : 5,7 Go au lieu de 32,7 Go.
- Autorisations : une signature par entrée ferait 331 Mo et 26 s de vérification pour chaque vérificateur. Groupées, il y a une signature et 544 octets de preuve par entrée, soit 54 Mo.

### 4.4 Retour après une absence

| | Coût | Ce qui est lu |
| --- | ---: | --- |
| Rejouer, fenêtres d'une minute | 7,4 Mo par jour d'absence, 52 Mo pour une semaine | tout ce qui a été manqué |
| Rejouer, fenêtres de 5 minutes | 2,0 Mo par jour d'absence, 13,7 Mo pour une semaine | tout ce qui a été manqué |
| Sauter | 32 Ko, quelle que soit l'absence | à partir du présent |

### 4.5 Le journal des membres

Voir tous les changements coûte 415 Ko par jour à 0,1 changement par seconde, 7,1 Mo à 1,7 et 50 Mo à 12. Une preuve d'appartenance d'un appareil coûte 640 octets.

## 5. Modèle formel

[`formal-parity/`](formal-parity/README.md) : 10 scénarios ProVerif 2.05, lancés par `docs/research/formal-parity/run.sh` et par le job du modèle formel de la CI. L'adversaire est le réseau, donc le DS ; les primitives sont idéales.

| Scénario | Ce qu'il vérifie | Verdict |
| --- | --- | --- |
| `batch_authorization` | Un vérificateur n'accepte une entrée qu'avec sa preuve d'inclusion dans une racine que l'autorisateur a signée pour la fenêtre. Le DS a ses propres appareils, pas la clé de l'autorisateur. | Prouvé : seuls les appareils autorisés entrent. |
| `batch_authorization_unsigned` | Le vérificateur ne vérifie pas la signature de la racine. | Attaque. |
| `authorizer_anchor` | Un entrant n'accepte l'époque où il entre que si le point de contrôle de l'autorisateur est signé et que le joiner secret de son welcome en reproduit le tag. | Prouvé : ce qu'il envoie reste secret, et il n'entre que dans la vraie époque. |
| `authorizer_anchor_unsigned` | L'entrant accepte un point de contrôle que personne n'a signé. | Attaque : le DS scelle son propre joiner secret à la clé d'init de l'entrant et calcule le tag. |
| `authorizer_follow` | Un membre qui suit le groupe vérifie aussi le point de contrôle de chaque fenêtre ; un initié de l'époque 1 et le DS inventent une fenêtre 2. | Prouvé : le membre n'accepte que l'époque signée, et ce qu'il envoie reste secret. |
| `authorizer_follow_unchecked` | Le membre ne vérifie que le tag, comme en v0.4. | Attaque : la bifurcation de la spécification (section 2.3). |
| `history_link` | Un membre absent à l'époque 2 la lit par un lien d'historique à son retour. Un membre retiré par la fenêtre 2 attaque avec le DS. | Prouvé : le retiré ne lit pas la vraie époque 2. Attaque attendue : il connaît l'init de l'époque 1 et invente une époque 2 pour le membre de retour, la bifurcation de la spécification (section 2.3). |
| `history_link_rejoin` | Le même retiré revient à la fenêtre 3. | Attaque : avec son ancienne init et le lien, il lit l'époque 2. Les liens d'historique sont rejetés. |
| `sender_hidden` | A ou B envoie un message tramé comme un PrivateMessage de MLS. | Prouvé : le DS ne distingue pas qui l'a envoyé (équivalence observationnelle). |
| `sender_visible` | Le même message, l'émetteur en clair. | Équivalence non prouvée, comme attendu. |

Restent valables dans [`formal-messages/`](formal-messages/README.md) :
- `burst_chain` et `burst_chain_mac_only` pour les rafales ;
- `card_revalidated` et `card_cached` pour les cartes ;
- les scénarios des lecteurs, qui montrent pourquoi ils sortent du profil.

Le modèle du protocole, [`docs/formal/`](../formal/README.md), couvre les taches, la chaîne d'init, les welcomes, l'ancrage des entrées, les sceaux d'entrant et les groupes ouverts.

## 6. Garanties : le profil proposé face à MLS

| # | MLS | Profil proposé |
| --- | --- | --- |
| G1 | Oui | Oui : tout membre dans l'arbre, taches, chaîne d'init. |
| G2 | Oui | Oui : données d'émetteur chiffrées. |
| G3 | Oui | Oui : cartes vérifiées contre la feuille de l'époque du message ; les messages d'une rafale sont livrés après leur signature. |
| G4 | Oui, avec le risque des membres inactifs | Oui, avec le même risque, borné par l'expulsion des inactifs. |
| G5 | Oui | Oui : clés de feuille, cartes et appareils uniques. |
| G6 | Oui | Oui. |
| G7 | Le DS ne lit ni ne forge ; bifurcations détectables hors bande | Idem ; le DS seul ne fabrique pas d'époque ; le journal scellé détecte aussi les suppressions de messages. En option, avec un autorisateur distinct, le membre refuse les bifurcations. |
| G8 | Compromission du service d'authentification | Compromission de l'autorisateur : il fait entrer qui il veut, visiblement. |
| G9 | Politique au DS ou aux clients | Mode autorisé, groupes fermés ou ouverts. En option, chaque membre vérifie que l'autorisateur a validé chaque fenêtre. |
| G10 | Chaque membre tient l'arbre entier | Chaque changement est engagé par le sceau ; la liste se lit à la demande. |
| G11 | Chaque membre traite chaque commit | Rejeu, ou saut sans le manqué. |
| G12 | Pas de déni, métadonnées visibles, rejeu par un initié possible, fragmentation | Pas de déni, métadonnées visibles, rejeu détecté par le journal ; fragmentation de même portée par rôle, mais plus de membres ont un rôle à chaque fenêtre. |
| R1 | Dizaines de milliers de membres | 2^20, et jusqu'à 2^24. |
| R2 | Un commit par membre qui change | Une fenêtre par vague, en parallèle, près de la borne inférieure. |
| R3 | Par la politique | Mode autorisé ; tout membre sort seul. |

## 7. Risques et questions ouvertes

- **Le prix de la parité.** Un membre qui lit peu paie le suivi, de 1 à 7 Mo par jour selon la cadence des fenêtres. Une cadence plus lente retarde les retraits ordinaires, pas les urgents.
- **La fragmentation par un initié qui a un rôle.** Un committer de quartier peut couper son quartier, le scelleur tout le groupe, et une fenêtre compte jusqu'à un committer par quartier changé. Des accusés de réception par sous-arbre, que suggère MLS, coûteraient une signature par nœud re-keyé. La note [re-key par le serveur](rekey-serveur-2026-09-26.md) propose des litiges prouvés en zero knowledge, qui ne révèlent ni clé ni secret passé, et une réparation ; la taille de leur preuve reste à mesurer.
- **L'autorisateur.** Il signe un point de contrôle par fenêtre, et les membres qui les vérifient l'attendent : sa disponibilité devient celle du groupe. Pour valider une fenêtre, il tient l'état public du groupe. S'il se confond avec le DS, la confiance est celle d'un service d'authentification compromis. La transparence des clés d'appareil (RFC 9750, §8.4.3.1) le rendrait vérifiable.
- **FN-DSA** n'est pas final, et sa signature en virgule flottante demande une implémentation soignée ; la carte peut aussi être une clé ML-DSA, au prix de la taille.
- **Le délai des rafales** se voit dans l'interface.
- **Connaître un million de membres.** La liste existe et se vérifie, mais aucune interface ne la montre en entier : il faut des journaux et des alertes ciblées, par exemple pour les appareils d'un contact.
- **Pas de preuve calculatoire** de l'ensemble.

## 8. Feuille de route

| Étape | Contenu | Critère |
| --- | --- | --- |
| 1 | Profil suivant, brouillon : mode autorisé (`AuthorizationBatch`, `AuthorizerCheckpoint`, retraits par l'autorisateur, vérification des points de contrôle par les membres), plan de messages (calendrier, `Message`, données d'émetteur, rafales, engagement, journal scellé), `LeafNode` avec carte et `device_id`, unicité des clés, journal des membres, retraits urgents et ordinaires (`WINDOW_ORDINARY`), exporteur et authentifiant d'époque | Spécification relue, labels et contextes enregistrés |
| 2 | `cityg-core` : ce qui précède, et le DS en mémoire | Tests de scénarios : vague autorisée en lot, entrant ancré sur le point de contrôle, fenêtre inventée refusée faute de point de contrôle, clé dupliquée refusée, émetteur absent des en-têtes, rafale livrée après sa signature, retrait urgent sous 5 s, retour par rejeu et par saut |
| 3 | Test d'échelle : 2^20 membres, vague de 100 000 entrées et 100 000 départs | Chiffres de la section 4 retrouvés |
| 4 | Modèle formel du profil entier ; preuves calculatoires ; analyse de la fragmentation | Verdicts attendus, preuves relues |

## 9. Sources

* R. Barnes et al., [The Messaging Layer Security (MLS) Protocol](https://www.rfc-editor.org/rfc/rfc9420.html), RFC 9420, 2023 : section 16.
* B. Beurdouche et al., [The Messaging Layer Security (MLS) Architecture](https://www.rfc-editor.org/rfc/rfc9750.html), RFC 9750, 2025 : sections 5.2, 6, 8.
* D. Micciancio, S. Panjwani, [Optimal Communication Complexity of Generic Multicast Key Distribution](https://www.iacr.org/archive/eurocrypt2004/30270154/final.pdf), Eurocrypt 2004.
* M. Anastos et al., [The Cost of Maintaining Keys in Dynamic Groups with Applications to Multicast Encryption and Group Messaging](https://eprint.iacr.org/2024/1097), 2024.
* Notes précédentes : [grands-groupes](grands-groupes-2026-09-25.md) (architecture et re-key), [plan de messages](plan-de-messages-2026-09-26.md) (cartes, rafales, journal scellé, et les lecteurs que cette note retire).
