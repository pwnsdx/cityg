# Au-delà de la v0.4 : un profil candidat et ce qui reste ouvert

| | |
| --- | --- |
| Date | 2026-09-26 |
| Nature | Note de recherche de synthèse. Elle rassemble les notes écrites depuis la v0.4 en un *profil candidat* pour la version suivante : ce que chaque note a établi ou écarté, les garanties face à MLS avec leurs preuves, les coûts, et les problèmes ouverts classés. Elle ajoute trois résultats : la *ville entretenue* au-dessus des îlots (note [îlots](ilots-2026-09-26.md), section 2.8), la *feuille scindée* pour les cartes d'émetteur, et des points de contrôle vérifiés par leur seule signature. Rien de ce qu'elle décrit n'est encore dans la spécification ni dans le code. |
| Question | Que serait City-G après la v0.4, avec les garanties de MLS, un million de membres, des vagues d'entrées et de départs, et des entrées que le serveur autorise ; et que reste-t-il à résoudre ? |
| Compagnons | [`ilots_sim.py`](ilots_sim.py), rapports 9 et 10 (`python3 docs/research/ilots_sim.py`), qui réutilise [`rekey_sim.py`](rekey_sim.py), [`msg_sim.py`](msg_sim.py) et [`parity_sim.py`](parity_sim.py). Modèles formels : [`docs/formal/`](../formal/README.md) (16 scénarios), [`formal-messages/`](formal-messages/README.md) (17) et [`formal-parity/`](formal-parity/README.md) (32, dont 3 nouveaux). |
| Auteur | Claude Code (assistant IA d'Anthropic), à la demande du mainteneur. Le modèle symbolique couvre les choix clés ; il n'existe aucune preuve calculatoire. Une relecture cryptographique humaine reste nécessaire. |

## 0. Résumé

1. **Le profil candidat tient en une phrase** : l'arbre binaire de la v0.4, lu par des *relais* au niveau d'îlots de 2^8 feuilles, re-keyé par de petites tâches que le serveur confie d'abord aux entrants, avec le mode autorisé et le plan de messages de la note [parité MLS](parite-mls-2026-09-26.md).
2. **Ce qui fait le gain, c'est qui lit l'arbre, pas sa forme.**
   - Avec la ville entretenue, l'arbre au-dessus des îlots est de nouveau celui de la v0.4. Mais les membres n'en lisent plus le haut : un relais de leur îlot leur passe le secret de fenêtre en 52 octets.
   - Suivre le groupe coûte 94 Ko par jour au lieu de 1,8 Mo (2^20 membres, 1,7 changement par seconde, fenêtres de 5 minutes), et ce coût ne dépend plus de la taille du groupe.
   - On peut donc passer de la v0.4 au profil candidat par étapes, chacune utile seule (section 3.6).
3. **Trois résultats nouveaux :**
   - **la ville entretenue** : une fenêtre qui change un îlot coûte 30 Ko au lieu de 4,8 Mo avec le sommet plat seul, et l'entrant seul qui applique un retrait 95 Ko au lieu de 4,8 Mo. Elle doit être re-keyée à chaque fenêtre le long des chemins changés : sinon deux retirés alliés au serveur lisent l'époque (`ilot_city_stale.pv`), alors qu'un retiré seul reste dehors grâce à la chaîne d'init (`ilot_city_sticky.pv`) ;
   - **la feuille scindée** : le haché de la feuille prend le haché de la clé X-Wing au lieu de la clé. Un lecteur ne télécharge que la partie carte de la feuille d'un émetteur, 1 019 octets au lieu de 2 203 ; la journée d'un lecteur de 10 000 messages passe de 12,3 à 9,9 Mo ;
   - **des points de contrôle vérifiés par leur seule signature** : le membre connaît déjà ce que signe l'autorisateur. Refuser les bifurcations à chaque fenêtre coûte alors 192 Ko par jour avec FN-DSA-512 au lieu de 278, ou 28 Ko avec une signature UOV réservée à cet usage.
4. **Les garanties.** Le profil candidat vise G1 à G12 de MLS et les exigences d'échelle R1 à R3 (section 4). Les trois modèles formels comptent 65 scénarios ProVerif, tous au verdict attendu. Le profil va au-delà de MLS sur trois points : un membre qui vérifie les points de contrôle d'un autorisateur distinct du DS refuse les bifurcations ; le journal scellé détecte le rejeu et la suppression de messages ; la fragmentation par un initié est bornée et réparable. Il garde les limites de MLS : métadonnées visibles du serveur, pas de déni.
5. **Les coûts** (section 5) : la journée d'un membre qui lit 100 messages, 213 Ko au lieu de 2,1 Mo ; une vague de 100 000 entrées et 100 000 départs, 3,7 Ko par membre ; entrer, 28 Ko ; entrer seul quand personne n'est en ligne, 24 Ko, ou 95 Ko si un retrait attend.
6. **Ce qui reste ouvert, par ordre d'importance** (section 6) :
   1. une preuve calculatoire, en premier du calendrier de clés avec des clés d'arbre stables ;
   2. les preuves de litige pour X-Wing, qui désignent le client fautif : leur taille et leur coût ;
   3. les bifurcations : la disponibilité de l'autorisateur, et la solidité d'UOV si on l'emploie ;
   4. les standards : FN-DSA pas encore final, le KEM multi-destinataires hors norme, l'alignement sur les suites post-quantiques de MLS ;
   5. le coût des cartes d'émetteur pour les gros lecteurs ;
   6. les métadonnées, dont la présence en ligne que le serveur déduit des tâches et des relais ;
   7. la spécification et l'implémentation.
7. **Recommandation.** Faire du profil candidat la cible de la version suivante, en trois étapes : les relais et la cadence des retraits sur l'arbre de la v0.4 ; les tâches d'îlot et le re-key par les entrants ; le reste de la parité. La spécification attend l'accord du mainteneur.

## 1. La cible

Les exigences sont celles de la note [parité MLS](parite-mls-2026-09-26.md) (section 1) :
- les garanties G1 à G12 de MLS ([RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html), section 16 ; [RFC 9750](https://www.rfc-editor.org/rfc/rfc9750.html), section 8) ;
- R1, des groupes d'un million de membres et plus ; R2, des vagues d'entrées et de départs ; R3, quiconque le serveur autorise entre, et tout membre sort quand il veut ;
- et deux demandes du mainteneur : oublier le système de committers, le serveur gérant ce qu'il peut, en zero knowledge au besoin (note [re-key par le serveur](rekey-serveur-2026-09-26.md)) ; et chercher hors du cadre la meilleure technique (note [îlots](ilots-2026-09-26.md)).

## 2. Ce que chaque note a établi

| Note | Retenu dans le profil candidat | Écarté | Scénarios clés |
| --- | --- | --- | --- |
| [grands-groupes](grands-groupes-2026-09-25.md), devenue la v0.4 | L'arbre binaire, les fenêtres, les taches, la chaîne d'init, les sceaux d'entrant, les audits par échantillonnage | Les quartiers de 2^12 comme unité de travail : les îlots de 2^8 les remplacent | `taint`, `forward_secrecy`, `fabrication`, `entrant_removal`, `external_checked` |
| [plan de messages](plan-de-messages-2026-09-26.md) | Cartes d'émetteur, chaînes de rafale, messages engageants, journal scellé, points de contrôle | Lecteurs hors de l'arbre, lots de clés, chaîne publique, rétention par les gardiens : ils n'ont pas la parité | `burst_chain`, `card_revalidated` ; attaques : `reader_removed_with_root`, `reader_removed_ratchet` |
| [parité MLS](parite-mls-2026-09-26.md) | Mode autorisé, points de contrôle de l'autorisateur, plan de messages à la MLS, unicité des clés, journal des membres, retraits urgents et ordinaires, exporteur et authentifiant d'époque | Liens d'historique | `batch_authorization`, `authorizer_anchor`, `authorizer_follow`, `sender_hidden` ; attaque : `history_link_rejoin` |
| [re-key par le serveur](rekey-serveur-2026-09-26.md) | Option D : les membres tirent les secrets, le serveur gère tout le reste par des tâches ; litiges prouvés en zero knowledge | A, un serveur qui tire les secrets ; C, une enclave ; le litige économique. B, plusieurs serveurs, reste une autre confiance, à déclarer comme telle | `member_rekey_removed`, `split_rekey`, `wrap_dispute`, `wrap_dispute_report` ; attaques : `server_rekey_removed`, `wrap_dispute_replay` |
| [îlots](ilots-2026-09-26.md) | Îlots de 2^8, relais, entrants qui re-keyent leur chemin, réparation par les feuilles, ville entretenue et éléments plats de secours, fenêtres d'entrant sans secret de fenêtre | L'init scellée par îlot ; vider la ville ; le sommet plat seul, sauf au-delà d'environ 3 changements par seconde avec des fenêtres de 5 minutes | `ilot_removal`, `ilot_relay`, `ilot_forward_secrecy`, `ilot_entrant_join`, `ilot_entrant_removal`, `ilot_city_maintained` ; attaques : `ilot_init_by_ilot`, `ilot_city_stale` |

## 3. Le profil candidat

### 3.1 Cinq principes

Presque tous les choix découlent de cinq principes, chacun appuyé par des scénarios ou par un modèle de coût.

1. **Qui tire un secret le connaît.** Le serveur gère donc tout ce qui ne demande aucun secret, et seuls des membres tirent les secrets. Le zero knowledge prouve qu'un calcul est juste, pas qu'un secret est ignoré (note re-key par le serveur, section 2 ; `server_rekey_removed.pv`, `member_rekey_removed.pv`).
2. **La chaîne d'init porte la sécurité dans le temps.** Chaque époque dérive de l'init de la précédente. Il en découle quatre résultats :
   - les clés d'arbre peuvent rester stables pendant des fenêtres sans coûter la confidentialité persistante (`ilot_forward_secrecy.pv`) ;
   - un retiré qui n'a pas pu calculer une époque ne calcule aucune des suivantes, même si le secret d'une fenêtre ultérieure lui parvient (`ilot_city_sticky.pv`) ;
   - une fenêtre d'entrant sans retrait peut tirer l'époque de l'init externe seule (`ilot_entrant_join.pv`) ;
   - le DS seul ne fabrique pas d'époque pour un membre qui vérifie le tag (`fabrication.pv`).
3. **Aucun secret ne va à une clé qu'un retiré connaît.** C'est la règle des taches de la v0.4 (décision E-4). Elle vaut pour les îlots, pour la ville et pour la clé externe (`taint.pv`, `ilot_removal_unrekeyed.pv`, `ilot_city_stale.pv`, `ilot_entrant_removal_without_top.pv`).
4. **Un membre n'accepte une époque que par une vérification qu'il fait seul** : le tag et la signature d'un scelleur admis, ou le point de contrôle de l'autorisateur. Un relais ou le serveur ne peut donc que retarder (`ilot_relay.pv`, `external_checked.pv`, `authorizer_follow.pv`).
5. **Le coût suit le churn.** Les niveaux saturés, qui changent à chaque fenêtre, ne sont lus que par les relais. Les niveaux bas, qui changent rarement, restent un arbre que chacun lit quand son îlot change (note îlots, section 1).

### 3.2 La structure : l'arbre de la v0.4, lu autrement

```text
arbre        := l'arbre binaire de la v0.4 (spécification, section 5), de hauteur H
îlot         := un sous-arbre de 2^c feuilles, c = 8 : 4 096 îlots pour 2^20 membres
ville        := les niveaux au-dessus des racines d'îlot, re-keyés à chaque fenêtre le long des chemins changés
r_n          := le secret de la nouvelle racine ; commit_secret_n := DeriveSecret(r_n, "commit")
Relay_{n,j}  := r_n chiffré sous une clé tirée du secret de la racine de l'îlot j : 52 octets
élément plat := r_n scellé à la racine d'un îlot sans relais, dans une fenêtre dense
```

- **Un membre** lit l'en-tête de la fenêtre, les enveloppes de son îlot quand celui-ci change (6 % des fenêtres), puis le relais de son îlot, et vérifie le tag. Sans relais, il lit un élément plat dans une fenêtre dense, et son chemin de ville dans une fenêtre creuse, une enveloppe.
- **Un relais** est un membre en ligne de l'îlot. Il lit son chemin de ville, 5,5 Ko par fenêtre dense, et publie le relais. Il y a 1,1 tâche de relais par membre et par jour, que le serveur répartit entre les membres en ligne.
- **La ville** est celle de la v0.4, étendue aux quatre niveaux du haut des anciens quartiers. Elle coûte moins que le sommet plat de la note îlots jusqu'à environ 3 changements par seconde par million de membres avec des fenêtres de 5 minutes, et à tous les débits étudiés avec des fenêtres d'une minute. Avec un KEM multi-destinataires, le sommet plat enverrait moins dans une fenêtre dense, 722 Ko ; mais il faudrait lire toutes les clés d'îlot, 4,8 Mo, à chaque fenêtre, creuse ou non (note îlots, section 2.8).
- **Un groupe de 256 membres ou moins** est un seul îlot, sans ville : la structure se réduit à l'arbre de la v0.4.

### 3.3 Le travail : le serveur gère, les membres tirent

- **Le serveur, sans aucun secret** : il recueille et vérifie les requêtes, place les entrants de préférence sur les feuilles que les départs libèrent, ferme les fenêtres, découpe le travail en tâches et les attribue, vérifie les commits contre l'état public, livre les paquets, garde les enregistrements d'audit.
- **Les tâches**, confiées à des clients en ligne, d'abord aux entrants de la fenêtre :
  - le re-key de son propre chemin, par l'entrant qui prend une feuille libérée : 8 enveloppes ;
  - le re-key d'un îlot à plusieurs changements : 9 enveloppes en moyenne ; au plus 181, en 42 ms, dans une vague de 100 000 entrées et 100 000 départs ;
  - la ville, par sous-villes de 256 îlots, et ses éléments plats ;
  - le sceau, par un membre de l'époque précédente, et les welcomes, à la clé d'init à usage unique de chaque entrant.
- **Les litiges.** Un membre qui ne peut pas ouvrir une enveloppe le prouve en zero knowledge, sans révéler sa clé ni un secret passé ; le client fautif est exclu des tâches (`wrap_dispute.pv`, `wrap_dispute_report.pv`).
- **La réparation.** Tout membre qui a `r_n` répare : un élément plat par îlot que la ville coupe, au plus 256 enveloppes par îlot qu'une tâche coupe. Les membres coupés lisent l'époque dans la même fenêtre.

### 3.4 Entrer, sortir, revenir

- **Entrer.** Dans le mode autorisé, l'autorisateur signe par fenêtre la racine des entrées qu'il autorise et le point de contrôle de l'époque créée, sur lequel l'entrant s'ancre. Les groupes fermés (admins, invitations) et ouverts de la v0.4 restent. Un entrant télécharge 28 Ko.
- **Personne en ligne.** L'entrant scelle seul la fenêtre avec une init externe : il envoie 24 Ko sans retrait en attente, 95 Ko s'il en applique un (note îlots, sections 2.7 et 2.8). Les membres qui reviennent vérifient son admission et sa signature, pas seulement le tag.
- **Sortir.** Tout membre sort par sa propre requête ; un admin ou l'autorisateur retire. Les retraits urgents ont leur fenêtre sous 5 secondes, avec la règle d'envoi ; les retraits ordinaires et les mises à jour attendent la fenêtre planifiée suivante, 5 minutes pour un million de membres.
- **Revenir.** Rejouer les fenêtres manquées coûte, par jour d'absence, un jour de suivi, et le membre lit tout ce qu'il a manqué (G11). Sauter au présent reste possible, sans le manqué.

### 3.5 Lire et écrire

Le plan de messages de la note de parité (section 3.3) : arbre de secrets, données d'émetteur chiffrées, carte FN-DSA dans la feuille, rafales livrées à l'application après leur signature, engagement de clé, journal scellé ; exporteur et authentifiant d'époque. Deux ajouts :

- **La feuille scindée.** Le haché de la feuille (spécification, section 5.3, avec la feuille de la note de parité) prend le haché de la clé X-Wing au lieu de la clé :

  ```text
  leaf_hash(i) := H_L("tree/leaf", [device_id, since, H_L("tree/leaf-key", encryption_key),
                                    card, admission_hash, updated])
  ```

  Un lecteur qui vérifie la carte d'un émetteur ne télécharge que cette partie de sa feuille, 1 019 octets au lieu de 2 203. Seuls ceux qui chiffrent vers la feuille, les tâches, prennent la clé X-Wing. La liaison ne change pas, sous la résistance aux collisions de `H_L`. Le coût des émetteurs baisse de 39 % : 3,7 Mo au lieu de 6,1 Mo par jour pour 10 000 messages lus (`ilots_sim.py`, rapport 10).
- **Les points de contrôle vérifiés par leur seule signature.** L'autorisateur signe `[gid, epoch, H(GroupContext), confirmation_tag, H(external_pk)]`. Le membre qui suit a le haché du contexte dans l'en-tête, et calcule le tag et la clé externe : il ne télécharge que la signature. Un entrant reçoit le contexte entier et en vérifie le haché (section 6, problème 3).

### 3.6 Passer de la v0.4 au profil candidat

La ville entretenue fait du profil candidat une évolution de la v0.4, pas une refonte : l'arbre, le calendrier de clés et les sceaux restent. Trois étapes, chacune utile seule :

| Étape | Ce qui change | Ce qu'elle apporte |
| --- | --- | --- |
| 1. Relais et cadence | Le serveur désigne un relais par îlot de 2^8 ; les membres prennent le secret de fenêtre du relais, ou d'un élément plat, au lieu de lire le haut de l'arbre. Retraits urgents et ordinaires. Les quartiers et les rôles de la v0.4 ne changent pas. | Le suivi passe à 94 Ko par jour, contre 44 Mo pour la v0.4 dont chaque départ ferme une fenêtre sous 5 secondes, et 1,8 Mo avec des fenêtres de 5 minutes sans relais. Un entrant ne lit plus le haut de l'arbre. |
| 2. Tâches d'îlot | Les quartiers deviennent des îlots ; les committers et le scelleur deviennent des tâches ; les entrants re-keyent leur propre chemin et se partagent la ville ; litiges prouvés et réparation. | Plus de rôle de committer visible ; une tâche coupe au plus 256 membres ; la tâche la plus lourde d'une vague prend 42 ms au lieu de 0,6 s. |
| 3. Parité | Mode autorisé, points de contrôle, plan de messages, feuille scindée, unicité des clés, journal des membres, exporteur. | Les garanties de MLS (section 4). |

## 4. Garanties face à MLS, et leurs preuves

Les scénarios sont dans [`docs/formal/`](../formal/README.md) (F), [`formal-messages/`](formal-messages/README.md) (M) et [`formal-parity/`](formal-parity/README.md) (P). Les attaques montrent que le mécanisme correspondant est nécessaire.

| # | MLS | Profil candidat | Prouvé | Attaques sans le mécanisme |
| --- | --- | --- | --- | --- |
| G1 | Seuls les membres d'une époque la lisent | Oui : règle des taches, re-key de l'îlot et de la ville du retiré, chaîne d'init | `taint`, `entrant_removal`, `join` (F) ; `ilot_removal`, `ilot_city_maintained`, `ilot_entrant_removal`, `member_rekey_removed` (P) | `taint_without_rule` (F) ; `ilot_removal_unrekeyed`, `ilot_city_stale`, `ilot_entrant_removal_without_top`, `server_rekey_removed` (P) |
| G2 | Le DS ne sait pas qui envoie | Oui : données d'émetteur chiffrées | `sender_hidden` (P) | `sender_visible` (P) |
| G3 | L'émetteur est authentifié | Oui : carte vérifiée contre la feuille de l'époque du message, rafales livrées après leur signature | `burst_chain`, `card_revalidated` (M) | `burst_chain_mac_only`, `card_cached` (M) |
| G4 | Confidentialité persistante et guérison | Oui : chaîne d'init, effacement, mises à jour qui re-keyent le chemin et les taches | `forward_secrecy`, `post_compromise` (F) ; `ilot_forward_secrecy` (P) | `forward_secrecy_without_init` (F) ; `ilot_forward_secrecy_without_init`, `ilot_init_by_ilot` (P) |
| G5 | Clés uniques dans l'arbre | Oui : clés de feuille, cartes et appareils uniques, par le registre | règle, sans scénario | – |
| G6 | Matériel d'entrée à usage unique | Oui : clé d'init à usage unique, jeton d'entrée égal au haché de la requête | `join` (F), pour la clé d'init ; le jeton, par règle | – |
| G7 | Le DS ne lit ni ne forge ; bifurcations détectables hors bande | Idem, et le DS seul ne fabrique pas d'époque ; avec les points de contrôle d'un autorisateur distinct, le membre refuse les bifurcations | `fabrication`, `external_checked` (F) ; `ilot_relay`, `authorizer_follow` (P) | `fabrication_without_init`, `external_tag_only` (F) ; `ilot_relay_unchecked`, `authorizer_follow_unchecked` (P) |
| G8 | Un service d'authentification compromis fait entrer qui il veut | Idem pour l'autorisateur, mais chaque entrée reste visible | `anchored_join` (F) ; `authorizer_anchor` (P) | `join_without_anchor` (F) ; `authorizer_anchor_unsigned` (P) |
| G9 | Politique au DS ou aux clients | Mode autorisé, groupes fermés ou ouverts | `open_group` (F) ; `batch_authorization` (P) | `batch_authorization_unsigned` (P) |
| G10 | Chaque membre connaît l'appartenance | Chaque changement est engagé par le sceau, la liste se lit à la demande | règle, sans scénario | – |
| G11 | Un membre rattrape et lit le manqué | Rejeu, au prix d'un jour de suivi par jour d'absence | `ilot_entrant_join` (P), pour un retour après une fenêtre d'entrant | `history_link_rejoin` (P), le raccourci rejeté |
| G12 | Pas de déni, métadonnées visibles, rejeu par un initié, fragmentation | Pas de déni, métadonnées visibles ; rejeu et suppression détectés par le journal scellé ; fragmentation bornée et réparable, fautif désigné par un litige | `wrap_dispute`, `wrap_dispute_report` (P) | `wrap_dispute_replay` (P), le litige économique rejeté |
| R1 | Des dizaines de milliers de membres | 2^20 et au-delà : le suivi ne dépend pas de la taille | modèles de coût | – |
| R2 | Un commit par changement | Une fenêtre par vague, en tâches parallèles | modèles de coût | – |
| R3 | Par la politique | Mode autorisé ; tout membre sort seul ; on entre même quand personne n'est en ligne | `entrant_removal` (F) ; `batch_authorization`, `ilot_entrant_join`, `ilot_entrant_removal` (P) | `ilot_entrant_removal_without_top` (P) |

Deux garanties reposent sur des règles sans scénario, G5 et G10 ; le journal scellé de G12 non plus n'est pas modélisé.

## 5. Coûts

**Pour un membre** (`ilots_sim.py` ; 2^20 membres, 1,7 changement par seconde, fenêtres de 5 minutes, placement apparié, cartes FN-DSA-512, rafales de 2) :

| Quoi | Profil candidat | Profil de la note de parité | Rapport |
| --- | ---: | ---: | ---: |
| Suivre le groupe, par jour | 94 Ko avec relais, 415 Ko sans | 1,8 Mo | 2 |
| Idem, fenêtres d'une minute | 385 Ko, 2,0 Mo | 6,5 Mo | 2 |
| La journée d'un lecteur de 100 messages | 238 Ko, 213 Ko avec la feuille scindée | 2,1 Mo | 10 |
| Idem, 1 000 messages | 1,4 Mo, 1,1 Mo | 3,2 Mo | 10 |
| Idem, 10 000 messages | 12,3 Mo, 9,9 Mo | 14,1 Mo | 10 |
| Refuser les bifurcations à chaque fenêtre (option) | 192 Ko par jour avec FN-DSA-512, 28 Ko avec UOV | 278 Ko | 10 |
| Une vague de 100 000 entrées et 100 000 départs | 3,7 Ko, 4,9 Ko sans relais | 11,3 Ko | 5 |
| Entrer | 28 Ko | 57 Ko | 6 |
| Entrer seul, sans retrait en attente | 24 Ko envoyés, 15 Ko lus | 52 et 29 Ko | 8 |
| Entrer seul, un retrait en attente | 95 Ko envoyés, 54 Ko lus | 100 et 54 Ko | 9 |
| Rattraper un jour d'absence en lisant tout | 94 à 415 Ko | 1,8 Mo | 2 |
| Groupes de 2^22 et 2^24 membres, suivre | 94 Ko | 2,1 et 2,4 Mo | 7 |

**Pour le travail**, par fenêtre dense (mêmes hypothèses) :

| Tâche | Qui | Coût |
| --- | --- | --- |
| Re-key de son chemin | l'entrant qui prend une feuille libérée | 8 enveloppes |
| Re-key d'un îlot | un entrant, sinon un membre en ligne | 9 enveloppes en moyenne, 2,2 ms, 24 Ko envoyés |
| La ville et les éléments plats | les entrants, par sous-villes de 256 îlots | 3,3 Mo envoyés et 1,8 Mo de clés lues en tout ; 30 Ko dans une fenêtre qui change un îlot |
| Le sceau | un membre de l'époque précédente | le tag et une signature |
| Les welcomes | des membres de l'époque précédente | 323 Ko pour 255 entrants, 46 Ko avec le KEM multi-destinataires |
| Les relais | un membre en ligne par îlot | 5,5 Ko lus, 52 octets publiés |
| Réparer | tout membre qui a `r_n` | un élément plat par îlot coupé par la ville ; au plus 256 enveloppes, 299 Ko, par îlot coupé par une tâche |

## 6. Problèmes ouverts, par ordre d'importance

La note [problèmes ouverts](problemes-ouverts-2026-09-26.md) les reprend dans cet ordre, en résout une partie et donne leur état (section 7).

1. **Une preuve calculatoire.**
   - *Pourquoi.* Toutes les garanties de la section 4 reposent sur un modèle symbolique à primitives idéales. Trois points n'ont pas d'équivalent dans les analyses de MLS : des clés d'arbre stables pendant des fenêtres, protégées par la seule chaîne d'init ; des fenêtres d'entrant dont le secret de commit est une constante publique ; des secrets tirés par des entrants, que la règle des taches suit.
   - *Prochain pas.* Un modèle [CryptoVerif](https://bblanche.gitlabpages.inria.fr/CryptoVerif/) du calendrier de clés d'une fenêtre (init, secret de commit, joiner secret, tag), puis une preuve par jeux de la règle des taches, dans le cadre des analyses de TreeKEM ([Alwen et al., Crypto 2020](https://eprint.iacr.org/2019/1189)).
2. **Les preuves de litige pour X-Wing.**
   - *Pourquoi.* Elles désignent le client qui envoie une enveloppe fausse. Sans elles, la réparation marche, mais le fautif reste inconnu, et un client hostile peut couper un îlot à chaque tâche qu'il reçoit.
   - *Où on en est.* Modélisées comme des preuves idéales de déchiffrement (`wrap_dispute.pv`) ; le litige économique, qui révélerait le secret partagé de l'encapsulation, est rejeté (`wrap_dispute_replay.pv`).
   - *Prochain pas.* Écrire l'énoncé : décapsulation ML-KEM-768 et X25519, combineur SHA3, dérivation de la clé AEAD, ouverture ChaCha20-Poly1305. Le prouver d'abord avec une machine virtuelle zero knowledge généraliste, pour une première mesure ; chercher ensuite une preuve dédiée, sur réseaux euclidiens pour ML-KEM et d'égalité de logarithmes discrets pour X25519. En attendant, le serveur réserve les tâches aux appareils présents depuis un certain temps et limite le débit des entrées.
3. **Les bifurcations.**
   - *Pourquoi.* C'est la garantie où City-G peut dépasser MLS. Un membre qui vérifie le point de contrôle de chaque fenêtre refuse les bifurcations (`authorizer_follow.pv`), mais attend l'autorisateur à chaque fenêtre.
   - *Nouveau.* Réduit à sa signature (section 3.5), le point de contrôle coûte 192 Ko par jour avec FN-DSA-512, au lieu de 278 Ko. L'autorisateur est aussi le cas idéal d'UOV : un signataire, un million de vérificateurs. Une signature de 96 octets, avec une clé de 67 Ko apprise une fois, ramène le coût à 28 Ko par jour, 30 % du suivi.
   - *La condition.* UOV est un candidat du [troisième tour des signatures additionnelles du NIST](https://csrc.nist.gov/News/2026/nist-advances-9-candidates-to-the-3rd-round-of-pqc), et HAWK a été retiré de ce tour. La clé UOV ne doit donc servir qu'au suivi ; les entrants s'ancrent sur une signature ML-DSA ou FN-DSA de l'autorisateur. Si UOV tombait, on ne perdrait que le refus des bifurcations, qui dépasse MLS. Sans cette séparation, un faux point de contrôle mènerait un entrant dans une époque du DS (`authorizer_anchor_unsigned.pv`).
   - *Reste ouvert.* La disponibilité de l'autorisateur, que des témoins pourraient répartir ; la transparence des clés d'appareil ([RFC 9750](https://www.rfc-editor.org/rfc/rfc9750.html), section 8.4.3.1).
4. **Les standards.**
   - FN-DSA (FIPS 206) n'est pas encore une norme finale ([NIST, état de FIPS 206](https://csrc.nist.gov/csrc/media/presentations/2025/fips-206-fn-dsa-(falcon)/images-media/fips_206-perlner_2.1.pdf)). Les cartes peuvent être des clés ML-DSA en attendant, au prix de la taille.
   - Le KEM multi-destinataires sort des normes ; la ville entretenue permet de s'en passer.
   - Le KEM de City-G est celui des suites hybrides de MLS. Le [projet de suites post-quantiques de MLS](https://datatracker.ietf.org/doc/html/draft-ietf-mls-pq-ciphersuites-06) emploie les KEM hybrides du [projet CFRG des KEM hybrides concrets](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-concrete-hybrid-kems), dont la construction ML-KEM-768 et X25519 est dite identique à [X-Wing](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/). Aucune de ses suites n'associe ce KEM à ML-DSA-65 : la plus proche, `MLS_128_MLKEM768X25519_CHACHA20POLY1305_SHA384_MLDSA44`, prend ML-DSA-44 et SHA-384. S'aligner permettrait de partager implémentations et analyses.
5. **Les cartes d'émetteur pour les gros lecteurs.**
   - *Où on en est.* La feuille scindée retire 39 % du coût des émetteurs. Il reste 3,7 Mo par jour pour 10 000 messages lus, pour 6,1 Mo de messages.
   - *Prochain pas.* Garder les cartes en cache d'une session à l'autre et ne revalider que leur preuve d'appartenance à l'époque du message : c'est sûr (`card_revalidated.pv`), le cache sans revalidation ne l'est pas (`card_cached.pv`). Le gain dépend de la fréquence à laquelle les mêmes émetteurs reviennent ; il faut le mesurer sur des traces.
6. **Les métadonnées.**
   - Le serveur voit l'appartenance et les fenêtres, comme un DS de MLS qui voit les messages de gestion (G12). En attribuant les tâches et les relais, il voit aussi qui est en ligne, plus qu'un DS de MLS, qui ne voit que qui commit.
   - À étudier : ce que révèlent exactement les tâches, et des tâches qu'on prendrait sans se nommer, en tension avec la désignation du fautif.
7. **La spécification et l'implémentation**, par les étapes de la section 3.6, quand le mainteneur le décidera.

## 7. Plan de recherche

| Étape | Contenu | Critère |
| --- | --- | --- |
| 1 | Modèle CryptoVerif du calendrier de clés d'une fenêtre, avec des clés d'arbre stables et des fenêtres d'entrant | Secret de l'époque prouvé dans le modèle calculatoire |
| 2 | Énoncé du litige X-Wing ; preuve dans une machine virtuelle zero knowledge, puis preuve dédiée | Taille et temps de preuve mesurés |
| 3 | Brouillon de spécification du profil candidat, en trois étapes (section 3.6), après accord du mainteneur | Spécification relue, labels et contextes enregistrés |
| 4 | `cityg-core` : relais, éléments plats et cadence d'abord ; puis tâches d'îlot et réparation ; puis parité | Tests de scénarios ; test d'échelle à 2^20 membres qui retrouve les chiffres de la section 5 |
| 5 | Mesures : cache des cartes sur des traces ; points de contrôle signés avec UOV | Chiffres mesurés |

## 8. Modèle formel

- **65 scénarios ProVerif 2.05, tous au verdict attendu** : 16 pour le protocole de la v0.4 ([`docs/formal/`](../formal/README.md)), 17 pour le plan de messages ([`formal-messages/`](formal-messages/README.md)), 32 pour la parité, le re-key par le serveur, les litiges et les îlots ([`formal-parity/`](formal-parity/README.md)). Chaque dossier a son `run.sh`, lancé aussi par la CI.
- **Nouveaux dans cette note** : `ilot_city_stale` (attaque), `ilot_city_maintained` et `ilot_city_sticky` (prouvés), décrits dans la note îlots (section 6).
- **Modèle calculatoire** : la note [problèmes ouverts](problemes-ouverts-2026-09-26.md) ajoute 14 modèles CryptoVerif dans [`formal-computational/`](formal-computational/README.md).
- **Non modélisé** : le profil entier en un seul modèle ; les réparations ; l'aléa partagé du KEM multi-destinataires ; la feuille scindée, qui ne change qu'un haché ; les signatures réelles, toutes idéales ; les métadonnées ; la sécurité calculatoire.

## 9. Sources

* R. Barnes et al., [The Messaging Layer Security (MLS) Protocol](https://www.rfc-editor.org/rfc/rfc9420.html), RFC 9420, 2023.
* B. Beurdouche et al., [The Messaging Layer Security (MLS) Architecture](https://www.rfc-editor.org/rfc/rfc9750.html), RFC 9750, 2025.
* R. Mahy, R. Barnes, [ML-KEM and Hybrid Cipher Suites for Messaging Layer Security](https://datatracker.ietf.org/doc/html/draft-ietf-mls-pq-ciphersuites-06), draft-ietf-mls-pq-ciphersuites-06, juillet 2026.
* D. Connolly, R. Barnes, [Concrete Hybrid PQ/T Key Encapsulation Mechanisms](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-concrete-hybrid-kems), draft-irtf-cfrg-concrete-hybrid-kems-04, juillet 2026.
* D. Connolly, P. Schwabe, B. E. Westerbaan, [X-Wing: general-purpose hybrid post-quantum KEM](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/), draft-connolly-cfrg-xwing-kem-10, mars 2026.
* R. Perlner, [FIPS 206 Status Update](https://csrc.nist.gov/csrc/media/presentations/2025/fips-206-fn-dsa-(falcon)/images-media/fips_206-perlner_2.1.pdf), NIST, 2025.
* NIST, [NIST Advances 9 Candidates to the 3rd Round of the Additional Digital Signature Schemes](https://csrc.nist.gov/News/2026/nist-advances-9-candidates-to-the-3rd-round-of-pqc), 2026.
* J. Alwen, S. Coretti, Y. Dodis, Y. Tselekounis, [Security Analysis and Improvements for the IETF MLS Standard for Group Messaging](https://eprint.iacr.org/2019/1189), Crypto 2020.
* B. Blanchet, [CryptoVerif](https://bblanche.gitlabpages.inria.fr/CryptoVerif/) et [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/).
* Notes précédentes : [grands-groupes](grands-groupes-2026-09-25.md), [plan de messages](plan-de-messages-2026-09-26.md), [parité MLS](parite-mls-2026-09-26.md), [re-key par le serveur](rekey-serveur-2026-09-26.md), [îlots](ilots-2026-09-26.md).
