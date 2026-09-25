# Audit cryptographique et de conformité de City-G, et propositions pour le standard

| | |
| --- | --- |
| Date | 2026-09-25 |
| Commit audité | `71ee261` (identique à `origin/main`) ; les numéros de ligne cités renvoient à ce commit |
| Spécification | [`docs/specs.md`](../specs.md) « v0.1.4 » (en-tête daté du 2026-03-23, texte modifié jusqu'au 2026-04-05) |
| Périmètre | spec normative, chapitres compagnons de [`docs/protocol/`](../protocol/), crates `msphf-*`, `capss`, `anchor-seed`, `cityg-client`, `cityg-server`, `cityg-api`, `cityg-api-client`, `cityg-pqc`, flux GUI join / leave / expel / messages |
| Preuves de concept | [`poc-2026-09-25/`](poc-2026-09-25/) (Rust et Python, reproductibles) |
| Auditeur | Claude Code (assistant IA d'Anthropic), à la demande du mainteneur. Les constats critiques sont étayés par du code exécuté ; une relecture cryptographique humaine indépendante reste recommandée avant toute décision de conception. |

## 0. Résumé exécutif

Les audits 1 à 7 (mars 2026) portaient uniquement sur le texte de `docs/specs.md`, sans accès au code, et se concentraient sur la machine à états de la barrière PRS et sur l'autorité d'historique. Le [rapport de vérification finale](final-verification-report-2026-03-26.md) conclut qu'aucun constat ne reste ouvert. Le présent audit examine ce que ces revues ne pouvaient pas voir : la solidité des primitives du cœur (SPHF/ME-OR, preuves CAPSS et ZK-VRF), la conformité du code à la spec, et la validité des propriétés de sécurité annoncées.

1. **La confidentialité des messages repose en pratique sur un seul mécanisme : la barrière PRS** (`K_barrier`, arbre KEM de type TreeKEM). La couche `msphf-we` (SPHF RLWE, ME-OR, `E_k`) et les preuves validées par le serveur (CAPSS Smallwood, SRX Smallwood, `hp_binding`, ZK-VRF) n'apportent aucune garantie. `E_k` n'est jamais un secret indépendant de `K_barrier` : pour les ancres MERGE, il se déduit de `K_barrier` et de l'en-tête public ; pour les ancres JOIN, le serveur le recalcule à partir des octets qu'il reçoit (PoC, C-01). Aucune de ces « preuves » ne prouve la connaissance d'un secret ni une relation (C-02).
2. **La barrière PRS a elle-même des failles de conception.** Un membre qui quitte volontairement le groupe génère lui-même la clé post-révocation (C-03). La clé feuille d'un appareil n'est jamais renouvelée, donc aucune PCS n'est possible après compromission (H-03). Un serveur actif peut s'admettre comme membre et être couvert par les mises à jour honnêtes (H-01).
3. **La « forward secrecy à la minute » n'existe pas pour les messages.** `K_fs` n'intervient dans aucune clé de message ; la granularité réelle est la durée de vie d'une version de barrière, sans borne temporelle (H-02).
4. **La spec n'est pas implémentable de façon indépendante.** L'encodage de `H_L` diffère entre spec et code (PoC, H-06). Le registre des clés d'en-tête diverge (H-07). Le cœur est déclaré « opaque ». La suite de signature est mal nommée et non interopérable entre les builds natif et wasm (PoC, H-05). Plusieurs transitions implémentées (départ, expulsion, réclamation de slot, genèse) ne figurent pas dans la spec ou la contredisent (H-07).
5. **`main` ne compile pas** (H-09).

Les propositions de la section 4 dessinent une révision `v0.2` du profil. Elles couvrent le modèle de menace explicite, un calendrier de clés chaîné par époque (inspiré de MLS, RFC 9420) à la place de ME-OR, une barrière v2, l'admission vérifiable par les clients, une signature d'ancre unique, un plan messages v3 et l'ingénierie de la spécification.

### Tableau des constats

| ID | Titre | Sévérité | Nature | Preuve |
| --- | --- | --- | --- | --- |
| [C-01](#c-01) | `E_k` n'est pas un secret indépendant ; recalculable par le serveur pour les JOIN | Critique | Conception, impl. | PoC `ek_recovery` |
| [C-02](#c-02) | SPHF, CAPSS/SRX Smallwood, `hp_binding` et ZK-VRF ne prouvent rien | Critique | Conception, impl. | Code |
| [C-03](#c-03) | Départ volontaire : le membre sortant choisit `K_barrier` post-révocation | Critique | Conception, impl. (viole S11.12.1.F) | Code |
| [H-01](#h-01) | Serveur actif : admission de membres fantômes | Élevée | Modèle de menace | Code |
| [H-02](#h-02) | Pas de FS « à la minute » ; `K_fs` inopérant et non conforme à S12.2 | Élevée | Conception, impl. | Code |
| [H-03](#h-03) | Pas de PCS pour la clé feuille de barrière | Élevée | Conception | Spec, code |
| [H-04](#h-04) | Authentification des ancres partielle | Élevée | Spec, impl. | Code |
| [H-05](#h-05) | Signature : « ML-DSA-65 » = Dilithium5 pré-FIPS ; natif ≠ wasm | Élevée | Impl., spec | PoC `mldsa_interop` |
| [H-06](#h-06) | `H_L` : map CBOR (code) contre tableau `CBOR_det` (spec) | Élevée | Interopérabilité | PoC `hl_encoding` |
| [H-07](#h-07) | Écarts spec ↔ implémentation non documentés | Élevée | Conformité | PoC `header_keys` |
| [H-08](#h-08) | Taille des mises à jour de barrière : passage à l'échelle et blocage | Élevée | Conception | `cover_sim.py` |
| [H-09](#h-09) | `main` ne compile pas | Élevée (dépôt) | Hygiène | `cargo check` |
| [H-10](#h-10) | Messages : signature hors contexte, pas de contrôle d'appartenance | Élevée | Spec, impl. | Code |
| [M-01](#m-01) | Anti-rejeu contradictoire et contournable | Moyenne | Spec, impl. | Code |
| [M-02](#m-02) | Collision de `msg_index` ⇒ réutilisation clé/nonce | Moyenne | Conception | Analyse |
| [M-03](#m-03) | Perte de messages aux changements de version | Moyenne | Conception | Spec |
| [M-04](#m-04) | Gouvernance de version et éléments vestigiaux | Moyenne | Spec | Code, historique git |
| [M-05](#m-05) | Exclusion sélective par un updater malveillant | Moyenne | Conception | Spec |
| [M-06](#m-06) | Configuration serveur par défaut permissive | Moyenne | Impl. | Code |
| [L-01](#l-01) | Rédaction de la spec | Faible | Spec | Spec |
| [L-02](#l-02) | Documentation et revendications | Faible | Doc | Doc |

## 1. Périmètre, méthode et limites

**Méthode.**

- Lecture intégrale de `docs/specs.md` (1 998 lignes), des chapitres compagnons 01, 05, 06, 10 et 21, des audits 1 à 7 et du rapport final.
- Revue ciblée du code (≈160 kLoC Rust) : génération d'ancres (`joiner_kgen_or`, `joiner_kgen_merge_or_with_state`), acceptation (`accept/`), SPHF (`msphf-rlwe`), preuves (`capss`, `proofs/`), barrière côté client et serveur, plan messages, PQC (`cityg-pqc`, `pqcrypto-kyber`), flux GUI join / leave / expel.
- Exécution de preuves de concept Rust contre le code du dépôt (avec la correction de compilation H-09 appliquée localement) et d'une simulation Python. Voir l'[annexe A](#annexe-a).

**Limites.** La suite de tests n'a pas pu être exécutée telle quelle (H-09). Pas d'analyse formelle, pas d'analyse de canaux auxiliaires, pas de revue de l'interface GUI ni du déploiement Cloudflare au-delà de la PQC. Les sévérités mesurent l'écart entre les propriétés revendiquées et les propriétés obtenues ; City-G se présente comme un prototype de recherche.

**Échelle de sévérité.**

- **Critique** : une propriété de sécurité centrale revendiquée par le standard est invalidée, ou un participant ordinaire peut casser la confidentialité ou la PRS.
- **Élevée** : propriété importante absente, attaque nécessitant une position privilégiée (serveur actif, appareil compromis), ou blocage d'interopérabilité ou de mise en œuvre.
- **Moyenne** : affaiblissement borné, ambiguïté pouvant produire des implémentations divergentes, ou perte de disponibilité.
- **Faible** : rédaction, documentation.

## 2. Points forts

- Discipline « fail-closed » systématique dans la spec (S3.3, S11.11, S11.14) comme dans le code ; bornes de ressources explicites (tailles, pagination, rétention).
- Vérification du déterminisme CBOR en entrée ; registre d'en-tête en monde fermé.
- Primitives standard pour le KEM (ML-KEM-768 via la crate `ml-kem`) et l'AEAD (ChaCha20-Poly1305), avec une liaison AAD étendue des enveloppes de barrière (S11.13.4).
- Exigences de persistance atomique et de *persist-before-publish* (S11.14) bien pensées ; nombreux tests d'état et de reprise après crash.
- CI stricte (clippy avec `-D unwrap_used`, etc.) et manifestes de couverture S14.

La barrière PRS (arbre KEM, couverture sur le chemin, contrôle `ExpectedPairs`, chain-check FULL) est la partie la plus solide du protocole. C'est elle qui porte réellement la confidentialité, d'où l'importance des constats C-03, H-01, H-03 et H-08.

## 3. Constats détaillés

<a id="c-01"></a>
### C-01 — `E_k` n'est pas un secret indépendant ; le serveur le recalcule pour les ancres JOIN

- **Sévérité** : Critique (propriété centrale invalidée ; n'ouvre pas à elle seule l'accès aux messages)
- **Spec** : S3.1, S3.4, S8.3 ; `10-security-model.md` §3 (« S cannot compute: hp, Y*, E_k, eid »)

**Constat.** Chez l'auteur, `E_k = H_epoch(X_k, Y*)` avec `Y* = H_L("msphf/ystar", [XOF(seed_DRBG), X_k, crs, params])` et `seed_DRBG = H_L("msphf/drbg", [seed_commit, rho_raw, xk_hash, seed_ctx_hash])` (`crates/msphf-orchestrator/src/lib.rs:2856`, `:2896-2915`, `:2978`). La seule entrée qui pourrait être secrète, `rho_raw`, vaut `H_L("msphf/rho/der", [pop_sig, xk_hash])`, où `pop_sig` est la signature PoP publiée en clair dans `header[109]` (`lib.rs:2816-2820`). Toutes les autres entrées sont publiques. Le serveur recalcule d'ailleurs lui-même `seed_DRBG` pendant l'acceptation des JOIN (`crates/msphf-rlwe/src/lib.rs:163-223`, appelé depuis `crates/msphf-orchestrator/src/accept/join.rs:369`).

Par ailleurs, `ClientEpochBundle` sérialise `capss_witness` (`crates/cityg-client/src/lib.rs:545`), qui contient `hp_a` et `hp_b` en clair. Ce bundle est envoyé tel quel à `/v1/accept_epoch` (`crates/cityg-api-client/src/epoch_routes.rs:75-82`) : des éléments de `hp`, que la spec considère protégés par `header[97]`, circulent en clair.

Pour les ancres MERGE, qui portent les époques utilisées pour les messages, le chemin de fusion retire la PoP de l'en-tête (`lib.rs:3202-3210`) : `E_k` n'est plus calculable depuis l'en-tête seul. Il se déduit toutefois de `K_barrier` et de l'en-tête public, puisque `header[97]` est scellé sous une clé dérivée de `K_barrier` et de données publiques (S3.4).

**Preuve.** PoC `ek_recovery` : à partir des seuls octets envoyés au serveur, `E_k` est recalculé exactement pour trois ancres JOIN de référence (`match=true` ×3), et 4 871 octets de `hp_a` sont transmis en clair.

**Impact.**

- La revendication « server-blind by construction » (README) et l'énoncé formel de `10-security-model.md` sont faux pour `E_k`, `Y*` et `hp`.
- L'argument de défense en profondeur de S8.3 (« Payload confidentiality requires compromise of both E_k and K_barrier ») ne tient pas : `K_barrier` suffit dans tous les cas. Tout événement qui expose `K_barrier` expose les messages (C-03, H-01, H-03).
- Les messages restent protégés tant que `K_barrier` reste secret : les époques JOIN ne servent pas au chiffrement des messages dans le profil actuel (S12.3).

**Recommandations.** Court terme : corriger la documentation ; ne plus sérialiser `capss_witness` vers le serveur. Standard : retirer `E_k` et ME-OR du chemin de confidentialité et dériver les clés d'un calendrier chaîné ([P-2](#p-2)). Une dérivation « sans interaction » ne peut être conservée que si elle repose sur un secret réellement inaccessible au serveur et s'accompagne d'une preuve de sécurité.

<a id="c-02"></a>
### C-02 — Les primitives « prouvées » du cœur ne prouvent rien

- **Sévérité** : Critique
- **Spec** : S9.1 à S9.3, S10.5, identifiants in-profile (`docs/specs.md:75-84`) ; chapitres 05 et 06

**Constats**, tous vérifiés dans le code :

1. **Le SPHF RLWE n'a aucune propriété de SPHF.** `hash_full` n'utilise le mot `X_k` que via une étiquette de contexte hachée ; aucune clé de hachage secrète n'intervient dans la valeur, qui vaut `H(ctx_tag, u, v)` calculé à partir de `hp` lui-même (`crates/msphf-rlwe/src/lib.rs:235-267`). `hash_proj` produit la même valeur **sans témoin** : le témoin n'intervient que via un `delta` qui compare deux racines publiques et qui est nul en l'absence de témoin (`:269-295`, `:499-523`). Le test du dépôt `hash_proj_allows_missing_witness` (`:729`) l'affirme explicitement. Il n'y a donc ni correction dépendante du témoin, ni lissage ; les calculs MLWE (`b = A·s + e`, etc.) sont décoratifs. L'identifiant in-profile imposé par la spec est d'ailleurs `msphf_params_id == "rlwe-params/mock"` (`docs/specs.md:79`).
   Sur le plan conceptuel, un chiffrement par témoin sur le langage « appartenance à un arbre de Merkle public » ne peut rien protéger : le témoin (un chemin de Merkle) est calculable par quiconque connaît l'arbre.
2. **CAPSS et SRX Smallwood.** `capss::prove` ignore le RNG et ne reçoit que des entrées publiques (`crates/msphf-orchestrator/src/proofs/capss.rs:65` ; idem `srx_smallwood.rs:60`). Le « témoin » est dérivé du condensat de l'énoncé public, via la relation jouet `x^16 = y` de l'implémentation de référence Sage (`crates/capss/src/smallwood/mod.rs:489-499`, `pacs/example.rs`). Le vérifieur contrôle seulement la cohérence commitment/ouvertures et le défi Fiat-Shamir ; il n'évalue jamais les contraintes PACS (`mod.rs:330-410`). N'importe qui peut donc produire une preuve valide pour n'importe quel énoncé, y compris pour un `hp_commit` arbitraire.
3. **`hp_binding`.** La « preuve » est un condensat déterministe d'entrées publiques (`crates/msphf-orchestrator/src/proofs/hp_binding.rs:48-62`).
4. **ZK-VRF.** Chaque client génère ses propres paramètres LB-VRF et sa clé à partir d'aléa local (`crates/cityg-client/src/vrf.rs:4-14`). La clé publique VRF voyage dans l'en-tête (clé 156) sans être liée à l'identité de l'appareil ni couverte par la PoP. Le message évalué est `bind_fs`, entièrement public, et la sortie VRF n'est utilisée nulle part (`proofs/zk_vrf/lb.rs:117-120`). La propriété « proves Y* correctness without revealing it » n'existe pas : `Y*` est dérivé indépendamment (C-01).
5. **MERGE.** Les preuves ne sont même pas recalculées : l'ancre MERGE recopie `vrf_proof`, `vrf_public`, les masques et `fs_capss` du pivot (`crates/msphf-orchestrator/src/lib.rs:3395-3407`).

**Impact.** Les propriétés anti-grinding, « dérivation déterministe seed→hp », « correction de Y* » et validité SRX ne sont pas obtenues. Les estimations de sécurité associées (« ≈96 bits quantiques », « Module-LWE ») ne s'appliquent à rien. La validation serveur des ancres est purement structurelle, pour un coût d'environ 20 Ko de « preuves » par ancre plus le temps CPU du serveur.

**Recommandations.** Standard : soit retirer ces mécanismes du profil de base (recommandé, cf. [P-2](#p-2) et [P-5](#p-5)), soit spécifier précisément chaque relation prouvée (énoncé, témoin secret, propriété visée), un système de preuve analysé et des vecteurs de test négatifs (preuve rejetée pour un faux témoin). Dans les deux cas, mettre à jour le README, `10-security-model.md` et le livre blanc.

<a id="c-03"></a>
### C-03 — Départ volontaire : le membre sortant génère lui-même `K_barrier` post-révocation

- **Sévérité** : Critique
- **Spec** : S10.4A, S11.9.1, S11.12.1.F (« updater-not-revoked »)

**Constat.** Le flux « Leave room » (`crates/cityg-gui/src/native/barrier_revocation_runtime.rs:187-203`) demande un ticket de fusion pour sa propre révocation, puis construit localement la `barrier_update` avec **son propre** bail de slot comme updater (`crates/cityg-client/src/barrier_snapshot_prepare.rs:211`). C'est donc lui qui tire `ps_leaf` et calcule `K_barrier_new` (`crates/cityg-client/src/barrier_build.rs:122`). Côté serveur, la règle « updater non révoqué » n'est vérifiée que contre les révocations **déjà engagées** (`committed_revoked_indices`, `crates/cityg-server/src/lib.rs:6244-6299`) : le slot révoqué par la mise à jour elle-même passe le contrôle. S11.12.1.F exige pourtant que le bail de l'updater n'apparaisse pas dans `RevokedLeafSet` *for this update*.

**Impact.** Le membre sortant connaît `K_barrier(v+1)`, donc toutes les clés de message de la version `v+1` (C-01). Il peut lire, et même écrire (H-10), jusqu'à la mise à jour de barrière suivante. Celle-ci n'intervient qu'à la prochaine adhésion, révocation ou PCS, et la PCS n'est déclenchée que manuellement (`crates/cityg-gui/src/native/lifecycle.rs:144-155`) : la fenêtre n'est pas bornée. Un appareil malveillant ou compromis peut donc « partir » et continuer à lire le groupe, soit l'exact contraire de la *post-revocation secrecy* annoncée.

Le re-blanking cumulatif des slots révoqués (H-08) empêche la fuite de s'étendre à la version suivante. Corriger H-08 sans corriger C-03 prolongerait donc la fuite indéfiniment.

**Recommandations.** Implémentation : rejeter toute mise à jour dont l'updater figure parmi les révocations introduites par l'ancre elle-même. Standard ([P-3](#p-3)) : faire du départ une **proposition de retrait** signée par le partant et engagée par un autre membre ou un administrateur. Aucune clé post-révocation ne doit jamais être générée par un membre révoqué.

<a id="h-01"></a>
### H-01 — Serveur actif : admission de membres fantômes

- **Sévérité** : Élevée
- **Spec** : S3.3 (autorité d'historique), S11.6, S12 ; `10-security-model.md` §2 (« Compromised Server … Cannot learn secrets », « Insider threats: malicious server operators ✅ »)

**Constat.** Seul le serveur autorise les adhésions. `join_ticket` n'exige qu'une limite de débit (`crates/cityg-api/src/ticket_routes.rs:40-52`), et la spec ne définit aucun objet d'admission signé par un administrateur ou un membre : le registre `RoomAdminProof` couvre le bootstrap, la rotation KBROAD, la gestion des admins et l'expulsion, pas l'admission. Les `JoinSet` que chaque updater doit couvrir (S11.6) proviennent du serveur. Leur « authentification » est une signature de l'autorité d'historique, dont la clé appartient au serveur, et dont le descripteur est fourni par le serveur lui-même sans ancrage hors bande.

**Impact.** Un opérateur malveillant, ou un serveur compromis, crée un appareil, obtient un ticket et publie un JOIN auto-signé. La mise à jour honnête suivante chiffre les secrets de chemin vers sa feuille : il apprend `K_barrier` et lit tout le groupe. Les mécanismes de S3.3 garantissent la cohérence de l'historique vu par un client, pas l'honnêteté de celui qui l'écrit.

**Recommandations** ([P-4](#p-4)) : un objet `Admission` signé par un administrateur (ou par un membre, selon la politique du groupe) et vérifié par tout updater avant de couvrir une feuille ; l'empreinte de la liste des membres intégrée au contexte de groupe ; de la transparence (journal de membres vérifiable, comparaison de numéros de sécurité). À défaut, la spec doit restreindre explicitement ses garanties au serveur honnête-mais-curieux.

<a id="h-02"></a>
### H-02 — Pas de forward secrecy « à la minute » ; `K_fs` inopérant

- **Sévérité** : Élevée
- **Spec** : S6, S8.3, S12.2, S14.6 ; README

**Constats.**

- Aucune clé de message ne dépend de `K_fs` ni de `tau_e` : `K_msg_epoch` dérive de `E_k` et de `K_barrier` (S8.3 ; `crates/cityg-client/src/message_crypto.rs:323-350`). S8.3 le reconnaît d'ailleurs dans sa note.
- Comme `E_k` se déduit de `K_barrier` (C-01), la compromission de `K_barrier` à l'instant T expose tous les messages de la version de barrière courante depuis son début. La granularité réelle de la FS est donc la durée d'une version de barrière. Elle n'a pas de borne temporelle, puisque la PCS est manuelle et soumise à limitation de débit.
- Chaque appareil tire `K_fs` aléatoirement à l'adhésion (`crates/cityg-client/src/join_runtime.rs:27-38`), ce que S12.2 interdit explicitement (« Joiners MUST NOT locally sample an unrelated fresh K_fs »). À l'inverse, S12.2 exige que le serveur fournisse `K_fs` au nouveau membre. C'est impossible sans que le serveur connaisse `K_fs`, ce que contredit S6.6 (« Servers do not learn K_fs »), et impossible tout court après un reseed PCS qui mêle `K_barrier_new`.
- S14.6 (« updater and non-updater client derive identical K_fs ») ne peut pas être satisfait. Le test cité par le manifeste (`try_recover_barrier_from_header_recovers_key_and_pcs_reseed`) ne vérifie qu'un seul client.

**Impact.** Les revendications « minutes-grade FS » (README, tableau comparatif) sont fausses. La chaîne FS, les clés 139 à 153 et le reseed PCS de `K_fs` n'ont aucun effet sur la confidentialité.

**Recommandations** ([P-2](#p-2)) : remplacer ce mécanisme par un calendrier de clés chaîné par époque avec effacement des secrets, et une politique de renouvellement temporelle (commit périodique) ; supprimer `K_fs` ou lui donner un rôle défini.

<a id="h-03"></a>
### H-03 — Pas de PCS pour la clé feuille de barrière

- **Sévérité** : Élevée
- **Spec** : S11.9 (`ExpectedNodeSet := pn[1..]`), S11.10 (« Does NOT apply to barrier leaf keys »), S12.1

**Constat.** La paire `(ek_leaf, dk_leaf)` générée à l'adhésion n'est jamais renouvelée. Les mises à jour ne régénèrent que les nœuds internes du chemin de l'updater, et aucun mécanisme de rotation n'existe dans le code.

**Impact.** Un attaquant qui a volé `dk_leaf` lors d'une compromission ponctuelle déchiffre toute couverture ultérieure ciblant cette feuille. Cela se produit dès qu'un nœud interne du chemin est vide, ce qui est fréquent après des adhésions et des révocations (H-08). Une « PCS refresh » de la victime ne déloge pas l'attaquant ; seule la révocation de l'appareil le fait.

**Recommandations** ([P-3](#p-3), point a) : inclure la feuille dans le chemin mis à jour, comme l'`UpdatePath` de MLS, avec un `ek_leaf'` dérivé de `path_secret[leaf]`, et exiger un renouvellement périodique.

<a id="h-04"></a>
### H-04 — Authentification des ancres partielle

- **Sévérité** : Élevée
- **Spec** : S7.4 (« Anchor authentication MUST bind to header[153] and to the canonical header map »), S4

**Constat.** La spec ne définit ni la signature d'ancre, ni le message signé, ni la suite. Dans le code :

- La PoP d'un JOIN signe `H_L("msphf/pop/msg", {xk, leaf_id, epoch})`. Or `X_k` n'inclut que `ANCHOR_SEED_CTX`, qui exclut notamment les clés 93 à 100, 107 à 109, 116, 119, 125, 146 et 154 à 156 (`crates/anchor-seed/src/lib.rs:15-31`), et `msphf_hp_commit` n'est pas dans `X_k` (`crates/msphf-core/src/instance.rs:38-50`). L'enveloppe HP, son engagement, les preuves et la clé VRF ne sont donc couverts par aucune signature.
- Les ancres MERGE suppriment la PoP (`crates/msphf-orchestrator/src/lib.rs:3202-3210`). Leur seule signature d'auteur est le reçu 181, qui ne couvre que `(gid, author_leaf_id, reason, slot, génération, header[180], header[182], header[175])`. Il ne couvre pas les racines 110/111, l'enveloppe 97/99, les champs FS ni les champs SRX, dont la charge utile décrivant le delta de membres.
- Sans autorité d'historique configurée (défaut de `ServerConfig::new()`), aucune signature d'auteur n'est exigée sur une MERGE (M-06).

**Impact.** Le serveur, non fiable par hypothèse, peut modifier sans être détecté les champs non couverts d'une ancre. Il peut par exemple altérer le delta de membres présenté aux clients, ou les racines et donc le `X_k` dont dépend `E_k`, ce qui provoque un déni de service. Les propriétés « liées à l'ancre » dépendent de sa bonne foi.

**Recommandations** ([P-5](#p-5)) : une signature unique par ancre, portant sur `CBOR_det` de l'en-tête complet privé du seul champ de signature, avec séparation de domaine, pour tous les types d'ancre.

<a id="h-05"></a>
### H-05 — Suite de signature mal nommée, non standard et non interopérable

- **Sévérité** : Élevée
- **Spec** : `docs/specs.md:48-49` et `:80-81` (« ML-DSA-87 / Dilithium5 ») ; en-tête 107

**Constats.**

- Le fil porte le libellé `"ML-DSA-65"`, vérifié par `ensure_join_pop`, alors que la signature est produite par `pqcrypto-dilithium 0.5.0` `dilithium5`, qui a les tailles de ML-DSA-87. Le code le reconnaît (`crates/cityg-pqc/src/lib.rs:5-16`).
- Le backend natif (`pqcrypto-dilithium`) et le backend wasm32 (`fips204` ML-DSA-87, FIPS 204 final) produisent des signatures mutuellement invérifiables (PoC `mldsa_interop` : `false` dans les deux sens). Le Worker Cloudflare (`cityg-worker`, wasm32) rejetterait donc toutes les PoP, preuves d'administration et reçus produits par les clients natifs.
- La spec assimile « ML-DSA-87 » et « Dilithium5 », qui ne sont pas interopérables.
- Une même clé PoP signe les ancres, les messages de discussion, les preuves d'administration et les reçus 181, sans chaîne de contexte (le paramètre `ctx` de FIPS 204) ni préfixe de domaine commun.

**Recommandations** ([P-7](#p-7)) : normer FIPS 204 ML-DSA-87 (ou ML-DSA-65) dans sa version finale, avec le libellé exact, une chaîne `ctx` par usage et des vecteurs de test ; abandonner `pqcrypto-dilithium 0.5.0`.

<a id="h-06"></a>
### H-06 — `H_L` : l'encodage du code n'est pas celui de la spec

- **Sévérité** : Élevée
- **Spec** : S1.3, S2.2 et toutes les formules `H_L(label, [args])`

**Constat.** S2.2 définit `H_L` sur `CBOR_det(args[])`, c'est-à-dire un tableau. Le code (`crates/msphf-core/src/hash.rs:50-73`) sérialise directement l'argument avec ciborium. Pour une trentaine de labels normatifs, cet argument est une `struct` à champs nommés, donc une **map** à clés textuelles émises dans l'ordre de déclaration, qui n'est même pas canonique au sens de RFC 8949 §4.2.1. Labels concernés, notamment : `barrier/tree/leaf-hash` et `barrier/tree/node-hash` (S11.4), `fs/dev/chain/v2` (S7.4), `fs/step/salt`, `fs/tau/salt`, `fs/epoch/sk_salt` (S6), toutes les dérivations de S8 (`fs/msg/epoch_salt`, `key_salt`, `nonce`, `replay/tuple`, `replay/context`), `hp/nonce` et `hp/barrier/salt` (S3.4), `barrier/history-commitment` (S3.1), `room-admin/replay-key`, `srx/bridge/v1`.

**Preuve.** PoC `hl_encoding` : `TreeHash` et `fs_dev_commit` calculés selon la spec diffèrent des valeurs produites par le code.

**Impact.** Une implémentation indépendante conforme à la lettre de la spec rejetterait toutes les ancres (947.2) et toutes les mises à jour de barrière (960.8) de l'implémentation de référence. En l'état, la spec n'est pas la source de vérité.

**Recommandations** ([P-7](#p-7)) : choisir un encodage unique (recommandé : des tableaux `CBOR_det`, conformes au texte actuel) et publier des vecteurs de test pour chaque label.

<a id="h-07"></a>
### H-07 — Écarts spec ↔ implémentation non documentés

- **Sévérité** : Élevée

1. **Registre fermé (S4.2).** L'ancre JOIN de référence n'a pas les clés 20 et 96, exigées par S4.2.1, et porte les clés 154, 155 et 156, hors registre (PoC `header_keys`). Le code accepte aussi les clés 102, 120, 123, 124, 140 et 170 à 172 (`crates/msphf-orchestrator/src/accept/mod.rs:1880-1941`). Un vérifieur conforme rejetterait (907.1) toutes les ancres du code. La sémantique de nombreuses clés requises (20, 90 à 96, 104, 105, 107, 109, 116, 119…) n'est définie nulle part dans la spec.
2. **Genèse (S10.4, S12.0).** La spec exige une première ancre MERGE de raison 0 et un artefact de provisioning de genèse. Le serveur initialise au contraire unilatéralement un arbre vide en version 0 (`crates/cityg-server/src/lib.rs:691-707`), et la première ancre est un JOIN « bootstrap ».
3. **MERGE sans mise à jour de barrière.** Autorisée par S10.4, elle est refusée par le code, qui exige `header[178]` sur toute MERGE (`crates/msphf-orchestrator/src/accept/merge.rs:79-84`).
4. **Réclamation de slot.** Elle est acceptée comme raison 0 **avec** `header[179]` (`crates/cityg-server/src/lib.rs:6285-6329`, `:6391-6414`), alors que S4.3 et S11.12.1.A exigent 179 si et seulement si la raison vaut 2, et que S12.3 interdit à un joiner en attente d'émettre une raison 0. Le slot réclamé est en outre retiré du `RevokedLeafSet`, règle absente de S11.6.
5. **Expulsion par un administrateur.** L'`updater_slot_index` est celui de la **cible** révoquée (`targeted_admin_revocation`, `:6276-6284`), contrairement à S11.12.1.F, qui impose le slot de l'auteur et exige qu'il ne soit pas révoqué.
6. **Départ volontaire** : voir C-03.

**Impact.** L'implémentation suit des règles que la spec ne décrit pas ; la conclusion du rapport de vérification finale (« No finding remains Open ») ne reflète donc pas l'état réel.

**Recommandations.** Spécifier normativement chaque transition (Join, JoinFinalize, Leave, Expel, Reclaim, Refresh, Genesis) avec ses préconditions ([P-3](#p-3)), puis aligner le code et la spec.

<a id="h-08"></a>
### H-08 — Taille des mises à jour de barrière : passage à l'échelle et blocage

- **Sévérité** : Élevée
- **Spec** : S3.3 (`MAX_BARRIER_N_MAX = 65 536`), S4.4 (`max_barrier_update_bytes`), S11.6

**Constats.**

- S11.6 ré-applique à chaque mise à jour **toutes** les révocations non réclamées, en effaçant la feuille et tout son chemin jusqu'à la racine. Les nœuds internes regarnis par les updaters précédents sont donc re-vidés, et la résolution des nœuds frères grossit.
- Chaque adhésion vide aussi le chemin du joiner (S11.6, étape 1).
- La simulation `cover_sim.py` donne, dans le cas le plus favorable (arbre entièrement garni avant les révocations) :

  | `N_max` | Slots révoqués non réclamés | `NodeCiphertext` par mise à jour | Taille |
  | --- | --- | --- | --- |
  | 1 024 | 0 % / 10 % / 25 % | ~10 / ~274 / ~385 | 0,01 / 0,32 / 0,45 Mo |
  | 65 536 | 0 % / 1 % / 10 % / 25 % | ~16 / ~3 806 / ~17 332 / ~24 693 | 0,02 / 4,4 / 20,2 / 28,7 Mo |
  | 65 536 | arbre plein, nœuds internes vides (genèse massive) | 65 535 | 76,3 Mo |

- Les valeurs par défaut sont `N_max = 1 024` et `max_barrier_update_bytes = 1 048 576` (`crates/cityg-server/src/roster_state.rs:212`, `:410`). Au-delà de ce plafond, aucune mise à jour valide ne peut être produite : plus d'adhésion finalisée, de révocation ni de PCS. Le groupe est bloqué.
- `MAX_BARRIER_N_MAX = 65 536` est incompatible avec « targeting millions of members » (README) et avec « simulations to ~10⁶ members ».

**Recommandations** ([P-3](#p-3), points d, e et g) : révocations en delta, feuilles non fusionnées (MLS), bornes de taille dérivées de `N_max`, et une documentation honnête de l'échelle réellement supportée.

<a id="h-09"></a>
### H-09 — `main` ne compile pas

- **Sévérité** : Élevée (dépôt)

Le commit `71ee261` (« Instrument barrier header parse failures ») formate une `ciborium::value::Integer` avec `{}` (`crates/msphf-orchestrator/src/accept/mod.rs:2028`). Or `Integer` n'implémente pas `Display` dans ciborium 0.2.2, la version verrouillée : `msphf-orchestrator` et toutes les crates qui en dépendent échouent, et la CI (`cargo check --workspace`) est rouge. Correction : `{reason_int:?}`.

Accessoirement, `Cargo.lock` n'enregistre pas la `source` de `gpui`, si bien que `cargo … --locked` échoue sur un clone propre.

<a id="h-10"></a>
### H-10 — Messages : signature hors contexte, pas de contrôle d'appartenance

- **Sévérité** : Élevée
- **Spec** : S8.1 (exige un émetteur authentifié et la vérification de son appartenance), S8.2

**Constats.**

- La spec exige seulement « an authenticated sender device identifier », sans définir de format : le format signé n'est défini que par le code.
- La signature couvre `leaf_id ‖ timestamp ‖ plaintext` (`crates/cityg-client/src/message_auth.rs:156-170`) : ni `gid` explicite, ni époque, ni `barrier_version`, ni `msg_index`, ni préfixe de domaine. Un membre peut donc rechiffrer le message signé d'un autre membre dans une époque ultérieure, avec un nouveau `msg_index` : la signature reste valide, et l'anti-rejeu, lié au tuple et à `msg_index`, ne le détecte pas.
- Le récepteur vérifie seulement que la clé publique embarquée correspond à `leaf_id` (`:215-253`). Contrairement à S8.1, il ne vérifie pas que `leaf_id` est un membre courant. Un détenteur de `K_barrier`, par exemple un partant (C-03), peut injecter des messages affichés comme vérifiés (« ✓ »), sous son identité révoquée ou sous une identité fraîche.
- `leaf_id` provient du champ `sender` fourni par le serveur, et l'horodatage affiché est celui du serveur, pas l'horodatage signé (`crates/cityg-gui/src/native/network_messages.rs:142`, `:198`).

**Recommandations** ([P-6](#p-6)) : un contenu encadré signé qui inclut le contexte complet, une vérification d'appartenance obligatoire, et l'affichage de l'horodatage signé.

<a id="m-01"></a>
### M-01 — Anti-rejeu contradictoire et contournable

- **Sévérité** : Moyenne
- **Spec** : S8.2

S8.2 exige à la fois de rejeter tout couple `(tuple_tag, msg_index)` déjà accepté et de ne conserver que 4 096 index par tuple. Comme `msg_index` est aléatoire, donc non ordonné, aucune « fenêtre » n'est possible. Le code évince l'index le plus ancien (`crates/cityg-client/src/message_crypto.rs:70-91`) : le serveur peut rejouer tout message antérieur aux 4 096 derniers d'un même émetteur dans un même tuple.

**Recommandation** ([P-6](#p-6)) : un compteur par émetteur avec fenêtre glissante, ou un identifiant aléatoire de 128 bits avec une durée de vie de tuple bornée.

<a id="m-02"></a>
### M-02 — Collision de `msg_index` ⇒ réutilisation clé/nonce

- **Sévérité** : Moyenne
- **Spec** : S8.2, S8.4

La clé et le nonce sont des fonctions déterministes de `msg_index` (64 bits aléatoires). Une collision au sein d'un tuple réutilise donc le couple clé/nonce ChaCha20-Poly1305, ce qui révèle le XOR des clairs et permet de falsifier Poly1305. La probabilité est d'environ 2^-25 pour 2^20 messages, ce qui n'est pas négligeable au sens cryptographique. De plus, le rejet des doublons (M-01) masque la collision côté récepteur : le second message est simplement perdu.

**Recommandation** ([P-6](#p-6)) : un identifiant de 128 bits ou un compteur, ou un nonce aléatoire XChaCha20.

<a id="m-03"></a>
### M-03 — Perte de messages aux changements de version

- **Sévérité** : Moyenne
- **Spec** : S8.1, S8.5

Chaque adhésion (join_finalize), révocation ou PCS incrémente `barrier_version`. S8.5 impose d'écarter tout message lié à une version antérieure, et l'enveloppe ne porte aucune référence publique d'époque ni de version : les clés sont sélectionnées d'après le contexte de transport. Sous forte rotation des membres, précisément le cas d'usage visé, les messages en vol sont perdus.

**Recommandation** ([P-6](#p-6)) : un `epoch_ref` public dans l'enveloppe et une fenêtre de grâce bornée.

<a id="m-04"></a>
### M-04 — Gouvernance de version et éléments vestigiaux

- **Sévérité** : Moyenne

- `docs/specs.md` reste « v0.1.4 / 2026-03-23 » alors que des formats filaires ont changé le 2026-04-05 (commits `6657383`, `0289678`, `c9f7218`). Les baux de slots ont modifié `RevokedOccupancyRecord`, `JoinOccupancyRecord`, `KemTreeCoverPayload.updater_slot_generation` et les champs des reçus et témoins. `21-slot-leases-v0.2.md` le reconnaît lui-même : « cut a fully versioned v0.2 spec profile ».
- L'identifiant in-profile est `rlwe-params/mock`.
- `kat/kat-rlwe-annex-k.json` contient un `header[97]` au format legacy `kbroad-v1`, hors profil v0.1.4.
- KBROAD (clés 104/105, opération `rotate_room_kbroad_v1`) : le serveur génère une paire ML-KEM et jette la clé secrète (`crates/cityg-server/src/lib.rs:5688-5691`). Rien n'est chiffré vers cette clé : ce sont des champs requis sans fonction.

<a id="m-05"></a>
### M-05 — Exclusion sélective par un updater malveillant

- **Sévérité** : Moyenne
- **Spec** : S11.13.1, code 960.6

Un updater peut placer des `wrapped_ps` indéchiffrables pour certaines cibles. Le serveur, aveugle, ne peut pas le détecter. La victime obtient 960.6 (« client-local, not a global reject ») et reste bloquée, sans procédure de recours.

**Recommandation** ([P-3](#p-3), point h) : un signalement authentifié de l'échec de couverture, suivi d'une re-couverture obligatoire par un autre membre.

<a id="m-06"></a>
### M-06 — Configuration serveur par défaut permissive

- **Sévérité** : Moyenne

`ServerConfig::new()` n'active aucune autorité d'historique. Dans ce cas, `validate_history_authority_headers` accepte les mises à jour sans les clés 181, 182 et 183 (`crates/cityg-server/src/lib.rs:5897-5920`), contrairement au profil de base. Le chemin `cityg-runtime` active bien l'autorité globale, mais un intégrateur qui utilise la bibliothèque directement obtient un serveur non conforme.

**Recommandation** : un comportement par défaut fail-closed.

<a id="l-01"></a>
### L-01 — Rédaction de la spec

- **Sévérité** : Faible

- `JoinLeafSet` est utilisé mais jamais défini (S11.12.1.F) ; le terme défini est `JoinSlotSet`.
- S10.4C : le contrôle « if RRH != barrier_roots_hash, reject 960.13 » est tautologique, puisque la section ne s'applique que si RRH == barrier_roots_hash.
- S11.9 restreint la vérification de `ek_n` aux clients FULL, alors que S11.13.6 l'impose à tous.
- S11.12.1.F écrit `current_slot_lease(header[108])` (une clé d'appareil) puis « for the acting leaf_id ».
- S3.1 : `X_k` « commits at minimum… » n'est pas une définition. `ANCHOR_SEED_CTX` (les listes de clés exclues) et la fonction `leaf_id` ne sont définis que dans le code.
- `E_k`, `Y*`, `HpArtifact.m_a/m_b` et `H_epoch` sont déclarés « opaques », alors que S8 en dépend.
- Genèse : la sémantique des clés 180 à 183 n'est pas définie lorsqu'il n'existe pas encore d'état courant.
- S12.2 : « signed and confidential provisioning artifact » est exigé sans mécanisme de confidentialité, et « implausibly far in the future » n'est pas défini.
- S2.3 : « HKDF-BLAKE3 » n'est pas HKDF (RFC 5869) ; il faudrait le nommer et le justifier comme KDF fondée sur BLAKE3 en mode clé.
- S8.4 place `E_k`, un secret, dans l'AAD, le nonce et `tuple_tag` (qui est persisté). Il n'y a pas de fuite directe, mais c'est une source d'erreurs d'implémentation (journalisation de l'AAD, par exemple) ; des identifiants publics d'époque seraient préférables.

<a id="l-02"></a>
### L-02 — Documentation et revendications

- **Sévérité** : Faible

- Les badges « build passing / tests passing » sont statiques (README, lignes 4 et 5), alors que `main` ne compile pas.
- Chemins absolus `/Users/admin/...` dans le Quick Start du README et dans `docs/audits/README.md`.
- Revendications à retirer ou à requalifier : « server-blind by construction », « minutes-grade FS », « millions of members », « ≈96-bit quantum security » (RLWE-HPS), le tableau comparatif avec MLS, Signal et Matrix, l'énoncé formel du §3 de `10-security-model.md`, le commentaire de `CityGServer` (« Server never derives epoch keys », `crates/cityg-server/src/lib.rs:291-292`), et `verify_no_secrets.sh` présenté comme une preuve de cécité, alors qu'il s'agit d'une vérification syntaxique par grep.
- Le rapport de vérification finale est à réviser à la lumière du présent audit.

## 4. Propositions d'amélioration du standard

Les propositions suivantes décrivent une direction pour une révision `v0.2`. Les extraits normatifs sont rédigés en anglais pour pouvoir être intégrés directement à `docs/specs.md`.

<a id="p-1"></a>
### P-1 — Modèle de menace et revendications explicites

Ajouter une section normative qui croise les adversaires et les propriétés, et interdire toute revendication qui n'y figure pas. Le tableau ci-dessous indique les garanties que la `v0.2` devrait viser une fois P-2 à P-6 adoptées ; le profil actuel ne les fournit pas toutes (voir la section 3).

| Adversaire | Confidentialité | Authenticité émetteur | Accord sur les membres | FS | PCS | PRS |
| --- | --- | --- | --- | --- | --- | --- |
| A1 serveur passif | garantie | garantie | garantie | garantie | garantie | garantie |
| A2 serveur actif | seulement avec P-4 | garantie | seulement avec P-4 | garantie | garantie | seulement avec P-4 |
| A3 membre malveillant | non (initié) | garantie (P-6) | détection (P-2) | n/a | n/a | n/a |
| A4 membre révoqué ou sortant | garantie (P-3) | garantie (P-6) | garantie | garantie | n/a | garantie (P-3) |
| A5 appareil compromis ponctuellement | fenêtre bornée | fenêtre bornée | n/a | `FS_WINDOW` | après auto-mise à jour (P-3.a) | n/a |

```text
S0A. SECURITY GOALS (normative)
* A deployment MUST NOT advertise a security property that is not listed as
  "guaranteed" for the stated adversary in this section.
* PRS: a member whose occupancy is revoked by anchor N MUST NOT be able to
  derive any payload key of an epoch >= N, even if it was the author of anchor N.
* FS: compromise of a device at time T MUST NOT reveal payloads of epochs that
  ended before T - FS_WINDOW. FS_WINDOW is a profile parameter (default 24h).
* PCS: after a compromised device completes a self-update (S11.9, leaf
  included), the attacker MUST NOT derive keys of later epochs.
```

<a id="p-2"></a>
### P-2 — Calendrier de clés chaîné par époque (remplace ME-OR, `E_k` et `K_fs`)

```text
GroupContext_n  := CBOR_det(["city-g/group-context/v2", gid, epoch_n,
                             tree_hash_n, roster_hash_n, profile_id,
                             confirmed_transcript_hash_{n-1}])
commit_secret_n := path_secret[root_node] of the barrier_update accepted in epoch n
                   (ZERO32 if epoch n carries no barrier_update)
epoch_secret_n  := KDF(ikm  = commit_secret_n,
                       salt = init_secret_{n-1},
                       info = "city-g|epoch|v2" || H(GroupContext_n))
init_secret_n   := Expand(epoch_secret_n, "city-g|init|v2")
msg_secret_n    := Expand(epoch_secret_n, "city-g|msg|v2")
confirm_key_n   := Expand(epoch_secret_n, "city-g|confirm|v2")
* Clients MUST erase epoch_secret_{n-1} and init_secret_{n-1} once epoch n is active.
* Every anchor MUST carry confirmation_tag := MAC(confirm_key_n,
  confirmed_transcript_hash_n); a mismatch MUST abort activation.
* A member MUST publish a self-update at least every FS_WINDOW while active.
```

Cette construction apporte la FS et la PCS par époque, lie l'état des membres (`tree_hash`, `roster_hash`) aux clés, détecte les divergences d'historique entre clients, et rend inutiles le SPHF, le VRF et CAPSS validés par le serveur. Elle a déjà fait l'objet d'analyses publiées (MLS, RFC 9420). La FS intra-époque (par message) peut être ajoutée par un arbre de secrets par émetteur, comme le *secret tree* de MLS.

**Adhésion asynchrone.** Le chaînage par `init_secret_{n-1}` empêcherait un nouveau membre de finaliser seul son adhésion (`join_finalize`), puisqu'il ne connaît pas l'époque précédente. Le *commit externe* de MLS (RFC 9420 §12.4.3.2) résout ce point sans exiger de membre en ligne :

```text
external_seed_n := Expand(epoch_secret_n, "city-g|external|v2")
(external_pub_n, external_priv_n)
                := ML-KEM-768.KeyGen_internal(Expand(external_seed_n, "d"),
                                              Expand(external_seed_n, "z"))
GroupInfo_n     := CBOR_det([GroupContext_n, external_pub_n, confirmation_tag_n]),
                   signed by the member that authored epoch n and published
                   with its anchor (never signed by the server alone)
* A joiner finalising epoch n+1 MUST verify GroupInfo_n, then compute
  (kem_output, init_secret') := ML-KEM-768.Encaps(external_pub_n) and use
  init_secret' in place of init_secret_n; kem_output is carried in the anchor.
* Existing members compute init_secret' := ML-KEM-768.Decaps(external_priv_n,
  kem_output).
```

La signature de `GroupInfo_n` par un membre est indispensable : un serveur actif qui pourrait fournir sa propre `external_pub` ou ses propres clés d'arbre retrouverait l'attaque de H-01 (voir P-4).

<a id="p-3"></a>
### P-3 — Barrière PRS v2

a. **Renouvellement de la feuille** : `ExpectedNodeSet := { pn[i] | i in [0..len(pn)-1] }` et `(ek_leaf', dk_leaf') := ML-KEM-768.KeyGen_internal(KDF(path_secret[leaf], "leaf-d"), KDF(path_secret[leaf], "leaf-z"))`. Le serveur remplace la clé publique de la feuille de l'updater.

b. **Éligibilité de l'updater** :

```text
The updater occupancy MUST be active before the anchor and MUST NOT be revoked
by any revocation introduced by the same anchor. Servers MUST reject with
960.1; clients MUST reject locally.
```

c. **Départ et retrait par proposition** :

```text
RemoveProposal := CBOR_det(["city-g/remove/v1", gid, target_leaf_id,
                            target_slot_index, target_slot_generation, not_after])
* Signed by the target (voluntary leave) or by a current admin, with
  ctx = "city-g/remove/v1". Servers store pending proposals.
* The next accepted barrier_update MUST include every pending proposal and
  MUST be authored by a member that is not a target, before LEAVE_DEADLINE.
* Once a proposal is recorded, receivers MUST reject payloads whose sender is
  one of its targets.
```

d. **Révocations en delta** : `RevokedLeafSet := ResolveRevokedOccupanciesSince(prev_barrier_version)`. L'arbre engagé conserve les effacements ; il ne faut pas les ré-appliquer.

e. **Feuilles non fusionnées** (comme les *unmerged leaves* de RFC 9420 §7.8) : une adhésion n'efface plus le chemin, et `resolution(i)` inclut les feuilles non fusionnées de `i`.

f. **Génération liée à la feuille** : `H_L("barrier/tree/leaf-hash/v2", [N_max, i, slot_generation, pk_i])`. Une révocation n'efface une feuille que si la génération correspond, et une transition `Reclaim` normative remplace la règle ad hoc actuelle (H-07).

g. **Bornes de taille** : donner une formule de taille maximale d'une mise à jour en fonction de `N_max` et exiger `max_barrier_update_bytes >= f(N_max)`. Limiter `N_max` du profil de base à ce qui est réellement tenable ; un passage à l'échelle au-delà relève de sous-groupes ou d'une fédération.

h. **Échec de couverture** : un `CoverFailureReport` authentifié oblige un autre membre à re-couvrir (raison 1, exemptée de limitation de débit).

<a id="p-4"></a>
### P-4 — Admission vérifiable par les clients et transparence

```text
Admission     := CBOR_det(["city-g/admission/v1", gid, leaf_id, H_pk(ek_leaf),
                           slot_index, slot_generation, not_after, admitter_pop_pk])
admission_sig := ML-DSA-87.Sign(admitter_sk, Admission, ctx = "city-g/admission/v1")
* A JOIN anchor MUST carry (Admission, admission_sig) in a new registry key.
* ResolveJoinOccupanciesSince MUST return them with each record.
* An updater MUST verify every JoinSet record against the current admin set
  (or member set, for groups whose policy is open-by-invite) before wrapping
  any path secret to that leaf; failure MUST abort origination (fail closed).
* roster_hash (P-2) MUST commit to the admitted set and to the admin set;
  admin grant/revoke MUST be member-signed chain objects, not server state.
```

Compléter par un mécanisme de transparence des membres : journal vérifiable, comparaison de numéros de sécurité, alerte lors de l'ajout d'un appareil.

<a id="p-5"></a>
### P-5 — Signature d'ancre unique ; sort des preuves

```text
anchor_tbs  := CBOR_det(header map without key 109)
header[109] := ML-DSA-87.Sign(sk_pop, anchor_tbs, ctx = "city-g/anchor/v2")
* Applies to JOIN, MERGE and REGULAR anchors. Verifiers MUST reject any anchor
  whose header[109] does not verify under header[108].
* An anchor MUST NOT carry proof material copied from another anchor.
```

Si P-2 est adopté, retirer les clés 91 à 95, 125, 146, 154 à 156 et 161 du profil de base. Si des preuves sont conservées, spécifier leur relation, leur système de preuve et leurs vecteurs de test négatifs.

<a id="p-6"></a>
### P-6 — Plan messages v3

```text
FramedContent   := CBOR_det(["city-g/msg/v3", gid, epoch_n, sender_leaf_id,
                             generation, content_type, authenticated_data,
                             signed_timestamp_ms, plaintext])
signature       := ML-DSA-87.Sign(sk_sender, FramedContent, ctx = "city-g/msg/v3")
epoch_ref       := H_L("city-g/msg/epoch-ref", [gid, epoch_n])
PayloadEnvelope := CBOR_det(["city-g-msg-v3", epoch_ref, sender_leaf_id,
                             generation, ct])
* Keys and nonces derive from a per-sender ratchet keyed by msg_secret_n
  (generation = per-sender counter). Replay: per-(epoch, sender) high-water
  mark plus bitmap window; generations below the window MUST be rejected.
* Receivers MUST check sender_leaf_id IN roster(epoch_n) and verify the
  signature before release; applications MUST display signed_timestamp_ms.
* Receivers MAY keep the keys of epoch n-1 for GRACE_WINDOW (<= 10 min) to
  decrypt late messages, then MUST erase them.
```

Un AEAD à engagement de clé (ou un tag d'engagement `H(K_msg)`) est recommandé pour exclure les ambiguïtés multi-clés.

<a id="p-7"></a>
### P-7 — Ingénierie de la spécification

- **Registre complet** : une table donnant, pour chaque clé, le nom, le type, la taille, la présence par type d'ancre, la couverture par la signature, la sémantique et la section de référence.
- **Encodage** : tout préimage de `H_L` est un tableau `CBOR_det` ; les maps sont interdites. Publier des vecteurs de conformité pour chaque label.
- **Suite cryptographique** : FIPS 203 ML-KEM-768 et FIPS 204 ML-DSA-87 finaux, avec chaînes `ctx` ; KDF BLAKE3 documentée ; libellés exacts.
- **Versionnement** : tout changement filaire incrémente `profile_version`, avec journal des changements et KAT étiquetés par version ; supprimer « mock ».
- **Séparation** entre le cœur protocolaire et une « liaison API/déploiement » (autorité d'historique, pagination, provisioning, tickets).
- **Vecteurs indépendants**, générés par une seconde implémentation (le dépôt dispose déjà d'une référence Sage pour Smallwood), et une suite de conformité qui ne référence pas les fonctions de test internes de l'implémentation.

<a id="p-8"></a>
### P-8 — Vérification formelle

Modéliser le calendrier de clés, la barrière, le retrait et l'admission dans Tamarin ou ProVerif, sur le modèle des analyses publiées de MLS et TreeKEM, et prouver les propriétés PRS, FS et PCS face aux adversaires de P-1.

## 5. Plan d'action priorisé

| Priorité | Action | Constats | Effort |
| --- | --- | --- | --- |
| P0 | Corriger la compilation (`{reason_int:?}`) et le `Cargo.lock` | H-09 | XS |
| P0 | Rejeter tout updater révoqué par l'ancre elle-même ; désactiver le départ auto-couvert | C-03 | S |
| P0 | Cesser d'envoyer `capss_witness` au serveur | C-01 | XS |
| P0 | Vérifier l'appartenance de l'émetteur à la réception ; afficher l'horodatage signé | H-10 | S |
| P0 | Corriger le README et le modèle de sécurité (revendications) | C-01, C-02, H-02, L-02 | S |
| P1 | Unifier la suite de signature (FIPS 204 final, `ctx` par usage) | H-05 | M |
| P1 | Aligner l'encodage de `H_L` et publier des vecteurs de test | H-06 | M |
| P1 | Serveur fail-closed par défaut | M-06 | XS |
| P1 | Spec v0.2 : registre complet, transitions normatives, genèse, versionnement | H-07, M-04, L-01 | L |
| P2 | Calendrier de clés chaîné (P-2), barrière v2 (P-3), admission (P-4), signature d'ancre (P-5), plan messages v3 (P-6) | C-01, C-02, H-01 à H-04, H-08, M-01 à M-03, M-05 | XL |
| P2 | Analyse formelle (P-8) | tous | L |

<a id="annexe-a"></a>
## Annexe A — Reproduction des preuves de concept

Instructions détaillées : [`poc-2026-09-25/README.md`](poc-2026-09-25/README.md). Sorties obtenues le 2026-09-25 (la correction H-09 appliquée localement) :

```text
$ cargo run -q --release --bin ek_recovery
alice: author E_k = 5739711585692a8601754180e087e75ff34d6c3e3e370906cac18583b6393636
alice: server E_k = 5739711585692a8601754180e087e75ff34d6c3e3e370906cac18583b6393636  match=true
alice: hp_a sent in clear inside capss_witness: 4871 bytes
  (idem bob, carol)
RESULT: E_k is computable from the accept_epoch request bytes alone.

$ cargo run -q --release --bin hl_encoding
TreeHash leaf  impl CBOR head = [a3, 65, 6e, 5f, 6d, 61, 78, 08] (map)
TreeHash leaf  spec CBOR head = [83, 08, 09, 59] (array)
TreeHash leaf  impl = b252c60f811090e1493546813197ee531127cae75f35f652313e79bc7877baa9
TreeHash leaf  spec = 6681e6e07c7f9efe845e2faa5aaf5ea8b81526f9e8a02a8f281b25a079ab2627
fs_dev_commit impl = 1f5f1f26620eb24bf290a8c906e3074a9ccda09523151fcb5f59b16172f35419
fs_dev_commit spec = dcbca653bf17bb45ad6f15f3e05f6e28251495aa519d4dc7b46d03cb00ead5ab

$ cargo run -q --release --bin header_keys
S4.2.1/S4.2.2 required keys MISSING from reference JOIN: [20, 96]
keys OUTSIDE the S4.2 closed-world registry (spec => reject 907.1): [154, 155, 156]

$ cargo run -q --release --bin mldsa_interop
pqcrypto dilithium5: pk=2592 sk=4896 sig=4627 | fips204 ml-dsa-87: pk=2592 sk=4896 sig=4627
fips204 ML-DSA-87 verifies a pqcrypto dilithium5 signature: false
pqcrypto dilithium5 verifies a fips204 ML-DSA-87 signature: false
```

Les valeurs de `E_k` changent à chaque exécution, puisque les signatures PoP sont aléatoires ; seule l'égalité auteur/serveur compte.

## Annexe B — Articulation avec les audits précédents

Les 51 constats des audits 1 à 7 portaient sur la cohérence textuelle de `docs/specs.md`, principalement l'autorité d'historique, la frontière FULL / recover-only et la reprise. Le présent audit ne les contredit pas un à un, mais il en modifie la portée :

- les constats « Reclassified » relatifs à une autorité fédérée (3.1, 3.2, 7.1) pèsent davantage qu'estimé, puisque l'autorité d'historique est opérée par le serveur, c'est-à-dire l'adversaire (H-01) ;
- la conclusion selon laquelle aucun constat ne reste ouvert est contredite par C-03, qui viole S11.12.1.F, et par H-06 et H-07, qui portent sur la conformité du code à la spec ;
- les constats 2.2 et 5.6 (liaison de `profile_version` dans `bind_fs`, registre fermé des suites de preuves) sont formellement clos, mais sans effet de sécurité, puisque les preuves qui portent ces liaisons ne prouvent rien (C-02).
