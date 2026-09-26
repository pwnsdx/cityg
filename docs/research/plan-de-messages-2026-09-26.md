# Le plan de messages des très grands groupes : techniques nouvelles pour City-G

| | |
| --- | --- |
| Date | 2026-09-26 |
| Nature | Note de recherche. Elle propose un plan de messages pour City-G, que le profil `city-g/v0.4` ne spécifie pas encore ([spécification](../specs.md), section 19). Rien de ce qu'elle décrit n'est dans la spécification ni dans le code : ce serait un profil suivant. |
| Question | Comment faire lire et écrire des millions de membres dans un groupe post-quantique sans que chaque lecteur paie, par jour, des mégaoctets de signatures et de paquets de re-key ? |
| Compagnons | [`msg_sim.py`](msg_sim.py) : modèle de coût (`python3 docs/research/msg_sim.py` redonne tous les chiffres de la section 4 en quelques secondes ; il réutilise [`rekey_sim.py`](rekey_sim.py)). [`formal-messages/`](formal-messages/README.md) : modèle ProVerif des mécanismes nouveaux (section 5). [`bench/`](bench/src/main.rs) : coût CPU de FN-DSA, de la dérivation d'une chaîne d'émetteur et de l'AEAD d'un message. |
| Auteur | Claude Code (assistant IA d'Anthropic), à la demande du mainteneur. Le modèle symbolique couvre les choix clés ; il n'existe aucune preuve calculatoire. Une relecture cryptographique humaine reste nécessaire. |

Vocabulaire :
- une *session* est une ouverture de l'application, pendant laquelle un client se met à jour et lit ;
- un *gardien* (keeper) est un membre qui a une feuille dans l'arbre de re-key : il suit chaque fenêtre, comme tout membre de la v0.4, et peut committer, sceller et servir des lots de clés ;
- un *lecteur* (reader) est un membre sans feuille dans l'arbre : il ne suit pas les fenêtres et reçoit, à chaque session, un *lot de clés* d'un gardien ;
- le *secret de lecteur* d'une époque est le secret que reçoivent les lecteurs, à la place du secret d'époque ; tout le plan de messages de l'époque en dérive ;
- l'*annuaire* (roster) associe à chaque appareil membre son rôle et sa *carte d'émetteur*, une clé de signature compacte réservée aux messages ;
- une *rafale* est une suite de messages d'un même émetteur, qu'une seule signature couvre ;
- une *enveloppe* garde le sens de la note [grands-groupes](grands-groupes-2026-09-25.md) : le secret d'un nœud chiffré vers un enfant (un *wrap* de la spécification). Le modèle de coût appelle *envelope* un message ;
- le *scelleur* (sealer) re-keye la ville et signe le *sceau* qui crée l'époque ;
- N est la taille du groupe, H = log2 N.

## 0. Résumé

1. **Ce que coûterait un plan de messages classique.** Il y en a un par défaut : chaque membre suit chaque fenêtre, et chaque message est signé avec la clé d'appareil ML-DSA-65 de son émetteur, comme dans MLS. Dans un groupe de 2^20 membres, un lecteur paierait alors :
   - 7,4 Mo par jour pour rester capable de lire, avant tout message ;
   - 3,5 Ko par message de 150 octets, dont 3,3 Ko de signature ;
   - 4,5 Ko pour apprendre la clé d'un émetteur.

   Le DS servirait 8 à 400 To par jour. Ce ne sont pas les messages qui coûtent : ce sont les signatures et le suivi du re-key.
2. **Six techniques, qui se composent :**
   - **Gardiens et lecteurs** (section 3.1). Seuls les gardiens sont dans l'arbre, soit quelques milliers d'appareils souvent en ligne. Les lecteurs reçoivent à chaque session un lot de clés, qui porte les secrets de lecteur des époques manquées :
     - le lot est scellé à une clé X-Wing à usage unique, signée par l'appareil du lecteur ;
     - chaque secret est vérifié contre un *tag de lecteur chaîné*, calculé avec une clé tirée du secret de l'époque précédente et porté par le sceau ; ni le DS seul ni le membre qui sert le lot ne peut donc imposer un secret, contrairement aux demandes de clés de Matrix.

     Retirer un lecteur ne demande aucun re-key : il n'a jamais tenu de secret dont les époques suivantes dérivent. Un lecteur dont l'état a fuité, sa clé d'appareil intacte, guérit à la session suivante, sans mise à jour.
   - **Cartes d'émetteur** (section 3.2). Les messages sont signés avec une clé compacte, inscrite dans l'annuaire et changée sans re-key : FN-DSA-512 aujourd'hui (666 octets). La clé d'appareil ML-DSA-65 reste l'identité. L'algorithme se choisit par carte, ce qui permet de suivre le troisième tour des signatures additionnelles du NIST.
   - **Chaînes de rafale** (section 3.3). Une signature couvre tous les messages d'une rafale, avec un retard d'authentification borné par T_AUTH. C'est la chaîne de hachés d'EMSS appliquée aux groupes.
   - **Messages engageants et signalement** (section 3.4). Un engagement de clé rend les signalements vérifiables (franking) : le signaleur ne peut pas accuser l'émetteur d'un contenu qu'il n'a pas envoyé.
   - **Journal scellé des messages** (section 3.5). Le sceau suivant fige la racine de Merkle des messages de l'époque, pour 40 octets par sceau. Deux membres d'accord sur le transcript sont d'accord sur les messages, ce qui répond aux attaques « Send and Pretend » (USENIX Security 2026). Le journal d'une époque close est immuable, donc servable par un CDN.
   - **Points de contrôle et témoins** (section 3.6). Ils bornent la bifurcation d'un lecteur à l'intervalle des points de contrôle (une heure).
3. **Chiffres** (modèle de coût, CPU mesuré ; section 4) :
   - **Par message :** 589 octets au lieu de 3 507 avec FN-DSA-512 et des rafales de 2 (×6,0). Avec une carte UOV, 304 octets (×11,5) : c'est le cas d'un canal de diffusion, où peu d'émetteurs écrivent à des millions de lecteurs.
   - **Rester à jour :** 231 Ko par jour au lieu de 7,4 Mo (×32), avec un lot et un point de contrôle par session et dix sessions par jour.
   - **Journée d'un lecteur :** ×24 pour 100 messages lus, ×5 pour 86 400. Le trafic du DS passe de 8,3 To à 345 Go par jour pour 2^20 lecteurs de 100 messages.
   - **Vague de 100 000 entrées et 100 000 départs :** avec 16 384 gardiens, 10 100 enveloppes au lieu de 648 420 (×64). Les changements de lecteurs ne coûtent que 40 octets d'enregistrement chacun.
   - **Gardiens :** chacun sert 640 lots par jour (0,3 s de CPU) quand 16 384 gardiens servent 2^20 lecteurs.
4. **Sécurité** (sections 5 et 6 ; 17 scénarios ProVerif, tous au verdict attendu) :
   - **Lots.** Leur secret et leur authenticité sont prouvés contre le DS. Sans vérification du tag, ou si le gardien ne vérifie pas la signature de la requête, le modèle trouve l'attaque.
   - **Retrait d'un lecteur.** Le lecteur retiré ne lit pas l'époque suivante, même sans re-key. Les variantes naïves sont attaquées : lecteurs qui tiennent la racine de l'arbre, ou secrets de lecteur en cliquet à la Megolm.
   - **Bifurcation.** Un membre de l'époque précédente peut faire accepter à un lecteur un faux secret, allié au DS ou en scellant lui-même la fenêtre. C'est la limite de n'importe quel membre de la v0.4 qui ne vérifie que des tags. Des lots signés et des sceaux confiés aux gardiens la réservent aux gardiens ; les points de contrôle la bornent.
   - **Chaînes et cartes.** La chaîne de rafale signée résiste à un initié, le MAC seul non. Une carte vérifiée contre l'annuaire de l'époque du message ne laisse pas parler un membre retiré, une carte gardée en cache si.
5. **Groupes publics, membres hostiles ou hors ligne** (section 3.8). Si chaque lot passait par un gardien, les gardiens seraient un point faible : ils peuvent être hors ligne, refuser de servir, épier qui lit, et, si le rôle était ouvert, être inscrits en masse. D'où quatre ajustements :
   - une *chaîne publique* : chaque sceau porte le secret de lecteur de l'époque chiffré sous celui de l'époque précédente. Un lecteur n'a alors besoin que du DS, sauf après une *rupture*, qu'un bannissement impose ;
   - après une rupture, n'importe quel membre en ligne sert le lot ;
   - n'importe quel membre, lecteur compris, peut sceller une fenêtre avec une init externe ;
   - dans un groupe public, les gardiens sont admis par un admin, et le DS leur confie les sceaux.

   Les lecteurs y gagnent sur la v0.4 : leurs entrées et départs ne coûtent aucune enveloppe. Il reste deux limites : le DS peut entrer et faire bifurquer un lecteur jusqu'au point de contrôle suivant, et un scelleur hostile peut empoisonner une époque pour les lecteurs.
6. **Ce qui reste à faire :**
   - le profil suivant (annuaire, secret, tag et lien de lecteur, ruptures, objets de lot, messages, journal) ;
   - l'implémentation et les tests ;
   - des preuves calculatoires du tag chaîné ;
   - le choix de l'algorithme des cartes quand FIPS 206 paraîtra, puis à la fin du troisième tour (section 8).

   Deux coûts sont à accepter :
   - les gardiens retiennent les secrets de lecteur pendant `RETENTION`, ce qui retarde la confidentialité persistante face à un gardien compromis ;
   - le membre qui sert un lot apprend quand un lecteur se connecte : à chaque session avec des lots, une fois par rupture avec la chaîne publique.

## 1. Ce que coûterait un plan de messages classique

La spécification laisse le plan de messages ouvert (section 19) : les membres de l'époque `n` partagent `msg_secret_n`, et les chaînes par émetteur doivent être dérivées à la demande. On obtient un portage direct en ajoutant ce que fait MLS :
- un arbre de secrets sur les feuilles, qui donne à chaque émetteur sa chaîne ;
- des messages chiffrés sous la clé de sa chaîne et signés avec sa clé d'appareil ;
- et chaque membre suit chaque fenêtre.

Pour un lecteur d'un groupe de 2^20 membres, le modèle de coût donne :

| Poste | Coût | D'où il vient |
| --- | --- | --- |
| Rester capable de lire | 7,4 Mo par jour à 1,7 changement par seconde (3,2 à 10,3 Mo entre 0,1 et 12) | un paquet par fenêtre, une fenêtre par minute (note grands-groupes, section 4.5) |
| Un message de 150 octets | 3 507 octets | 3 309 octets de signature ML-DSA-65 |
| Vérifier un message | 262 µs | vérification ML-DSA-65 mesurée (crate `fips204`) |
| La clé d'un émetteur, la première fois | 4,5 Ko | sa feuille (clé d'appareil de 1 952 octets et clé de feuille de 1 216 octets) et sa preuve de feuille, 64 octets par niveau |
| La même, à chaque session | 1,3 Ko par émetteur | un chemin frais : l'émetteur a pu être retiré depuis |

Trois observations guident la suite :
- **La signature domine.** Le texte pèse 150 octets. La signature en pèse 22 fois plus, et chaque lecteur la télécharge.
- **Le suivi domine pour ceux qui lisent peu.** La plupart des membres d'un grand groupe lisent sans écrire : c'est la règle 90-9-1 de la participation inégale ([Nielsen](https://www.nngroup.com/articles/participation-inequality/)). Pourtant, chacun paie les 7,4 Mo quotidiens de re-key, alors que ce re-key ne sert qu'à maintenir la clé de groupe.
- **Chaque membre de l'arbre coûte au re-key.** Une vague de 100 000 entrées et 100 000 départs coûte 648 420 enveloppes, 1,4 Go de commits (section 4.5). Or, dans un grand groupe, la plupart des membres qui entrent et sortent ne font que lire.

## 2. Ce que dit la recherche

### 2.1 Signatures post-quantiques compactes

- **FN-DSA (Falcon), FIPS 206.** Il donne des signatures de 666 octets (FN-DSA-512, niveau I) ou 1 280 octets (FN-DSA-1024, niveau V), pour des clés publiques de 897 et 1 793 octets. Le standard reste un projet en 2026, en revue finale, avec une publication attendue vers début 2027 ([DigiCert](https://www.digicert.com/blog/quantum-ready-fndsa-nears-draft-approval-from-nist), [NIST, présentation FIPS 206](https://csrc.nist.gov/csrc/media/presentations/2025/fips-206-fn-dsa-%28falcon%29/images-media/fips_206-perlner_2.1.pdf)). La signature repose sur un échantillonnage gaussien en virgule flottante, difficile à implémenter en temps constant ; la vérification n'a pas cette difficulté. Mesuré ici avec la crate `fn-dsa` : signature en 367 µs, vérification en 23 µs (FN-DSA-512).
- **Le troisième tour des signatures additionnelles du NIST** a été annoncé le 14 mai 2026 : FAEST, HAWK, MAYO, MQOM, QR-UOV, SDitH, SNOVA, SQIsign, UOV ([NIST](https://csrc.nist.gov/News/2026/nist-advances-9-candidates-to-the-3rd-round-of-pqc)). HAWK, une signature compacte sur réseaux euclidiens, a été retiré le 29 juillet 2026 : une réduction de la récupération de clé à un SVP en dimension n/2 + 1 fait passer HAWK-512 d'environ 2^150 à au plus 2^108 opérations ([The Qubit Report](https://thequbitreport.com/security-policy/2026/08/13/hawk-lattice-signature-scheme-withdrawn-from-nist-round-3-after-ai-assisted-key-recovery-attack/)). Leçon pour City-G : une signature compacte récente peut tomber, il faut pouvoir en changer sans refaire les identités.
- **Tailles des candidats** (niveau I sauf mention ; [zoo de PQShield](https://pqshield.github.io/nist-sigs-zoo/), [sqisign.org](https://sqisign.org/) pour la version 3.0 du 1er septembre 2026) :

  | Schéma | Signature | Clé publique | Vérification |
  | --- | ---: | ---: | ---: |
  | ML-DSA-65 (niveau III) | 3 309 | 1 952 | 35 µs optimisé ; 260 µs mesuré ici |
  | FN-DSA-512 | 666 | 897 | 20 µs ; 23 µs mesuré ici |
  | MAYO-2 | 239 | 2 928 | 11 µs |
  | SQIsign-I / III | 200 / 306 | 83 / 129 | 12,1 / 31,5 Mcycles (4 / 10,5 ms à 3 GHz) |
  | UOV-Is-pkc | 96 | 66 576 | 48 µs |

  Deux profils se dégagent :
  - des signatures minuscules avec des clés énormes (UOV), bonnes quand peu d'émetteurs écrivent à beaucoup de lecteurs ;
  - des clés et des signatures petites, mais une vérification lente (SQIsign), trop lente pour un gros lecteur sur téléphone aujourd'hui.

### 2.2 Authentifier un flux avec peu de signatures

TESLA et EMSS ([Perrig, Canetti, Tygar, Song, IEEE S&P 2000](https://people.eecs.berkeley.edu/~dawnsong/papers/tesla.pdf)) authentifient un flux multicast à peu de frais :
- **EMSS** chaîne les hachés des paquets et signe de temps en temps : une signature authentifie tout ce que la chaîne couvre ;
- **TESLA** retarde la divulgation de clés de MAC, ce qui suppose des horloges synchronisées.

City-G reprend le chaînage d'EMSS (section 3.3), pas les clés retardées de TESLA : un membre du groupe connaît déjà toutes les clés symétriques de l'époque.

### 2.3 Clients légers et membres inactifs

- **Light MLS et Partial MLS.** Les brouillons [`draft-kiefer-mls-light`](https://datatracker.ietf.org/doc/draft-kiefer-mls-light/) et [`draft-ietf-mls-partial`](https://datatracker.ietf.org/doc/draft-ietf-mls-partial/) définissent des clients qui ne tiennent pas l'arbre :
  - ils vérifient des preuves d'appartenance contre le haché de l'arbre, qu'ils partagent par le calendrier de clés ;
  - ils ne peuvent pas committer.

  Ils restent pourtant dans l'arbre et reçoivent chaque commit. Les lecteurs de la section 3.1 vont plus loin : ils sortent de l'arbre et sautent les époques.
- **Quarantined-TreeKEM** ([Chevalier, Lebrun, Martinelli, Plût, eprint 2023/1903](https://eprint.iacr.org/2023/1903)) traite les membres inactifs de MLS : leurs clés sont renouvelées par d'autres membres. Les lecteurs, eux, n'ont pas de clé dans l'arbre à renouveler.

### 2.4 Distribuer des clés à la demande

- **Matrix** laisse un appareil demander les clés de session Megolm qui lui manquent. L'analyse de [Albrecht, Celi, Dowling, Jones (Black Hat EU 2022)](https://i.blackhat.com/EU-22/Wednesday-Briefings/EU-22-Jones-Practically-exploitable-Cryptographic-Vulnerabilities-in-Matrix-wp.pdf) montre que rien ne prouvait qu'une clé transmise était légitime : des clients acceptaient des clés qu'ils n'avaient pas demandées, et un serveur pouvait injecter les siennes. Leçon pour City-G : un secret reçu d'un pair doit se vérifier contre quelque chose que le pair ne choisit pas.
- **Megolm** ([spécification](https://spec.matrix.org/unstable/olm-megolm/megolm/)) fait avancer chaque session en cliquet : qui tient l'état d'une session lit la suite jusqu'à ce que l'émetteur la remplace. Retirer un membre oblige chaque émetteur à renouveler sa session, ce qui coûte O(N) par émetteur.
- **La gestion de clés multicast** (GKMP, [RFC 2093](https://datatracker.ietf.org/doc/html/rfc2093)) confie la clé de groupe à un contrôleur qui la sert aux membres autorisés. City-G répartit ce rôle entre tous les gardiens, et le lecteur vérifie ce qu'il reçoit.

### 2.5 Cohérence du transcript

- **Send and Pretend.** [Gegenhuber et al., USENIX Security 2026](https://www.usenix.org/conference/usenixsecurity26/presentation/gegenhuber) ([arXiv 2607.27510](https://arxiv.org/abs/2607.27510)) montrent qu'un membre malveillant peut, dans les groupes de Threema, WhatsApp, Signal et iMessage, omettre, réordonner ou modifier ce que voient différents destinataires, sans avertissement. Il passe par des repliements du protocole ou par les canaux deux à deux qui livrent les messages de groupe. Poll truqué et évasion de modération en sont des exemples.
- **MINGLE.** [Fasllija, Heimberger, Paul, eprint 2026/1010](https://eprint.iacr.org/2026/1010) ajoute, avant chiffrement, un engagement compact de transparence des clés à une partie des messages ordinaires (119 octets). Les clients détectent ainsi un serveur qui leur montre des vues divergentes, en quelques minutes à grande échelle.

### 2.6 Signalement

- **Franking.** [Grubbs, Lu, Ristenpart, CRYPTO 2017](https://eprint.iacr.org/2017/664) formalisent le franking de Facebook : un chiffrement authentifié *engageant*, dont une petite partie engage le contenu. [Dodis, Grubbs, Ristenpart, Woodage, CRYPTO 2018](https://eprint.iacr.org/2019/016) montrent qu'un AEAD non engageant comme ChaCha20-Poly1305 laisse fabriquer un chiffré qui se déchiffre en deux contenus sous deux clés (les « invisible salamanders »).
- **Franking de transcript.** Le [franking de transcript](https://link.springer.com/chapter/10.1007/978-981-95-5096-8_1) permet de signaler un extrait de conversation en prouvant l'ordre des messages.
- **MIMI.** Le brouillon [MIMI](https://datatracker.ietf.org/doc/draft-ietf-mimi-protocol/03/) prévoit du franking au-dessus de MLS.

### 2.7 Agréger des signatures

- **LaBRADOR.** [Aardal, Aranha, Boudgoust, Kolby, Takahashi, CRYPTO 2024](https://eprint.iacr.org/2024/311) agrègent des signatures Falcon avec LaBRADOR. Selon une [synthèse de 2026](https://hackmd.io/@goatresearch/H1G2tOCwGx), 10 000 signatures Falcon-512 tiennent en environ 74 Ko, vérifiés en 2,65 s, une vérification qui se parallélise mal.
- **Signatures à base de hachage.** [Drake, Khovratovich, Kudinov, Wagner, eprint 2025/055](https://eprint.iacr.org/2025/055) agrègent des signatures XMSS avec des SNARK (leanMultisig), pour des preuves de 128 à 377 Kio (même synthèse).

C'est encore de la recherche, mais c'est ce qui rendrait vérifiable un long historique (section 3.7).

### 2.8 Cliquets post-quantiques

Le [Sparse Post-Quantum Ratchet de Signal](https://signal.org/blog/spqr/) ajoute ML-KEM au Double Ratchet en découpant les gros objets post-quantiques en morceaux, envoyés avec les messages ordinaires. L'idée est la même qu'ici : un objet post-quantique de plusieurs kilooctets n'est acceptable qu'amorti sur de nombreux messages.

## 3. Les techniques proposées

### 3.1 Gardiens et lecteurs

**Idée.** Séparer *tenir la clé de groupe* de *lire le groupe* :
- seuls les gardiens sont dans l'arbre de re-key, qui reste celui de la v0.4 (quartiers, ville, taches, fenêtres) ;
- les lecteurs sont dans l'annuaire (section 3.2), pas dans l'arbre.

Un membre choisit son rôle et en change par une requête signée. Un appareil souvent en ligne et sur un réseau illimité devient gardien, un téléphone reste lecteur. Une politique de groupe peut exiger que les admins soient gardiens.

**Calendrier de clés.** Le calendrier de la v0.4 (section 9) gagne un secret, entre le secret d'époque et le plan de messages :

```text
reader_secret_n := DeriveSecret(epoch_secret_n, "reader")
msg_secret_n    := DeriveSecret(reader_secret_n, "msg")         (au lieu de DeriveSecret(epoch_secret_n, "msg"))
reader_tag_n    := MAC(DeriveSecret(reader_secret_n-1, "reader next"),
                       [confirmed_transcript_hash_n, H(reader_secret_n)])
```

Un lecteur ne tient jamais `epoch_secret`, `init`, `joiner_secret`, `external_secret` ni aucun secret de l'arbre. Tout ce qui fait les époques suivantes lui échappe donc.

**Le tag de lecteur chaîné.** Le scelleur le calcule et le met dans le sceau. La signature du sceau le couvre, comme le tag de confirmation (`[seal_hash, confirmation_tag, reader_tag, external_pk]`), et le haché intérimaire aussi :

```text
interim_transcript_hash_n := H_L("interim-transcript", [confirmed_transcript_hash_n, confirmation_tag_n, reader_tag_n])
```

Chaque gardien qui suit la fenêtre le vérifie comme le tag de confirmation, et un tag faux fait rejeter la fenêtre : il n'y a qu'un tag par époque. Il prouve que le secret de lecteur de l'époque `n` est celui qu'a engagé quelqu'un qui connaissait celui de l'époque `n - 1`, donc un membre de l'époque `n - 1`. Le DS seul ne le peut pas. Le gardien qui sert un lot non plus, puisque le tag vient du sceau et non de lui ; le scelleur, lui, le peut (section 3.8). C'est la garantie que le tag de confirmation donne aux membres de la v0.4, et qui repose sur `init_n-1`.

Une fenêtre scellée par un entrant (kind 2) n'a pas de tag chaîné, car l'entrant ne connaît pas `reader_secret_n-1`. Le lecteur vérifie alors la preuve d'entrant (section 13.2 de la spécification : admission et signature du sceau), comme les gardiens. Ces fenêtres n'ont lieu que sans gardien en ligne.

**Requête et lot.**

```text
BundleRequest := ["city-g/bundle-request/v5", gid, reader, from_epoch, known_interim,
                  one_time_pk, signature]                            (clé d'appareil du lecteur)
Bundle        := ["city-g/bundle/v5", gid, request_ref, kem_output,
                  AEAD(k, [[n, reader_secret_n] for n in from_epoch..to_epoch], ad = request_ref)]
(kem_output, k) := X-Wing.Encaps(one_time_pk)
```

Le gardien sert une requête ainsi :
1. il vérifie la signature et que le lecteur est dans l'annuaire de l'époque courante ;
2. il vérifie que `from_epoch` n'est pas avant l'entrée du lecteur (secret des entrants, sauf politique d'historique, section 3.7) ;
3. il vérifie que `known_interim` est bien le haché intérimaire de l'époque `from_epoch - 1` sur sa propre chaîne. S'il diffère, le lecteur est sur une autre branche, et le gardien le lui dit.

Le DS sert la partie publique, par époque : le haché du sceau, le tag de confirmation et le tag de lecteur, soit 96 octets. Le lecteur fait ensuite, de proche en proche :
- `confirmed_n = H_L("confirmed-transcript", [interim_n-1, seal_hash_n])` ;
- la vérification de `reader_tag_n` avec le secret de l'époque `n - 1` et celui de l'époque `n` ;
- `interim_n = H_L("interim-transcript", [confirmed_n, confirmation_tag_n, reader_tag_n])`.

Un secret faux ou une époque inventée par le DS échoue au premier tag. Le lot coûte 1,2 Ko, plus 128 octets par époque, dont 32 de secret.

**Entrée d'un lecteur.** Un lecteur qui entre n'a pas de secret de l'époque précédente. Il s'ancre comme un entrant de la v0.4 : sur un point de contrôle d'admin, puis par la chaîne des sceaux (section 12.9). Son premier lot est signé par un gardien de l'époque d'entrée, dont la clé est vérifiée par une preuve de feuille contre le haché de l'arbre de cette époque, que la chaîne des sceaux authentifie. Un entrant de la v0.4 fait de même avec le tag de confirmation signé du sceau (`anchored_join.pv`).

**Lecteur en ligne.** Tant qu'une session dure, son gardien lui pousse le secret de chaque nouvelle époque sous une clé de session tirée du lot, avec un cliquet de hachage par époque. Cela coûte environ 144 octets par époque, au lieu d'un paquet de plusieurs kilooctets.

**Ce que l'on gagne :**
- **Retrait sans re-key.** Un lecteur retiré garde les secrets de lecteur des époques où il était membre, et rien d'autre. `reader_secret_n` dérive de `epoch_secret_n`, qui dérive de `init_n-1` et de la racine de l'arbre, deux secrets qu'il n'a jamais eus. Même une fenêtre qui ne re-keye rien garde l'époque suivante secrète pour lui (modèle `reader_removed.pv`). Les gardiens refusent ses requêtes dès la fenêtre qui applique le retrait. Une vague de départs de lecteurs coûte 40 octets d'enregistrement par départ, sans aucune enveloppe.
- **Guérison sans mise à jour.** Un lecteur dont l'état a fuité (A5, clé d'appareil intacte) guérit dès la première époque dont le secret n'était pas dans l'état volé. Le lot suivant est scellé à une clé à usage unique neuve, signée par la clé d'appareil que l'attaquant n'a pas.
- **Suivi en O(1) par session**, au lieu d'un paquet par fenêtre.
- **Arbre réduit.** Il ne compte que les gardiens : ×64 d'enveloppes en moins avec 16 384 gardiens pour 2^20 membres (section 4.5).

**Ce que l'on paie :**
- **Rétention.** Les gardiens retiennent les secrets de lecteur pendant `RETENTION` (7 jours proposés) pour servir les lecteurs absents. La confidentialité persistante face à un gardien compromis ne vaut qu'au-delà. Un déploiement peut réserver la rétention à quelques gardiens.
- **Présence.** Un gardien apprend quand un lecteur demande un lot. Il doit vérifier la signature lui-même : un DS qui vérifierait à sa place pourrait demander un lot avec sa propre clé (modèle `reader_bundle_unsigned_request.pv`).
- **Disponibilité.** Sans gardien en ligne, un lecteur ne reçoit plus de lot et personne ne scelle. La section 3.8 lève cette dépendance : chaîne publique, lots servis et sceaux posés par n'importe quel membre.
- **Bifurcation.** Un membre de l'époque précédente, allié au DS ou scelleur de la fenêtre, peut faire accepter à un lecteur un faux secret (sections 3.6 et 3.8).

### 3.2 Cartes d'émetteur et annuaire

**Idée.** La clé d'appareil (ML-DSA-65, 1 952 octets, signatures de 3 309 octets, idéalement dans un coffre matériel) reste l'identité :
- elle signe les requêtes, les commits et les sceaux ;
- elle certifie une *carte d'émetteur*, une clé compacte qui ne signe que des messages.

**L'annuaire.** C'est une carte de Merkle creuse, comme les deux cartes du registre de la v0.4 (section 8). Elle associe à chaque appareil membre :
- son rôle (gardien ou lecteur) ;
- son époque d'entrée ;
- sa carte, avec un identifiant d'algorithme ;
- l'époque de la carte ;
- le haché de son admission.

Sa racine entre dans le registre, donc dans `GroupContext`. Une preuve d'appartenance coûte environ 32 octets par niveau occupé, soit 640 octets pour 2^20 membres. Créer ou changer une carte passe par une requête signée par la clé d'appareil, vérifiée par le DS, par le scelleur (structure) et par les audits par échantillonnage (section 15), comme toute entrée. Cela ne demande aucun re-key.

**Vérifier une carte.** Un lecteur vérifie la carte d'un émetteur contre l'annuaire de l'époque du message, pas contre un cache. Sans cela, un membre retiré qui garde sa clé de carte continue de parler avec l'aide d'un initié (modèles `card_revalidated.pv` et `card_cached.pv`). En pratique :
- la carte elle-même (987 octets pour FN-DSA-512) se garde en cache ;
- à chaque session, le lecteur vérifie contre la dernière racine le chemin de chaque émetteur qu'il lit, en une preuve groupée ;
- l'occupation est continue depuis l'époque d'entrée : un chemin frais couvre donc tous les messages de l'émetteur depuis son entrée et depuis l'époque de sa carte.

**Choisir l'algorithme par carte.** FN-DSA-512 par défaut quand FIPS 206 paraîtra. Un émetteur de canal de diffusion, qui écrit à des millions de lecteurs, peut préférer UOV : 96 octets par signature, contre une clé de 66 Ko apprise une fois par lecteur. Les candidats du troisième tour s'ajouteront à sa fin. Si un algorithme tombe, comme HAWK, une requête signée par la clé d'appareil remplace la carte, sans ré-entrée.

**Rotation.** Si la clé de carte n'est pas dans un coffre, un état d'appareil compromis (A5) la donne, et l'attaquant signe des messages comme le membre jusqu'à la rotation. C'est un recul sur un plan de messages signé par la clé d'appareil. On propose donc une rotation à chaque mise à jour et au moins quotidienne. Une rotation ne coûte qu'un enregistrement de l'annuaire, même à 12 rotations par seconde pour 2^20 membres.

### 3.3 Chaînes de rafale

**Idée.** Un émetteur signe au plus une fois par rafale ; les messages non signés d'une rafale sont couverts par la signature suivante (EMSS) :

```text
chain_g     := H_L("msg-chain", [chain_g-1, H(message_g sans signature)])     (chain_-1 := ZERO32 à chaque époque)
signature_g := Card.Sign([gid, epoch, sender, first_generation, chain_g])
```

**Règles :**
- un émetteur dont la dernière signature a plus de `T_BURST` (2 s proposées) signe tout de suite : un message isolé est signé ;
- sinon il envoie non signé, et signe au plus `T_AUTH` (5 s proposées) après le premier message non signé. La signature part avec son message suivant, ou seule dans un message de clôture ;
- un lecteur montre un message non signé comme « en attente d'authentification », ou le retient au plus `T_AUTH` et un délai de livraison. Sans signature à temps, il l'écarte et le signale.

**Sécurité.** Avant sa signature, un message n'est authentifié que par la clé de groupe : il pourrait venir de n'importe quel membre. Après, il est authentifié par la carte de l'émetteur. Un initié peut fabriquer un message non signé, mais aucune signature ne le couvrira (modèle `burst_chain.pv`). Si la chaîne était authentifiée par un MAC sous une clé de l'époque, tout membre parlerait comme l'émetteur (`burst_chain_mac_only.pv`).

**Gain.** Une signature pour b messages. Une conversation vive a des rafales de 2 à 4 messages, un robot ou un canal de diffusion bien plus.

### 3.4 Messages engageants et signalement

```text
Message    := [epoch, sender, generation, ciphertext, commitment, signature or null]
ciphertext := ChaCha20-Poly1305(key_g, nonce_g, content, ad = [gid, epoch, sender, generation])
commitment := H_L("msg-commit", [key_g, nonce_g, H(ciphertext)])
```

`key_g` et `nonce_g` viennent de la chaîne de l'émetteur, dérivée à la demande de `msg_secret_n` par un arbre de secrets sur les positions de l'annuaire, comme dans MLS. Cela coûte 8,1 µs mesurés pour 2^24 positions. L'arbre efface ses nœuds à mesure que les chaînes sont dérivées : un message lu reste protégé contre une compromission ultérieure dans l'époque, ce qu'une dérivation directe par émetteur ne donne pas.

**L'émetteur est visible du DS.** Le DS le sait déjà par la connexion : City-G ne promet pas de confidentialité des métadonnées. Le DS peut ainsi rejeter, avant de le diffuser à des millions de lecteurs, un message que ne couvre pas la carte d'un membre courant. Un déploiement sur un transport anonyme peut chiffrer l'émetteur comme MLS (sender data), au prix de ce filtrage.

**Signalement.** Le signaleur révèle `key_g` et `nonce_g`. Le modérateur (le DS ou un admin) vérifie :
- l'engagement, et que le chiffré se déchiffre en ce contenu ;
- la chaîne et la signature de la carte ;
- la carte contre l'annuaire de l'époque ;
- l'inclusion du message dans le journal scellé (section 3.5).

Avec l'engagement, le signaleur ne peut pas faire endosser à l'émetteur un contenu qu'il n'a pas envoyé (les « invisible salamanders »), et révéler `key_g` ne révèle aucun autre message. Il n'y a pas de déni plausible, comme dans MLS : les messages sont signés.

### 3.5 Journal scellé des messages

**Idée.** Le DS numérote les messages de l'époque `n` dans leur ordre d'arrivée, jusqu'au sceau de la fenêtre suivante. Ce sceau porte alors `log_n = [count, root]`, 40 octets, où `root` est la racine de Merkle des hachés des messages. `log_n` entre dans `seal_hash_n+1`, donc dans le transcript de tous les membres.

**Ce que cela donne :**
- **Cohérence globale du transcript, par époque.** Deux membres qui acceptent l'époque `n + 1` avec le même haché intérimaire sont d'accord sur l'ensemble et l'ordre des messages de l'époque `n`. Il n'y a pas de canaux deux à deux : chaque message passe par le journal, et un émetteur ne peut pas donner deux versions d'une même génération à deux lecteurs. Un DS qui montre des messages différents à deux membres leur montre deux transcripts, donc une bifurcation, que les points de contrôle révèlent. C'est la réponse de City-G à Send and Pretend.
- **Livraison vérifiable.** Un émetteur vérifie que ses messages sont dans le journal, avec une preuve d'inclusion de 448 octets parmi 10 000 messages. Un message écarté se voit.
- **CDN.** Le journal d'une époque close est immuable et chiffré. Des caches peuvent le servir sans rien apprendre, et le trafic sortant du DS ne croît plus avec le nombre de lecteurs pour l'historique.
- **Retard.** Un message de l'époque `n` arrivé après le sceau de `n + 1` est refusé ; l'émetteur le rechiffre dans la nouvelle époque.

Un lecteur qui lit une époque entière recalcule la racine lui-même, sans preuve.

### 3.6 Points de contrôle et témoins

**Le risque.** Un lecteur qui ne vérifie que des tags chaînés peut être mené sur une branche. Il suffit d'un membre de l'époque précédente, qui connaît le secret de lecteur, et du DS ; ou que ce membre scelle lui-même la fenêtre (section 3.8). Le membre choisit un faux secret, calcule le tag chaîné et le scelle à la clé à usage unique du lecteur (trace de `reader_removed.pv`). C'est la même limite que la v0.4 pour les membres qui ne vérifient que le tag de confirmation (spécification, section 2.3). Mais comme les lecteurs sont nombreux, beaucoup d'anciens membres ont cette possibilité.

**Trois parades :**
- **Points de contrôle.** À chaque session, le lecteur vérifie le dernier point de contrôle signé par un admin, qui porte l'époque et le haché intérimaire (3,5 Ko ; `CHECKPOINT_INTERVAL` = 1 heure). Une bifurcation se découvre au plus un intervalle plus tard, et un DS qui retient les points de contrôle se voit à leur âge.
- **Lots signés.** Le gardien signe le lot. Sa clé est vérifiée par une preuve de feuille contre le haché de l'arbre à l'époque d'ancrage du lecteur, et le lecteur a vérifié l'en-tête de ce sceau. Il faut alors un gardien pour faire bifurquer un lecteur (`reader_removed_signed_bundle.pv`). Cela coûte environ 7,4 Ko de plus par session. C'est recommandé pour un groupe fermé sensible.
- **Témoins dans les autres conversations.** À la manière de MINGLE, un client glisse, dans ses conversations deux à deux, le dernier haché intérimaire des groupes qu'il partage avec son correspondant. Une vue divergente se détecte alors hors du canal que le DS contrôle.

### 3.7 Historique

**Qui peut lire le passé.** Par défaut, un entrant ne lit rien d'avant son entrée (secret des entrants). Une politique d'historique signée par un admin, visible comme l'ouverture d'un groupe, fixe ce que les gardiens servent d'antérieur à l'entrée : rien (par défaut), l'historique depuis l'invitation, ou les `RETENTION` derniers jours. Le choix est explicite et vérifiable, jamais implicite.

**Vérifier un long historique.** Cela veut dire vérifier des milliers de signatures : 6,7 Mo pour 10 000 signatures FN-DSA-512. Une agrégation LaBRADOR les ramènerait à environ 74 Ko, qu'un gardien archiviste produirait par époque. La preuve reste lente à produire et à vérifier : c'est une piste, pas une proposition.

### 3.8 Groupes publics : membres hostiles ou hors ligne

Dans un groupe public (un groupe ouvert, décision E-14), n'importe quel appareil entre sans admission, celui du DS compris : il n'y a pas de confidentialité face à qui entre. Ce qu'un tel groupe garde :
- personne ne parle pour un autre ;
- les entrées restent visibles ;
- les retraits et les bannissements gardent leurs règles ;
- les époques d'avant une entrée restent fermées à l'entrant.

Chaque membre peut y être hostile, et l'activité varie : la nuit, il se peut que personne ne réponde. Les gardiens de la section 3.1 y posent six problèmes :

| Problème | Détail |
| --- | --- |
| Vivacité | Un lecteur dépend d'un gardien en ligne pour chaque lot. La v0.4 ne demande qu'un DS. |
| Gardiens hostiles | Le gardien qui sert un lot ne peut ni imposer un faux secret (le tag vient du sceau) ni parler pour un autre (cartes). Mais il peut refuser de servir, et il apprend quand le lecteur se connecte. |
| Sybil | Si le rôle est ouvert, un attaquant inscrit des milliers de gardiens. L'arbre regrossit, et leurs entrées et départs forcent des re-keys. |
| Scelleur hostile | Le scelleur calcule le tag (ou le lien, ci-dessous) avec le secret de lecteur de l'époque précédente, qu'il connaît. Il peut donc faire accepter aux lecteurs un secret de son choix. Les gardiens, qui dérivent le vrai, rejettent la fenêtre, et lecteurs et gardiens se séparent. C'est la forme « lecteurs » d'un problème ouvert de la v0.4 : un committer hostile y coupe déjà des membres (spécification, section 19). |
| Bifurcations | Le DS peut entrer, donc être membre de l'époque précédente, voire gardien. Il fait alors bifurquer un lecteur seul, lot signé ou non. Il le peut déjà face aux membres de la v0.4 dans un groupe ouvert. |
| Fenêtres d'entrant | Quand aucun gardien n'est en ligne, les entrants scellent eux-mêmes. Ces fenêtres n'ont pas de tag chaîné : le lecteur doit vérifier la preuve d'entrant, environ 10 Ko. Dans un groupe ouvert, elle ne prouve que l'entrée d'un nouvel appareil. |

**Les parades :**

1. **Chaîne publique des secrets de lecteur.** Le sceau porte, au lieu du tag chaîné, un *lien* :

   ```text
   reader_link_n := AEAD(DeriveSecret(reader_secret_n-1, "reader link"), reader_secret_n,
                         ad = confirmed_transcript_hash_n)                      (48 octets)
   ```

   Comme le tag, le lien est couvert par la signature du sceau et le haché intérimaire, et chaque gardien le vérifie. Un lecteur qui tient le secret de l'époque `n - 1` ouvre le lien et obtient celui de l'époque `n`, authentifié par une clé que seuls les membres de l'époque `n - 1` connaissent : c'est la garantie du tag chaîné (`reader_link.pv`). Entre deux ruptures, le lecteur ne dépend de personne d'autre que du DS, et aucun membre n'apprend quand il lit.
2. **Ruptures.** Un lien donne l'époque `n` à tous les membres de l'époque `n - 1`, y compris ceux que la fenêtre retire (`reader_link_no_break.pv`). Le scelleur l'omet donc quand la politique veut couper la lecture : c'est une *rupture*. Le sceau porte alors le tag chaîné, et les lecteurs demandent un lot pour cette seule époque. Après elle, les liens reprennent, et un lecteur banni ne les ouvre plus (`reader_link_ban.pv`).
   - Dans un groupe fermé, toute fenêtre qui retire un membre rompt la chaîne : c'est le schéma de la section 3.1.
   - Dans un groupe public, les départs volontaires ne la rompent pas : qui part peut revenir, visiblement. Les bannissements la rompent, regroupés à `BREAK_INTERVAL` (un jour proposé), ou tout de suite si un admin le demande. Un banni ne peut plus écrire dès la fenêtre qui le bannit : sa carte sort de l'annuaire.
   - Une rupture périodique sert aussi de guérison (PCS) : un état de lecteur volé ne suit la chaîne que jusqu'à la rupture suivante.
3. **Tout membre sert un lot.** Le tag du sceau vérifie le secret ; l'identité du serveur ne compte pas (`bundle_any_member.pv`). Après une rupture, n'importe quel membre en ligne qui en tient le secret le sert, lecteurs compris. Un serveur n'apprend une session qu'à chaque rupture. Dans un groupe dont la politique d'historique ouvre déjà le passé aux entrants, le DS peut même relayer les requêtes sans l'identité du lecteur : on n'y perd, face au DS, que la visibilité des lecteurs.
4. **Tout membre scelle.** Tout membre de l'époque `n - 1`, lecteur compris, peut sceller une fenêtre :
   - il prend une *init externe* à la place de `init_n-1` : un secret frais scellé à la clé externe de l'époque `n - 1`, que seuls les gardiens tiennent ;
   - il tire une nouvelle racine, et re-keye depuis l'état public les chemins des gardiens que la fenêtre retire ;
   - il signe, et les gardiens vérifient qu'il était dans l'annuaire de l'époque `n - 1`, comme pour une ré-entrée (`reader_seal.pv`). Sans cette vérification, le DS scelle à sa place (`reader_seal_unchecked.pv`).

   Il connaît le secret de lecteur de l'époque `n - 1` : il produit le lien ou le tag. Ce qu'il tire le tache, comme un committer. Les fenêtres d'entrant ne servent plus que dans un groupe où personne n'est en ligne.
5. **Gardiens sur admission, et scelleurs gardiens par défaut.** La politique d'un groupe public ouvre la lecture à tous et réserve la garde aux appareils qu'un admin admet : pas de Sybil dans l'arbre.
   - Les gardiens deviennent l'ossature durable du groupe : ils reçoivent les secrets frais par l'arbre, même hors ligne, et gardent l'époque en vie quand son scelleur disparaît. Ils ne sont plus un passage obligé.
   - Le DS confie les sceaux aux gardiens, et à un autre membre seulement quand aucun gardien n'est en ligne.
   - Un lecteur peut tenir pour provisoire une époque scellée par un non-gardien jusqu'à ce qu'un gardien scelle par-dessus. Il le vérifie par la signature de ce sceau, environ 6 Ko.
   - Un scelleur hostile garde alors le pouvoir de séparer les lecteurs des gardiens pour une fenêtre. Il est identifié par sa signature, et ses victimes le voient : elles n'ouvrent plus les messages des gardiens.
6. **Bifurcations.** Elles restent bornées par les points de contrôle des admins et par les témoins (section 3.6). Si les admins restent longtemps hors ligne, il ne reste que les témoins.

**Ce que l'on gagne sur la v0.4.** Dans un groupe ouvert de la v0.4, tout membre est dans l'arbre :
- un attaquant qui fait entrer et sortir des milliers d'appareils force des re-keys de tout le groupe ;
- tout membre peut être désigné committer, et couper d'autres membres avec des enveloppes illisibles.

Ici, les lecteurs entrent et sortent sans aucune enveloppe. Un lecteur ne scelle que faute de gardien, et ne commite que ce que sa fenêtre demande.

**Ce qui reste :**
- dans un groupe ouvert, le DS peut entrer et faire bifurquer un lecteur, jusqu'au point de contrôle suivant ;
- un scelleur hostile peut empoisonner une époque pour les lecteurs, sans pouvoir parler pour un autre ;
- un banni lit jusqu'à la rupture suivante ;
- une fenêtre scellée par un entrant, quand personne n'est en ligne, reste le cas faible.

Le coût ne bouge presque pas : 112 octets par époque, soit 198 Ko par jour avec une rupture par jour, contre 231 Ko avec un lot à chaque session (section 4.3). Ce qui change, c'est qu'un lecteur n'a besoin d'un membre en ligne qu'une fois par rupture. Avec une rupture par jour, 10 % des membres en ligne servent chacun une dizaine de lots par jour (section 4.6).

### 3.9 Pistes écartées

| Piste | Pourquoi |
| --- | --- |
| Donner aux lecteurs la racine de l'arbre, ou le secret d'époque avec elle, pour qu'ils dérivent les époques eux-mêmes | Un retrait sans re-key laisse alors le lecteur retiré lire la suite (`reader_removed_with_root.pv`). |
| Faire avancer les secrets de lecteur en cliquet, sans secret frais ni rupture, à la Megolm | Même attaque (`reader_removed_ratchet.pv`). La chaîne publique de la section 3.8, elle, porte des secrets frais de l'arbre et se rompt quand il faut couper un membre. |
| Clés d'émetteur distribuées deux à deux (sender keys) | O(N) par émetteur et par rotation, et un retrait fait tourner toutes les clés. |
| Accepter un lot sans le vérifier, comme les premières demandes de clés de Matrix | Le DS injecte le secret de son choix (`reader_bundle_no_tag.pv`). |
| Signer chaque message avec la clé d'appareil | C'est le portage direct de la section 1 : 3,3 Ko par message. |
| SQIsign pour les cartes, aujourd'hui | 4 à 10,5 ms par vérification. Un gros lecteur de 86 400 messages par jour y passerait 3 à 8 minutes de CPU, même avec des rafales de 2. À revoir si les implémentations accélèrent. |

## 4. Chiffres

Sauf mention, `python3 docs/research/msg_sim.py` :
- groupe de 2^20 membres, quartiers de 2^12 ;
- une fenêtre par minute, 1,7 changement par seconde (une mise à jour hebdomadaire par membre) ;
- dix sessions par jour, textes de 150 octets.

« Aujourd'hui » désigne le portage direct de la section 1.

CPU mesuré par [`bench/`](bench/src/main.rs), sur un cœur, lors d'une exécution ; les temps varient de quelques pour cent d'une exécution à l'autre :

| Opération | Temps |
| --- | ---: |
| FN-DSA-512 : signature / vérification | 367 µs / 23 µs |
| FN-DSA-1024 : signature / vérification | 697 µs / 42 µs |
| ML-DSA-65 : signature / vérification (crate `fips204`) | 1 027 µs / 260 µs |
| Chaîne d'un émetteur dans un arbre de secrets de 2^24 positions | 8,1 µs |
| ChaCha20-Poly1305 sur 150 octets | 1,9 µs |
| BLAKE3 d'un message de 300 octets | 0,3 µs |
| X-Wing : encapsulation / décapsulation | 214 µs / 388 µs |

L'écart de CPU entre ML-DSA-65 et FN-DSA dépend beaucoup des implémentations : 260 µs contre 23 µs ici, mais 35 µs contre 20 µs pour des implémentations optimisées (zoo de PQShield). Le gain en octets, lui, n'en dépend pas.

### 4.1 Par message

Octets téléchargés par message lu. Une rafale de b porte une signature pour b messages, dans un message de clôture ; chaque message porte un engagement de 32 octets.

| Schéma | Statut | Signature | Rafale 1 | Rafale 2 | Rafale 4 | Gain, rafale 2 | Vérification, rafale 2 |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Aujourd'hui : ML-DSA-65 à chaque message | FIPS 204 | 3 309 | 3 507 | | | ×1,0 | 262 µs |
| ML-DSA-65 | FIPS 204 | 3 309 | 3 543 | 1 910 | 1 070 | ×1,8 | 132 µs |
| FN-DSA-512 | FIPS 206 (projet) | 666 | 900 | 589 | 410 | ×6,0 | 13 µs |
| FN-DSA-1024 | FIPS 206 (projet) | 1 280 | 1 514 | 896 | 563 | ×3,9 | 23 µs |
| MAYO-2 | 3e tour | 239 | 473 | 376 | 303 | ×9,3 | 8 µs |
| SQIsign-I | 3e tour | 200 | 434 | 356 | 293 | ×9,9 | 2,0 ms |
| SQIsign-III | 3e tour | 306 | 540 | 409 | 320 | ×8,6 | 5,3 ms |
| UOV-Is-pkc | 3e tour | 96 | 330 | 304 | 267 | ×11,5 | 26 µs |

Les chaînes de rafale seules divisent le coût d'ML-DSA-65 par 1,8 à 3,3. Les cartes FN-DSA-512 seules le divisent par 3,9. Les deux ensemble le divisent par 6,0, et par 8,6 avec des rafales de 4.

### 4.2 La clé d'un émetteur

| | Première fois | Chaque session, 1 émetteur | 20 émetteurs | 200 émetteurs |
| --- | ---: | ---: | ---: | ---: |
| Aujourd'hui : clé d'appareil et clé de feuille, preuve dans l'arbre | 4,5 Ko | 1,3 Ko | 20,5 Ko | 166 Ko |
| Carte FN-DSA-512, preuve dans l'annuaire | 1,6 Ko | 640 o | 10,2 Ko | 83 Ko |
| Carte FN-DSA-1024 | 2,5 Ko | 640 o | 10,2 Ko | 83 Ko |
| Carte SQIsign-III | 859 o | 640 o | 10,2 Ko | 83 Ko |
| Carte UOV-Is-pkc | 67,3 Ko | 640 o | 10,2 Ko | 83 Ko |

Pour k émetteurs, la preuve groupée vaut à peu près k·(H − log2 k) niveaux.

### 4.3 Rester capable de lire

Par lecteur et par jour :

| | Volume |
| --- | ---: |
| Suivre chaque fenêtre, 0,1 changement par seconde | 3,2 Mo |
| Suivre chaque fenêtre, 1,7 changement par seconde | 7,4 Mo |
| Suivre chaque fenêtre, 12 changements par seconde | 10,3 Mo |
| Lots et points de contrôle, 1 session par jour | 189 Ko |
| Lots et points de contrôle, 10 sessions par jour | 231 Ko |
| Lots et points de contrôle, 48 sessions par jour | 410 Ko |
| Chaîne publique, une rupture par jour, 10 sessions | 198 Ko |
| Chaîne publique, une rupture par heure, 10 sessions | 209 Ko |

Un lot pèse 1,2 Ko, plus 128 octets par époque ; un point de contrôle, 3,5 Ko ; la chaîne publique, 112 octets par époque. Le coût ne dépend presque plus du rythme des changements : c'est le nombre d'époques qui compte, pas leur contenu. La chaîne publique coûte à peu près autant que les lots ; elle change la dépendance, pas le volume.

### 4.4 La journée d'un lecteur

Dix sessions. Un émetteur pour cinq messages lus, tous nouveaux chaque jour, ce qui est pessimiste. Lecteurs : cartes FN-DSA-512, rafales de 2, un lot et un point de contrôle par session. Le trafic du DS est donné pour 2^20 lecteurs, sans cache.

| Messages lus | Émetteurs | Aujourd'hui | Lecteurs | Gain | CPU aujourd'hui | CPU lecteurs | DS aujourd'hui | DS lecteurs |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | 21 | 7,9 Mo | 329 Ko | ×24 | 26 ms | 5 ms | 8,3 To | 345 Go |
| 1 000 | 201 | 11,8 Mo | 1,1 Mo | ×10 | 0,26 s | 17 ms | 12,4 To | 1,2 To |
| 10 000 | 2 001 | 50,6 Mo | 8,9 Mo | ×6 | 2,6 s | 0,14 s | 53 To | 9,4 To |
| 86 400 | 17 281 | 377 Mo | 73,7 Mo | ×5 | 22,6 s | 1,2 s | 396 To | 77 To |

Pour qui lit peu, le gain vient surtout de la fin du suivi des fenêtres ; pour qui lit beaucoup, des cartes et des rafales. Le journal scellé réduit encore le trafic du DS, puisqu'un CDN sert les époques closes.

### 4.5 Vagues

Une vague de 100 000 entrées et 100 000 départs dans un groupe de 2^20 membres, une seule fenêtre :

| | Enveloppes | Commits | Changements de lecteurs |
| --- | ---: | ---: | --- |
| Tous les membres dans l'arbre | 648 420 | 1,4 Go | – |
| 16 384 gardiens (1,6 %), la même part de la vague | 10 100 (×64 de moins) | 22,6 Mo | 7,9 Mo d'enregistrements, aucune enveloppe |
| 65 536 gardiens (6,2 %) | 40 489 (×16 de moins) | 90,4 Mo | 7,5 Mo d'enregistrements |

### 4.6 Charge des gardiens

Chaque lecteur demande un lot à chaque session. Une requête coûte une vérification ML-DSA-65, une preuve d'annuaire, une encapsulation et un AEAD. La partie publique des lots vient du DS.

| Gardiens | Sessions par jour | Requêtes par gardien et par jour | CPU | Envoyé |
| ---: | ---: | ---: | ---: | ---: |
| 4 096 | 10 | 2 560 | 1,2 s | 14,9 Mo |
| 4 096 | 48 | 12 288 | 5,9 s | 26,5 Mo |
| 16 384 | 10 | 640 | 0,3 s | 3,7 Mo |
| 16 384 | 48 | 3 072 | 1,5 s | 6,6 Mo |
| 65 536 | 10 | 160 | 0,1 s | 0,9 Mo |
| 65 536 | 48 | 768 | 0,4 s | 1,7 Mo |

Quelques milliers de gardiens suffisent à servir un million de lecteurs. Ce qui limite leur nombre vers le bas, c'est la disponibilité et la confiance, pas la charge.

Avec la chaîne publique (section 3.8), un lecteur ne demande un lot qu'après une rupture, à n'importe quel membre en ligne. Si 10 % des 2^20 membres sont en ligne, chacun sert une dizaine de requêtes par jour avec une rupture par jour, une centaine avec une rupture par heure.

### 4.7 Historique

| | Rejouer chaque fenêtre | Un lot et un point de contrôle | Gain |
| --- | ---: | ---: | ---: |
| Retour après 1 jour | 7,4 Mo | 189 Ko | ×39 |
| Retour après 7 jours | 51,9 Mo | 1,3 Mo | ×40 |

- Journal scellé : 40 octets par sceau ; inclusion d'un message parmi 10 000 : 448 octets.
- 10 000 signatures FN-DSA-512 : 6,7 Mo une à une, environ 74 Ko agrégées avec LaBRADOR.

## 5. Modèle formel

[`formal-messages/`](formal-messages/README.md) : 17 scénarios ProVerif 2.05, lancés par `docs/research/formal-messages/run.sh` et par le job du modèle formel de la CI, en une seconde environ. L'adversaire est le réseau, donc le DS. Les primitives sont idéales. Les scénarios ont deux à quatre époques ; les chaînes plus longues, les hachés de transcript, le journal et les points de contrôle ne sont pas modélisés.

| Scénario | Ce qu'il vérifie | Verdict |
| --- | --- | --- |
| `reader_bundle` | Un lecteur reçoit le secret de lecteur de l'époque 2 d'un gardien, scellé à sa clé à usage unique signée, et le vérifie contre le tag chaîné. | Prouvé : ce qu'il envoie reste secret, et il n'accepte que le vrai secret. |
| `reader_bundle_no_tag` | Le même lecteur ne vérifie pas le tag. | Attaque : le DS scelle son propre secret à la clé à usage unique, qui est publique. |
| `reader_bundle_unsigned_request` | Le gardien ne vérifie pas la signature de la requête. | Attaque sur le secret : le DS demande un lot avec sa propre clé. Prouvé : le lecteur n'accepte toujours que le vrai secret. |
| `reader_removed` | Deux lecteurs, R et Q, à l'époque 1. La fenêtre 2 retire R sans rien re-keyer ; l'attaquant est R avec le DS. | Prouvé : R ne lit pas la vraie époque 2. Attaque attendue : R et le DS font bifurquer Q (section 3.6). |
| `reader_removed_signed_bundle` | La même chose, avec des lots signés par un gardien. | Prouvé, les deux propriétés. |
| `reader_removed_with_root` | Les lecteurs tiennent la racine de l'arbre et le secret d'époque. | Attaque : R lit l'époque 2. |
| `reader_removed_ratchet` | Les secrets de lecteur avancent en cliquet, à la Megolm. | Attaque. |
| `reader_link` | Un lecteur ouvre le lien du sceau de l'époque 2 avec le secret de l'époque 1, sans aucun membre en ligne. | Prouvé : ce qu'il envoie reste secret, et il n'accepte que le vrai secret. |
| `reader_link_ban` | La chaîne publique sur trois fenêtres : un lien, une rupture qui bannit R, un lien. L'attaquant est R avec le DS. | Attendu : R lit l'époque 2, où il était membre. Prouvé : il ne lit ni l'époque 3 ni l'époque 4. |
| `reader_link_no_break` | La fenêtre 3 retire R sans rompre la chaîne, comme un départ volontaire dans un groupe public. | Attaque, attendue : R lit l'époque 3 ; c'est ce que la politique accepte. |
| `bundle_any_member` | Après une rupture, un membre hostile de l'époque 1 sert le lot ; le DS livre le sceau intact. | Prouvé : le lecteur n'accepte que le vrai secret. |
| `reader_seal` | Un lecteur scelle la fenêtre 2, qui bannit un autre lecteur : nouvelle racine, init externe, signature vérifiée par le gardien. L'attaquant est le banni avec le DS. | Prouvé : le banni ne lit pas l'époque 2. |
| `reader_seal_unchecked` | Le gardien ne vérifie pas qui a scellé. | Attaque : le DS scelle à sa place. |
| `burst_chain` | Une rafale de deux messages, une signature de carte sur la chaîne ; l'attaquant est un membre. | Prouvé : un lecteur n'attribue à l'émetteur que ce qu'il a envoyé. |
| `burst_chain_mac_only` | La chaîne est authentifiée par un MAC sous une clé de l'époque. | Attaque : tout membre parle comme l'émetteur. |
| `card_revalidated` | Un membre retiré garde sa clé de carte et s'allie à un initié ; le lecteur vérifie la carte contre l'annuaire de l'époque du message. | Prouvé. |
| `card_cached` | Le lecteur garde la carte qu'il a vérifiée à l'époque 1. | Attaque : le membre retiré parle encore. |

Ce que le modèle ne couvre pas :
- l'entrée d'un lecteur, ancrée comme celle d'un entrant de la v0.4 (`anchored_join.pv` de [`docs/formal/`](../formal/README.md)) ;
- la poussée en ligne ;
- la rétention.

## 6. Garanties

Pour un lecteur, face aux adversaires de la spécification (section 2.1). Un gardien a les garanties d'un membre de la v0.4, et en plus celles du journal scellé et des cartes.

| Propriété | A1, A2 : DS | A3 : membre malveillant | A4 : membre retiré | A5 : état compromis | A6 : clé d'appareil volée |
| --- | --- | --- | --- | --- | --- |
| Confidentialité des secrets de lecteur | garantie en groupe fermé : lot scellé à une clé à usage unique signée | non (initié) | garantie dès la fenêtre qui applique le retrait, sans re-key, sur la branche où il est appliqué | hors des fenêtres FS et PCS ; FS retardée par la rétention des gardiens ; PCS à la session suivante, sans mise à jour | non, jusqu'au retrait |
| Authenticité des secrets reçus | garantie : tag chaîné ou lien | un membre de l'époque précédente peut faire accepter un faux secret au lecteur, en scellant la fenêtre (les gardiens la rejettent) ou avec le DS (bifurcation), au plus pour un intervalle de points de contrôle ; avec des lots signés et des sceaux confiés aux gardiens, il faut un gardien | comme A3 | garantie | comme A3 |
| Authenticité des messages | garantie : carte | garantie : il ne parle pas pour un autre | garantie si la carte est vérifiée contre l'annuaire de l'époque du message | non jusqu'à la rotation de la carte, si elle n'est pas dans un coffre | non, jusqu'au retrait |
| Cohérence des messages d'une époque | garantie : journal scellé ; une vue divergente est une bifurcation | garantie : pas d'envoi divergent | garantie | garantie | garantie |
| Authentification d'un message non signé d'une rafale | du groupe seulement, pendant `T_AUTH` au plus | idem | idem | idem | idem |
| Visibilité des entrées | à la demande : le lecteur liste les entrées d'une fenêtre à partir de son sceau (spécification, section 12.11) | idem | idem | idem | idem |
| Métadonnées | non : le DS voit les sessions, et le membre qui sert un lot aussi, une fois par rupture avec la chaîne publique | non | non | non | non |

Dans un groupe public (section 3.8), la confidentialité ne vaut que face à qui n'est pas entré : le DS et quiconque entre lisent. Ce qui compte y est l'authenticité des messages, la cohérence du transcript, la visibilité des entrées et la vivacité. Avec la chaîne publique, les lecteurs ne dépendent que du DS entre deux ruptures.

## 7. Risques et questions ouvertes

- **FN-DSA :**
  - FIPS 206 n'est pas final ;
  - la signature en virgule flottante expose le signataire aux canaux auxiliaires.

  L'agilité des cartes limite le risque, mais le remplacement d'un algorithme cassé demande une requête par membre.
- **Retrait de HAWK.** Il rappelle que les schémas compacts récents peuvent tomber. Les cartes ne protègent pas l'identité, qui reste ML-DSA-65, mais une carte cassée permet d'usurper des messages jusqu'à son remplacement.
- **Clé de carte hors coffre.** C'est un recul face à A5 pour l'authenticité des messages. La rotation quotidienne le borne à un jour.
- **Bifurcation des lecteurs.** Elle est bornée par les points de contrôle, ce qui suppose des admins qui en signent. Un DS peut les retenir ; le lecteur doit alors avertir. Dans un groupe ouvert, le DS peut entrer et la provoquer seul.
- **Scelleur hostile.** Il peut faire accepter aux lecteurs un faux secret de lecteur pour une fenêtre. Sa signature l'identifie, et ses victimes le voient, puisqu'elles n'ouvrent plus les messages des gardiens. Mais aucune preuve de fraude ne le montre sans révéler de secret. C'est, pour les lecteurs, le problème ouvert des committers hostiles de la v0.4.
- **Rétention.** C'est un compromis entre servir les lecteurs absents et la confidentialité persistante face aux gardiens. Il faut mesurer ce que les lecteurs demandent vraiment.
- **Présence.** Le membre qui sert un lot apprend l'identité du lecteur et l'heure de sa session : à chaque session avec des lots, une fois par rupture avec la chaîne publique. Des justificatifs anonymes post-quantiques d'appartenance à l'annuaire l'éviteraient, mais leur coût est inconnu.
- **Bannis.** Avec la chaîne publique, un banni lit jusqu'à la rupture suivante, et un état de lecteur volé aussi : `BREAK_INTERVAL` règle ce délai.
- **Disponibilité et incitations.** Avec la chaîne publique, il ne faut un membre en ligne qu'aux ruptures, et n'importe lequel convient. Qui fait tourner les gardiens admis d'un groupe public reste une question sociale : la charge est faible (section 4.6).
- **Retard d'authentification des rafales.** Il se voit dans l'interface ; `T_AUTH` est à régler par usage.
- **Rejeu entre époques et réordonnancement.** Les messages sont liés à leur époque, à leur génération et au journal. Un modèle de la chaîne sur plusieurs époques reste à faire.
- **Pas de preuve calculatoire.** Le tag chaîné, le lot et la chaîne de rafale n'ont qu'un modèle symbolique.

## 8. Feuille de route

| Étape | Contenu | Critère |
| --- | --- | --- |
| 1 | Profil suivant, brouillon : annuaire et rôles, carte et identifiant d'algorithme, secret, tag et lien de lecteur, ruptures, sceau par tout membre avec une init externe, politique de garde (gardiens sur admission), `BundleRequest` et `Bundle`, messages, chaînes de rafale, engagement, journal scellé dans le sceau, politique d'historique, paramètres (`RETENTION`, `BREAK_INTERVAL`, `T_BURST`, `T_AUTH`) | Spécification relue, labels et contextes enregistrés |
| 2 | `cityg-core` : calendrier de clés, annuaire, liens et lots, sceau par un lecteur, messages et chaînes, journal du DS | Tests de scénarios : vague de lecteurs sans enveloppe, lecteur qui suit la chaîne sans aucun gardien en ligne, banni coupé à la rupture, sceau d'un lecteur accepté par les gardiens, lien faux rejeté par les gardiens, lot faux refusé, bifurcation détectée au point de contrôle, rafale falsifiée écartée |
| 3 | Test d'échelle : 2^20 membres dont 2^14 gardiens | Chiffres de la section 4 retrouvés |
| 4 | Modèle formel étendu : chaîne de liens et de tags sur plusieurs époques, journal, points de contrôle ; preuve calculatoire du tag et du lien ; preuve de fraude d'un scelleur hostile qui ne révèle pas de secret | Verdicts attendus, preuve relue |
| 5 | Algorithme des cartes : FN-DSA-512 à la parution de FIPS 206 ; réévaluation à la fin du troisième tour (MAYO, SQIsign, UOV) | Décision documentée |

## 9. Sources

Signatures :
* NIST, [NIST Advances 9 Candidates to the 3rd Round of PQC](https://csrc.nist.gov/News/2026/nist-advances-9-candidates-to-the-3rd-round-of-pqc), mai 2026.
* The Qubit Report, [HAWK Lattice Signature Scheme Withdrawn from NIST Round 3](https://thequbitreport.com/security-policy/2026/08/13/hawk-lattice-signature-scheme-withdrawn-from-nist-round-3-after-ai-assisted-key-recovery-attack/), août 2026.
* DigiCert, [Quantum-ready FN-DSA nears draft approval from NIST](https://www.digicert.com/blog/quantum-ready-fndsa-nears-draft-approval-from-nist) ; NIST, [FIPS 206 FN-DSA (Falcon)](https://csrc.nist.gov/csrc/media/presentations/2025/fips-206-fn-dsa-%28falcon%29/images-media/fips_206-perlner_2.1.pdf), 2025.
* PQShield, [NIST PQC signatures zoo](https://pqshield.github.io/nist-sigs-zoo/) ; [SQIsign](https://sqisign.org/), version 3.0.
* M. A. Aardal, D. F. Aranha, K. Boudgoust, S. Kolby, A. Takahashi, [Aggregating Falcon Signatures with LaBRADOR](https://eprint.iacr.org/2024/311), CRYPTO 2024 ; chiffres d'agrégation : [synthèse sur l'agrégation post-quantique](https://hackmd.io/@goatresearch/H1G2tOCwGx), 2026.
* J. Drake, D. Khovratovich, M. Kudinov, B. Wagner, [Hash-Based Multi-Signatures for Post-Quantum Ethereum](https://eprint.iacr.org/2025/055), 2025.

Authentification de flux, distribution de clés, clients légers :
* A. Perrig, R. Canetti, J. D. Tygar, D. Song, [Efficient Authentication and Signing of Multicast Streams over Lossy Channels](https://people.eecs.berkeley.edu/~dawnsong/papers/tesla.pdf), IEEE S&P 2000.
* M. R. Albrecht, S. Celi, B. Dowling, D. Jones, [Practically-exploitable Cryptographic Vulnerabilities in Matrix](https://i.blackhat.com/EU-22/Wednesday-Briefings/EU-22-Jones-Practically-exploitable-Cryptographic-Vulnerabilities-in-Matrix-wp.pdf), Black Hat EU 2022 ; [spécification de Megolm](https://spec.matrix.org/unstable/olm-megolm/megolm/).
* H. Harney, C. Muckenhirn, [Group Key Management Protocol (GKMP) Specification](https://datatracker.ietf.org/doc/html/rfc2093), RFC 2093, 1997.
* [Light MLS](https://datatracker.ietf.org/doc/draft-kiefer-mls-light/) et [Partial MLS](https://datatracker.ietf.org/doc/draft-ietf-mls-partial/), brouillons IETF.
* C. Chevalier, G. Lebrun, A. Martinelli, J. Plût, [Quarantined-TreeKEM](https://eprint.iacr.org/2023/1903).
* Signal, [SPQR: the Sparse Post-Quantum Ratchet](https://signal.org/blog/spqr/), 2025.
* R. Barnes et al., [The Messaging Layer Security (MLS) Protocol](https://datatracker.ietf.org/doc/html/rfc9420), RFC 9420.

Transcript et signalement :
* G. K. Gegenhuber et al., [Send and Pretend: Exploiting Transcript Consistency Issues in End-to-End Encrypted Group Chats](https://www.usenix.org/conference/usenixsecurity26/presentation/gegenhuber), USENIX Security 2026 ([arXiv](https://arxiv.org/abs/2607.27510)).
* E. Fasllija, L. Heimberger, K. Paul, [Signal and Ready to MINGLE: In-Band Gossip for Key Transparency Split-View Detection in E2EE Messengers](https://eprint.iacr.org/2026/1010), 2026.
* P. Grubbs, J. Lu, T. Ristenpart, [Message Franking via Committing Authenticated Encryption](https://eprint.iacr.org/2017/664), CRYPTO 2017.
* Y. Dodis, P. Grubbs, T. Ristenpart, J. Woodage, [Fast Message Franking: From Invisible Salamanders to Encryptment](https://eprint.iacr.org/2019/016), CRYPTO 2018.
* [Transcript Franking for Encrypted Messaging](https://link.springer.com/chapter/10.1007/978-981-95-5096-8_1) ; [MIMI using HTTPS and MLS](https://datatracker.ietf.org/doc/draft-ietf-mimi-protocol/03/), brouillon IETF.

Usage :
* J. Nielsen, [Participation Inequality: The 90-9-1 Rule for Social Features](https://www.nngroup.com/articles/participation-inequality/), 2006.
