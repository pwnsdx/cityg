# Confier le re-key au serveur ?

| | |
| --- | --- |
| Date | 2026-09-26 |
| Nature | Note de recherche. Elle examine la proposition de supprimer les committers et le scelleur, et de confier le re-key de l'arbre au serveur, éventuellement avec des preuves à divulgation nulle de connaissance (*zero knowledge*, ZK). Elle complète la note [parité MLS](parite-mls-2026-09-26.md). Rien de ce qu'elle décrit n'est encore dans la spécification ni dans le code. |
| Question | Le serveur peut-il faire le re-key à la place des membres, éventuellement en zero knowledge, sans perdre les garanties de MLS ? |
| Compagnons | [`parity_sim.py`](parity_sim.py), section 6 : coûts (`python3 docs/research/parity_sim.py`). [`formal-parity/`](formal-parity/README.md) : 9 scénarios ProVerif nouveaux (section 6). |
| Auteur | Claude Code (assistant IA d'Anthropic), à la demande du mainteneur. Le modèle symbolique couvre les choix clés ; il n'existe aucune preuve calculatoire. Une relecture cryptographique humaine reste nécessaire. |

Vocabulaire :
- le *re-key* d'une fenêtre : tirer les secrets des nœuds au-dessus des feuilles qui changent, et les chiffrer vers leurs enfants ;
- une *enveloppe* est, comme dans les notes précédentes, le secret d'un nœud chiffré vers un enfant (un *wrap* de la spécification) ;
- les *rôles de membre* de la v0.4 : committer de quartier, scelleur, welcomer. Le DS les attribue aux membres en ligne que la fenêtre ne touche pas, qu'elle appelle volontaires sans qu'ils s'inscrivent (spécification, section 14.4) ;
- un *ancien membre* : un membre qu'une fenêtre retire. Il garde les secrets des époques où il était membre ;
- le *serveur* : le DS, ou un service qui re-keye pour lui. Dans les modèles, c'est l'adversaire.

## 0. Résumé

1. **Le serveur gère déjà tout ce qui ne demande aucun secret** : recueillir les requêtes, placer les entrants, fermer les fenêtres, répartir le travail, vérifier les commits contre l'état public, découper les paquets, garder les enregistrements d'audit. Il ne reste aux membres que ce qui demande un secret : tirer les secrets des nœuds et les chiffrer, calculer le tag, sceller les welcomes.
2. **Le serveur ne peut pas tirer les secrets sans les connaître, et le ZK n'y change rien.** Une preuve ZK montre qu'un calcul sur des valeurs cachées est juste ; elle cache ces valeurs au vérificateur, pas à celui qui les a tirées. Aucune preuve n'atteste qu'un serveur ignore ou a effacé ce qu'il a tiré. Et qui connaît le secret d'un nœud connaît ceux de tous ses ancêtres, donc l'époque (section 2).
3. **Si le serveur tire les secrets** :
   - seul, il ne lit pas l'époque, pourvu qu'un membre calcule le tag et scelle les welcomes, ou qu'un entrant fasse une init externe : le calendrier de clés la protège (`server_rekey.pv`) ;
   - avec un seul ancien membre, il lit l'époque du retrait et toutes les suivantes, puisqu'il tire toutes les racines (`server_rekey_removed.pv`). Dans MLS et dans le profil à parité, le DS et un ancien membre, même ensemble, ne lisent rien après le retrait (`member_rekey_removed.pv`) ;
   - le serveur peut être lui-même cet ancien membre : là où il autorise les entrées, il fait entrer un de ses appareils, visiblement, puis le retire, et lit ensuite sans trace ;
   - sans aucun rôle de membre, les entrants ne reçoivent l'époque que de lui : il les connaît toutes dès la première fenêtre avec une entrée. C'est un chiffrement côté serveur.
4. **Les options** (section 3) :
   - **A**, un serveur tire les secrets : pas de parité. Rejetée pour le profil ;
   - **B**, k serveurs indépendants tirent chacun une part de chaque nœud. Les garanties de MLS tiennent tant qu'un serveur au moins reste honnête (`split_rekey.pv`). C'est un autre modèle de confiance, celui de la récupération de clés de Signal, répartie sur trois enclaves de trois fabricants. Avec deux serveurs et des fenêtres de 5 minutes, suivre le groupe coûte 3,9 Mo par jour si un membre calcule encore le tag, 6,2 Mo sinon, au lieu de 2,0 Mo ;
   - **C**, une enclave matérielle : les garanties tiennent tant que l'enclave tient. Or les attaques physiques publiées en 2025 cassent SGX, TDX et SEV-SNP pour qui a la machine en main, c'est-à-dire l'opérateur ;
   - **D**, les membres tirent, le serveur gère tout le reste : la parité.
5. **Recommandation : D, où les committers deviennent des tâches de fond vérifiables** (section 3.4).
   - Le serveur découpe chaque fenêtre en *tâches* : le re-key d'un quartier, celui de la ville avec le tag, les welcomes. Il les confie en arrière-plan à des clients en ligne, avec les clés publiques dont elles ont besoin et leurs preuves. C'est déjà presque la v0.4, dont les « volontaires » sont simplement les membres en ligne ; rien n'en est visible des utilisateurs.
   - Une tâche prend quelques millisecondes : 6 ms pour un quartier et 83 ms pour la ville avec des fenêtres de 5 minutes, 0,6 s pour le plus gros quartier d'une vague de 100 000 entrées et 100 000 départs.
   - Ce qui est nouveau, et c'est là que le ZK aide : un membre qui ne peut pas ouvrir une enveloppe le prouve, sans révéler sa clé ni un secret passé (`wrap_dispute.pv`, `wrap_dispute_report.pv`). Le client fautif est identifié et exclu des tâches, et un membre qui connaît le secret répare l'enveloppe. Cela répond à l'item ouvert de la spécification sur les enveloppes qu'un membre ne peut pas ouvrir (section 19).
   - La version économique de ces litiges, qui révélerait le secret partagé de l'encapsulation, est rejetée : un client hostile y rejoue l'encapsulation d'une enveloppe ancienne, et le litige ouvre un secret passé (`wrap_dispute_replay.pv`).
6. **Si l'application ne veut aucun calcul chez les membres**, B est la seule option où la confidentialité ne dépend pas d'un seul serveur. Ce n'est pas la parité, mais une confiance répartie, à déclarer comme telle.

## 1. Ce que les rôles de membre font aujourd'hui

| Travail | Qui, en v0.4 | Ce qu'il faut savoir |
| --- | --- | --- |
| Tirer les secrets des nœuds re-keyés d'un quartier, les chiffrer vers leurs enfants, publier leurs clés publiques | le committer du quartier | les clés publiques des enfants ; il connaît ensuite ce qu'il a tiré (ses taches) |
| La même chose pour la ville, jusqu'à la racine | le scelleur | idem |
| Calculer l'époque et le tag de confirmation | le scelleur | `init_n-1`, donc être membre de l'époque `n - 1`, ou l'init externe d'un entrant |
| Sceller les welcomes des entrants | les committers, le scelleur | `joiner_secret_n`, donc `init_n-1` |
| Signer son commit ou son sceau | chacun | sa clé d'appareil |
| Recueillir, placer, fermer les fenêtres, attribuer les rôles, vérifier, découper, auditer | le DS | rien |

La dernière ligne est déjà au serveur. La question porte sur les quatre premières.

Les travaux sur les serveurs qui aident un protocole de groupe vont dans le même sens. Dans SAIK, le serveur découpe chaque commit en paquets par destinataire, et reste non fiable ([Alwen et al., CCS 2022](https://eprint.iacr.org/2021/1456)). Dans CoCoA, il arbitre entre des mises à jour concurrentes ([Alwen et al., Eurocrypt 2022](https://eprint.iacr.org/2022/251)). Aucun ne lui fait tirer les secrets.

## 2. Ce qu'un serveur ne peut pas faire, même en zero knowledge

### 2.1 Trois faits

1. **Qui tire un secret le connaît.**
   - Une preuve ZK établit qu'un calcul sur des valeurs cachées est juste, par exemple qu'une enveloppe contient le secret dont le nœud publie la clé.
   - Elle cache ces valeurs au vérificateur, pas au prouveur.
   - Il n'existe pas de preuve qu'un serveur ignore ce qu'il a tiré, ni qu'il l'a effacé.
2. **Qui connaît le secret d'un nœud connaît ceux de ses ancêtres.**
   - Une enveloppe chiffre le secret d'un nœud vers un enfant : pour la produire, il faut ce secret.
   - Le secret de chaque ancêtre est chiffré vers un nœud du chemin, ou dérivé de lui. Qui connaît un nœud d'un chemin re-keyé connaît donc tout le chemin jusqu'à la racine, et le commit secret.
   - Laisser au serveur le bas des chemins et aux membres le haut ne change rien : le haut est chiffré vers le bas.
   - Mêler dans chaque nœud une part du serveur et une part d'un membre ne change rien non plus. La part du membre doit atteindre tous les membres restants et aucun retiré : c'est tout le re-key, fait par un membre. Ce sont les D·log(N/D) chiffrés de la borne inférieure ([Micciancio et Panjwani, Eurocrypt 2004](https://www.iacr.org/archive/eurocrypt2004/30270154/final.pdf)), et chacun est produit par quelqu'un qui connaît ce qu'il chiffre.
3. **Les entrants ont besoin d'un secret de l'époque précédente.** `joiner_secret_n` dépend de `init_n-1`, que seuls les membres de l'époque `n - 1` connaissent (spécification, section 9). Sans rôle de membre, il faut remplacer `init_n-1` par une init externe tirée par le serveur, qui la connaît alors.

### 2.2 Ce qui en découle

Soit un serveur qui tire les racines de toutes les fenêtres.

- **Le serveur seul.** Si un membre calcule le tag et scelle les welcomes, ou si un entrant fait une init externe, le serveur connaît le commit secret mais pas ce que le calendrier y ajoute : l'époque lui reste cachée (`server_rekey.pv`).
- **Le serveur et un ancien membre.** Un membre retiré par la fenêtre `n` connaît l'époque `n - 1`, donc `init_n-1` et la clé externe qui ouvre l'init externe d'un entrant. Avec la racine que le serveur a tirée, ils calculent l'époque `n`, puis `init_n`, puis chaque époque suivante, puisque le serveur tire chaque racine (`server_rekey_removed.pv`). Le retrait n'a jamais d'effet contre eux. Dans le profil, les racines viennent de membres, et ni le serveur ni l'ancien membre ne les apprennent (`member_rekey_removed.pv`).
- **Le serveur lui-même comme ancien membre.** Là où le serveur autorise les entrées (exigence R3 de la note de parité), il fait entrer un de ses appareils, ce qui se voit dans le journal des membres, puis le retire. Il lit ensuite toutes les époques sans apparaître nulle part. Dans un groupe public d'un million de membres, un ancien membre complaisant se trouve aussi sans cela.
- **Un appareil compromis.** Quand un membre compromis se met à jour, les secrets qui le guérissent viennent du serveur : un attaquant qui travaille avec le serveur ne perd jamais l'accès.
- **Sans aucun rôle de membre.** Les entrants reçoivent l'init du serveur (fait 3) : il connaît chaque époque dès la première fenêtre avec une entrée, c'est-à-dire, dans un grand groupe, dès la première fenêtre.
- **La compromission ultérieure du serveur.** Le serveur n'a besoin de garder que les clés publiques de l'arbre. S'il efface les secrets après chaque fenêtre, sa compromission plus tard ne révèle pas les époques passées ; mais personne ne peut le vérifier.

### 2.3 La règle

Pour que le serveur ignore une époque, un secret qu'il ne connaît pas doit, à chaque re-key, atteindre tous les membres restants et aucun retiré. Ce secret vient d'un membre, d'un autre serveur qui ne collabore pas avec lui, ou d'un matériel qui le lui cache. C'est l'argument de la note de parité (section 2.2) appliqué au serveur.

## 3. Les options

### 3.1 A — Un serveur tire les secrets

Le serveur re-keye tout l'arbre : il tire, chiffre, publie les clés des nœuds et signe chaque fenêtre. Deux variantes :
- **A1** : un membre en ligne de l'époque `n - 1` calcule encore le tag et scelle les welcomes ;
- **A0** : aucun rôle de membre ; le serveur fait l'init externe des entrants et signe chaque fenêtre à la place du tag.

Les garanties sont celles de la section 2.2 : A1 protège l'époque du serveur seul, pas du serveur allié à un ancien membre ; A0 ne la protège pas du serveur. Le ZK pourrait prouver que les enveloppes du serveur sont bien formées. Cela l'empêcherait de couper des membres par des enveloppes fausses, mais il peut déjà les couper en ne livrant pas.

**Verdict.** Pas de chiffrement de bout en bout face au serveur. A est rejetée pour le profil à parité. Une application qui ferait confiance au serveur pourrait l'employer en le déclarant, comme un chiffrement côté serveur.

### 3.2 B — k serveurs, chacun tire une part

```text
root_secret_n := KDF("split root", root_n^1, ..., root_n^k)
    root_n^i : la racine de l'arbre de parts du serveur i ; KDF : une dérivation à étiquette,
               comme celles de la section 3.3 de la spécification
```

- Chaque serveur `i` tient, sur les mêmes feuilles, les clés des membres, un arbre de parts qu'il est seul à connaître. À chaque fenêtre, il le re-keye comme un committer : parts fraîches sur les chemins qui changent, enveloppes vers les enfants, clés publiques des nœuds. Il signe son commit. Un membre déchiffre k chemins et combine les k racines.
- Chaque part doit être authentifiée : sans la signature de son serveur, le DS la remplace par la sienne (`split_rekey_unsigned.pv`).
- **B0**, aucun rôle de membre : chaque serveur donne aux entrants sa part d'une init externe, et chaque membre vérifie les k signatures. Les k serveurs ensemble connaissent tout.
- **B1**, un membre calcule encore le tag et scelle les welcomes, comme un scelleur sans enveloppes. Lui vérifie les k signatures ; les autres membres vérifient le tag, comme en v0.4. Il faut en plus aux k serveurs un ancien membre.

**Garanties.**
- k − 1 serveurs et un ancien membre n'apprennent rien ; les k serveurs et un ancien membre lisent (pour k = 2 : `split_rekey.pv`, `split_rekey_collude.pv`).
- Un membre compromis guérit dès qu'un serveur honnête re-keye son chemin.
- La compromission ultérieure des serveurs ne révèle le passé que s'ils n'ont pas effacé.

**Confiance.** C'est le modèle de la récupération de clés de Signal (SVR3). Le secret y est partagé entre trois enclaves de trois fabricants, dans trois nuages, de sorte qu'en casser deux ne suffit pas ([Connell et al., OSDI 2024](https://eprint.iacr.org/2024/887)). La garantie repose sur l'indépendance des opérateurs, qui est une propriété juridique et d'organisation, non cryptographique.

**Coûts** (section 5).
- Suivre le groupe coûte k fois les enveloppes. Avec deux serveurs et des fenêtres de 5 minutes, B1 coûte 3,9 Mo par jour au lieu de 2,0 Mo. B0 ajoute une signature et une preuve d'inclusion par serveur et par fenêtre : 6,2 Mo, ou 4,7 Mo si les serveurs signent avec FN-DSA-512.
- Chaque entrant télécharge 106 Ko au lieu de 57 Ko.
- Chaque serveur calcule 1,5 s par fenêtre de 5 minutes sur un cœur, et 155 s pour une vague de 100 000 entrées et 100 000 départs, soit 4,8 s sur 32 cœurs.

**Disponibilité.** Chaque serveur doit répondre à chaque fenêtre : il en faut k sur k. Un seuil, t sur k, demanderait une génération distribuée de clés entre serveurs à chaque fenêtre ; il n'est pas étudié ici.

### 3.3 C — Une enclave

Le re-key tourne dans une enclave attestée (SGX, TDX, SEV-SNP, Nitro) qui tient la chaîne d'init. Elle tire, chiffre, calcule le tag, scelle les welcomes, signe, puis efface. Les membres vérifient l'attestation, par exemple une clé attestée qui signe chaque fenêtre.

Les garanties sont celles de MLS tant que l'enclave tient. Mais l'adversaire est ici l'opérateur, qui a la machine en main, et c'est précisément ce que cassent les attaques de 2025 :
- [TEE.fail](https://tee.fail/) : une sonde sur le bus DDR5, pour moins de 1 000 dollars, extrait des clés de TDX et de SEV-SNP, et la clé d'attestation d'Intel, ce qui permet de falsifier l'attestation de SGX et de TDX ;
- [Battering RAM](https://durham-repository.worktribe.com/output/4699312/battering-ram-low-cost-interposer-attacks-on-confidential-computing-via-dynamic-memory-aliasing) (IEEE S&P 2026) : un interposeur à 50 dollars lit et écrit la mémoire d'une enclave SGX et falsifie l'attestation de SEV-SNP.

Une enclave ne donne pas de garantie cryptographique contre celui qui l'héberge. Combinée à B, avec k enclaves de fabricants différents chez des opérateurs distincts, elle oblige à les casser toutes : c'est SVR3. Pour les membres, elle coûte comme A0, une signature par fenêtre.

### 3.4 D — Les membres tirent, le serveur gère le reste

C'est le profil à parité. La proposition garde l'entropie chez les membres, donne au serveur tout le reste, et rend vérifiable ce que font les membres :

1. **Des tâches, pas des rôles.**
   - Le serveur découpe chaque fenêtre en tâches : le re-key d'un quartier avec les welcomes de ses entrants ; le re-key de la ville, le tag et le sceau.
   - Il les confie à des clients en ligne de l'époque `n - 1` que la fenêtre ne touche pas (spécification, section 10.5), en arrière-plan, comme ils déchiffrent un message. C'est déjà ce que fait la v0.4 : ses « volontaires » sont simplement les membres en ligne (section 14.4).
   - Il leur fournit les clés publiques dont la tâche a besoin, avec leurs preuves contre l'en-tête de l'époque : les vues de quartier de la section 12.3, un item ouvert de la section 19. Le client n'a pas à tenir l'état du groupe.
   - Une tâche prend quelques millisecondes (section 5), et rien n'en est visible des utilisateurs.
2. **Aucune entropie du serveur.** Chaque secret vient d'un client ; le serveur ne tire jamais le secret d'un nœud.
3. **Des litiges vérifiables.**
   - Un membre voit déjà qu'une fenêtre est fausse : il ne peut pas dériver son chemin, ou le tag ne se vérifie pas (spécification, section 12.2). Il trouve l'étape fautive en comparant chaque secret qu'il obtient à la clé publique que le commit publie pour le nœud, comme le fait déjà un entrant (section 7.4). Il lui manquait de pouvoir le prouver (sections 2.3 et 19).
   - Un *litige* contient le commit signé, l'enveloppe, et une preuve ZK, par un membre placé sous l'enfant. Elle établit que, dans le contexte de l'enveloppe (spécification, section 7.2), celle-ci ne s'ouvre pas, ou s'ouvre sur un secret dont la clé n'est pas celle du nœud. Pour une étape `Chain`, elle établit que la clé publiée n'est pas celle du secret dérivé.
   - N'importe qui vérifie le litige et établit la faute du signataire. La preuve ne révèle ni la clé de l'enfant ni ce qu'elle protégeait (`wrap_dispute_report.pv`). Un client qui chiffre juste ne peut pas être déclaré fautif, même par un membre placé sous l'enfant (`wrap_dispute.pv`).
   - **La version économique est rejetée.** Elle révélerait le secret partagé de l'encapsulation X-Wing, avec une preuve de décapsulation correcte : une preuve de déchiffrement pour ML-KEM et une preuve d'égalité de logarithmes discrets pour X25519. Mais l'encapsulation ne dépend pas du contexte de l'enveloppe. Un client hostile y rejoue l'encapsulation d'une enveloppe ancienne vers le même nœud, et le litige révèle la clé de cette enveloppe, donc un secret passé (`wrap_dispute_replay.pv`). La preuve doit couvrir la dérivation de la clé de l'enveloppe à partir du contexte, et l'AEAD.
   - **Son coût.** La preuve porte sur la décapsulation ML-KEM-768 avec rejet implicite, X25519, le combineur de X-Wing (SHA3-256), la dérivation de la clé de l'enveloppe, ChaCha20-Poly1305 et la clé du nœud. À cause des fonctions de hachage, elle demande un système de preuve généraliste. Sa taille et son temps restent à mesurer ; pour donner un ordre de grandeur, la seule preuve de déchiffrement correct d'un chiffré Kyber (paramètres de rang 2), sans les hachages, pèse 43,6 Ko ([Lyubashevsky, Nguyen et Seiler, PKC 2021](https://eprint.iacr.org/2020/1448), d'après la comparaison de [Gjøsteen et al., ACISP 2022](https://eprint.iacr.org/2021/558)). On ne la paie qu'en cas de litige.
4. **La réparation.**
   - Un membre qui connaît le secret du plus proche ancêtre que les membres coupés n'ont pas le chiffre vers une couverture de leur sous-arbre, faite de nœuds qu'aucun retiré ne connaît. Le serveur la calcule à partir de l'état public et des taches.
   - Les membres coupés vérifient le secret contre la clé publique déjà publiée.
   - Les nœuds du client fautif sont re-keyés à la fenêtre suivante, comme la règle des taches le fait pour un membre retiré.
   - Sans réparation, les membres coupés perdent cette fenêtre et reviennent à la suivante.
5. **L'exclusion.** Un client reconnu fautif ne reçoit plus de tâches, et la politique du groupe peut le retirer. En mode autorisé, chaque faute coûte à l'attaquant un appareil autorisé.
6. **Personne en ligne.** L'entrant fait tout, comme en v0.4 (sceau d'entrant, kind 2).

**Ce qui reste.**
- Un client hostile chargé de la ville peut bloquer une fenêtre par un tag faux. Aucun membre n'accepte alors une époque fausse ; le serveur confie la tâche à un autre, et la fenêtre prend du retard. Prouver qu'un tag est faux demanderait une preuve sur la chaîne d'init, plus lourde, que cette note n'étudie pas.
- Un client connaît les secrets qu'il tire : c'est un membre, comme le committer de MLS, et les taches bornent ce qu'il garde après son retrait.

## 4. Où le zero knowledge aide, et où il n'aide pas

| Usage | Ce qu'il apporterait | Coût | Verdict |
| --- | --- | --- | --- |
| Rendre le serveur ignorant de ce qu'il tire | rien : impossible (section 2.1) | – | – |
| Prouver que le serveur a effacé | rien : impossible | – | – |
| Litiges sur une enveloppe (section 3.4) | attribuer une enveloppe fausse sans révéler de clé | une preuve par litige, à mesurer | proposé |
| Chiffrement vérifiable de chaque enveloppe | empêcher d'avance toute enveloppe fausse | une preuve par enveloppe, 648 420 dans une vague | hors de portée aujourd'hui |
| Preuve de validité de chaque fenêtre, par le serveur | chaque membre sait que l'état public suit les règles, au lieu des audits par échantillonnage (spécification, section 15) | des centaines de vérifications ML-DSA et de mises à jour de Merkle par fenêtre, dans un circuit | possible, lourd, inutile à la parité |
| Cacher l'appartenance au serveur | le serveur applique la politique sur des entrées chiffrées sans savoir qui est membre ([Signal PGS, CCS 2020](https://eprint.iacr.org/2019/1416) ; sa version post-quantique, [2026](https://eprint.iacr.org/2026/453)) | des accréditations anonymes | au-delà de MLS (G12), compatible avec chaque option, hors du sujet de cette note |

## 5. Chiffres

`python3 docs/research/parity_sim.py`, section 6 : 2^20 membres, quartiers de 2^12, 1,7 changement par seconde, suite de la spécification (X-Wing, ML-DSA-65).

**Suivre le groupe**, par membre et par jour. Quand un membre calcule le tag (profil, A1, B1), les autres membres vérifient le tag. Sans rôle de membre (A0, B0, C), chaque serveur signe chaque fenêtre, et le membre vérifie chaque signature et la preuve d'inclusion de ses enveloppes.

| Fenêtre | Profil, ou A1 | A0, ou C | B1, k = 2 | B1, k = 3 | B0, k = 2 | B0, k = 3 |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 60 s | 7,4 Mo | 13,1 Mo (9,3 Mo) | 14,8 Mo | 22,2 Mo | 26,2 Mo (18,6 Mo) | 39,3 Mo (27,9 Mo) |
| 5 min | 2,0 Mo | 3,1 Mo (2,3 Mo) | 3,9 Mo | 5,9 Mo | 6,2 Mo (4,7 Mo) | 9,3 Mo (7,0 Mo) |

Entre parenthèses : les serveurs signent avec FN-DSA-512.

**Ce que calcule un serveur qui re-keye** (A, B pour chaque serveur, C) :
- avec des fenêtres de 60 s, 1 490 enveloppes et 0,36 s d'un cœur par fenêtre, 0,15 cœur-heure par jour ;
- avec des fenêtres de 5 minutes, 6 074 enveloppes et 1,5 s par fenêtre, 0,12 cœur-heure par jour ;
- pour une vague de 100 000 entrées et 100 000 départs, 648 420 enveloppes : 155 s d'un cœur, 4,8 s sur 32 cœurs.

Chaque entrant télécharge 57 Ko avec un arbre, 106 Ko avec deux arbres de parts.

**Les tâches des membres** (D), sur un cœur de la machine de mesure (Xeon à 2,1 GHz) :

| | Tâches de quartier | La plus grosse | Tâche de la ville | Welcomes |
| --- | --- | --- | --- | ---: |
| Fenêtres de 60 s | 82, de 15 enveloppes en moyenne : 4 ms, 39 Ko envoyés | 34 enveloppes | 251 enveloppes : 57 ms, 518 Ko | 51 |
| Fenêtres de 5 min | 221, de 26 enveloppes : 6 ms, 64 Ko | 75 enveloppes | 373 enveloppes : 83 ms, 743 Ko | 255 |
| Vague de 100 000 et 100 000 | 256 | 2 683 enveloppes : 0,6 s, 6,0 Mo | 383 enveloppes | 100 000 |

Si 100 000 membres sont en ligne, avec 222 tâches par fenêtre de 5 minutes, un client reçoit une tâche toutes les 450 fenêtres environ, soit à peu près une tous les jours et demi.

## 6. Modèle formel

Neuf scénarios nouveaux dans [`formal-parity/`](formal-parity/README.md), lancés par `docs/research/formal-parity/run.sh` et par le job du modèle formel de la CI. L'adversaire est le réseau, donc le serveur ; les primitives sont idéales.

| Scénario | Ce qu'il vérifie | Verdict |
| --- | --- | --- |
| `server_rekey` | Le serveur tire la racine de la fenêtre 2 ; un entrant fait une init externe signée ; personne qui connaît l'époque 1 n'aide le serveur. | Prouvé : ce que le membre et l'entrant envoient reste secret. |
| `server_rekey_removed` | Le même serveur tire les racines des fenêtres 2 et 3 ; un membre retiré par la fenêtre 2 lui donne l'époque 1. | Attaque sur les deux époques : le retrait n'a pas d'effet contre eux. |
| `member_rekey_removed` | Le même retrait quand des membres tirent les racines, comme en v0.4. | Prouvé : ni le retiré ni le serveur ne lisent les vraies époques 2 et 3. |
| `split_rekey` | Deux serveurs tiennent chacun un arbre de parts ; le premier et le retiré aident l'attaquant ; le second signe ses parts. | Prouvé. |
| `split_rekey_unsigned` | Le membre ne vérifie pas la signature du second serveur. | Attaque : le DS glisse sa propre part. |
| `split_rekey_collude` | Les deux serveurs et le retiré aident l'attaquant. | Attaque. |
| `wrap_dispute` | Un client chiffre juste ; un membre hostile placé sous l'enfant dépose des litiges. | Prouvé : le client n'est jamais déclaré fautif. |
| `wrap_dispute_report` | Un membre dépose un litige contre un client hostile, qui peut rejouer une enveloppe de l'époque 1. | Prouvé : la clé du nœud et le secret de l'époque 1 restent secrets. Le client hostile est déclaré fautif (événement atteignable, comme voulu). |
| `wrap_dispute_replay` | Le litige révèle le secret partagé de l'encapsulation ; le client hostile rejoue une encapsulation de l'époque 1. | Attaque : l'attaquant lit le secret de l'époque 1. |

La preuve d'un litige y est idéale : elle rend le clair de l'enveloppe dans son contexte, ou le verdict qu'elle n'est pas bien formée. Sa taille et sa solidité ne sont pas modélisées.

## 7. Garanties comparées

| | MLS | D : profil et tâches | A1 : un serveur, un membre pour le tag | A0 : un serveur seul | B : k serveurs | C : une enclave |
| --- | --- | --- | --- | --- | --- | --- |
| Le serveur seul lit | Non | Non | Non | Oui | Non ; oui si les k s'entendent, en B0 | Non, tant que l'enclave tient |
| Le serveur et un ancien membre lisent la suite (G1) | Non | Non | Oui, pour toujours | Oui | Non, sauf si les k s'entendent | Non, tant que l'enclave tient |
| Un attaquant allié au serveur garde l'accès à un appareil compromis qui s'est mis à jour (G4) | Non | Non | Oui | Oui | Non, sauf si les k s'entendent | Non, tant que l'enclave tient |
| Le passé, si le serveur est compromis plus tard | Protégé | Protégé | S'il a effacé, invérifiable | Idem | Idem | Effacement attesté |
| Travail des membres | Un commit | Des tâches de quelques ms | Le tag et les welcomes | Aucun | Aucun (B0) ; le tag et les welcomes (B1) | Aucun |
| Enveloppe fausse | D'un committer : membres coupés, sans preuve | D'un client : réparée, attribuée | Sans objet : seul le serveur chiffre | Idem | Idem | Idem |
| Disponibilité | Un committer | Un client en ligne, ou l'entrant | Le serveur et un membre | Le serveur | Les k serveurs | L'enclave |
| Suivi, fenêtres de 5 min | – | 2,0 Mo | 2,0 Mo | 3,1 Mo | Pour k = 2 : 3,9 Mo (B1), 6,2 Mo (B0) | 3,1 Mo |

## 8. Recommandation

- **D pour le profil à parité.** Garder l'entropie chez les membres, sans rien de visible :
  - le serveur gère les fenêtres, découpe le travail en tâches confiées en arrière-plan à des clients en ligne, et leur fournit ce qu'il faut pour les faire ;
  - des litiges vérifiables en ZK rendent un client hostile attribuable, et la réparation borne ce qu'il coupe.

  Le suivi ne change pas (2,0 Mo par jour avec des fenêtres de 5 minutes), et une tâche prend des millisecondes.
- **B si l'application refuse tout calcul chez les membres**, avec deux ou trois opérateurs indépendants, de préférence dans des enclaves de fabricants différents. Ce n'est pas la parité : c'est une confiance dans la non-collusion des serveurs, qui se déclare. Avec deux serveurs, le suivi coûte deux fois plus si un membre calcule encore le tag, trois fois plus sinon.
- **A est rejetée**, sauf pour une application qui fait confiance au serveur et le dit.
- **C seule est rejetée** ; elle n'a de sens que combinée à B.

Étapes, si D est retenue :
1. décrire le travail des membres comme des tâches dans le brouillon du profil suivant (sections 10.5, 12.4 à 12.7 et 14.4 de la spécification), avec les vues de quartier que le serveur fournit ;
2. spécifier le litige : l'énoncé, le système de preuve, sa taille et son temps mesurés ;
3. spécifier la réparation et son lien avec les taches ;
4. prolonger le modèle formel, puis une preuve calculatoire du litige.

## 9. Risques et questions ouvertes

- **La preuve d'un litige** n'existe pas encore pour X-Wing avec la dérivation du contexte et l'AEAD ; sa taille et son temps décident si un téléphone peut la produire.
- **La réparation** demande un membre en ligne qui connaît le bon ancêtre ; plusieurs fautes dans une même fenêtre compliquent la couverture.
- **Les clients jetables.** Dans un groupe ouvert, un appareil ne coûte rien : un attaquant peut perdre un appareil par fenêtre. Le serveur peut réserver les tâches aux appareils présents depuis un certain temps, au prix de la vivacité quand peu de membres sont en ligne.
- **B** repose sur l'indépendance des opérateurs, que rien ne vérifie cryptographiquement, et chaque serveur doit répondre à chaque fenêtre.
- **C** cède aux attaques physiques de son opérateur.
- **Pas de preuve calculatoire.**

## 10. Sources

* J. Alwen, D. Hartmann, E. Kiltz, M. Mularczyk, [Server-Aided Continuous Group Key Agreement](https://eprint.iacr.org/2021/1456), ACM CCS 2022.
* J. Alwen et al., [CoCoA: Concurrent Continuous Group Key Agreement](https://eprint.iacr.org/2022/251), Eurocrypt 2022.
* G. Connell et al., [Secret Key Recovery in a Global-Scale End-to-End Encryption System](https://eprint.iacr.org/2024/887), OSDI 2024 (SVR3).
* [TEE.fail: Breaking Trusted Execution Environments via DDR5 Memory Bus Interposition](https://tee.fail/), 2025.
* [Battering RAM: Low-Cost Interposer Attacks on Confidential Computing via Dynamic Memory Aliasing](https://durham-repository.worktribe.com/output/4699312/battering-ram-low-cost-interposer-attacks-on-confidential-computing-via-dynamic-memory-aliasing), IEEE S&P 2026.
* V. Lyubashevsky, N. K. Nguyen, G. Seiler, [Shorter Lattice-Based Zero-Knowledge Proofs via One-Time Commitments](https://eprint.iacr.org/2020/1448), PKC 2021.
* K. Gjøsteen, T. Haines, J. Müller, P. Rønne, T. Silde, [Verifiable Decryption in the Head](https://eprint.iacr.org/2021/558), ACISP 2022.
* M. Chase, T. Perrin, G. Zaverucha, [The Signal Private Group System and Anonymous Credentials Supporting Efficient Verifiable Encryption](https://eprint.iacr.org/2019/1416), ACM CCS 2020.
* G. Connell et al., [A Quantum-Safe Private Group System for Signal from Key Re-Randomizable Signatures](https://eprint.iacr.org/2026/453), 2026.
* D. Micciancio, S. Panjwani, [Optimal Communication Complexity of Generic Multicast Key Distribution](https://www.iacr.org/archive/eurocrypt2004/30270154/final.pdf), Eurocrypt 2004.
* R. Barnes et al., [The Messaging Layer Security (MLS) Protocol](https://www.rfc-editor.org/rfc/rfc9420.html), RFC 9420, 2023.
* Notes précédentes : [grands-groupes](grands-groupes-2026-09-25.md), [plan de messages](plan-de-messages-2026-09-26.md), [parité MLS](parite-mls-2026-09-26.md).
