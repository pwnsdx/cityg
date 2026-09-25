# PoC de l'audit du 2026-09-25

Preuves de concept reproductibles associées à
[`../audit-crypto-conformite-2026-09-25.md`](../audit-crypto-conformite-2026-09-25.md).

Ce dossier est un crate autonome (`[workspace]` propre) : il ne fait pas partie
du workspace principal et n'est pas compilé par la CI.

> **Profil v0.1.4 uniquement.** Les PoC s'appuient sur les crates du profil
> v0.1.4 (`anchor-seed`, `cityg-client`, `msphf-core`, `msphf-rlwe`), retirées
> depuis le passage au profil v0.2. Pour les exécuter, utiliser une copie de
> travail du commit audité :
>
> ```bash
> git worktree add /tmp/cityg-71ee261 71ee261
> cp -r docs/audits/poc-2026-09-25 /tmp/cityg-71ee261/docs/audits/
> cd /tmp/cityg-71ee261/docs/audits/poc-2026-09-25
> ```
>
> Le devenir de chaque constat dans le profil v0.2 est consigné à la fin du
> rapport d'audit.

## Prérequis

Le commit audité (`71ee261`) ne compile pas (constat H-09). Avant de lancer les
PoC Rust, appliquer localement la correction d'une ligne :

```diff
--- a/crates/msphf-orchestrator/src/accept/mod.rs
+++ b/crates/msphf-orchestrator/src/accept/mod.rs
@@
-            format!("barrier_update_reason must fit in u64, got {reason_int}"),
+            format!("barrier_update_reason must fit in u64, got {reason_int:?}"),
```

Pour obtenir les mêmes versions de dépendances que le dépôt, copier le lockfile
racine avant la première compilation :

```bash
cd docs/audits/poc-2026-09-25
cp ../../../Cargo.lock .
```

## Exécution

| Commande | Constat | Résultat attendu |
| --- | --- | --- |
| `cargo run -q --release --bin ek_recovery` | C-01 | `E_k` recalculé à partir des seuls octets envoyés à `/v1/accept_epoch` (`match=true` ×3) ; `hp_a` transmis en clair |
| `cargo run -q --release --bin hl_encoding` | H-06 | `TreeHash` (S11.4) et `fs_dev_commit` (S7.4) : formule de la spec ≠ valeur du code |
| `cargo run -q --release --bin header_keys` | H-07 | JOIN de référence : clés 20 et 96 absentes, clés 154/155/156 hors registre |
| `cargo run -q --release --bin mldsa_interop` | H-05 | `pqcrypto-dilithium 0.5.0` ↔ `fips204` ML-DSA-87 : `false` dans les deux sens |
| `python3 cover_sim.py` | H-08 | Taille d'une `barrier_update` selon N_max et la part de slots révoqués non réclamés |
