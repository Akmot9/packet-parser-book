# Introduction

**Packet Parser** est une bibliothèque Rust modulaire et performante permettant d'analyser et de décoder des trames réseau.  
Ce guide explique comment utiliser Packet Parser, son architecture interne, et comment y contribuer.

## Pourquoi Packet Parser ?

- **Support multi-couches** : prise en charge des couches liaison, réseau, transport et application.
- **Validation des données** : mécanismes intégrés pour garantir l'intégrité des paquets.
- **Gestion précise des erreurs** : chaque couche dispose de ses propres types d'erreurs.
- **Performances optimisées** : benchmarks intégrés avec Criterion.
- **Extensibilité** : architecture modulaire permettant l'ajout facile de nouveaux protocoles.

---
