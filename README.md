# Secure RFID Access System (Raspberry Pi + Ed25519)

## Projet

Ce projet consiste en la conception d'un système de contrôle d'accès RFID sécurisé, visant à corriger les vulnérabilités des badges RFID classiques, souvent facilement clonables ou falsifiables.

La solution repose sur l'utilisation de signatures numériques **Ed25519** afin de garantir :
- l'authenticité du badge ;
- l'intégrité des données ;
- une gestion des accès limitée dans le temps.

---

## Fonctionnement

Chaque badge RFID contient :
- un payload structuré (numéro de chambre, période de validité) ;
- une signature générée côté serveur à l'aide d'une clé privée.

Côté porte (Raspberry Pi + RC522), le système :
- lit le badge ;
- vérifie la signature via la clé publique ;
- contrôle la période de validité ;
- autorise ou refuse l'accès.

---

## Sécurité

- Signature asymétrique : **Ed25519**
- Clé privée conservée côté serveur
- Vérification effectuée sur le système embarqué
- Protection contre :
  - le clonage de badge ;
  - la modification des données ;
  - l'utilisation hors période autorisée.

### Structure du payload

Le payload est compacté sur **16 octets** et contient :
- la version ;
- le numéro de chambre ;
- le slot de début ;
- la durée de validité (en slots).

---

## Stack technique

- Python 3
- Raspberry Pi
- GPIO
- Lecteur RFID RC522
- Bibliothèque `cryptography` (Ed25519)

---

## Structure du projet

- `server_keys_ed25519.py` : génération des clés ;
- `make_badge_signed_rc522.py` : création et signature des badges ;
- `door_signed_rc522.py` : vérification des badges et contrôle d'accès ;
- `payload_common.py` : construction et parsing du payload.

---

## Installation

```bash
git clone https://github.com/your-username/secure-rfid-door.git
cd secure-rfid-door
pip install cryptography
```

---

## Utilisation

### 1. Génération des clés

```bash
python3 server_keys_ed25519.py
```

Ce script génère :
- une clé privée côté serveur ;
- une clé publique utilisée par la porte.

### 2. Création d'un badge

```bash
python3 make_badge_signed_rc522.py
```

Entrer :
- le numéro de chambre ;
- la durée de validité (en minutes).

Le badge est alors :
- construit sous forme de payload ;
- signé avec la clé privée ;
- écrit sur la carte RFID.

### 3. Lancement du système de contrôle d'accès

```bash
python3 door_signed_rc522.py
```

Fonctionnement :
- attente de la présentation d'un badge ;
- lecture des blocs RFID ;
- vérification de la signature ;
- contrôle de la validité temporelle ;
- ouverture ou refus d'accès.
