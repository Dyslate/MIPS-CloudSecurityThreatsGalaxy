# Cloud Security Threats Galaxy

## Description
Ce projet, **Cloud Security Threats Galaxy**, vise à rassembler, formater et partager des données sur les menaces de sécurité dans les environnements cloud. Il utilise l'API du National Vulnerability Database (NVD) pour récupérer des informations sur les vulnérabilités liées aux services cloud tels qu'AWS, Azure et GCP, et les formate pour une intégration avec le logiciel MISP (Malware Information Sharing Platform & Threat Sharing).

## Fonctionnalités
- **Récupération automatisée** des données de vulnérabilité du NVD.
- **Filtrage des données** basé sur des mots-clés spécifiques aux environnements cloud.
- **Formatage des données** pour une compatibilité avec la structure de cluster MISP.
- **Prévention des duplications** dans les données récupérées.
- **Mise à jour facile** et gestion des clusters MISP.

## Comment l'utiliser
1. **Clonez** le dépôt sur votre machine locale.

## Installation des dépendances
2. Pour installer les dépendances nécessaires au projet, exécutez la commande suivante :
```bash
pip install -r requirements.txt
```
3. **Configurez** les mots-clés et le chemin du fichier de cluster selon vos besoins dans le script principal.
4. **Exécutez** le script pour récupérer et formater les données.

## Contribution
Les **contributions** à ce projet sont les bienvenues. Voici comment vous pouvez contribuer :
- En proposant de **nouveaux mots-clés** ou des **logiques de filtrage**.
- En **améliorant le code** pour une meilleure performance ou une meilleure lisibilité.
- En **signalant des bugs** ou en suggérant des **améliorations**.

## Contact
Pour toute question ou suggestion, n'hésitez pas à [me contacter](mailto:lucas.franchina0@gmail.com).

---

> **Note :** Ce projet est toujours en développement et peut subir des modifications importantes.
