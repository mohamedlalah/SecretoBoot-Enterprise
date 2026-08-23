# SecretoBoot V9 — Guide français

## À quoi sert SecretoBoot ?

SecretoBoot fournit une interface Windows simple pour détecter les systèmes d’exploitation pris en charge et déployer un menu de démarrage UEFI basé sur rEFInd avec l’identité visuelle SecretoBoot.

Le tableau de bord peut afficher Windows, Android/Bliss OS et Linux. Le nombre de cartes est dynamique : deux systèmes détectés = deux cartes, quatre systèmes détectés = quatre cartes. Les éléments inconnus ou obsolètes restent dans **Advanced Diagnostics**.

## Prérequis

- Windows 10 ou Windows 11 en 64 bits
- Démarrage en mode UEFI
- Validation administrateur uniquement lorsque SecretoBoot la demande
- Secure Boot ne doit pas bloquer le chargeur rEFInd inclus ; SecretoBoot peut interrompre l’opération si Secure Boot est actif ou impossible à valider
- BitLocker/chiffrement de l’appareil peut devoir être suspendu ou désactivé si SecretoBoot indique que le volume système protégé bloque l’opération

## Procédure recommandée

1. Extraire le ZIP de SecretoBoot dans un nouveau dossier local.
2. Lancer `SecretoBoot.exe` normalement. Ne forcez pas toute l’application en mode Administrateur.
3. Cliquer sur **Scan Systems**.
4. Ouvrir **rEFInd Setup Preview** et vérifier les cibles détectées.
5. Installer SecretoBoot lorsque l’application propose l’installation validée.
6. Ouvrir **Boot Manager Actions** puis choisir **Test Next Restart**.
7. Redémarrer, vérifier que le menu SecretoBoot apparaît et que Windows démarre correctement.
8. De retour sous Windows, refaire un scan puis choisir **Make SecretoBoot Default**.
9. Redémarrer normalement.
10. Si le firmware remet toujours Windows en premier, SecretoBoot peut proposer **Enable Windows-First Compatibility**. Activez cette option uniquement lorsqu’elle est proposée par l’application.

Windows reste le choix automatique dans SecretoBoot avec un délai de 10 secondes.

## Advanced / Recovery

Les actions de réparation sont séparées du parcours normal afin d’éviter les erreurs. Utilisez-les uniquement si nécessaire. Un outil de restauration d’urgence du démarrage Windows natif est également fourni.

## Suppression d’un système

Après avoir supprimé un système d’exploitation, relancez **Scan Systems**. Le tableau de bord principal affiche les familles de systèmes reconnues ; les traces inconnues ou anciennes peuvent rester visibles uniquement dans Advanced Diagnostics.

## Compatibilité

SecretoBoot a été testé sur la machine de développement réelle, mais les firmwares diffèrent selon les fabricants. Il ne faut pas présenter le logiciel comme compatible avec tous les PC.
