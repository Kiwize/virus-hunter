##################################
# Détail des options (conf.yaml) #
##################################

enableDirScan: Active ou non le scan des répertoires.

logHealthyFiles: Active ou non le traçage des fichiers sains dans les logs simpleifiés.

createHTMLRapport: Active ou non la génération de rapport complet au format HTML.

queryThreshold: Spécifie le seuil du nombre de requêtes maximal avant de faire une pause.

queryCooldown: Spécifie le temps en seconde de pause l'orsque le seuil queryThreshold est atteint.

enableQueryLimiter: Active ou non le limiteur de requêtes.

VT_API_Key: Spécifie la clé d'API utilisée l'or des requêtes.

htmlOutputFolder: Si la génération de rapport HTML est activée, alors ceux-ci seront placés dans le répertoire spécifié.

textLogsOutputFolder: Spécifie le répertoire où sont déposés les logs simplifiés.

filelist: Spécifie la liste des fichiers à scanner.

folderlist: Spécifie la liste des répertoires à scanner.


##########################
# Option des alertes SMS #
##########################

enableSMSAlert: Active ou non les alertes par SMS.

Vonage_API_Key: Spécifie la clé d'API utilisé par le client Vonage

Vonage_API_Secret: Spécifié le mot de passe nécessaire par le client Vonage

SMSSender: Nom utilisé comme expéditeur du SMS.

receiver: Numéro de téléphone du destinataire, doit être au format suivant : 33612345678


