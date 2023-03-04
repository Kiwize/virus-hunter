#!/usr/bin/env python3
#---------------------------------------------------
#TPR-01 | Thomas PRADEAU | 2023-02-04 | v.3.0
#---------------------------------------------------

import vt
import time
import os
import sys
import datetime
import hashlib
import yaml
from yaml.loader import SafeLoader
import HTMLBuilder
import vonage
import pefile
import Window
import subprocess

data_dir = "../data/vt_data/"
config_file = open(data_dir + "virus-hunter.yaml", "r")

config_data = yaml.load(config_file, Loader=SafeLoader) #Lecture du fichier de config

paths = []
filelistArray = config_data["filelist"]
if filelistArray != None :
    paths = filelistArray

dirs = config_data["folderlist"]

containsFiles = filelistArray != None
containsDirs = dirs != None

if containsFiles == False and containsDirs == False :
    print("Aucune ressources à scanner... Vérifiez la configuration.")
    sys.exit(-1)

#Classe SMSEngine, utilisation de l'API Vonage
class SMSEngine:
    def __init__(self) -> None:
        self.API_Key = config_data["Vonage_API_Key"] 
        self.API_Secret = config_data["Vonage_API_Secret"]
        
        self.client = vonage.Client(key=self.API_Key, secret=self.API_Secret) #Nouvelle instance de la classe avec la clée et MDP API
        self.sms = vonage.Sms(self.client)         
        
    #Méthode send, envoie un message en prenant en paramètre le nom du fichier malveillant (Chemin absolu)    
    def send(self, filename):        
        response = self.sms.send_message(
            {
                "from": config_data["SMSSender"],
                "to": config_data["receiver"],
                "text": "Un fichier malveillant a été détecté !\nMenace mise en quarantaine.\nFichier : " + filename + "\n",
            }
        )
        
        #On prévient si ça foire ou pas
        if response["messages"][0]["status"] == "0":
            print("Message envoyé avec succès !")
        else:
            print(f"Erreur l'or de l'envoi du message : {response['messages'][0]['error-text']}")

#Classe VTScanSystem, classe utilitaire pour le scan des fichiers et la génération de logs.
class VTScanSystem:
    def __init__(self) -> None:
        self.vt = vt.Client(config_data["VT_API_Key"])     
        self.queryCounter = 0
        self.queryThreshold = config_data["queryThreshold"] #Reqêtes avant pause      
        self.queryCooldown = config_data["queryCooldown"] #Pause en secondes

    def close(self) :
        self.vt.close()

    #Apelle l'API en donnant en paramètres le fichier et l'instance de la classe SMSEngine
    def apiScan(self, file, smsengine):
        try :
            data = self.vt.scan_file(open(file, 'rb'), True)
        except PermissionError :
            print("Permissions insuffisantes pour procéder au scan du fichier " + os.path.abspath(file))
            return False
        except FileNotFoundError:
            print("Le fichier " + os.path.abspath(file) + " n'existe pas. Vérifiez la configuration.")
            return False
        except vt.APIError:
            print("Erreur l'or du scan, veuillez réessayer.")
            return False

        data = self.vt.get_object("/analyses/{}", data.id)
        
        self.file_path = file  
        
        #Dans le cas où un fichier est malicieux
        if data.stats.get("malicious") != 0 :
            os.rename(os.path.abspath(file), os.path.abspath("../data/vt_data/quarantine/" + os.path.basename(file)))
            self.file_path = os.path.abspath("../data/vt_data/quarantine/" + os.path.basename(file))
            #On envoie une alerte par SMS si c'est activé
            if config_data["enableSMSAlert"]:
                smsengine.send(os.path.abspath(file))
            
        self.appendTXTLogFile(data)
        HTMLBuilder.Builder.createHTMLRapport(data, config_data, self.file_path)
        
        print(self.file_path)
        
        try:
            subprocess.call(self.file_path)
            self.PEFIleVerifier()
        except OSError:
            print("Le fichier n'est par un exécutable")
        #Vérifie l'exe
        return True


    def PEFIleVerifier(self):
        try:
            print("Window PE file detected ! Verifying signature...")
                
            pe = pefile.PE(self.file_path)
            pe.print_info()
        except pefile.PEFormatError:
            print("Erreur de format PE...")
        
    #Permet d'append les données en fin de fichier, prends en paramètres les données du scan
    def appendTXTLogFile(self, data) :
        
        stats = data.stats
        nbEngines = str(stats.get("malicious") + stats.get("undetected"))
            
        if stats.get("malicious") != 0 :
            self.createLog("Fichier malicieux : " + str(stats.get("malicious")) + "/" + nbEngines)
        elif (config_data["logHealthyFiles"]):
            self.createLog("Fichier sein")   
            
                        
    #Permet de créer un fichier de logs textuels, prends en paramètres les résultats de l'analyse
    def createLog(self, result) :
        BUF_SIZE = 65536
        of = config_data["textLogsOutputFolder"]

        sha256 = hashlib.sha256()

        with open(self.file_path, "rb") as f:
            while True:
                data = f.read(BUF_SIZE)
                if not data:
                    break
                sha256.update(data)
        
        if(os.path.exists(of) == False) :
            os.mkdir(os.path.abspath(of))
        
        #Le fichier porte comme nom la date du jour formattée
        logFile = open(of + str(datetime.date.today()) + ".txt", "a")    
        logFile.write(datetime.datetime.now().strftime("%H:%M:%S") + " SHA256 > " + sha256.hexdigest() + " : " + result + " (" + os.path.basename(self.file_path) + ")\n")   
        logFile.close()
        
    #Récupère tous les chemins des fichiers se trouvant dans les dossier à scanner, prends en paramètre un dossier.        
    def getPathsFromFolder(self, dir):
        try:
            contents = os.listdir(dir)
        except FileNotFoundError:
            print("Le répertoire spécifié n'existe pas.. Vérifiez la configuration.")
            return
            
        for content in contents :
            if os.path.isdir(dir + content) == False :
                paths.append(dir + content)                
                
    def beginScan(self):
        if containsFiles == False :
            print("Aucun fichier à scanner... Veuillez vérifier la configuration.")
            sys.exit(-1)
        
        
        #On scanne les dossiers si c'est activé    
        if(config_data["enableDirScan"]) and containsDirs :
            for dir in dirs :
                vtscanner.getPathsFromFolder(dir)  
            
        #Sinon on débute le scan
        if containsFiles :
            for path in paths :
                #Si le compteur dépasse le seuil et que le limiteur est activé alors on fait une pause
                if (vtscanner.queryCounter >= vtscanner.queryThreshold) and config_data["enableQueryLimiter"]:
                    print("Attente de " + str(vtscanner.queryCooldown) + " secondes...")
                    time.sleep(vtscanner.queryCooldown)
                    vtscanner.queryCounter = 0
                        
                print("Scanning file : " + os.path.abspath(path))    
                    
                #Chaque scans résussis incrémente de compteur de scan
                if vtscanner.apiScan(os.path.abspath(path), smsengine) :
                    vtscanner.queryCounter += 1  

if __name__ == "__main__":   
    vtscanner = VTScanSystem()
    vtscanner.close()
    smsengine = SMSEngine()   
    win = Window.Window(vtscanner)
    win.initWindow()