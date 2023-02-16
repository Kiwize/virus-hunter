#!/usr/bin/env python3
# @Author: Thomas PRADEAU
# @Date: 03/02/2023
# @Email: pradeau.thomas0@gmail.com

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

data_dir = "../data/vt_data/"
config_file = open(data_dir + "conf.yaml", "r")

config_data = yaml.load(config_file, Loader=SafeLoader) #Lecture du fichier de config

paths = config_data["filelist"]
dirs = config_data["folderlist"]

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
        
        if data.stats.get("malicious") != 0 :
            os.rename(os.path.abspath(file), os.path.abspath("../data/vt_data/quarantine/" + os.path.basename(file)))
            self.file_path = os.path.abspath("../data/vt_data/quarantine/" + os.path.basename(file))
            if config_data["enableSMSAlert"]:
                smsengine.send(os.path.abspath(file))
            
        self.appendTXTLogFile(data)
        self.createHTMLRapport(data)
        return True

    #Permet d'append les données en fin de fichier, prends en paramètres les données du scan
    def appendTXTLogFile(self, data) :
        
        stats = data.stats
        nbEngines = str(stats.get("malicious") + stats.get("undetected"))
            
        if stats.get("malicious") != 0 :
            self.createLog("Fichier malicieux : " + str(stats.get("malicious")) + "/" + nbEngines)
        elif (config_data["logHealthyFiles"]):
            self.createLog("Fichier sein")   

    #Permer de créer un rapport HTML, prends en paramètres les données du scan
    def createHTMLRapport(self, data):
        stats = data.stats
        results = data.results

        if config_data["createHTMLRapport"] :
            nbEngines = str(stats.get("malicious") + stats.get("undetected"))
            
            of = config_data["htmlOutputFolder"]

            if(os.path.exists(of) == False) :
                os.mkdir(of)
              
            #Utilise une nouvelle instance d'HTMLBuilder pour créer un nouveau fichier.
            hb = HTMLBuilder.Builder(config_data["htmlOutputFolder"])  
            
            if stats.get("malicious") != 0 :
                hb = HTMLBuilder.Builder(config_data["htmlOutputFolder"], True)
            
            #CSS
            hb.style("h1, p, a", ["font-family: Verdana, Geneva, sans-serif;"])
            hb.style(".engine_result", ["background-color: rgb(186, 189, 182);", "width: 20%;", "border-radius: 15px;", "padding: 10px;","margin-bottom: 2%;" ,"margin-left: 3%"])
            hb.style(".bad", ["background-color: rgb(255, 51, 51)"])
            hb.style(".good", ["background-color: rgb(26, 255, 26)"])
            hb.style("#engines_list", ["display: flex;", "flex-direction: row;", "flex-wrap: wrap;"])
            hb.style(".engine_name", ["text-align: center;", "font-weight: bold;", "background-color: rgb(166, 170, 161);", "border-radius: 5px;"])
            hb.style(".result", ["color: black;", "font-weight: bold;"])
            hb.style("h1", ["text-align: center;", "font-weight: bold;"])
                
            #HTML    
            hb.H("", "1", "Rappport d'analyses du fichier " + self.file_path)
            hb.P([], "Nombre de moteurs utilisés : " + nbEngines)
            hb.P(["id='undetected_count'"], "Non détecté(s) : " + str(stats.get("undetected")))
            hb.P(["id='undetected_count'"], "Détecté(s) : " + str(stats.get("malicious")))
            
            if stats.get("malicious") != 0 :
                hb.P(["id='file_status'"], "Fichier malicieux détecté !")
            else :
                hb.P(["id='file_status'"], "Fichier sain.")
                
            hb.open(["id='engines_list'"])

            for k in results :
                if results[k].get("category") == "malicious" :
                    hb.open(["class='engine_result bad'"])       
                else :
                    hb.open(["class='engine_result good'"])
                hb.P(["class='engine_name'"], results[k].get("engine_name"))
                hb.P(["class='engine_version'"], "Version : " + str(results[k].get("engine_version")))
                hb.P(["class='engine_category'"], "Catégorie : " + str(results[k].get("category")))
                if results[k].get("category") == "malicious" :
                    hb.P(["class='result'"], "Résultat : " + str(results[k].get("result")))
                hb.P(["class='method'"], "Méthode : " + str(results[k].get("method")))
                hb.P(["class='engine_update'"], "Update : " + str(results[k].get("engine_update")))
                hb.close()        
            hb.close()    
            hb.CloseFile()
            print("Rapport généré avec succès ! Fichier : " + hb.file.name)
            
    #Récupère tous les chemins des fichiers se trouvant dans les dossier à scanner, prends en paramètre un dossier.        
    def getPathsFromFolder(self, dir) :
        try:
            contents = os.listdir(dir)
        except FileNotFoundError:
            print("Le répertoire spécifié n'existe pas.. Vérifiez la configuration.")
            return
            
        for content in contents :
            if os.path.isdir(dir + content) == False :
                paths.append(dir + content)             

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
            os.mkdir(of)
        
        #Le fichier porte comme nom la date du jour formattée
        logFile = open(of + str(datetime.date.today()) + ".txt", "a")    
        logFile.write(datetime.datetime.now().strftime("%H:%M:%S") + " SHA256 > " + sha256.hexdigest() + " : " + result + " (" + os.path.basename(self.file_path) + ")\n")   
        logFile.close()
    
    
if __name__ == "__main__":
    vtscanner = VTScanSystem()
    smsengine = SMSEngine()
    
    #On scanne les dossier si c'est activé
    if(config_data["enableDirScan"]) :   
        if(dirs == None) :
            print("Aucun dossier à scanner... Vérifiez la configuration.")
        else : 
            for dir in dirs :
                vtscanner.getPathsFromFolder(dir)
    
    #Si ill n'y a pas de fichiers à scanner on quitte en erreur
    if(paths == None) :
        print("Aucun fichier à scanner... Vérifiez la configuration.")
        sys.exit(-1)
    else :
        #Sinon on débute le scan
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