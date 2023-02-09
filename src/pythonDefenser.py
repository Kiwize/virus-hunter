import requests
import os
import sys
import datetime
import json
import hashlib
import yaml
from yaml.loader import SafeLoader
import HTMLBuilder

# Couleurs dans le terminal
class Colors:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    PURPLE = '\033[95m'
    ENDC = '\033[0m'


vt_url = "https://www.virustotal.com/api/v3/"

api_key = "eb09093303b95b702d41a7aeb73d5d2e1c0a766587d2d85133cef714a49d8cea"
data_dir = "../data/vt_data/"
config_file = open(data_dir + "conf.yaml", "r")

config_data = yaml.load(config_file, Loader=SafeLoader)

paths = config_data["filelist"]
dirs = config_data["folderlist"]

class VTScanSystem:
    def __init__(self) -> None:
        # Header html query vt
        self.headers = {
            "x-apikey": api_key,
            "accept": "application/json"
        }

    def upload(self, file):
        self.file_path = file
        print(Colors.BLUE + "Uploading file : " + file + "..." + Colors.ENDC)
        files = {"file": (file, open(file, "rb"), "text/plain")}

        self.file_url = vt_url + "files"
        print(Colors.YELLOW + "Uploading to " + self.file_url + Colors.ENDC)
        res = requests.post(self.file_url, headers=self.headers, files=files)

        if res.status_code == 200:
            result = res.json()
            self.file_id = result.get("data").get("id")
            print(Colors.YELLOW + self.file_id + Colors.ENDC)
            print(Colors.GREEN + "Files successfully uploaded." + Colors.ENDC)
        else:
            print(Colors.RED + "Failed to upload files..." + Colors.ENDC)
            print(Colors.RED + "Response code: " + str(res.status_code) + Colors.ENDC)
            sys.exit()

    def analyse(self):
        print(Colors.BLUE + "Get info about the results of analysis..." + Colors.ENDC)
        analysis_url = vt_url + "analyses/" + self.file_id
        res = requests.get(analysis_url, headers=self.headers)
        if res.status_code == 200:
            result = res.json()
            status = result.get("data").get("attributes").get("status")
            if status == "completed":
                stats = result.get("data").get("attributes").get("stats")
                results = result.get("data").get("attributes").get("results")
                self.appendTXTLogFile(stats)            
                self.createHTMLRapport(stats, results)
            elif status == "queued":
                print(Colors.BLUE + "status QUEUED..." + Colors.ENDC)
                with open(os.path.abspath(self.file_path), "rb") as file_path:
                    b = file_path.read()
                    hashsum = hashlib.sha256(b).hexdigest()
                    self.info(hashsum)
        else:
            print(Colors.RED + "failed to get results of analysis :(" + Colors.ENDC)
            print(Colors.RED + "status code: " + str(res.status_code) + Colors.ENDC)
            sys.exit()

    def info(self, file_hash):
        print(Colors.BLUE + "get file info by ID: " + file_hash + Colors.ENDC)
        info_url = vt_url + "files/" + file_hash
        res = requests.get(info_url, headers=self.headers)
        if res.status_code == 200:
            result = res.json()     
            if result.get("data").get("attributes").get("last_analysis_results"):
                stats = result.get("data").get( "attributes").get("last_analysis_stats")
                results = result.get("data").get( "attributes").get("last_analysis_results")
                self.appendTXTLogFile(stats) 
                self.createHTMLRapport(stats, results)            
            else:
                print(Colors.BLUE + "failed to analyse :(..." + Colors.ENDC)

        else:
            print(Colors.RED + "failed to get information :(" + Colors.ENDC)
            print(Colors.RED + "status code: " + str(res.status_code) + Colors.ENDC)
            sys.exit()

    def start(self, file):
        self.upload(file)
        self.analyse()

    def appendTXTLogFile(self, stats) :
        nbEngines = str(stats.get("malicious") + stats.get("undetected"))
            
        if stats.get("malicious") != 0 :
            createLog("Fichier malicieux : " + str(stats.get("malicious")) + "/" + nbEngines, self.file_path)
        else :
            if(config_data["logHealthyFiles"]) :
                createLog("Fichier sein", self.file_path)   

    def createHTMLRapport(self, stats, results):
        if config_data["createHTMLRapport"] :
            print(Colors.BLUE + "Génération du rapport HTML..." + Colors.ENDC)
            
            nbEngines = str(stats.get("malicious") + stats.get("undetected"))
            
            hb = HTMLBuilder.Builder(config_data["htmlOutputFolder"])
            
            hb.style(".engine_result", ["background-color: rgb(186, 189, 182);", "width: 20%;", "border-radius: 15px;", "padding: 10px;","margin-bottom: 2%;" ,"margin-left: 3%"])
            hb.style(".bad", ["background-color: rgb(255, 51, 51)"])
            hb.style(".good", ["background-color: rgb(26, 255, 26)"])
            hb.style("#engines_list", ["display: flex;", "flex-direction: row;", "flex-wrap: wrap;"])
            hb.style(".engine_name", ["text-align: center;", "font-weight: bold;", "background-color: rgb(166, 170, 161);", "border-radius: 5px;"])
            hb.style(".result", ["color: black;", "font-weight: bold;"])
            hb.style("h1", ["text-align: center;", "font-weight: bold;"])
                
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
            print(Colors.GREEN + "Rapport généré avec succès ! " + Colors.ENDC)
            print(Colors.GREEN + "Fichier : " + hb.file.name)
            
    def getPathsFromFolder(self, dir) :
        contents = os.listdir(dir)
        
        for content in contents :
            if os.path.isdir(dir + content) == False :
                paths.append(dir + content)
                

def createLog(result, scannedFile) :
    BUF_SIZE = 65536
    of = config_data["textLogsOutputFolder"]

    sha256 = hashlib.sha256()

    with open(scannedFile, "rb") as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            sha256.update(data)
    
    if(os.path.exists(of) == False) :
        os.mkdir(of)
    
    logFile = open(of + str(datetime.date.today()) + ".txt", "a")    
    logFile.write(datetime.datetime.now().strftime("%H:%M:%S") + " SHA256 > " + sha256.hexdigest() + " : " + result + " (" + os.path.basename(scannedFile) + ")\n")   
    logFile.close()
    
    
if __name__ == "__main__":
    vtscanner = VTScanSystem()
    
    if(config_data["enableDirScan"]) :
        if(paths == None) :
            print("Aucun dossier à scanner... Vérifiez la configuration.")
            sys.exit(-1)
        else :
            for dir in dirs :
                vtscanner.getPathsFromFolder(dir)
    
    if(paths == None) :
        print("Aucun fichier à scanner... Vérifiez la configuration.")
        sys.exit(-1)
    else :
        for path in paths :
            vtscanner.start(path)
