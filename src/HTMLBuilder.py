#!/usr/bin/env python3
#---------------------------------------------------
#TPR-01 | Thomas PRADEAU | 2023-02-04 | v.3.0
#---------------------------------------------------

import datetime
import codecs
import os

class Builder :
    #Génération du header du doc
    def __init__(self, dest, scan_res = False, headcontent = ["<meta charset=\"UTF-8\">"], title = "Virustotal Rapport") -> None:
        date = datetime.datetime.now()
        
        #scan_res = Si le résultat et positif (malveillant)
        if scan_res == False :
            filename = dest + str(date.day) + "_" + str(date.month) + "_" + str(date.year) + "_" + str(date.hour) + "-" + str(date.minute) + "-" + str(date.second) + ".html"
        else :
            title = "Positive Virustotal rapport"
            filename = dest + "D_" + str(date.day) + "_" + str(date.month) + "_" + str(date.year) + "_" + str(date.hour) + "-" + str(date.minute) + "-" + str(date.second) + ".html"

        #On ouvre le doc en utf8 pour les accents et tt
        self.file = codecs.open(filename, "w", "utf-8")
        
        #htmlcontent stocke tout le fichier pendant la phase d"écriture
        self.htmlcontent = "<!DOCTYPE html>\n<html>\n<head>\n"

        for c in headcontent :
           self.htmlcontent += c + "\n"
           
        self.htmlcontent += "<title>"+title+"</title>\n</head>\n<body>\n"
        
    #Permet d'ajouter une balise style, prends en paramètres les classes, id et attributs CSS   
    def style(self, classid, css = []) :
        self.wt("<style>")
        self.wt(classid + " {")
        for c in css :
            self.wt(c)
            
        self.wt("}\n</style>")                
    
    #Permet d'ajouter une balise p, prends en paramètres les classes et id sous forme de tableau et le contenu.
    def P(self, attributes = [], content = "") :
        self.wt("<p ", False)
        for a in attributes :
            self.wt(a + " ", False)
        
        self.wt(">"+str(content)+"</p>")           
        
    #Permet d'ajouter une balise h, prends en paramètres les classes et id, le niveau (1 à 6) et le contenu.        
    def H(self, attributes, level, content) :
        self.wt("<h"+level + attributes + ">"+str(content) +"</h"+level+">")
    
    #Met à jour le contenu à écrire dans le fichier final    
    def wt(self, content, ln=True) :
        self.htmlcontent += str(content)
        if ln : self.htmlcontent += "\n"
        
    #Ouvre une balise parent, prends en paramètres les classes et id, et le type, genre "div", "section"...    
    def open(self, attributes = [], type = "div") :
        self.wt("<" + type + " ", False)    
        for a in attributes :
            self.wt(a + " ", False)          
        self.wt(">")
        
    #Permet de fermer une balise ouverte avec la méthode "open"    
    def close(self, type = "div") :
        self.wt("</"+type+">")
        
    #Ferme le fichier et enregistre tout le contenu    
    def CloseFile(self) :
        self.wt("</body>\n</html>")
        
        self.file.write(self.htmlcontent)
        self.file.close()
        
    #Permer de créer un rapport HTML, prends en paramètres les données du scan
    def createHTMLRapport(data, config_data, file_path):
        stats = data.stats
        results = data.results

        if config_data["createHTMLRapport"] :
            nbEngines = str(stats.get("malicious") + stats.get("undetected"))
            
            of = config_data["htmlOutputFolder"]

            if(os.path.exists(of) == False) :
                os.mkdir(of)
              
            #Utilise une nouvelle instance d'HTMLBuilder pour créer un nouveau fichier.
            hb = Builder(config_data["htmlOutputFolder"])  
            
            if stats.get("malicious") != 0 :
                hb = Builder(config_data["htmlOutputFolder"], True)
            
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
            hb.H("", "1", "Rappport d'analyses du fichier " + file_path)
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