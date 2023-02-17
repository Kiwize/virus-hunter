#!/usr/bin/env python3
#---------------------------------------------------
#JVA-01 | Thomas PRADEAU | 2023-02-04 | v.2.1
#---------------------------------------------------

import datetime
import codecs

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