#Custom tool for building HTML documents.
#Author: Thomas Pradeau

import datetime

class Builder :
    def __init__(self, dest, headcontent = ["<meta charset='utf-8'>"], title = "Virustotal Rapport") -> None:
        # Get current datetime for log files.
        date = datetime.datetime.now()
        
        self.file = open(dest + str(date.day) + "_" + str(date.month) + "_" + str(date.year) + "_" + str(date.hour) + "-" + str(date.minute) + "-" + str(date.second) + ".html", "w")
        self.htmlcontent = "<!DOCTYPE html>\n<html>\n<head>\n"

        for c in headcontent :
           self.htmlcontent += c + "\n"
           
        self.htmlcontent += "<title>"+title+"</title>\n"
        self.htmlcontent += "</head>\n<body>\n"                
    
    def P(self, attributes = [], content = "") :
        self.wt("<p ", False)
        for a in attributes :
            self.wt(a + " ", False)
        
        self.wt(">"+str(content)+"</p>")           
        
    def H(self, attributes, level, content) :
        self.wt("<h"+level + attributes + ">"+str(content) +"</h"+level+">")
        
    def wt(self, content, ln=True) :
        self.htmlcontent += str(content)
        if ln : self.htmlcontent += "\n"
        
    def open(self, attributes = [], type = "div") :
        self.wt("<" + type + " ", False)    
        for a in attributes :
            self.wt(a + " ", False)          
        self.wt(">")
        
    def close(self, type = "div") :
        self.wt("</"+type+">")
        
    def CloseFile(self) :
        self.wt("</body>\n</html>")
        
        self.file.write(self.htmlcontent)
        self.file.close()