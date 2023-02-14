#Custom tool for building HTML documents.
#Author: Thomas Pradeau

import datetime
import codecs

class Builder :
    def __init__(self, dest, headcontent = ["<meta charset=\"UTF-8\">"], title = "Virustotal Rapport") -> None:
        # Get current datetime for log files.
        date = datetime.datetime.now()
        
        self.file = codecs.open(dest + str(date.day) + "_" + str(date.month) + "_" + str(date.year) + "_" + str(date.hour) + "-" + str(date.minute) + "-" + str(date.second) + ".html", "w", "utf-8")
        self.htmlcontent = "<!DOCTYPE html>\n<html>\n<head>\n"

        for c in headcontent :
           self.htmlcontent += c + "\n"
           
        self.htmlcontent += "<title>"+title+"</title>\n</head>\n<body>\n"
        
    def style(self, classid, css = []) :
        self.wt("<style>")
        self.wt(classid + " {")
        for c in css :
            self.wt(c)
            
        self.wt("}\n</style>")                
    
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