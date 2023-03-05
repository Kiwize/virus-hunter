#!/usr/bin/env python3
#---------------------------------------------------
#TPR-01 | Thomas PRADEAU | 2023-03-05 | v.3.2
#---------------------------------------------------

import PyQt5.QtWidgets as widgets
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QTabWidget, QVBoxLayout, QHBoxLayout, QLineEdit
from PyQt5.QtGui import QFont
from PyQt5.QtCore import QCoreApplication
import sys
import VirusHunter

class Window:
    def __init__(self, vtscanner):
        self.winH = 300
        self.winW = 300
        self.winName = "Virustotal Scanbot"
        self.vtscanner = vtscanner
        
    def initWindow(self):
        self.app = QApplication(sys.argv)
        self.app.setStyleSheet(QSSLoader("qss/globalStyle.css"))
        win = QMainWindow()
        win.setGeometry(0, 0, self.winW,self.winH)
        win.setFixedSize(self.winW, self.winH)
        win.setWindowTitle(self.winName)
        
        self.win = win
        self.subWindow = SubWindow()
        
        label = widgets.QLabel(win)
        label.setText("Virustotal Scanbot V3.0")
        label.adjustSize()
        label.move(int(self.winW / 2 - label.width() / 2), 10)
        
        button = widgets.QPushButton(win)
        button.setText("Begin scan")
        button.adjustSize()
        button.move(int(self.winW / 2 - button.width() / 2), 50)
        button.clicked.connect(self.beginScanCallback)
        self.button = button
        
        configButton = widgets.QPushButton(win)
        configButton.setText("Configuration")
        configButton.adjustSize()
        configButton.move(int(self.winW / 2 - configButton.width() / 2), int(self.winH - configButton.height()))
        configButton.clicked.connect(self.subWindow.show)
        self.configButton = configButton
        
        scanstate = widgets.QLabel(win)
        scanstate.setObjectName("scan_state_default")
        scanstate.setText("Aucun scan en cours.")
        scanstate.adjustSize()
        scanstate.move(int(self.winW / 2 - scanstate.width() / 2), 80)
         
        self.scanstate = scanstate
        
        win.show()   
        self.vtscanner.close()
        sys.exit(self.app.exec_())
        
        
    def windowResizeCallback(self):
        self.configButton.move(int(self.winW / 2 - self.configButton.width() / 2), int(self.winH - self.configButton.height()))
        
    def beginScanCallback(self):
        self.scanstate.setObjectName("scan_state_default")
        self.button.setEnabled(False)
        self.scanstate.setText("Scan en cours...")
        self.scanstate.adjustSize()
        self.scanstate.move(int(self.winW / 2 - self.scanstate.width() / 2), 80)     
        QCoreApplication.processEvents()

        self.vtscanner.beginScan()
        
        self.scanstate.setObjectName("scan_state_good")
        self.button.setEnabled(True)
        self.scanstate.setText("Scan terminé !")    
        self.scanstate.adjustSize()
        self.scanstate.move(int(self.winW / 2 - self.scanstate.width() / 2), 80)
        self.app.setStyleSheet(QSSLoader("qss/globalStyle.css"))


class SubWindow(QWidget):
    def __init__(self):
        super(SubWindow, self).__init__()
        self.resize(450, 300)    
        self.setFixedSize(450, 300)
        self.setStyleSheet(QSSLoader("qss/configStyle.css"))
        self.widgetMap = {}
        self.settingsLabel = {}
        
        self.settingsLabel["enableDirScanLabel"] = "Scanner les dossiers : "
        self.settingsLabel["enableQueryLimiterLabel"] = "Limiteur de requêtes : "
        self.settingsLabel["VT_API_KeyLabel"] = "Clé d'API VirusTotal : "
        
        font = QFont()
        font.setPointSize(11)
        
        self.tabs = QTabWidget()
        
        self.tabGeneral = QWidget()
        self.tabLogs = QWidget()
        self.fileTab = QWidget()
        self.dirTab = QWidget()
        
        self.tabs.addTab(self.tabGeneral, "Général")
        self.tabs.addTab(self.tabLogs, "Logs")
        self.tabs.addTab(self.fileTab, "Fichiers à scanner")
        self.tabs.addTab(self.dirTab, "Dossiers à scanner")
        
        self.tabGeneral.layout = QVBoxLayout()
        self.tabGeneral.setLayout(self.tabGeneral.layout)  
        
        self.HLayout = QHBoxLayout()
        
        self.enableDirScanLabel = widgets.QLabel()    
        self.enableQueryLimiterLabel = widgets.QLabel()
        self.VT_API_KeyLabel = widgets.QLabel()
        
        self.enableDirScanButton = widgets.QPushButton()
        self.enableQueryLimiterButton = widgets.QPushButton()  
        
        self.VT_API_KeyField = QLineEdit()
        
        self.widgetMap["enableDirScanLabel"] = self.enableDirScanLabel
        self.widgetMap["enableQueryLimiterLabel"] = self.enableQueryLimiterLabel 
        self.widgetMap["VT_API_KeyLabel"] = self.VT_API_KeyLabel

        self.widgetMap["enableDirScanButton"] = self.enableDirScanButton
        self.widgetMap["enableQueryLimiterButton"] = self.enableQueryLimiterButton
        
        self.widgetMap["VT_API_KeyField"] = self.VT_API_KeyField
        
        btnOffY = -1
        lblOffY = -1
        
        for key, widget in self.widgetMap.items():
            if isinstance(widget, widgets.QPushButton):
                btnOffY += 1
                widget.setCheckable(True)
                widget.setGeometry(self.width() - 50, 13 + (20 * btnOffY), 13, 13)
                
            if isinstance(widget, widgets.QLabel):
                lblOffY += 1
                try:
                    text = self.settingsLabel[key]
                    widget.setText(text)
                    widget.setFont(font)
                    widget.adjustSize()
                    widget.move(10, 10 + (20 * lblOffY))
                except KeyError:
                    widget.setText("N/A")    
                    
            self.HLayout.addWidget(widget)
                    
        self.VT_API_KeyField.move(self.VT_API_KeyLabel.width(), self.VT_API_KeyLabel.y()) 
        self.VT_API_KeyField.setFixedSize(self.width() - self.VT_API_KeyLabel.width() - 30, self.VT_API_KeyLabel.height())             
                    
        self.tabGeneral.layout.addChildLayout(self.HLayout)
        
        self.saveButton = widgets.QPushButton("Save")
        self.saveButton.setFixedSize(50, 20)
        self.saveButton.clicked.connect(self.setSettings)
        
        self.layout = QVBoxLayout()
        self.layout.addWidget(self.tabs)
        self.layout.addWidget(self.saveButton)
        self.setLayout(self.layout)
        
        self.loadSettings()
        
        
    def loadSettings(self):
        self.enableDirScanButton.setChecked(VirusHunter.config_data["enableDirScan"])
        self.enableQueryLimiterButton.setChecked(VirusHunter.config_data["enableQueryLimiter"])
        self.VT_API_KeyField.setText(VirusHunter.config_data["VT_API_Key"])
        
    def setSettings(self):
        VirusHunter.cfg.setSetting("enableDirScan", self.enableDirScanButton.isChecked())
        VirusHunter.cfg.setSetting("enableQueryLimiter", self.enableQueryLimiterButton.isChecked())
        VirusHunter.cfg.setSetting("VT_API_Key", self.VT_API_KeyField.text())
        
        VirusHunter.cfg.saveSettings()
        
        self.close()
        
     
def QSSLoader(fileData):
    data = ""
    
    with open(fileData, 'r') as file:   
        data = file.read()
        
    return data