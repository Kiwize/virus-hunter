#!/usr/bin/env python3
#---------------------------------------------------
#TPR-01 | Thomas PRADEAU | 2023-02-04 | v.3.0
#---------------------------------------------------

import PyQt5.QtWidgets as widgets
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget
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
        app = QApplication(sys.argv)
        app.setStyleSheet(QSSLoader("qss/globalStyle.css"))
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
        sys.exit(app.exec_())
        
        
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


class SubWindow(QWidget):
    def __init__(self):
        super(SubWindow, self).__init__()
        self.resize(400, 300)    
        self.setStyleSheet(QSSLoader("qss/configStyle.css"))
        
        font = QFont()
        font.setPointSize(15)
        
        self.enableDirScanLabel = widgets.QLabel(self)
        self.enableDirScanLabel.setText("Scan des dossier : ")
        self.enableDirScanLabel.setFont(font)
        self.enableDirScanLabel.adjustSize()
        self.enableDirScanLabel.move(10, 10)
        
        self.enableDirScanButton = widgets.QPushButton(self)
        self.enableDirScanButton.setCheckable(True)
        self.enableDirScanButton.setGeometry(15 + self.enableDirScanLabel.width(), 15, 15, 15)
        
        self.saveButton = widgets.QPushButton("Save", self)
        self.saveButton.setGeometry(100, 100, 50, 50)
        self.saveButton.clicked.connect(self.setSettings)
        
        
    def loadSettings(self):
        self.enableDirScanButton.setChecked(VirusHunter.config_data["enableDirScan"])
        
    def setSettings(self):
        VirusHunter.cfg.setSetting("enableDirScan", self.saveButton.isChecked())
        
        VirusHunter.cfg.saveSettings()
        
     
def QSSLoader(fileData):
    data = ""
    
    with open(fileData, 'r') as file:   
        data = file.read()
        
    return data