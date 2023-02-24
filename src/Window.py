#!/usr/bin/env python3
#---------------------------------------------------
#JVA-01 | Thomas PRADEAU | 2023-02-04 | v.3.0
#---------------------------------------------------

import PyQt5.QtWidgets as widgets
from PyQt5.QtWidgets import QApplication, QMainWindow
from PyQt5.QtCore import QCoreApplication
import sys
import VirusHunter as vh

class Window:
    def __init__(self, vtscanner) -> None:
        self.winH = 300
        self.winW = 300
        self.winName = "Virustotal Scanbot"
        self.vtscanner = vtscanner

    def initWindow(self):
        app = QApplication(sys.argv)
        win = QMainWindow()
        win.setGeometry(0, 0, self.winW,self.winH)
        win.setWindowTitle(self.winName)
        
        self.win = win
        
        label = widgets.QLabel(win)
        label.setText("Virustotal Scanbot V3.0")
        label.adjustSize()
        label.move(self.winW / 2 - label.width() / 2, 10)
        
        button = widgets.QPushButton(win)
        button.setText("Begin scan")
        button.adjustSize()
        button.move(self.winW / 2 - button.width() / 2, 50)
        button.clicked.connect(self.beginScanCallback)
        self.button = button
        
        scanstate = widgets.QLabel(win)
        scanstate.setText("Aucun scan en cours.")
        scanstate.adjustSize()
        scanstate.move(self.winW / 2 - scanstate.width() / 2, 80)
        
        self.scanstate = scanstate
        
        win.show()   
        sys.exit(app.exec_())
        
        
    def beginScanCallback(self):
        self.button.setEnabled(False)
        self.scanstate.setText("Scan en cours...")
        self.scanstate.adjustSize()
        self.scanstate.move(self.winW / 2 - self.scanstate.width() / 2, 80)
        QCoreApplication.processEvents()

        self.vtscanner.beginScan()
        
        self.button.setEnabled(True)
        self.scanstate.setText("Scan terminé !")
        self.scanstate.adjustSize()
        self.scanstate.move(self.winW / 2 - self.scanstate.width() / 2, 80)
