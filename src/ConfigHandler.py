import yaml
from yaml import SafeLoader

class Config:
    def __init__(self, config_file) -> None:
        self.config_file = config_file
    
    def load(self):
        with open(self.config_file, "r") as f:
            self.yaml_data = yaml.load(f, Loader=SafeLoader) #Lecture du fichier de config
            
    def setSetting(self, key, value):
        self.yaml_data[key] = value
        
        
    def saveSettings(self):
        with open(self.config_file, 'w') as f:
            yaml.dump(self.yaml_data, f)
            
    def getData(self):
        return self.yaml_data