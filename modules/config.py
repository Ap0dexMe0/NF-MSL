from configparser import ConfigParser

def setup_config(config_file='config.ini'):
    config = ConfigParser()
    config.read(config_file)
    return config