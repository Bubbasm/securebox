import os
import configparser
from xdg_base_dirs import xdg_config_home, xdg_data_home

APP_NAME = 'SecureBox'
APP_VERSION = 'v0.1'
AUTHORS = 'Samuel de Lucas and Bhavuk Sikka'
SAVE_FILE = 'securebox.json'
CONFIG_FILE = 'securebox.conf'
SAVE_FOLDER = os.path.join(xdg_data_home(), 'securebox')
CONFIG_FOLDER = os.path.join(xdg_config_home(), 'securebox')
AUTO_UPLOAD = False

# ------------------------------------------------------------------------------

CONFIG_PATH = os.path.join(CONFIG_FOLDER, CONFIG_FILE)

if not os.path.exists(CONFIG_PATH):
    CONFIG_FILE_EXAMPLE = "[securebox]" + os.linesep
    CONFIG_FILE_EXAMPLE += f"SAVE_FOLDER = {SAVE_FOLDER}" + os.linesep
    CONFIG_FILE_EXAMPLE += "AUTO_UPLOAD = False"

    os.makedirs(CONFIG_FOLDER, exist_ok=True)

    with open(CONFIG_PATH, 'w') as f:
        f.write(CONFIG_FILE_EXAMPLE)

# Load the configuration file
config = configparser.ConfigParser()
config.read(CONFIG_PATH)
SAVE_FOLDER = config['securebox'].get('SAVE_FOLDER', SAVE_FOLDER)
SAVE_PATH = os.path.join(SAVE_FOLDER, SAVE_FILE)
AUTO_UPLOAD = config['securebox'].getboolean('AUTO_UPLOAD', AUTO_UPLOAD)

if not os.path.exists(SAVE_FOLDER):
    os.makedirs(SAVE_FOLDER, exist_ok=True)
