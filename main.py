"""
Main script and configuration file.
"""
import json
import logging.config
from pathlib import Path

Path("network_mapper.log")
logger = logging.getLogger(__name__)

def setup_logging():
    with open("src/logging.json") as config_file:
        config = json.load(config_file)

    logging.config.dictConfig(config)


class App:
    def __init__(self):
        setup_logging()

    def run(self):
        # Idk we're probably gonna first call the network scanning module here and thats about it...
        pass

if __name__ == "__main__":
    App().run()