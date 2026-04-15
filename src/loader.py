from pathlib import Path

import yaml


def load_yaml_documents(path):
    file_path = Path(path)
    with file_path.open("r", encoding="utf-8") as handle:
        documents = yaml.safe_load_all(handle)
        return [doc for doc in documents if doc]
