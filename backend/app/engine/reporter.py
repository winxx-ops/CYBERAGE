"""CyberAge Report Artifact Generator."""

import json

class CyberReporter:
    @staticmethod
    def save_json(filepath: str, data: dict) -> None:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
