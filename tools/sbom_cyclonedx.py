
#!/usr/bin/env python3
import json, sys, subprocess, hashlib
from datetime import datetime

def cargo_metadata():
    md = subprocess.check_output(["cargo", "metadata", "--format-version", "1"], text=True)
    return json.loads(md)

def to_cyclonedx(md):
    pkgs = {p["id"]: p for p in md["packages"]}
    deps = {d["name"]: d for d in md.get("resolve",{}).get("nodes",[])}
    components = []
    for p in md["packages"]:
        comp = {
            "type": "library",
            "bom-ref": p["id"],
            "name": p["name"],
            "version": p.get("version",""),
            "licenses": [{"license": {"id": lic}}] if (lic:=p.get("license")) else [],
            "purl": f"pkg:cargo/{p['name']}@{p.get('version','')}"
        }
        components.append(comp)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "metadata": {"timestamp": datetime.utcnow().isoformat()+"Z", "tools":[{"vendor":"AI-NRF1","name":"sbom.py"}]},
        "components": components
    }

if __name__=="__main__":
    md = cargo_metadata()
    print(json.dumps(to_cyclonedx(md), indent=2))
