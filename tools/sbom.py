import json,sys
sbom={
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "metadata": {
    "component": {
      "type": "application",
      "name": "ainrf1",
      "version": "0.1.0"
    }
  }
}
print(json.dumps(sbom))
