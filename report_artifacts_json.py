"""
Copyright 2023 Flexera Software LLC
See LICENSE.TXT for full license text
SPDX-License-Identifier: MIT

Author : sgeary
Created On : Wed Sep 06 2023
File : report_artifacts_json.py
"""

import logging, json

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------------#
vulnerabilities = []

def generate_json_report(reportData):
    logger.info("    Entering generate_json_report")

    reportFileNameBase = reportData["reportFileNameBase"]
    jsonFile = reportFileNameBase + ".json"

    inventoryData = reportData["inventoryData"]
    specVersion = reportData["specVersion"]
    serialNumber = reportData["serialNumber"]
    bomFormat = reportData["bomFormat"]
    bomVersion = reportData["bomVersion"]
    reportUTCTimeStamp = reportData["reportUTCTimeStamp"]
    releaseDetails = reportData["releaseDetails"]

    reportDetails = {}
    reportDetails["bomFormat"] = bomFormat
    reportDetails["specVersion"] = specVersion
    reportDetails["serialNumber"] = serialNumber
    reportDetails["version"] = int(bomVersion)

    reportDetails["metadata"] = {}
    reportDetails["metadata"]["timestamp"] = reportUTCTimeStamp
    reportDetails["metadata"]["tools"] = {}

    reportDetails["metadata"]["tools"]["components"] = []
    componentsData = {}
    componentsData["type"] = "application"
    componentsData["author"] = releaseDetails["vendor"]
    componentsData["name"] = releaseDetails["tool"]
    componentsData["version"] = releaseDetails["releaseVersion"]
    reportDetails["metadata"]["tools"]["components"].append(componentsData)

    reportDetails["metadata"]["component"] = {}
    reportDetails["metadata"]["component"]["type"] = "application"
    reportDetails["metadata"]["component"]["name"] = reportData["topLevelProjectName"]

    reportDetails["components"] = []
    reportDetails["dependencies"] = []

    if reportData["reportOptions"]["includeVDRReport"] and reportData["reportOptions"]["includeVEXReport"]:
        # Merge both dicts, VEX can override VDR if same id
        combined = {**reportData["vulnerabilityVdrData"], **reportData["vulnerabilityVexData"]}
        vulnerabilities = transform_vulnerabilities(combined)
    elif reportData["reportOptions"]["includeVDRReport"]:
        vulnerabilities = transform_vulnerabilities(reportData["vulnerabilityVdrData"])
    elif reportData["reportOptions"]["includeVEXReport"]:
        vulnerabilities = transform_vulnerabilities(reportData["vulnerabilityVexData"])

    if vulnerabilities:
        reportDetails["vulnerabilities"] = vulnerabilities

    for inventoryID in inventoryData:

        bomref = inventoryData[inventoryID]["bomref"]
        componentName = inventoryData[inventoryID]["componentName"]
        componentVersionName = inventoryData[inventoryID]["componentVersionName"]
        componentDescription = inventoryData[inventoryID]["componentDescription"]
        licenseDetails = inventoryData[inventoryID]["licenseDetails"]
        componentUrl = inventoryData[inventoryID]["componentUrl"]
        purl = inventoryData[inventoryID]["purl"]
        componentSupplier = inventoryData[inventoryID]["componentSupplier"]
        componentDependency = inventoryData[inventoryID]["componentDependency"]


        component = {}
        if bomref != "":
            component["bom-ref"] = bomref

        component["type"] = "library"
        component["supplier"] = {"bom-ref":bomref ,"name": componentSupplier}
        component["name"] = componentName
        component["version"] = componentVersionName
        component["description"] = componentDescription
        component["licenses"] = []

        license = {}

        if licenseDetails["licenseObjectType"] == "expression":
            license["expression"] = licenseDetails["possibleLicenses"]
        else:

            license["license"] = {}
            if "SPDXID" in licenseDetails:
                license["license"]["id"] = licenseDetails["SPDXID"]
            else:
                license["license"]["name"] = licenseDetails["licenseName"]

            license["license"]["url"] = licenseDetails["licenseURL"]

        component["licenses"].append(license)
        if componentDependency.get("ref") != "" and len(componentDependency.get("dependsOn")) > 0:
            # Flatten dependsOn to a list of invName strings
            flat_depends_on = []
            for inner_list in componentDependency["dependsOn"]:
                for dep in inner_list:
                    if isinstance(dep, dict) and "invName" in dep:
                        flat_depends_on.append(dep["invName"])
            # Create a new dependency dict with flattened dependsOn
            dependency_entry = {
                "ref": componentDependency["ref"],
                "dependsOn": flat_depends_on
            }
            reportDetails["dependencies"].append(dependency_entry)

        component["purl"] = purl
        component["externalReferences"] = []
        externalReference = {}
        externalReference["type"] = "website"
        externalReference["url"] = componentUrl
        component["externalReferences"].append(externalReference)

        reportDetails["components"].append(component)

    try:
        report_ptr = open(jsonFile, "w")
    except:
        print("Failed to open file %s:" % jsonFile)
        logger.error("Failed to open file %s:" % jsonFile)
        return {"errorMsg": "Failed to open file %s:" % jsonFile}

    json.dump(reportDetails, report_ptr, indent=4)

    report_ptr.close()

    logger.info("    Exiting generate_json_report")

    return jsonFile

def transform_vulnerabilities(vuln_dict):
    """
    Transform vulnerabilityVdrData dict to CycloneDX JSON format list.
    """
    unique_ids = set()
    transformed = []
    for vuln_id, vuln_data in vuln_dict.items():
        if vuln_id in unique_ids:
            continue
        unique_ids.add(vuln_id)
    
        def to_iso(date_str):
            # Accepts 'MM/DD/YYYY' or 'MM/DD/YYYY' and returns 'YYYY-MM-DDT00:00:00Z'
            try:
                import datetime
                if "/" in date_str:
                    m, d, y = date_str.split("/")
                    return f"{y.zfill(4)}-{m.zfill(2)}-{d.zfill(2)}T00:00:00Z"
                else:
                    return date_str  # fallback
            except Exception:
                return date_str

        vuln = {
            "bom-ref": "|".join(vuln_data["affectedComponents"]),
            "id": vuln_id,
            "source": {
                "url": vuln_data.get("vulnerabilityUrl", ""),
                "name": vuln_data.get("vulnerabilitySource", "")
            },
            "ratings": [{
                "source": {
                    "url": vuln_data.get("vulnerabilityUrl", ""),
                    "name": vuln_data.get("vulnerabilitySource", "")
                },
                "score": float(vuln_data.get("vulnerabilityScore", 0)),
                "severity": vuln_data.get("vulnerabilitySeverity", "").lower(),
                "method": vuln_data.get("vulnerabilityMethod", ""),
                "vector": vuln_data.get("vulnerabilityVector", "")
            }],
            "cwes": [int(cwe) for cwe in vuln_data.get("vulnerabilityCWE", []) if str(cwe).isdigit()],
            "description": vuln_data.get("vulnerabilityDescription", ""),
            "created": to_iso(vuln_data.get("createdDate", "")),
            "published": to_iso(vuln_data.get("publishedDate", "")),
            "updated": to_iso(vuln_data.get("modifiedDate", "")),
        }

        # Add analysis if any analysis fields are present
        analysis_fields = ["state", "justification", "detail", "response"]
        analysis = {}
        for field in analysis_fields:
            key = field if field != "response" else "response"
            value = vuln_data.get(key)
            if value:
                # Normalize state value by removing spaces if needed
                if field == "state" and isinstance(value, str):
                    value = value.replace(" ", "")
                # response should be a list
                if field == "response" and not isinstance(value, list):
                    value = [value]
                analysis[field] = value
        if analysis:
            vuln["analysis"] = analysis

        transformed.append(vuln)
    return transformed

