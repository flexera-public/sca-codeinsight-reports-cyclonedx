"""
Copyright 2022 Flexera Software LLC
See LICENSE.TXT for full license text
SPDX-License-Identifier: MIT

Author : sgeary
Created On : Thu Mar 10 2022
File : report_artifacts_xml.py
"""

import logging, json
import xml.etree.ElementTree as ET
from xml.dom import minidom

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------#
def generate_cyclonedx_report(reportData):
    logger.info("    Entering generate_cyclonedx_report")

    reportFileNameBase = reportData["reportFileNameBase"]
    inventoryData = reportData["inventoryData"]
    serialNumber = reportData["serialNumber"]
    bomVersion = reportData["bomVersion"]
    specVersion = reportData["specVersion"]
    reportUTCTimeStamp = reportData["reportUTCTimeStamp"]
    releaseDetails = reportData["releaseDetails"]

    xmlFile = reportFileNameBase + ".xml"

    root = ET.Element(
        "bom",
        xmlns="http://cyclonedx.org/schema/bom/" + specVersion,
        serialNumber=serialNumber,
        version=bomVersion,
    )

    metadata = ET.SubElement(root, "metadata")
    timestamp = ET.SubElement(metadata, "timestamp")
    timestamp.text = reportUTCTimeStamp

    tools = ET.SubElement(metadata, "tools")
    tool = ET.SubElement(tools, "components")
    toolsComponents = ET.SubElement(tool, "component", type="application")

    author = ET.SubElement(toolsComponents, "author")
    author.text = releaseDetails["vendor"]
    toolName = ET.SubElement(toolsComponents, "name")
    toolName.text = releaseDetails["tool"]
    toolVersion = ET.SubElement(toolsComponents, "version")
    toolVersion.text = releaseDetails["releaseVersion"]
    component = ET.SubElement(metadata, "component", type="application")

    publisherName = ET.SubElement(component, "publisher")

    name = ET.SubElement(component, "name")
    version = ET.SubElement(component, "version")

    inventoryComponents = ET.SubElement(root, "components")

    for inventoryID in inventoryData:

        bomref = inventoryData[inventoryID]["bomref"]
        componentName = inventoryData[inventoryID]["componentName"]
        componentVersionName = inventoryData[inventoryID]["componentVersionName"]
        componentDescription = inventoryData[inventoryID]["componentDescription"]
        licenseDetails = inventoryData[inventoryID]["licenseDetails"]
        componentUrl = inventoryData[inventoryID]["componentUrl"]
        purl = inventoryData[inventoryID]["purl"]

        cycloneDXEntry = ET.SubElement(inventoryComponents, "component", type="library")

        if bomref != "":
            cycloneDXEntry.set("bom-ref", bomref)

        author = ET.SubElement(cycloneDXEntry, "author")

        componentNameValue = ET.SubElement(cycloneDXEntry, "name")
        componentNameValue.text = componentName

        componentVersionValue = ET.SubElement(cycloneDXEntry, "version")
        componentVersionValue.text = componentVersionName

        descriptionValue = ET.SubElement(cycloneDXEntry, "description")
        descriptionValue.text = componentDescription

        licenses = ET.SubElement(cycloneDXEntry, "licenses")

        if licenseDetails["licenseObjectType"] == "expression":

            expression = ET.SubElement(licenses, "expression")
            expression.text = licenseDetails["possibleLicenses"]

        else:
            license = ET.SubElement(licenses, "license")

            if "SPDXID" in licenseDetails:
                licenseID = ET.SubElement(license, "id")
                licenseID.text = licenseDetails["SPDXID"]
            else:
                licenseName = ET.SubElement(license, "name")
                licenseName.text = licenseDetails["licenseName"]

            licenseURL = ET.SubElement(license, "url")
            licenseURL.text = licenseDetails["licenseURL"]

            if purl:
                purlValue = ET.SubElement(cycloneDXEntry, "purl")
                purlValue.text = purl

        externalReferences = ET.SubElement(cycloneDXEntry, "externalReferences")
        reference = ET.SubElement(externalReferences, "reference", type="website")
        url = ET.SubElement(reference, "url")
        url.text = componentUrl

    xmlstr = minidom.parseString(ET.tostring(root)).toprettyxml(indent="   ")
    with open(xmlFile, "w", encoding="utf-8") as f:
        f.write(xmlstr)

    logger.info("    Exiting generate_html_report")
    return xmlFile


# ------------------------------------------------------------------#
def generate_vdr_report(reportData):
    logger.info("    Entering generate_vdr_report")

    reportFileNameBase = reportData["reportFileNameBase"]
    vulnerabilityData = reportData["vulnerabilityVdrData"]

    xmlVRDFile = reportFileNameBase.replace("CycloneDX", "VDR") + ".xml"

    root = ET.Element("bom", xmlns="http://cyclonedx.org/schema/bom/1.6", version="1")
    vulnerabilities = ET.SubElement(root, "vulnerabilities")

    for vulnerability in vulnerabilityData:

        vulnerabilityDetails = vulnerabilityData[vulnerability]

        vulnerabilityRoot = ET.SubElement(vulnerabilities, "vulnerability")
        vulnerabilityID = ET.SubElement(vulnerabilityRoot, "id")
        vulnerabilityID.text = vulnerability

        vulnerabilitySource = ET.SubElement(vulnerabilityRoot, "source")
        vulnerabilitySourceName = ET.SubElement(vulnerabilitySource, "name")
        vulnerabilitySourceName.text = vulnerabilityDetails["vulnerabilitySource"]
        vulnerabilitySourceURL = ET.SubElement(vulnerabilitySource, "url")
        vulnerabilitySourceURL.text = vulnerabilityDetails["vulnerabilityUrl"]

        vulnerabilityRatings = ET.SubElement(vulnerabilityRoot, "ratings")
        vulnerabilityRating = ET.SubElement(vulnerabilityRatings, "rating")

        vulnerabilityRatingSource = ET.SubElement(vulnerabilityRating, "source")
        vulnerabilityRatingSourceName = ET.SubElement(vulnerabilityRatingSource, "name")
        vulnerabilityRatingSourceName.text = vulnerabilityDetails["vulnerabilitySource"]
        vulnerabilityRatingSourceURL = ET.SubElement(vulnerabilityRatingSource, "url")
        vulnerabilityRatingSourceURL.text = vulnerabilityDetails["vulnerabilityUrl"]

        vulnerabilityRatingScore = ET.SubElement(vulnerabilityRating, "score")
        vulnerabilityRatingScore.text = vulnerabilityDetails["vulnerabilityScore"]
        vulnerabilityRatingSseverity = ET.SubElement(vulnerabilityRating, "severity")
        vulnerabilityRatingSseverity.text = vulnerabilityDetails[
            "vulnerabilitySeverity"
        ]
        vulnerabilityRatingMethod = ET.SubElement(vulnerabilityRating, "method")
        vulnerabilityRatingMethod.text = vulnerabilityDetails["vulnerabilityMethod"]
        vulnerabilityRatingVector = ET.SubElement(vulnerabilityRating, "vector")
        vulnerabilityRatingVector.text = vulnerabilityDetails["vulnerabilityVector"]

        vulnerabilitycwes = ET.SubElement(vulnerabilityRoot, "cwes")

        for cwe in vulnerabilityDetails["vulnerabilityCWE"]:
            vulnerabilitycwe = ET.SubElement(vulnerabilitycwes, "cwe")
            vulnerabilitycwe.text = cwe

        vulnerabilityDescription = ET.SubElement(vulnerabilityRoot, "description")
        vulnerabilityDescription.text = vulnerabilityDetails["vulnerabilityDescription"]

        vulnerabilityCreatedDate = ET.SubElement(vulnerabilityRoot, "created")
        vulnerabilityCreatedDate.text = vulnerabilityDetails["createdDate"]
        vulnerabilityPublishedDate = ET.SubElement(vulnerabilityRoot, "published")
        vulnerabilityPublishedDate.text = vulnerabilityDetails["publishedDate"]
        vulnerabilityUpdatedDate = ET.SubElement(vulnerabilityRoot, "updated")
        vulnerabilityUpdatedDate.text = vulnerabilityDetails["modifiedDate"]

        vulnerabilityAffects = ET.SubElement(vulnerabilityRoot, "affects")
        vulnerabilityAffectsTarget = ET.SubElement(vulnerabilityAffects, "target")

        for affectedComponent in vulnerabilityDetails["affectedComponents"]:
            vulnerabilityAffectsTargetRef = ET.SubElement(
                vulnerabilityAffectsTarget, "ref"
            )
            vulnerabilityAffectsTargetRef.text = affectedComponent

    xmlstr = minidom.parseString(ET.tostring(root)).toprettyxml(indent="   ")
    with open(xmlVRDFile, "w", encoding="utf-8") as f:
        f.write(xmlstr)

    logger.info("    Exiting generate_vdr_report")
    return xmlVRDFile


# ------------------------------------------------------------------#
def generate_vex_report(reportData):
    logger.info("    Entering generate_vex_report")

    reportFileNameBase = reportData["reportFileNameBase"]
    vulnerabilityData = reportData["vulnerabilityVexData"]
    xmlVEXFile = reportFileNameBase.replace("CycloneDX", "VEX") + ".xml"

    root = ET.Element("bom", xmlns="http://cyclonedx.org/schema/bom/1.6", version="1")
    vulnerabilities = ET.SubElement(root, "vulnerabilities")
    for vulnerability in vulnerabilityData:

        vulnerabilityDetails = vulnerabilityData[vulnerability]

        vulnerabilityRoot = ET.SubElement(vulnerabilities, "vulnerability")
        vulnerabilityID = ET.SubElement(vulnerabilityRoot, "id")
        vulnerabilityID.text = vulnerability

        vulnerabilitySource = ET.SubElement(vulnerabilityRoot, "source")
        vulnerabilitySourceName = ET.SubElement(vulnerabilitySource, "name")
        vulnerabilitySourceName.text = vulnerabilityDetails["vulnerabilitySource"]
        vulnerabilitySourceURL = ET.SubElement(vulnerabilitySource, "url")
        vulnerabilitySourceURL.text = vulnerabilityDetails["vulnerabilityUrl"]

        vulnerabilityRatings = ET.SubElement(vulnerabilityRoot, "ratings")
        vulnerabilityRating = ET.SubElement(vulnerabilityRatings, "rating")

        vulnerabilityRatingSource = ET.SubElement(vulnerabilityRating, "source")
        vulnerabilityRatingSourceName = ET.SubElement(vulnerabilityRatingSource, "name")
        vulnerabilityRatingSourceName.text = vulnerabilityDetails["vulnerabilitySource"]
        vulnerabilityRatingSourceURL = ET.SubElement(vulnerabilityRatingSource, "url")
        vulnerabilityRatingSourceURL.text = vulnerabilityDetails["vulnerabilityUrl"]

        vulnerabilityRatingScore = ET.SubElement(vulnerabilityRating, "score")
        vulnerabilityRatingScore.text = vulnerabilityDetails["vulnerabilityScore"]
        vulnerabilityRatingSseverity = ET.SubElement(vulnerabilityRating, "severity")
        vulnerabilityRatingSseverity.text = vulnerabilityDetails[
            "vulnerabilitySeverity"
        ]
        vulnerabilityRatingMethod = ET.SubElement(vulnerabilityRating, "method")
        vulnerabilityRatingMethod.text = vulnerabilityDetails["vulnerabilityMethod"]
        vulnerabilityRatingVector = ET.SubElement(vulnerabilityRating, "vector")
        vulnerabilityRatingVector.text = vulnerabilityDetails["vulnerabilityVector"]

        vulnerabilitycwes = ET.SubElement(vulnerabilityRoot, "cwes")

        for cwe in vulnerabilityDetails["vulnerabilityCWE"]:
            vulnerabilitycwe = ET.SubElement(vulnerabilitycwes, "cwe")
            vulnerabilitycwe.text = cwe

        vulnerabilityDescription = ET.SubElement(vulnerabilityRoot, "description")
        vulnerabilityDescription.text = vulnerabilityDetails["vulnerabilityDescription"]

        vulnerabilityCreatedDate = ET.SubElement(vulnerabilityRoot, "created")
        vulnerabilityCreatedDate.text = vulnerabilityDetails["createdDate"]
        vulnerabilityPublishedDate = ET.SubElement(vulnerabilityRoot, "published")
        vulnerabilityPublishedDate.text = vulnerabilityDetails["publishedDate"]
        vulnerabilityUpdatedDate = ET.SubElement(vulnerabilityRoot, "updated")
        vulnerabilityUpdatedDate.text = vulnerabilityDetails["modifiedDate"]

        vulnerabilityAnalysis = ET.SubElement(vulnerabilityRoot, "analysis")
        vulnerabilityAnalysisState = ET.SubElement(vulnerabilityAnalysis, "state")
        if "state" in vulnerabilityDetails and vulnerabilityDetails["state"]:
            vulnerabilityAnalysisState = ET.SubElement(vulnerabilityAnalysis, "state")
            vulnerabilityAnalysisState.text = vulnerabilityDetails["state"]

        if "justification" in vulnerabilityDetails and vulnerabilityDetails["justification"]:
            vulnerabilityAnalysisJustification = ET.SubElement(vulnerabilityAnalysis, "justification")
            vulnerabilityAnalysisJustification.text = vulnerabilityDetails["justification"]

        if "response" in vulnerabilityDetails and vulnerabilityDetails["response"]:
            vulnerabilityAnalysisResponses = ET.SubElement(vulnerabilityAnalysis, "responses")
            vulnerabilityAnalysisResponse = ET.SubElement(vulnerabilityAnalysisResponses, "responses")
            vulnerabilityAnalysisResponse.text = vulnerabilityDetails["response"]

        if "detail" in vulnerabilityDetails and vulnerabilityDetails["detail"]:
            vulnerabilityAnalysisDetail = ET.SubElement(vulnerabilityAnalysis, "details")
            vulnerabilityAnalysisDetail.text = vulnerabilityDetails["detail"]

        vulnerabilityAffects = ET.SubElement(vulnerabilityRoot, "affects")
        vulnerabilityAffectsTarget = ET.SubElement(vulnerabilityAffects, "target")

        for affectedComponent in vulnerabilityDetails["affectedComponents"]:
            vulnerabilityAffectsTargetRef = ET.SubElement(
                vulnerabilityAffectsTarget, "ref"
            )
            vulnerabilityAffectsTargetRef.text = affectedComponent

    xmlstr = minidom.parseString(ET.tostring(root)).toprettyxml(indent="   ")
    with open(xmlVEXFile, "w", encoding="utf-8") as f:
        f.write(xmlstr)

    logger.info("    Exiting generate_vex_report")
    return xmlVEXFile


def generate_vdr_json_report(reportData):
    logger.info("    Entering generate_vdr_json_report")

    bomFormat = reportData["bomFormat"]
    bomVersion = reportData["bomVersion"]
    specVersion = reportData["specVersion"]
    serialNumber = reportData["serialNumber"]
    reportFileNameBase = reportData["reportFileNameBase"]
    vulnerabilityData = reportData["vulnerabilityData"]

    jsonVDRFile = reportFileNameBase.replace("CycloneDX", "VDR") + ".json"

    reportDetails = {
        "bomFormat": bomFormat,
        "specVersion": specVersion,
        "serialNumber": serialNumber,
        "version": int(bomVersion),
        "vulnerabilities": [],
    }

    for vulnerability in vulnerabilityData:
        vulnerabilityDetails = vulnerabilityData[vulnerability]

        vulnerabilityEntry = {
            "id": vulnerability,
            "source": {
                "name": vulnerabilityDetails["vulnerabilitySource"],
                "url": vulnerabilityDetails["vulnerabilityUrl"],
            },
            "ratings": [
                {
                    "source": {
                        "name": vulnerabilityDetails["vulnerabilitySource"],
                        "url": vulnerabilityDetails["vulnerabilityUrl"],
                    },
                    "score": (
                        float(vulnerabilityDetails["vulnerabilityScore"])
                        if vulnerabilityDetails["vulnerabilityScore"]
                        and vulnerabilityDetails["vulnerabilityScore"].strip().lower()
                        != "n/a"
                        else 0.0
                    ),
                    "severity": vulnerabilityDetails["vulnerabilitySeverity"].lower(),
                    "method": vulnerabilityDetails["vulnerabilityMethod"],
                    "vector": vulnerabilityDetails["vulnerabilityVector"],
                }
            ],
            "cwes": [int(cwe) for cwe in vulnerabilityDetails["vulnerabilityCWE"]],
            "description": vulnerabilityDetails["vulnerabilityDescription"],
            "created": vulnerabilityDetails["createdDate"],
            "published": vulnerabilityDetails["publishedDate"],
            "updated": vulnerabilityDetails["modifiedDate"],
            "affects": [
                {"ref": affectedComponent}
                for affectedComponent in vulnerabilityDetails["affectedComponents"]
            ],
        }

        reportDetails["vulnerabilities"].append(vulnerabilityEntry)

    try:
        report_ptr = open(jsonVDRFile, "w", encoding="utf-8")
    except:
        print("Failed to open file %s:" % jsonVDRFile)
        logger.error("Failed to open file %s:" % jsonVDRFile)
        return {"errorMsg": "Failed to open file %s:" % jsonVDRFile}

    json.dump(reportDetails, report_ptr, indent=4)

    report_ptr.close()

    logger.info("    Exiting generate_json_report")

    return jsonVDRFile


def generate_vex_json_report(reportData):
    logger.info("    Entering generate_vex_json_report")

    reportFileNameBase = reportData["reportFileNameBase"]
    vulnerabilityData = reportData["vulnerabilityData"]
    suppressedVulnerabilityData = reportData["supressedVulnerabilityData"]
    jsonVEXFile = reportFileNameBase.replace("CycloneDX", "VEX") + ".json"

    # Merge suppressed vulnerabilities into the main vulnerability data
    for vuln, data in suppressedVulnerabilityData.items():
        vulnerabilityData[vuln] = data

    reportDetails = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "vulnerabilities": [],
    }

    for vulnerability in vulnerabilityData:
        vulnerabilityDetails = vulnerabilityData[vulnerability]

        # Skip if the item is not excluded
        if "excluded" not in vulnerabilityDetails:
            continue

        vulnerabilityEntry = {
            "id": vulnerability,
            "source": {
                "name": vulnerabilityDetails["vulnerabilitySource"],
                "url": vulnerabilityDetails["vulnerabilityUrl"],
            },
            "ratings": [
                {
                    "source": {
                        "name": vulnerabilityDetails["vulnerabilitySource"],
                        "url": vulnerabilityDetails["vulnerabilityUrl"],
                    },
                    "score": (
                        float(vulnerabilityDetails["vulnerabilityScore"])
                        if vulnerabilityDetails["vulnerabilityScore"]
                        and vulnerabilityDetails["vulnerabilityScore"].strip().lower()
                        != "n/a"
                        else None
                    ),
                    "severity": vulnerabilityDetails["vulnerabilitySeverity"].lower(),
                    "method": vulnerabilityDetails["vulnerabilityMethod"],
                    "vector": vulnerabilityDetails["vulnerabilityVector"],
                }
            ],
            "cwes": [int(cwe) for cwe in vulnerabilityDetails["vulnerabilityCWE"]],
            "description": vulnerabilityDetails["vulnerabilityDescription"],
            "created": vulnerabilityDetails["createdDate"],
            "published": vulnerabilityDetails["publishedDate"],
            "updated": vulnerabilityDetails["modifiedDate"],
            "analysis": {
                "state": vulnerabilityDetails["state"],
                "justification": vulnerabilityDetails["justification"],
                "responses": [vulnerabilityDetails["response"]],
                "detail": vulnerabilityDetails["detail"],
            },
            "affects": [
                {"ref": affectedComponent}
                for affectedComponent in vulnerabilityDetails["affectedComponents"]
            ],
        }

        reportDetails["vulnerabilities"].append(vulnerabilityEntry)

    try:
        with open(jsonVEXFile, "w", encoding="utf-8") as f:
            json.dump(reportDetails, f, indent=4)
    except Exception as e:
        logger.error(f"Failed to write JSON file: {e}")
        return None

    logger.info("    Exiting generate_vex_json_report")
    return jsonVEXFile
