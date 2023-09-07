'''
Copyright 2023 Flexera Software LLC
See LICENSE.TXT for full license text
SPDX-License-Identifier: MIT

Author : sgeary  
Created On : Wed Sep 06 2023
File : report_artifacts_json.py
'''
import logging, json
logger = logging.getLogger(__name__)

#--------------------------------------------------------------------------------#

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

    applicationPublisher = reportData["applicationDetails"]["applicationPublisher"]
    applicationName = reportData["applicationDetails"]["applicationName"]
    applicationVersion = reportData["applicationDetails"]["applicationVersion"]

    reportDetails = {}
    reportDetails["bomFormat"] = bomFormat
    reportDetails["specVersion"] = specVersion
    reportDetails["serialNumber"] = serialNumber
    reportDetails["version"] = int(bomVersion)

    reportDetails["metadata"] = {}
    reportDetails["metadata"]["timestamp"] = reportUTCTimeStamp
    reportDetails["metadata"]["tools"] = []

    toolDetails = {}
    toolDetails["vendor"] = releaseDetails["vendor"]
    toolDetails["name"] = releaseDetails["tool"]
    toolDetails["version"] = releaseDetails["releaseVersion"]
    
    reportDetails["metadata"]["tools"].append(toolDetails)

    reportDetails["metadata"]["component"] = {}
    reportDetails["metadata"]["component"]["type"] = "application"
    if applicationPublisher:
        reportDetails["metadata"]["component"]["publisher"] = applicationPublisher
    if applicationName:
        reportDetails["metadata"]["component"]["name"] = applicationName
    if applicationVersion:
        reportDetails["metadata"]["component"]["version"] = applicationVersion

    reportDetails["components"]= []


    for inventoryID in inventoryData:

        bomref = inventoryData[inventoryID]["bomref"]
        componentName = inventoryData[inventoryID]["componentName"]
        componentVersionName = inventoryData[inventoryID]["componentVersionName"]
        componentDescription = inventoryData[inventoryID]["componentDescription"]
        licenseDetails = inventoryData[inventoryID]["licenseDetails"]
        componentUrl = inventoryData[inventoryID]["componentUrl"]
        purl = inventoryData[inventoryID]["purl"]

        component = {}
        if bomref != "":
            component["bom-ref"] = bomref
        
        component["type"] = "library"
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

        component["purl"] = purl
        component["externalReferences"] = []
        externalReference = {}
        externalReference["type"] = "website"
        externalReference["url"] = componentUrl
        component["externalReferences"].append(externalReference)

        reportDetails["components"].append(component)



    try:
        report_ptr = open(jsonFile,"w")
    except:
        print("Failed to open file %s:" %jsonFile)
        logger.error("Failed to open file %s:" %jsonFile)
        return {"errorMsg" : "Failed to open file %s:" %jsonFile}

    json.dump(reportDetails, report_ptr, indent=4)

    report_ptr.close() 

    logger.info("    Exiting generate_json_report")

    return jsonFile