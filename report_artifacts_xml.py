'''
Copyright 2022 Flexera Software LLC
See LICENSE.TXT for full license text
SPDX-License-Identifier: MIT

Author : sgeary  
Created On : Thu Mar 10 2022
File : report_artifacts_xml.py
'''

import logging
import xml.etree.ElementTree as ET
from xml.dom import minidom


import _version

logger = logging.getLogger(__name__)


#------------------------------------------------------------------#
def generate_xml_report(reportData):
    logger.info("    Entering generate_html_report")
    

    reportFileNameBase = reportData["reportFileNameBase"]
    inventoryData = reportData["inventoryData"]
    serialNumber = reportData["serialNumber"]
    reportUTCTimeStamp = reportData["reportUTCTimeStamp"]
    CodeInsightReleaseYear = reportData["CodeInsightReleaseYear"]


    applicationPublisher = reportData["applicationPublisher"]
    applicationName = reportData["applicationName"]
    applicationVersion = reportData["applicationVersion"] 


    xmlFile = reportFileNameBase + ".xml"

    root= ET.Element("bom", xmlns="http://cyclonedx.org/schema/bom/1.4", serialNumber="urn:uuid:" + serialNumber, version="1")

    metadata = ET.SubElement(root, "metadata")
    timestamp = ET.SubElement(metadata, "timestamp")
    timestamp.text = reportUTCTimeStamp
    
    tools = ET.SubElement(metadata, "tools")
    tool = ET.SubElement(tools, "tool")

    toolVendor = ET.SubElement(tool, "vendor")
    toolVendor.text = "Revenera"
    toolName = ET.SubElement(tool, "name")
    toolName.text = "Code Insight"
    toolVersion = ET.SubElement(tool, "version")
    toolVersion.text = CodeInsightReleaseYear

    component = ET.SubElement(metadata, "component", type="application")

    publisherName= ET.SubElement(component, "publisher")
    publisherName.text = applicationPublisher

    name= ET.SubElement(component, "name")
    name.text = applicationName
    version = ET.SubElement(component, "version")
    version.text = applicationVersion
    

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

        purlValue = ET.SubElement(cycloneDXEntry, "purl")
        purlValue.text = purl

        externalReferences = ET.SubElement(cycloneDXEntry, "externalReferences")
        reference = ET.SubElement(externalReferences, "reference", type="website")
        url = ET.SubElement(reference, "url")
        url.text = componentUrl

        


    xmlstr = minidom.parseString(ET.tostring(root)).toprettyxml(indent="   ")
    with open(xmlFile, "w") as f:
        f.write(xmlstr)


   

    logger.info("    Exiting generate_html_report")
    return xmlFile