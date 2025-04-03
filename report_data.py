'''
Copyright 2022 Flexera Software LLC
See LICENSE.TXT for full license text
SPDX-License-Identifier: MIT

Author : sgeary  
Created On : Thu Mar 10 2022
File : report_data.py
'''

import logging, uuid, unicodedata
from collections import OrderedDict

import common.api.component.get_component_version_vulnerabilities
import common.api.inventory.inventory_vulnerability_analysis
import common.application_details
import common.project_heirarchy
import common.api.project.get_project_inventory
import common.api.project.get_project_information

import purl
import SPDX_license_mappings # To map evidence to an SPDX license name

logger = logging.getLogger(__name__)

#-------------------------------------------------------------------#
def gather_data_for_report(baseURL, projectID, authToken, reportData):
    logger.info("Entering gather_data_for_report")


    projectList = [] # List to hold parent/child details for report
    inventoryData = {}  # Create a dictionary containing the inventory data using inventoryID as keys
    vulnerabilityData = {}  # Create dictionary to hold all unsuppressed vulnerability data based on vul ID across all projects
    suppresedVulnerabilityData = {}  # Create dictionary to hold all suppressed vulnerability data based on vul ID across all projects
    suppressedVulnerabilities = set() # Created a set of vulnerabilities that are suppressed and should not be reanalyzed if present in different inventories.
    reportOptions = reportData["reportOptions"]

    # Parse report options
    includeChildProjects = reportOptions["includeChildProjects"]  # True/False

    serialNumber = "urn:uuid:" + str(uuid.uuid1())
    bomFormat = "CycloneDX"
    bomVersion = "1"
    specVersion = "1.6"

    applicationDetails = common.application_details.determine_application_details(projectID, baseURL, authToken)
    projectList = common.project_heirarchy.create_project_heirarchy(baseURL, authToken, projectID, includeChildProjects)
    topLevelProjectName = projectList[0]["projectName"]

    #  Gather the details for each project and summerize the data
    for project in projectList:

        projectID = project["projectID"]
        projectName = project["projectName"]

        print("        Collect data for project: %s" %projectName)
        print("            Collect inventory details.")
        logger.info("            Collect inventory details")
        projectInventory = common.api.project.get_project_inventory.get_project_inventory_details(baseURL, projectID, authToken)
        inventoryItems = projectInventory["inventoryItems"]
        print("            Inventory has been collected and will be processed.")
        logger.info("            Inventory has been collected and will be processed.")
        # Collect the required data for each inventory item
        for inventoryItem in inventoryItems:
            
            inventoryType = inventoryItem["type"]

            # This is not a component for move to the next item
            if inventoryType != "Component":
                continue

            inventoryID = inventoryItem["id"]  
            inventoryItemName = inventoryItem["name"]     
            componentName = inventoryItem["componentName"]
            componentVersionName = inventoryItem["componentVersionName"]
            componentUrl = inventoryItem["componentUrl"]

            componentDescription = inventoryItem["description"][:100].replace("\n", " - ")
            componentDescription = unicodedata.normalize('NFKD', componentDescription).encode('ASCII', 'ignore').decode('utf-8') 

            # Is there a specified component version?
            if componentDescription == "N/A":
                componentDescription = ""

            # Is there a specified component version?
            if componentVersionName == "N/A" or componentVersionName.lower() == "unknown":
                componentVersionName = ""

            # Attempt to generate a purl string for the component
            try:
                purlString = purl.get_purl_string(inventoryItem, baseURL, authToken)
            except:
                logger.warning("Unable to create purl string for inventory item.")
                purlString = ""

            if purlString != "":
                bomref = purlString + "-" + str(inventoryID)
            else:
                bomref = ""

            # Manage license details
            licenseDetails  = {}

            selectedLicenseSPDXIdentifier = inventoryItem["selectedLicenseSPDXIdentifier"]
            selectedLicenseName = inventoryItem["selectedLicenseName"]
            selectedLicenseUrl = inventoryItem["selectedLicenseUrl"]

            if selectedLicenseName == "I don't know":
                # Grab possible licenses since one was not selected
                possibleLicensesOptions = inventoryItem["possibleLicenses"]
                possibleLicenses = []
                for license in possibleLicensesOptions:
                    possibleLicenses.append(license["licenseName"])

                licenseDetails["licenseObjectType"] = "expression" 
                licenseDetails["possibleLicenses"] = ' OR '.join(possibleLicenses)

            elif selectedLicenseSPDXIdentifier in SPDX_license_mappings.LICENSEMAPPINGS:
                logger.info("        \"%s\" maps to SPDX ID \"%s\"" %(selectedLicenseSPDXIdentifier, SPDX_license_mappings.LICENSEMAPPINGS[selectedLicenseSPDXIdentifier]) )
                licenseDetails["licenseObjectType"] = "license"
                licenseDetails["SPDXID"] = SPDX_license_mappings.LICENSEMAPPINGS[selectedLicenseSPDXIdentifier]
                licenseDetails["licenseURL"] =  selectedLicenseUrl

            else:
                # There is not a valid SPDX ID here
                licenseDetails["licenseObjectType"] = "license"
                licenseDetails["licenseName"] = selectedLicenseName
                licenseDetails["licenseURL"] =  selectedLicenseUrl


            # Store the data for the inventory item for reporting
            inventoryData[inventoryID] = {
                "projectName" : projectName,
                "componentName" : componentName,
                "componentVersionName" : componentVersionName,
                "componentUrl" : componentUrl,
                "componentDescription" : componentDescription, 
                "licenseDetails" : licenseDetails,
                "purl" : purlString,
                "bomref" : bomref
            }

            bomLink = serialNumber + "/" + bomVersion + "#" + componentName + "-" + componentVersionName
            # Grab vulnerability data for support for VEX and VDR reports
            try:
                vulnerabilities = inventoryItem["vulnerabilities"]
                vulnerabilitiesAnalysis = common.api.inventory.inventory_vulnerability_analysis.get_inventory_item_vulnerabilities_any_state(
                    inventoryID, baseURL, authToken)
            except:
                logger.warning("    No vulnerabilty data for %s" %inventoryItemName)
                vulnerabilities = []   

            # Remap the data with vulnerability as key
            componentVersionId = None
            if not vulnerabilities:
                suppressedVulnerabilitiesOnly = common.api.inventory.inventory_vulnerability_analysis.get_inventory_item_vulnerabilities_suppressed_state(inventoryID,baseURL,authToken)
                if suppressedVulnerabilitiesOnly["data"]["analyzedVulnerabilities"]:
                    for suppressedVulnerability in suppressedVulnerabilitiesOnly["data"]["analyzedVulnerabilities"]:
                        if suppressedVulnerability["vulnerabilityName"] not in suppressedVulnerabilities:
                            componentVersionVulnerabilities = common.api.component.get_component_version_vulnerabilities.get_component_version_vulnerabilities(baseURL, suppressedVulnerability["componentVersionId"], authToken)
                            for componentVersionVulnerability in componentVersionVulnerabilities["data"]:
                                if componentVersionVulnerability["vulnerabilityName"] not in suppressedVulnerabilities and componentVersionVulnerability["vulnerabilityName"] == suppressedVulnerability["vulnerabilityName"]:
                                    componentVersionVulnerability["vulnerabilityAnalysis"] = suppressedVulnerability["analysis"]
                                    update_vulnerability_data(suppresedVulnerabilityData, componentVersionVulnerability, projectName, bomLink)
                                    suppresedVulnerabilityData[componentVersionVulnerability["vulnerabilityName"]
                                                                ]["excluded"] = True
                                    suppresedVulnerabilityData[componentVersionVulnerability["vulnerabilityName"]
                                                            ]["state"] = suppressedVulnerability["analysis"]["state"]
                                    suppresedVulnerabilityData[componentVersionVulnerability["vulnerabilityName"]
                                                            ]["justification"] = suppressedVulnerability["analysis"]["justification"]
                                    suppresedVulnerabilityData[componentVersionVulnerability["vulnerabilityName"]
                                                            ]["response"] = suppressedVulnerability["analysis"]["response"]
                                    suppresedVulnerabilityData[componentVersionVulnerability["vulnerabilityName"]
                                                            ]["detail"] = suppressedVulnerability["analysis"]["detail"]
                                    suppressedVulnerabilities.add(
                                        suppressedVulnerability["vulnerabilityName"])
            else:
                for vulnerability in vulnerabilities:
                    vulnerabilityName = vulnerability["vulnerabilityName"]
                    update_vulnerability_data(
                        vulnerabilityData, vulnerability, projectName, bomLink)
                    for analysisvul in vulnerabilitiesAnalysis["data"]["analyzedVulnerabilities"]:
                        if analysisvul["vulnerabilityName"] == vulnerabilityName:
                            vulnerabilityData[vulnerabilityName]["excluded"] = True
                            vulnerabilityData[vulnerabilityName]["state"] = analysisvul["analysis"]["state"]
                            vulnerabilityData[vulnerabilityName]["justification"] = analysisvul["analysis"]["justification"]
                            vulnerabilityData[vulnerabilityName]["response"] = analysisvul["analysis"]["response"]
                            vulnerabilityData[vulnerabilityName]["detail"] = analysisvul["analysis"]["detail"]
                        elif analysisvul["suppressed"] and analysisvul["vulnerabilityName"] not in suppressedVulnerabilities:
                            if analysisvul["componentVersionId"] != componentVersionId:
                                componentVersionVulnerabilities = common.api.component.get_component_version_vulnerabilities.get_component_version_vulnerabilities(
                                    baseURL, analysisvul["componentVersionId"], authToken)
                                componentVersionId = analysisvul["componentVersionId"]
                            for componentVersionVulnerability in componentVersionVulnerabilities["data"]:
                                if componentVersionVulnerability["vulnerabilityName"] not in suppressedVulnerabilities and componentVersionVulnerability["vulnerabilityName"] == analysisvul["vulnerabilityName"]:
                                    componentVersionVulnerability["vulnerabilityAnalysis"] = analysisvul["analysis"]
                                    update_vulnerability_data(
                                        suppresedVulnerabilityData, componentVersionVulnerability, projectName, bomLink)
                                    suppresedVulnerabilityData[componentVersionVulnerability["vulnerabilityName"]
                                                            ]["excluded"] = True
                                    suppresedVulnerabilityData[componentVersionVulnerability["vulnerabilityName"]
                                                            ]["state"] = analysisvul["analysis"]["state"]
                                    suppresedVulnerabilityData[componentVersionVulnerability["vulnerabilityName"]
                                                            ]["justification"] = analysisvul["analysis"]["justification"]
                                    suppresedVulnerabilityData[componentVersionVulnerability["vulnerabilityName"]
                                                            ]["response"] = analysisvul["analysis"]["response"]
                                    suppresedVulnerabilityData[componentVersionVulnerability["vulnerabilityName"]
                                                            ]["detail"] = analysisvul["analysis"]["detail"]
                                    suppressedVulnerabilities.add(
                                        analysisvul["vulnerabilityName"])

    # Sort the inventory data by Component Name / Component Version / Selected License Name
    sortedInventoryData = OrderedDict(sorted(inventoryData.items(), key=lambda x: (
        x[1]['componentName'],  x[1]['componentVersionName'])))

    reportData["applicationDetails"] = applicationDetails
    reportData["topLevelProjectName"] = topLevelProjectName
    reportData["bomFormat"] = bomFormat
    reportData["bomVersion"] = bomVersion
    reportData["specVersion"] = specVersion
    reportData["serialNumber"] = serialNumber
    reportData["projectList"] = projectList
    reportData["inventoryData"] = sortedInventoryData
    reportData["vulnerabilityData"] = vulnerabilityData
    reportData["supressedVulnerabilityData"] = suppresedVulnerabilityData
    return reportData


# -----------------------------------------------

def create_project_hierarchy(project, parentID, projectList, baseURL):
    logger.debug("Entering create_project_hierarchy")

    # Are there more child projects for this project?
    if len(project["childProject"]):

        # Sort by project name of child projects
        for childProject in sorted(project["childProject"], key=lambda i: i['name']):

            nodeDetails = {}
            nodeDetails["projectID"] = str(childProject["id"])
            nodeDetails["parent"] = parentID
            nodeDetails["projectName"] = childProject["name"]
            nodeDetails["projectLink"] = baseURL + "/codeinsight/FNCI#myprojectdetails/?id=" + \
                str(childProject["id"]) + "&tab=projectInventory"

            projectList.append(nodeDetails)

            create_project_hierarchy(
                childProject, childProject["id"], projectList, baseURL)

    return projectList
# ------------------------------------------------#

def update_vulnerability_data(vulnerabilityData, vulnerability, projectName, bomLink):
    vulnerabilityName = vulnerability["vulnerabilityName"]

    if vulnerabilityName in vulnerabilityData and projectName in vulnerabilityData[vulnerabilityName]["affectedProjects"]:
        vulnerabilityData[vulnerabilityName]["affectedComponents"].append(bomLink)
    else:
        vulnerabilityData[vulnerabilityName] = {}
        vulnerabilityData[vulnerabilityName]["affectedProjects"] = [projectName]

        vulnerabilityData[vulnerabilityName]["vulnerabilityDescription"] = ''.join(vulnerability["vulnerabilityDescription"].splitlines())
        vulnerabilityData[vulnerabilityName]["vulnerabilitySource"] = vulnerability["vulnerabilitySource"]
        vulnerabilityData[vulnerabilityName]["vulnerabilityUrl"] = vulnerability["vulnerabilityUrl"]

        vulnerabilityData[vulnerabilityName]["publishedDate"] = vulnerability["publishedDate"]
        vulnerabilityData[vulnerabilityName]["modifiedDate"] = vulnerability["modifiedDate"]
        vulnerabilityData[vulnerabilityName]["createdDate"] = vulnerability["publishedDate"]  # No created date in response so use published date

        CWE = []
        if vulnerability["vulnerabilityCWE"]:
            for cwe in vulnerability["vulnerabilityCWE"]:
                CWE.append(cwe["name"].split("-")[1])

            CWE.sort()
            vulnerabilityData[vulnerabilityName]["vulnerabilityCWE"] = CWE
        else:
            vulnerabilityData[vulnerabilityName]["vulnerabilityCWE"] = []

        # Default to CVSSv3 data but use v2 if v3 data not accessible
        vulnerabilityScore = vulnerability["vulnerabilityCvssV3Score"]

        if vulnerabilityScore == "N/A":
            vulnerabilitySeverity = vulnerability["vulnerabilityCvssV2Severity"]
            vulnerabilityScore = vulnerability["vulnerabilityCvssV2Score"]
            vulnerabilityVector = vulnerability["vulnerabilityCvssV2Vector"]
            vulnerabilityMethod = "CVSSv2"
        else:
            vulnerabilitySeverity = vulnerability["vulnerabilityCvssV3Severity"]
            if vulnerability["vulnerabilityCvssV3Vector"] != "N/A":
                vulnerabilityMethod, vulnerabilityVector = vulnerability["vulnerabilityCvssV3Vector"].split("/", 1)
                vulnerabilityMethod = vulnerabilityMethod.replace(".", "").replace(":", "v")
            else:
                vulnerabilityVector = ""
                vulnerabilityMethod = ""

        if vulnerabilityVector == "N/A":
            vulnerabilityVector = ""

        vulnerabilityData[vulnerabilityName]["vulnerabilitySeverity"] = vulnerabilitySeverity
        vulnerabilityData[vulnerabilityName]["vulnerabilityScore"] = str(vulnerabilityScore)
        vulnerabilityData[vulnerabilityName]["vulnerabilityVector"] = vulnerabilityVector
        vulnerabilityData[vulnerabilityName]["vulnerabilityMethod"] = vulnerabilityMethod

        # Create a list of lists to hold the component data
        vulnerabilityData[vulnerabilityName]["affectedComponents"] = []
        if bomLink not in set(vulnerabilityData[vulnerabilityName]["affectedComponents"]):
            vulnerabilityData[vulnerabilityName]["affectedComponents"].append(bomLink)

