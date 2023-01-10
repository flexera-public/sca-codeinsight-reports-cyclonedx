'''
Copyright 2022 Flexera Software LLC
See LICENSE.TXT for full license text
SPDX-License-Identifier: MIT

Author : sgeary  
Created On : Thu Mar 10 2022
File : report_data.py
'''

import logging
import uuid
from collections import OrderedDict

import CodeInsight_RESTAPIs.project.get_child_projects
import CodeInsight_RESTAPIs.project.get_project_inventory
import CodeInsight_RESTAPIs.project.get_project_information
import purl
import SPDX_license_mappings # To map evidence to an SPDX license name

logger = logging.getLogger(__name__)

#-------------------------------------------------------------------#
def gather_data_for_report(baseURL, projectID, authToken, reportName, reportVersion, reportOptions):
    logger.info("Entering gather_data_for_report")

    # Parse report options
    includeChildProjects = reportOptions["includeChildProjects"]  # True/False

    projectList = [] # List to hold parent/child details for report
    inventoryData = {}  # Create a dictionary containing the inventory data using inventoryID as keys

    # Get the list of parent/child projects start at the base project
    projectHierarchy = CodeInsight_RESTAPIs.project.get_child_projects.get_child_projects_recursively(baseURL, projectID, authToken)
    projectName = projectHierarchy["name"]

    applicationDetails = determine_application_details(baseURL, projectName, projectID, authToken)


    # Create a list of project data sorted by the project name at each level for report display  
    # Add details for the parent node
    nodeDetails = {}
    nodeDetails["parent"] = "#"  # The root node
    nodeDetails["projectName"] = projectName
    nodeDetails["projectID"] = projectID
    nodeDetails["projectLink"] = baseURL + "/codeinsight/FNCI#myprojectdetails/?id=" + str(projectHierarchy["id"]) + "&tab=projectInventory"

    projectList.append(nodeDetails)

    if includeChildProjects == "true":
        projectList = create_project_hierarchy(projectHierarchy, projectID, projectList, baseURL)
    else:
        logger.debug("Child hierarchy disabled")

    #  Gather the details for each project and summerize the data
    for project in projectList:

        projectID = project["projectID"]
        projectName = project["projectName"]

        projectInventory = CodeInsight_RESTAPIs.project.get_project_inventory.get_project_inventory_details_without_vulnerabilities(baseURL, projectID, authToken)
        inventoryItems = projectInventory["inventoryItems"]

        # Collect the required data for each inventory item
        for inventoryItem in inventoryItems:
            
            inventoryType = inventoryItem["type"]

            # This is not a component for move to the next item
            if inventoryType != "Component":
                continue

            inventoryID = inventoryItem["id"]       
            componentName = inventoryItem["componentName"]
            componentVersionName = inventoryItem["componentVersionName"]
            componentUrl = inventoryItem["componentUrl"]

            componentDescription = inventoryItem["description"][:100].replace("\n", " - ")

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
                licenseDetails["SPDXID"] = selectedLicenseSPDXIdentifier
                licenseDetails["licenseURL"] =  selectedLicenseUrl

            else:
                # There should be a valid SPDX ID here
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


    # Sort the inventory data by Component Name / Component Version / Selected License Name
    sortedInventoryData = OrderedDict(sorted(inventoryData.items(), key=lambda x: (x[1]['componentName'],  x[1]['componentVersionName'])  ) )



    # Was an application name entered for the project
    if applicationDetails["applicationName"] == "":
        applicationName = projectHierarchy["name"]
    else:
        applicationName = applicationDetails["applicationName"]
    
    # Was an application version entered for the project
    if applicationDetails["applicationVersion"] == "":
        applicationVersion = "0.0.0"
    else:
        applicationVersion = applicationDetails["applicationVersion"] 


    reportData = {}
    reportData["reportName"] = reportName

    reportData["applicationName"] = applicationName
    reportData["applicationVersion"]  = applicationVersion
    reportData["applicationPublisher"]  = applicationDetails["applicationPublisher"]
    reportData["applicationReportName"]  = applicationDetails["applicationReportName"]


    reportData["serialNumber"] = str(uuid.uuid1())
    reportData["projectName"] =  projectHierarchy["name"]
    reportData["projectID"] = projectHierarchy["id"]
    reportData["projectList"] = projectList
    reportData["reportVersion"] = reportVersion
    reportData["inventoryData"] = sortedInventoryData
    reportData["CodeInsightReleaseYear"] = "2022"


    return reportData


#----------------------------------------------#
def create_project_hierarchy(project, parentID, projectList, baseURL):
    logger.debug("Entering create_project_hierarchy")

    # Are there more child projects for this project?
    if len(project["childProject"]):

        # Sort by project name of child projects
        for childProject in sorted(project["childProject"], key = lambda i: i['name'] ) :

            nodeDetails = {}
            nodeDetails["projectID"] = str(childProject["id"])
            nodeDetails["parent"] = parentID
            nodeDetails["projectName"] = childProject["name"]
            nodeDetails["projectLink"] = baseURL + "/codeinsight/FNCI#myprojectdetails/?id=" + str(childProject["id"]) + "&tab=projectInventory"

            projectList.append( nodeDetails )

            create_project_hierarchy(childProject, childProject["id"], projectList, baseURL)

    return projectList

#--------------------------------------------
def determine_application_details(baseURL, projectName, projectID, authToken):
    logger.debug("Entering determine_application_details.")
    # Create a application name for the report if the custom fields are populated
    # Default values
    applicationName = projectName
    applicationVersion = ""
    applicationPublisher = ""

    projectInformation = CodeInsight_RESTAPIs.project.get_project_information.get_project_information_summary(baseURL, projectID, authToken)

    # Project level custom fields added in 2022R1
    if "customFields" in projectInformation:
        customFields = projectInformation["customFields"]

        # See if the custom project fields were propulated for this project
        for customField in customFields:

            # Is there the reqired custom field available?
            if customField["fieldLabel"] == "Application Name":
                if customField["value"]:
                    applicationName = customField["value"]

            # Is the custom version field available?
            if customField["fieldLabel"] == "Application Version":
                if customField["value"]:
                    applicationVersion = customField["value"]     

            # Is the custom version field available?
            if customField["fieldLabel"] == "Application Publisher":
                if customField["value"]:
                    applicationPublisher = customField["value"]    


    # Join the custom values to create the application name for the report artifacts
    if applicationName != projectName:
        if applicationVersion != "":
            applicationReportName = applicationName + " - " + applicationVersion
        else:
            applicationReportName = applicationName
    else:
        applicationReportName = projectName

    
    applicationDetails = {}
    applicationDetails["applicationName"] = applicationName
    applicationDetails["applicationVersion"] = applicationVersion
    applicationDetails["applicationPublisher"] = applicationPublisher
    applicationDetails["applicationReportName"] = applicationReportName

    logger.info("    applicationDetails: %s" %applicationDetails)



    return applicationDetails