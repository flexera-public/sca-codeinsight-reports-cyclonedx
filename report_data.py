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

import CodeInsight_RESTAPIs.project.get_child_projects
import CodeInsight_RESTAPIs.project.get_project_inventory
import purl

logger = logging.getLogger(__name__)

#-------------------------------------------------------------------#
def gather_data_for_report(baseURL, projectID, authToken, reportName, reportVersion, reportOptions):
    logger.info("Entering gather_data_for_report")

    # Parse report options
    includeChildProjects = reportOptions["includeChildProjects"]  # True/False
    
    try:
        applicationPublisher = reportOptions["applicationPublisher"]  
    except:
        logger.info("Application publisher was not provdied")
        applicationPublisher = ""
    
    try:
        applicationName = reportOptions["applicationName"] 
    except:
        logger.info("Application Name was not provdied")
        applicationName = ""

    try:
        applicationVersion = reportOptions["applicationVersion"]  
    except:
        logger.info("Application Version was not provdied")
        applicationVersion = ""

    projectList = [] # List to hold parent/child details for report
    inventoryData = {}  # Create a dictionary containing the inventory data using inventoryID as keys

    # Get the list of parent/child projects start at the base project
    projectHierarchy = CodeInsight_RESTAPIs.project.get_child_projects.get_child_projects_recursively(baseURL, projectID, authToken)
    projectName = projectHierarchy["name"]

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
            selectedLicenseSPDXIdentifier = inventoryItem["selectedLicenseSPDXIdentifier"]
            selectedLicenseUrl = inventoryItem["selectedLicenseUrl"]
            componentDescription = inventoryItem["description"][:100]

            # Is there a specified component version?
            if componentDescription == "N/A":
                componentDescription = ""

            # Is there a specified component version?
            if componentVersionName == "N/A" or componentVersionName.lower() == "unknown":
                componentVersionName = ""

            purlString = purl.get_purl_string(inventoryItem, baseURL, authToken)

            # Store the data for the inventory item for reporting
            inventoryData[inventoryID] = {
                "projectName" : projectName,
                "componentName" : componentName,
                "componentVersionName" : componentVersionName,
                "componentUrl" : componentUrl,
                "componentDescription" : componentDescription, 
                "selectedLicenseSPDXIdentifier" : selectedLicenseSPDXIdentifier,
                "selectedLicenseUrl" : selectedLicenseUrl,
                "purl" : purlString
            }



    # Was an application name provided as an option or default to the project name
    if applicationName == "":
        applicationName = projectHierarchy["name"]
    
    # Was an application version provided as an option or default 0.0.0
    if applicationVersion == "":
        applicationVersion = "0.0.0"



    reportData = {}
    reportData["reportName"] = reportName

    reportData["applicationPublisher"]  = applicationPublisher
    reportData["applicationName"] = applicationName
    reportData["applicationVersion"]  = applicationVersion

    reportData["serialNumber"] = str(uuid.uuid1())
    reportData["projectName"] =  projectHierarchy["name"]
    reportData["projectID"] = projectHierarchy["id"]
    reportData["projectList"] = projectList
    reportData["reportVersion"] = reportVersion
    reportData["inventoryData"] = inventoryData
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