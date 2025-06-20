"""
Copyright 2022 Flexera Software LLC
See LICENSE.TXT for full license text
SPDX-License-Identifier: MIT

Author : sgeary
Created On : Thu Mar 10 2022
Modified By : sarthak
Modified On: Thu Apr 24 2025
File : report_data.py
"""

import logging, uuid, unicodedata
from collections import OrderedDict
from decimal import Decimal

import report_data_db
import purl
import SPDX_license_mappings  # To map evidence to an SPDX license name

logger = logging.getLogger(__name__)


# -------------------------------------------------------------------#
def gather_data_for_report(projectID, reportData, reportOptions):
    logger.info("Entering gather_data_for_report")
    inventoryData = (
        {}
    )  # Create a dictionary containing the inventory data using inventoryID as keys
    vulnerabilityVdrData = (
        {}
    )  # Create dictionary to hold all VDR vulnerability data based on vul ID across all projects
    vulnerabilityVexData = (
        {}
    )  # Create dictionary to hold all VEX vulnerability data based on vul ID across all projects
    serialNumber = "urn:uuid:" + str(uuid.uuid1())
    bomFormat = "CycloneDX"
    bomVersion = "1"
    specVersion = "1.6"
    reportOptions = reportData["reportOptions"]

    if reportOptions["includeChildProjects"]:
        projectList = report_data_db.get_child_projects(projectID)
    else:
        projectList = []
        projectList.append(projectID)

    for projectID in projectList:
        project_Name = report_data_db.get_projects_data(projectID)
        inventoryItems = report_data_db.get_inventory_data(projectID)
        if inventoryItems is None:
            inventoryItems = []
        inventoryItemsCustom = report_data_db.get_inventory_data_custom(projectID)
        if inventoryItemsCustom is not None and inventoryItemsCustom != []:
            inventoryItems += inventoryItemsCustom

        #  Gather the details for each project and summerize the data

        for inventoryItem in inventoryItems:

            inventoryID = inventoryItem["inventoryID"]
            inventoryItemName = inventoryItem["inventoryItemName"]
            componentName = inventoryItem["componentName"]
            componentVersionName = inventoryItem["componentVersionName"]
            componentUrl = inventoryItem["componentUrl"]
            if inventoryItem["componentDescription"] != None:
                componentDescription = inventoryItem["componentDescription"][
                    :100
                ].replace("\n", " - ")
            else:
                componentDescription = ""
            componentDescription = (
                unicodedata.normalize("NFKD", componentDescription)
                .encode("ASCII", "ignore")
                .decode("utf-8")
            )

            # Is there a specified component version?
            if componentDescription == "N/A":
                componentDescription = ""

            # Is there a specified component version?
            if (
                componentVersionName == "N/A" or componentVersionName == None
                or componentVersionName.lower() == "unknown"
            ):
                componentVersionName = ""

            # Attempt to generate a purl string for the component
            try:
                purlString = purl.get_purl_string(
                    inventoryItem,
                    componentVersionName,
                    inventoryItemName
                )
            except:
                logger.warning("Unable to create purl string for inventory item.")
                purlString = ""

            if purlString != "":
                bomref = purlString + "-" + str(inventoryID)
            else:
                bomref = ""

            # Manage license details
            licenseDetails = {}

            selectedLicenseSPDXIdentifier = inventoryItem[
                "selectedLicenseSPDXIdentifier"
            ]
            selectedLicenseName = inventoryItem["selectedLicenseName"]
            selectedLicenseUrl = inventoryItem["selectedLicenseUrl"]

            if selectedLicenseName == "I don't know":
                comp_license = report_data_db.get_comp_license(
                    inventoryItem["component_id"]
                )
                if comp_license:
                    possibleLicensesOptions = [
                        item["licenseName"] for item in comp_license
                    ]
                    possibleLicenses = []
                    for license in possibleLicensesOptions:
                        possibleLicenses.append(license)

                    licenseDetails["licenseObjectType"] = "expression"
                    licenseDetails["possibleLicenses"] = " OR ".join(possibleLicenses)
                else:
                    logger.warning(
                        f"No license data found for component ID: {inventoryItem['component_id']}"
                    )
                    licenseDetails["licenseObjectType"] = "license"
                    licenseDetails["licenseURL"] = ""
                    licenseDetails["licenseName"] = "I don't know"

            elif selectedLicenseSPDXIdentifier in SPDX_license_mappings.LICENSEMAPPINGS:
                logger.info(
                    '        "%s" maps to SPDX ID "%s"'
                    % (
                        selectedLicenseSPDXIdentifier,
                        SPDX_license_mappings.LICENSEMAPPINGS[
                            selectedLicenseSPDXIdentifier
                        ],
                    )
                )
                licenseDetails["licenseObjectType"] = "license"
                licenseDetails["SPDXID"] = SPDX_license_mappings.LICENSEMAPPINGS[
                    selectedLicenseSPDXIdentifier
                ]
                licenseDetails["licenseURL"] = selectedLicenseUrl

            else:
                # There is not a valid SPDX ID here
                licenseDetails["licenseObjectType"] = "license"
                licenseDetails["licenseName"] = selectedLicenseName
                licenseDetails["licenseURL"] = selectedLicenseUrl

            # Store the data for the inventory item for reporting
            inventoryData[inventoryID] = {
                "projectName": project_Name,
                "componentName": componentName,
                "componentVersionName": componentVersionName,
                "componentUrl": componentUrl,
                "componentDescription": componentDescription,
                "licenseDetails": licenseDetails,
                "purl": purlString,
                "bomref": bomref,
            }

            bomLink = (
                serialNumber
                + "/"
                + bomVersion
                + "#"
                + componentName
                + "-"
                + componentVersionName
            )
            try:
                if reportOptions["includeVDRReport"]:
                    logger.debug("getting VDR data from DB")
                    vdrVulnerabilities = (
                        report_data_db.get_component_version_vdr_vulnerabilities(
                            projectID, inventoryItem["component_version_id"]
                        )
                    )
                    for vulnerability in vdrVulnerabilities:
                        update_vulnerability_data(
                            vulnerabilityVdrData, vulnerability, project_Name, bomLink
                        )
                if reportOptions["includeVEXReport"]:
                    logger.debug("getting VEX data from DB")
                    vexVulnerabilities = (
                        report_data_db.get_component_version_vex_vulnerabilities(
                            projectID, inventoryItem["component_version_id"]
                        )
                    )
                    for vulnerability in vexVulnerabilities:
                        update_vulnerability_data(
                            vulnerabilityVexData, vulnerability, project_Name, bomLink
                        )
            except:
                logger.warning("    No vulnerabilty data for %s" % inventoryItemName)
                vulnerabilities = []

    # Sort the inventory data by Component Name / Component Version / Selected License Name
    sortedInventoryData = OrderedDict(
        sorted(
            inventoryData.items(),
            key=lambda x: (x[1]["componentName"], x[1]["componentVersionName"]),
        )
    )

    # reportData["applicationDetails"] = applicationDetails
    reportData["topLevelProjectName"] = project_Name
    reportData["bomVersion"] = bomVersion
    reportData["bomFormat"] = bomFormat
    reportData["specVersion"] = specVersion
    reportData["serialNumber"] = serialNumber
    reportData["projectList"] = projectList
    reportData["inventoryData"] = sortedInventoryData
    if reportOptions["includeVDRReport"]:
        reportData["vulnerabilityVdrData"] = vulnerabilityVdrData
    if reportOptions["includeVEXReport"]:
        reportData["vulnerabilityVexData"] = vulnerabilityVexData
    return reportData


# ------------------------------------------------#


def update_vulnerability_data(vulnerabilityData, vulnerability, projectName, bomLink):
    vulnerabilityName = vulnerability["vulnerabilityName"]

    if (
        vulnerabilityName in vulnerabilityData
        and projectName in vulnerabilityData[vulnerabilityName]["affectedProjects"]
    ):
        vulnerabilityData[vulnerabilityName]["affectedComponents"].append(bomLink)
    else:
        vulnerabilityData[vulnerabilityName] = {}
        vulnerabilityData[vulnerabilityName]["affectedProjects"] = [projectName]

        vulnerabilityData[vulnerabilityName]["vulnerabilityDescription"] = "".join(
            vulnerability["vulnerabilityDescription"].splitlines()
        )
        vulnerabilityData[vulnerabilityName]["vulnerabilitySource"] = vulnerability[
            "vulnerabilitySource"
        ]
        vulnerabilityData[vulnerabilityName]["vulnerabilityUrl"] = vulnerability[
            "vulnerabilityUrl"
        ]

        vulnerabilityData[vulnerabilityName]["publishedDate"] = vulnerability[
            "publishedDate"
        ]
        vulnerabilityData[vulnerabilityName]["modifiedDate"] = vulnerability[
            "modifiedDate"
        ]
        vulnerabilityData[vulnerabilityName]["createdDate"] = vulnerability[
            "publishedDate"
        ]  # No created date in response so use published date

        CWE = []
        if vulnerability["vulnerabilityCWE"]:
            CWE.append(vulnerability["vulnerabilityCWE"].split("-")[1])

            CWE.sort()
            vulnerabilityData[vulnerabilityName]["vulnerabilityCWE"] = CWE
        else:
            vulnerabilityData[vulnerabilityName]["vulnerabilityCWE"] = []

        # Default to CVSSv3 data but use v2 if v3 data not accessible
        vulnerabilityScore = vulnerability["vulnerabilityCvssV3Score"]

        # Convert Decimal to string if necessary
        if isinstance(vulnerabilityScore, Decimal):
            vulnerabilityScore = str(vulnerabilityScore)

        if vulnerabilityScore == "N/A" or vulnerabilityScore == "0.0" or vulnerabilityScore == None:
            vulnerabilitySeverity = vulnerability["vulnerabilityCvssV2Severity"]
            vulnerabilityScore = vulnerability["vulnerabilityCvssV2Score"]
            vulnerabilityVector = vulnerability["vulnerabilityCvssV2Vector"]
            vulnerabilityMethod = "CVSSv2"
        else:
            vulnerabilitySeverity = vulnerability["vulnerabilityCvssV3Severity"]
            if vulnerability["vulnerabilityCvssV3Vector"] != None:
                vulnerabilityMethod, vulnerabilityVector = vulnerability[
                    "vulnerabilityCvssV3Vector"
                ].split("/", 1)
                vulnerabilityMethod = vulnerabilityMethod.replace(".", "").replace(
                    ":", "v"
                )
            else:
                vulnerabilityVector = ""
                vulnerabilityMethod = ""

        if vulnerabilityVector == "N/A" or vulnerabilityVector is None:
            vulnerabilityVector = ""

        vulnerabilityData[vulnerabilityName][
            "vulnerabilitySeverity"
        ] = vulnerabilitySeverity
        vulnerabilityData[vulnerabilityName]["vulnerabilityScore"] = str(
            vulnerabilityScore
        )
        vulnerabilityData[vulnerabilityName][
            "vulnerabilityVector"
        ] = vulnerabilityVector
        vulnerabilityData[vulnerabilityName][
            "vulnerabilityMethod"
        ] = vulnerabilityMethod

        # Create a list of lists to hold the component data
        vulnerabilityData[vulnerabilityName]["affectedComponents"] = []
        if bomLink not in set(
            vulnerabilityData[vulnerabilityName]["affectedComponents"]
        ):
            vulnerabilityData[vulnerabilityName]["affectedComponents"].append(bomLink)
        # Supply annotated vulnerabilities values
        if vulnerability["state"] is not None:
            vulnerabilityData[vulnerability["vulnerabilityName"]]["state"] = (
                vulnerability["state"]
            )

        if vulnerability["justification"] is not None:
            vulnerabilityData[vulnerability["vulnerabilityName"]]["justification"] = (
                vulnerability["justification"]
            )

        if vulnerability["response"] is not None:
            vulnerabilityData[vulnerability["vulnerabilityName"]]["response"] = (
                vulnerability["response"]
            )

        if vulnerability["detail"] is not None:
            vulnerabilityData[vulnerability["vulnerabilityName"]]["detail"] = (
                vulnerability["detail"]
            )
