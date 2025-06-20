"""
Copyright 2022 Flexera Software LLC
See LICENSE.TXT for full license text
SPDX-License-Identifier: MIT

Author : sgeary
Created On : Thu Mar 10 2022
File : report_artifacts.py
"""

import logging

import report_artifacts_xml
import report_artifacts_json

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------------#
def create_report_artifacts(reportData, reportOptions):
    logger.info("Entering create_report_artifacts")

    # Dict to hold the complete list of reports
    reports = {}

    jsonFile = report_artifacts_json.generate_json_report(reportData)
    xmlFile = report_artifacts_xml.generate_cyclonedx_report(reportData)

    reports["viewable"] = jsonFile
    reports["allFormats"] = [jsonFile]

    if reportOptions["includeVDRReport"]:
        vdrFile = report_artifacts_xml.generate_vdr_report(reportData)
        reports["allFormats"].append(vdrFile)

    if reportOptions["includeVEXReport"]:
        vexFile = report_artifacts_xml.generate_vex_report(reportData)
        reports["allFormats"].append(vexFile)

    logger.info("Exiting create_report_artifacts")

    return reports
