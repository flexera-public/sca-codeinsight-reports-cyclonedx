'''
Copyright 2022 Flexera Software LLC
See LICENSE.TXT for full license text
SPDX-License-Identifier: MIT

Author : sgeary  
Created On : Thu Mar 10 2022
File : report_artifacts.py
'''

import logging

import report_artifacts_xml

logger = logging.getLogger(__name__)

#--------------------------------------------------------------------------------#
def create_report_artifacts(reportData):
    logger.info("Entering create_report_artifacts")

    # Dict to hold the complete list of reports
    reports = {}

    xmlFile = report_artifacts_xml.generate_xml_report(reportData)

    reports["viewable"] = xmlFile
    reports["allFormats"] = [xmlFile]

    logger.info("Exiting create_report_artifacts")
    
    return reports 