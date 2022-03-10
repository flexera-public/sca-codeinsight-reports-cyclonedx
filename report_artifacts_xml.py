'''
Copyright 2022 Flexera Software LLC
See LICENSE.TXT for full license text
SPDX-License-Identifier: MIT

Author : sgeary  
Created On : Thu Mar 10 2022
File : report_artifacts_xml.py
'''

import logging


import _version

logger = logging.getLogger(__name__)


#------------------------------------------------------------------#
def generate_xml_report(reportData):
    logger.info("    Entering generate_html_report")
    
    projectName = reportData["projectName"]
    reportFileNameBase = reportData["reportFileNameBase"]



    xmlFile = reportFileNameBase + ".xml"

    # Create cycloneDX xml file
    try:
        xml_ptr = open(xmlFile,"w")
    except:
        logger.error("Failed to open xmlfile %s:" %xmlFile)
        raise

    xml_ptr.write("Project Name: %s" %projectName)

    xml_ptr.close() 

    logger.info("    Exiting generate_html_report")
    return xmlFile