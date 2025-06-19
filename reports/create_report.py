'''
Copyright 2020 Flexera Software LLC
See LICENSE.TXT for full license text
SPDX-License-Identifier: MIT

Author : sgeary  
Created On : Sun Aug 16 2020
File : create_report.py
'''

import logging
import requests
import json

logger = logging.getLogger(__name__)

#------------------------------------------------------------------------------------------#
def register_report(reportName, reportPath, reportOrder, enableProjectPickerValue, reportOptions, baseURL, authToken):
    logger.info("Entering register_report")

    RESTAPI_BASEURL = baseURL + "/codeinsight/api/"
    ENDPOINT_URL = RESTAPI_BASEURL + "reports/"
    RESTAPI_URL = ENDPOINT_URL
    logger.debug("    RESTAPI_URL: %s" %RESTAPI_URL)

    #Take the list of reportOptions and create a string
    if len(reportOptions):
        optionsString = ""
        for option in reportOptions:
            optionsString += json.dumps(reportOptions[option]) +","

        optionsString = optionsString[:-1]  # Get rid of last comma

    else:
        optionsString = ""

    createReportBody = '''
    {
        "name": "''' + reportName + '''",
        "path": "''' + reportPath + '''",
        "enabled": "true",
        "order": "''' + str(reportOrder) + '''",
        "enableProjectPicker": "''' + enableProjectPickerValue + '''",
        "reportOptions" : [''' + optionsString + ''']
    }'''
   
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + authToken}     
       
    ##########################################################################   
    # Make the REST API call with the project data           
    try:
        response = requests.post(RESTAPI_URL, headers=headers, data=createReportBody)
    except requests.exceptions.RequestException as error:  # Just catch all errors
        logger.error(error)
        return {"error" : error}

    ###############################################################################
    # We at least received a response from so check the status to see
    # what happened if there was an error or the expected data
    if response.status_code == 201:
        logger.debug("%s was sucessfully registered." %(reportName))
        return response.json()
    else: 
        logger.error("Response code %s - %s" %(response.status_code, response.text))
        return {"error" : response.text}
