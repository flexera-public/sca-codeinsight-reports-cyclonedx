'''
Copyright 2020 Flexera Software LLC
See LICENSE.TXT for full license text
SPDX-License-Identifier: MIT

Author : sgeary  
Created On : Sun Aug 16 2020
File : delete_report.py
'''
import logging
import requests

logger = logging.getLogger(__name__)

#------------------------------------------------------------------------------------------#
def unregister_report_by_id(baseURL, authToken, reportId):
    logger.info("Entering unregister_report_by_id")

    RESTAPI_BASEURL = baseURL + "/codeinsight/api/"
    ENDPOINT_URL = RESTAPI_BASEURL + "reports/"
    RESTAPI_URL = ENDPOINT_URL + str(reportId)
    logger.debug("    RESTAPI_URL: %s" %RESTAPI_URL)
    
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + authToken}   
       
    ##########################################################################   
    # Make the REST API call with the project data           
    try:
        response = requests.delete(RESTAPI_URL, headers=headers)
    except requests.exceptions.RequestException as error:  # Just catch all errors
        logger.error(error)
        return {"error": error}
    
    ###############################################################################
    # We at least received a response from so check the status to see
    # what happened if there was an error or the expected data
    if response.status_code == 200:
        return(response.json())  
    else: 
        logger.error("Response code %s - %s" %(response.status_code, response.text))
        return {"error" : response.text}

#------------------------------------------------------------------------------------------#
def unregister_report_by_name(baseURL, authToken, reportName):
    logger.info("Entering unregister_report_by_name")

    RESTAPI_BASEURL = baseURL + "/codeinsight/api/"
    ENDPOINT_URL = RESTAPI_BASEURL + "reports/"
    RESTAPI_URL = ENDPOINT_URL + reportName
    logger.debug("    RESTAPI_URL: %s" %RESTAPI_URL)
    
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + authToken}   
       
    ##########################################################################   
    # Make the REST API call with the project data           
    try:
        response = requests.delete(RESTAPI_URL, headers=headers)
    except requests.exceptions.RequestException as error:  # Just catch all errors
        logger.error(error)
        return {"error": error}

    ###############################################################################
    # We at least received a response from so check the status to see
    # what happened if there was an error or the expected data
    if response.status_code == 200:
        return(response.json())  
    else: 
        logger.error("Response code %s - %s" %(response.status_code, response.text))
        return {"error" : response.text}