'''
Copyright 2020 Flexera Software LLC
See LICENSE.TXT for full license text
SPDX-License-Identifier: MIT

Author : sgeary  
Created On : Sun Aug 16 2020
File : get_reports.py
'''
import logging
import requests

logger = logging.getLogger(__name__)

#------------------------------------------------------------------------------------------#
def get_all_currently_registered_reports(baseURL, authToken):
    logger.info("Entering get_all_currently_registered_reports")

    APIOPTIONS = ""
    currentReports = get_currently_registered_reports(baseURL, authToken, APIOPTIONS)

    return currentReports

#------------------------------------------------------------------------------------------#
def get_all_currently_registered_reports_by_name(baseURL, authToken, reportName):
    logger.info("Entering get_all_currently_registered_reports_by_name")

    APIOPTIONS = "?name=" + reportName
    currentReports = get_currently_registered_reports(baseURL, authToken, APIOPTIONS)

    return currentReports

#------------------------------------------------------------------------------------------#
def get_currently_registered_reports(baseURL, authToken, APIOPTIONS):
    logger.info("Entering get_currently_registered_reports")

    RESTAPI_BASEURL = baseURL + "/codeinsight/api/"
    ENDPOINT_URL = RESTAPI_BASEURL + "reports/"
    RESTAPI_URL = ENDPOINT_URL + APIOPTIONS
    logger.debug("    RESTAPI_URL: %s" %RESTAPI_URL)
    
    headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer ' + authToken}   
       
    ##########################################################################   
    # Make the REST API call with the project data           
    try:
        response = requests.get(RESTAPI_URL, headers=headers)
    except requests.exceptions.RequestException as error:  # Just catch all errors
        logger.error(error)
        return {"error" : error}
        
    ###############################################################################
    # We at least received a response from so check the status to see
    # what happened if there was an error or the expected data
    if response.status_code == 200:
        return(response.json()["data"])  
    else: 
        logger.error("Response code %s - %s" %(response.status_code, response.text))
        return {"error" : response.text }