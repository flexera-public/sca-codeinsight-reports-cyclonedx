'''
Copyright 2022 Flexera Software LLC
See LICENSE.TXT for full license text
SPDX-License-Identifier: MIT

Author : sgeary  
Created On : Fri May 20 2022
File : purl.py
'''

import logging

import CodeInsight_RESTAPIs.component.get_component_details
logger = logging.getLogger(__name__)


##############################
def get_purl_string(inventoryItem, baseURL, authToken):
    logger.info("entering get_purl_string")

    purlString = "pkg:"  # Default value 

    componentId = inventoryItem["componentId"]

    # Since the summary does not have the forge grab that plus title from component lookup
    componentDetails = CodeInsight_RESTAPIs.component.get_component_details.get_component_details_v3_summary(baseURL, componentId, authToken)
    forge = componentDetails["data"]["forge"]
    componentTitle = componentDetails["data"]["title"]

    componentName = inventoryItem["componentName"]
    componentVersionName = inventoryItem["componentVersionName"]

    # Ensure there are no spaces in the version name
    if " " in componentVersionName:
        logger.debug("    Remove space from version name: %s" %componentVersionName)
        componentVersionName = componentVersionName.replace(" ", "")
        logger.debug("    is now: %s" %componentVersionName)


    inventoryItemName = inventoryItem["name"]

    logger.info("    Forge: %s  Inventory Item: %s" %(forge, inventoryItemName))

    # Create the purl based on the forge
    if forge in ["apache", "crates", "nuget gallery", "pypi", "rubygems", "sourceforge"]:

        if forge == "rubygems":
            purlRepo = "gem"
        elif forge == "crates":
            purlRepo = "cargo"
        elif forge == "nuget gallery":
            purlRepo = "nuget"
        else:
            purlRepo = forge


        if forge in ["pypi"]:
            purlName = componentName.replace("_", "-")
        else:
            purlName = componentName

        purlVersion = componentVersionName
        purlNameSpace = ""

    elif forge in ["centos", "fedora-koji"]:

        purlRepo = "rpm"
        purlName = componentName
        purlVersion = componentVersionName

        if forge == "centos":
            purlNameSpace = forge
        else:
            purlNameSpace = "fedora"

    elif forge in ["clojars", "maven-google", "maven2-ibiblio"]:

        if forge == "clojars":
            purlRepo = forge
        else:
            purlRepo = "maven"

        purlName = componentName
        purlVersion = componentVersionName

        purlNameSpace = componentTitle.split("/")[0] # parse groupId from component title (start of string to forward slash "/")


    elif forge in ["cpan", "cran", "hackage"]:

        purlRepo = forge
        purlNameSpace = ""
        purlVersion = componentVersionName  
        
        purlName = componentTitle.split(" - ")[0] # parse case-sensitive name from component title (start of string to dash "-" minus 1)

    elif forge in ["npm"]:

        purlRepo = forge
        purlNameSpace = ""
        
        purlVersion = componentVersionName  
        purlName = componentName

    elif forge in ["packagist"]:

        purlRepo = "composer"
        purlNameSpace = ""

        purlName = componentTitle.split(" - ")[0] # parse case-sensitive name from component title (start of string to dash "-" minus 1)

        purlVersion = componentVersionName  

    elif forge in ["github", "gitlab"]:

        purlRepo = forge
        purlVersion = componentVersionName  

      
        componentName = componentTitle.split(" - ")[0] # parse case-sensitive name from component title (start of string to dash "-" minus 1)

        purlNameSpace, purlName  = componentName.split("/") # parse groupId from component title (start of string to forward slash "/")
      
    elif forge in ["fsf-directory", "codeplex", "gnu", "java.net", "kernel.org", "mozilla", "mysqlab", "savannah", "googlecode"]:
        logger.warning("        No purl string for repository %s."  %forge)
        purlString = ""

    else:
        logger.error("        Unsupported forge")
        purlString = ""

    # Is there a value
    if purlString != "":
        if purlNameSpace == "":
            purlString = "pkg:" + purlRepo + "/" + purlName + "@" + purlVersion 
        else:
            purlString = "pkg:" + purlRepo + "/" + purlNameSpace +"/" + purlName + "@" + purlVersion 

        if purlVersion == "N/A":
            purlString = purlString[:-4]

    logger.info("        purlString: %s" %(purlString))

    return purlString

