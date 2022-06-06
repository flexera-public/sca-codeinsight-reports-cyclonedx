'''
Copyright 2022 Flexera Software LLC
See LICENSE.TXT for full license text
SPDX-License-Identifier: MIT

Author : sgeary  
Created On : Fri May 20 2022
File : purl.py
'''

from email.mime import base
import logging

import CodeInsight_RESTAPIs.component.get_component_details
logger = logging.getLogger(__name__)


##############################
def get_purl_string(inventoryItem, baseURL, authToken):
    logger.info("entering get_purl_string")

    forge = inventoryItem["componentForgeName"]
    inventoryName = inventoryItem["name"]
    componentName = inventoryItem["componentName"]
    componentVersionName = inventoryItem["componentVersionName"]

    componentId = inventoryItem["componentId"]


    print("  Forge:  %s" %forge)
    print("      Inv Name:  %s" %inventoryName)
    print("      componentId:  %s" %componentId)


    if forge in ["apache", "cargo", "nuget", "pypi", "rubygems", "sourceforge"]:


        if forge == "rubygems":
            purlRepo = "gem"
        elif forge == "crates":
            purlRepo = "cargo"
        elif forge == "nuget gallery":
            purlRepo = "nuget"
        else:
            purlRepo = forge

        purlName = componentName
        purlVersion = componentVersionName
        purlNameSpace = ""

        purlString = "pkg:" + purlRepo + "/" + purlName + "@" + purlVersion 

    elif forge in ["centos", "fedora-koji"]:

        purlRepo = "rpm"
        purlName = componentName
        purlVersion = componentVersionName

        if forge == "centos":
            purlNameSpace = forge
        else:
            purlNameSpace = "fedora"

        purlString = "pkg:" + purlRepo + "/" + purlNameSpace +"/" + purlName + "@" + purlVersion 

    elif forge in ["clojars", "maven-google", "maven2-ibiblio"]:

        if forge == "clojars":
            purlRepo = forge
        else:
            purlRepo = "maven"

        purlName = componentName
        purlVersion = componentVersionName

        # Get namespace from component lookup
        componentDetails = CodeInsight_RESTAPIs.component.get_component_details.get_component_details_v3_summary(baseURL, componentId, authToken)
        componentTitle = componentDetails["data"]["title"]

        purlNameSpace = componentTitle.split("/")[0] # parse groupId from component title (start of string to forward slash "/")

        purlString = "pkg:" + purlRepo + "/" + purlNameSpace +"/" + purlName + "@" + purlVersion 


    elif forge in ["cpan", "cran", "hackage"]:

        purlRepo = forge
        purlNameSpace = ""
        
        # Get case sensitive name from component lookup
        componentDetails = CodeInsight_RESTAPIs.component.get_component_details.get_component_details_v3_summary(baseURL, componentId, authToken)
        componentTitle = componentDetails["data"]["title"]
        purlName = componentTitle.split(" - ")[0] # parse case-sensitive name from component title (start of string to dash "-" minus 1)

        purlVersion = componentVersionName  

        purlString = "pkg:" + purlRepo + "/" + purlName + "@" + purlVersion 

    elif forge in ["npm"]:

        purlRepo = forge
        purlNameSpace = ""
        
        purlVersion = componentVersionName  
        purlName = componentName

        print(" *** %s" %purlName)
   
        purlName = "TBD" # component name (replace "@" with "%40")

        purlString = "pkg:" + purlRepo + "/" + purlName + "@" + purlVersion 

    elif forge in ["packagist"]:

        purlRepo = "composer"
        purlNameSpace = ""

        # Get case sensitive name from component lookup
        componentDetails = CodeInsight_RESTAPIs.component.get_component_details.get_component_details_v3_summary(baseURL, componentId, authToken)
        componentTitle = componentDetails["data"]["title"]
        purlName = componentTitle.split(" - ")[0] # parse case-sensitive name from component title (start of string to dash "-" minus 1)

        purlVersion = componentVersionName  

        purlString = "pkg:" + purlRepo + "/" + purlName + "@" + purlVersion 


    elif forge in ["github", "gitlab"]:

        purlRepo = forge
        purlVersion = componentVersionName  

        # Get case sensitive name from component lookup
        componentDetails = CodeInsight_RESTAPIs.component.get_component_details.get_component_details_v3_summary(baseURL, componentId, authToken)
        componentTitle = componentDetails["data"]["title"]

        print("  ***  %s" %componentTitle)
        
        componentName = componentTitle.split(" - ")[0] # parse case-sensitive name from component title (start of string to dash "-" minus 1)

        purlNameSpace, purlName  = componentName.split("/") # parse groupId from component title (start of string to forward slash "/")
   
        purlString = "pkg:" + purlRepo + "/" + purlNameSpace +"/" + purlName + "@" + purlVersion 

    
    elif forge in ["fsf-directory", "codeplex", "gnu", "java.net", "kernel.org", "mozilla", "mysqlab", "savannah"]:
        purlString = ""

    else:
        print("        Unsupported forge")
        
        purlString = ""


    print("        purlString:  %s" %purlString)

    print("")

    return purlString

