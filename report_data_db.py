"""
Copyright 2022 Flexera Software LLC
See LICENSE.TXT for full license text
SPDX-License-Identifier: MIT

Author : sarthak
Created On : Thu Apr 24 2022
File : report_data_db.py
"""
import sys
import threading
import subprocess
import logging
import os
import configparser
import json
from packaging.version import parse as parse_version

logger = logging.getLogger(__name__)


# User can set this variable directly in code
user_java_path = ""

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Determine the correct Java executable name
java_exec = "java.exe" if os.name == "nt" else "java"
DEFAULT_JAVA_PATH = os.path.abspath(os.path.join(BASE_DIR, '..', '..', 'jre', 'bin', java_exec))
# Check JAVA_HOME and construct the java path
java_home = os.environ.get('JAVA_HOME')
if user_java_path != "":
    JAVA_PATH = user_java_path
elif java_home:
    JAVA_PATH = os.path.join(java_home, 'bin', java_exec)
else:
    JAVA_PATH = DEFAULT_JAVA_PATH

if not os.path.exists(JAVA_PATH):
    error_msg = (
        f"Java executable not found at: {JAVA_PATH}\n"
        "Please ensure Java is installed and accessible. You can:\n"
        "1. Set the JAVA_HOME environment variable to your Java installation directory\n"
        "2. Manually set the 'user_java_path' variable in this file:\n"
        f"   {os.path.abspath(__file__)}\n"
        f"   Example: user_java_path = r'C:\\Program Files\\Java\\jdk-11\\bin\\{java_exec}'"
    )
    logger.error(error_msg)
    sys.exit(error_msg)
print(f"Using Java path: {JAVA_PATH}")  # Debugging line to check the Java path
JAR_PATH = os.path.join(BASE_DIR, '..', '..', 'samples', 'customreport_helper', 'DbConnection.jar')
properties_file = os.path.join(BASE_DIR, '..', '..', 'config', 'core', 'core.db.properties')

if not os.path.exists(JAR_PATH):
    error_msg = (
        "DbConnection.jar is missing at: "
        f"{os.path.abspath(JAR_PATH)}. "
        "This means your Code Insight server is older than 2025 R3. "
        "Please upgrade to 2025 R3 or later, or get DbConnection.jar file from support "
        "and place it in <Install Location>\\samples\\customreport_helper."
    )
    logger.error(error_msg)
    sys.exit(error_msg)

class InteractiveDbQueryRunner:
    def __init__(self, jar_path, java_path=JAVA_PATH):
        self.proc = subprocess.Popen(
            ["java", "-jar", jar_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1
        )
        self.lock = threading.Lock()

    def run_query(self, sql_query):
        with self.lock:
            if self.proc.poll() is not None:
                raise RuntimeError("Java process is not running")
            self.proc.stdin.write(sql_query + "\n")
            self.proc.stdin.flush()
            output = ""
            while True:
                line = self.proc.stdout.readline()
                if not line:
                    break
                output += line
                if line.strip().endswith("]") or line.strip().endswith("}"):
                    break
            try:
                return json.loads(output)
            except json.JSONDecodeError:
                return []

    def close(self):
        if self.proc and self.proc.poll() is None:
            try:
                if self.proc.stdin:
                    self.proc.stdin.write("exit\n")
                    self.proc.stdin.flush()
            except Exception as e:
                logger.warning(f"Error sending exit to Java process: {e}")
            try:
                self.proc.terminate()
            except Exception as e:
                logger.warning(f"Error terminating Java process: {e}")
            self.proc = None
db_runner = InteractiveDbQueryRunner(JAR_PATH, JAVA_PATH)


def get_db_vendor():
    global db_vendor # Declare db_vendor as global variable
    is_property_file_exists = check_properties_file_exists()
    if is_property_file_exists:
        logger.info("Reading core.db.properties file")
        with open(properties_file, 'r') as file:
            # Add a dummy section header to make it compatible with configparser
            lines = ['[DEFAULT]\n']
            for line in file:
                # Skip comments starting with #
                if not line.strip().startswith('#'):
                    lines.append(line)
    
        config = configparser.ConfigParser()
        config.read_string(''.join(lines))

        # Read database configuration from the selected section
        db_vendor = config['DEFAULT']['db.vendor']
        if db_vendor is not None:
            return db_vendor.lower()

def check_properties_file_exists():
    try:
        with open(properties_file, 'r') as file:
            return True
    except FileNotFoundError:
        print(f"Properties file {properties_file} not found.")
        return False

def get_projects_data(project_id):
    sql = f"SELECT NAME_ AS topLevelProjectName FROM PAS_PROJECT WHERE ID_ = {project_id};"
    result = db_runner.run_query(sql)
    if result and isinstance(result, list) and len(result) > 0 and 'topLevelProjectName' in result[0]:
        return result[0]['topLevelProjectName']
    else:
        logger.warning(f"No project found for ID {project_id}")
        return None

def get_inventory_name(inventory_id):
    sql = f"SELECT NAME_ AS invName FROM PSE_INVENTORY_GROUPS WHERE ID_ = {inventory_id};"
    return db_runner.run_query(sql)

def get_patch_comp_version(component_id, version_name):
    sql = f"SELECT VERSION_NAME_ FROM PDL_COMPONENT_VERSION WHERE COMPONENT_ID_ = {component_id};"
    results = db_runner.run_query(sql)
    numeric_versions = []
    for row in results:
        v = row['VERSION_NAME_']
        if v and v[0].isdigit():
            try:
                # Try to parse both the candidate and the reference version
                parse_version(v)
                parse_version(version_name)
                numeric_versions.append(v)
            except Exception:
                continue
    higher_versions = []
    for v in numeric_versions:
        try:
            if parse_version(v) > parse_version(version_name):
                higher_versions.append(v)
        except Exception:
            continue
    if not higher_versions:
        return None
    return str(max(higher_versions, key=parse_version))

def get_inventory_data(project_id):
    sql = f"""SELECT REPO_TAB.ITEM_TYPE_ AS inventoryType, REPO_TAB.COMPONENT_ID_ AS component_id, REPO_TAB.COMPONENT_VERSION_ID_ AS component_version_id, FORGE.NAME_ AS forge, INV_GRP.ID_ AS inventoryID, INV_GRP.NAME_ AS inventoryItemName, INV_GRP.USAGE_TEXT_ AS usageText, INV_GRP.PARENT_GROUP_ID_ AS parentGroupId, INV_GRP.PRIORITY_ID_ AS priority, INV_GRP.AUDITOR_REVIEW_NOTES_ AS auditNotes, INV_GRP.DISTRIBUTION_TYPE_ AS disType, COMP.NAME_ AS componentName, COMP_VER.VERSION_NAME_ AS componentVersionName,COMP.ID_ AS componentId, COMP.URL_ AS componentUrl, INV_GRP.DESCRIPTION_ AS componentDescription, LIC.SPDX_LICENSE_IDENTIFIER_ AS selectedLicenseSPDXIdentifier, LIC.NAME_ AS selectedLicenseName, LIC.URL_ AS selectedLicenseUrl FROM PSE_INVENTORY_GROUPS INV_GRP JOIN PAS_REPOSITORY_ITEM REPO_TAB ON INV_GRP.REPOSITORY_ITEM_ID_ = REPO_TAB.ID_ JOIN PDL_COMPONENT COMP ON REPO_TAB.COMPONENT_ID_ = COMP.ID_ JOIN PDL_FORGE FORGE ON FORGE.ID_ = COMP.FORGE_ID_ LEFT JOIN PDL_COMPONENT_VERSION COMP_VER ON REPO_TAB.COMPONENT_VERSION_ID_ = COMP_VER.ID_ JOIN PDL_LICENSE LIC ON REPO_TAB.LICENSE_ID_ = LIC.ID_ WHERE INV_GRP.PROJECT_ID_ = {project_id} and INV_GRP.PUBLISHED_ =1;"""
    return db_runner.run_query(sql)

def get_inventory_data_custom(project_id):
    sql = f"""SELECT REPO_TAB.ITEM_TYPE_ AS inventoryType, REPO_TAB.COMPONENT_ID_ AS component_id, REPO_TAB.COMPONENT_VERSION_ID_ AS component_version_id, FORGE.NAME_ AS forge, INV_GRP.ID_ AS inventoryID, INV_GRP.NAME_ AS inventoryItemName, INV_GRP.USAGE_TEXT_ AS usageText, INV_GRP.PARENT_GROUP_ID_ AS parentGroupId, INV_GRP.PRIORITY_ID_ AS priority, INV_GRP.AUDITOR_REVIEW_NOTES_ AS auditNotes, INV_GRP.DISTRIBUTION_TYPE_ AS disType,COMP.NAME_ AS componentName, CUST_COMP_VER.VERSION_NAME_ AS componentVersionName, COMP.ID_ AS componentId, COMP.URL_ AS componentUrl, INV_GRP.DESCRIPTION_ AS componentDescription, LIC.SPDX_LICENSE_IDENTIFIER_ AS selectedLicenseSPDXIdentifier, LIC.NAME_ AS selectedLicenseName, LIC.URL_ AS selectedLicenseUrl FROM PSE_INVENTORY_GROUPS INV_GRP JOIN PAS_REPOSITORY_ITEM REPO_TAB ON INV_GRP.REPOSITORY_ITEM_ID_ = REPO_TAB.ID_ JOIN PDL_COMPONENT COMP ON REPO_TAB.COMPONENT_ID_ = COMP.ID_ JOIN PDL_FORGE FORGE ON FORGE.ID_ = COMP.FORGE_ID_ JOIN PDL_COMPONENT_VERSION_CUSTOM CUST_COMP_VER ON REPO_TAB.COMPONENT_VERSION_ID_ = CUST_COMP_VER.ID_ JOIN PDL_LICENSE LIC ON REPO_TAB.LICENSE_ID_ = LIC.ID_ WHERE INV_GRP.PROJECT_ID_ = {project_id} and INV_GRP.PUBLISHED_ =1;"""
    return db_runner.run_query(sql)

def get_component_forge(component_id):
    sql = f"SELECT frg.NAME_ AS forge, comp.TITLE_ AS title FROM PDL_FORGE frg JOIN PDL_COMPONENT comp ON frg.ID_ = comp.FORGE_ID_ WHERE comp.ID_= {component_id};"
    return db_runner.run_query(sql)

def get_comp_license(component_id):
    sql = f"SELECT lic.NAME_ AS licenseName, lic.URL_ AS licenseURL FROM PDL_LICENSE lic JOIN PDL_COMPONENT_LICENSE cmplic ON lic.ID_ = cmplic.LICENSE_ID_ WHERE cmplic.COMPONENT_ID_= {component_id};"
    return db_runner.run_query(sql)

def get_comp_ver_custom_license(component_version_id):
    sql = f"SELECT lic.NAME_ AS licenseName, lic.URL_ AS licenseURL FROM PDL_LICENSE lic JOIN PDL_CUSTOM_COMP_VER_LICENSE cmplic ON lic.ID_ = cmplic.LICENSE_ID_ WHERE cmplic.VERSION_ID_= {component_version_id};"
    return db_runner.run_query(sql)

def get_comp_ver_license_data(component_version_id):
    sql = f"SELECT lic.NAME_ AS licenseName, lic.URL_ AS licenseURL FROM PDL_LICENSE lic JOIN PDL_COMP_VER_LICENSE cmplic ON lic.ID_ = cmplic.LICENSE_ID_ WHERE cmplic.COMPONENT_VERSION_ID_= {component_version_id};"
    return db_runner.run_query(sql)

def get_component_version_vdr_vulnerabilities(project_id, component_version_id):
    vendor = get_db_vendor()
    if vendor == "mysql":
        sql = f"""SELECT VUL.ID_ AS vulnerabilityId, VUL.NAME_ AS vulnerabilityName,  VUL.DESCRIPTION_ AS vulnerabilityDescription, REG.NAME_ AS vulnerabilitySource, VUL.URL_ AS vulnerabilityUrl, DATE_FORMAT(VUL.ORIGINAL_RELEASE_DATE_, '%m/%d/%Y') AS publishedDate, DATE_FORMAT(VUL.LAST_REVISED_DATE_, '%m/%d/%Y') AS modifiedDate, DATE_FORMAT(VUL.ORIGINAL_RELEASE_DATE_, '%m/%d/%Y') AS createdDate, CWE.CWE_NAME_ AS vulnerabilityCWE, VUL.CVSSV3_SEVERITY_ AS vulnerabilityCvssV3Severity, VUL.CVSSV3_SCORE_ AS vulnerabilityCvssV3Score, VUL.SEVERITY_ AS vulnerabilityCvssV2Severity, VUL.SCORE_ AS vulnerabilityCvssV2Score, VUL.CVSS3_VECTOR_ AS vulnerabilityCvssV3Vector, VUL.CVSS2_VECTOR_ AS vulnerabilityCvssV2Vector, VEX.VULNERABILITY_STATE_ AS state, VEX.JUSTIFICATION_ AS justification, VEX.VULNERABILITY_RESPONSE_ AS response, VEX.DETAIL_ AS detail FROM PDL_COMP_VER_VULNERABILITY VER_VUL LEFT JOIN PDL_VULNERABILITY VUL ON VUL.ID_ = VER_VUL.VULNERABILITY_ID_ LEFT JOIN PDL_VULNERABILITY_REGISTRY REG ON VUL.REGISTRY_ID_ = REG.ID_ LEFT JOIN PDL_VULNERABILITY_CWE_MAP CWE ON VUL.ID_ = CWE.VULNERABILITY_ID_ LEFT JOIN PAS_VEX_ANALYSIS VEX ON VEX.VULNERABILITY_ID_ = VER_VUL.VULNERABILITY_ID_ AND VEX.PROJECT_ID_ = {project_id} WHERE VER_VUL.COMPONENT_VERSION_ID_ = {component_version_id} AND VER_VUL.VULNERABILITY_ID_ NOT IN (SELECT SUP.VULNERABILITY_ID_ FROM PSE_SUPPRESSED_VULNERABILITY SUP LEFT JOIN PAS_VEX_ANALYSIS SVEX ON SUP.VULNERABILITY_ID_ = SVEX.VULNERABILITY_ID_ WHERE SVEX.PROJECT_ID_ = {project_id} OR SVEX.PROJECT_ID_ IS NULL);"""
    else:
        sql = f"""SELECT VUL.ID_ AS vulnerabilityId, VUL.NAME_ AS vulnerabilityName, VUL.DESCRIPTION_ AS vulnerabilityDescription, REG.NAME_ AS vulnerabilitySource, VUL.URL_ AS vulnerabilityUrl, FORMAT(VUL.ORIGINAL_RELEASE_DATE_, 'MM/dd/yyyy') AS publishedDate, FORMAT(VUL.LAST_REVISED_DATE_, 'MM/dd/yyyy') AS modifiedDate, FORMAT(VUL.ORIGINAL_RELEASE_DATE_, 'MM/dd/yyyy') AS createdDate, CWE.CWE_NAME_ AS vulnerabilityCWE, VUL.CVSSV3_SEVERITY_ AS vulnerabilityCvssV3Severity, VUL.CVSSV3_SCORE_ AS vulnerabilityCvssV3Score, VUL.SEVERITY_ AS vulnerabilityCvssV2Severity, VUL.SCORE_ AS vulnerabilityCvssV2Score, VUL.CVSS3_VECTOR_ AS vulnerabilityCvssV3Vector, VUL.CVSS2_VECTOR_ AS vulnerabilityCvssV2Vector, VEX.VULNERABILITY_STATE_ AS state, VEX.JUSTIFICATION_ AS justification, VEX.VULNERABILITY_RESPONSE_ AS response, VEX.DETAIL_ AS detail FROM PDL_COMP_VER_VULNERABILITY VER_VUL LEFT JOIN PDL_VULNERABILITY VUL ON VUL.ID_ = VER_VUL.VULNERABILITY_ID_ LEFT JOIN PDL_VULNERABILITY_REGISTRY REG ON VUL.REGISTRY_ID_ = REG.ID_ LEFT JOIN PDL_VULNERABILITY_CWE_MAP CWE ON VUL.ID_ = CWE.VULNERABILITY_ID_ LEFT JOIN PAS_VEX_ANALYSIS VEX ON VEX.VULNERABILITY_ID_ = VER_VUL.VULNERABILITY_ID_ AND VEX.PROJECT_ID_ = {project_id} WHERE VER_VUL.COMPONENT_VERSION_ID_ = {component_version_id} AND VER_VUL.VULNERABILITY_ID_ NOT IN (SELECT SUP.VULNERABILITY_ID_ FROM PSE_SUPPRESSED_VULNERABILITY SUP LEFT JOIN PAS_VEX_ANALYSIS SVEX ON SUP.VULNERABILITY_ID_ = SVEX.VULNERABILITY_ID_ WHERE SVEX.PROJECT_ID_ = {project_id} OR SVEX.PROJECT_ID_ IS NULL);"""
    return db_runner.run_query(sql)

def get_component_version_vex_vulnerabilities(project_id, component_version_id):
    vendor = get_db_vendor()
    if vendor == "mysql":
        sql = f"""SELECT VUL.ID_ AS vulnerabilityId, VUL.NAME_ AS vulnerabilityName, VUL.DESCRIPTION_ AS vulnerabilityDescription, REG.NAME_ AS vulnerabilitySource, VUL.URL_ AS vulnerabilityUrl, DATE_FORMAT(VUL.ORIGINAL_RELEASE_DATE_, '%m/%d/%Y') AS publishedDate, DATE_FORMAT(VUL.LAST_REVISED_DATE_, '%m/%d/%Y') AS modifiedDate, DATE_FORMAT(VUL.ORIGINAL_RELEASE_DATE_, '%m/%d/%Y') AS createdDate, CWE.CWE_NAME_ AS vulnerabilityCWE, VUL.CVSSV3_SEVERITY_ AS vulnerabilityCvssV3Severity, VUL.CVSSV3_SCORE_ AS vulnerabilityCvssV3Score, VUL.SEVERITY_ AS vulnerabilityCvssV2Severity, VUL.SCORE_ AS vulnerabilityCvssV2Score, VUL.CVSS3_VECTOR_ AS vulnerabilityCvssV3Vector, VUL.CVSS2_VECTOR_ AS vulnerabilityCvssV2Vector, VEX.VULNERABILITY_STATE_ AS state, VEX.JUSTIFICATION_ AS justification, VEX.VULNERABILITY_RESPONSE_ AS response, VEX.DETAIL_ AS detail FROM PDL_COMP_VER_VULNERABILITY VER_VUL LEFT JOIN PDL_VULNERABILITY VUL ON VUL.ID_ = VER_VUL.VULNERABILITY_ID_ LEFT JOIN PDL_VULNERABILITY_REGISTRY REG ON VUL.REGISTRY_ID_ = REG.ID_ LEFT JOIN PDL_VULNERABILITY_CWE_MAP CWE ON VUL.ID_ = CWE.VULNERABILITY_ID_ LEFT JOIN PAS_VEX_ANALYSIS VEX ON VEX.VULNERABILITY_ID_ = VER_VUL.VULNERABILITY_ID_ AND VEX.PROJECT_ID_ = {project_id} LEFT JOIN PSE_SUPPRESSED_VULNERABILITY SUP ON SUP.VULNERABILITY_ID_ = VER_VUL.VULNERABILITY_ID_ WHERE VER_VUL.COMPONENT_VERSION_ID_ = {component_version_id} AND (VEX.VULNERABILITY_ID_ IS NOT NULL OR SUP.VULNERABILITY_ID_ IS NOT NULL);"""
    else:
        sql = f"""SELECT VUL.ID_ AS vulnerabilityId, VUL.NAME_ AS vulnerabilityName, VUL.DESCRIPTION_ AS vulnerabilityDescription, REG.NAME_ AS vulnerabilitySource, VUL.URL_ AS vulnerabilityUrl, FORMAT(VUL.ORIGINAL_RELEASE_DATE_, 'MM/dd/yyyy') AS publishedDate, FORMAT(VUL.LAST_REVISED_DATE_, 'MM/dd/yyyy') AS modifiedDate, FORMAT(VUL.ORIGINAL_RELEASE_DATE_, 'MM/dd/yyyy') AS createdDate, CWE.CWE_NAME_ AS vulnerabilityCWE, VUL.CVSSV3_SEVERITY_ AS vulnerabilityCvssV3Severity, VUL.CVSSV3_SCORE_ AS vulnerabilityCvssV3Score, VUL.SEVERITY_ AS vulnerabilityCvssV2Severity, VUL.SCORE_ AS vulnerabilityCvssV2Score, VUL.CVSS3_VECTOR_ AS vulnerabilityCvssV3Vector, VUL.CVSS2_VECTOR_ AS vulnerabilityCvssV2Vector, VEX.VULNERABILITY_STATE_ AS state, VEX.JUSTIFICATION_ AS justification, VEX.VULNERABILITY_RESPONSE_ AS response, VEX.DETAIL AS detail FROM PDL_COMP_VER_VULNERABILITY VER_VUL LEFT JOIN PDL_VULNERABILITY VUL ON VUL.ID_ = VER_VUL.VULNERABILITY_ID_ LEFT JOIN PDL_VULNERABILITY_REGISTRY REG ON VUL.REGISTRY_ID_ = REG.ID_ LEFT JOIN PDL_VULNERABILITY_CWE_MAP CWE ON VUL.ID_ = CWE.VULNERABILITY_ID_ LEFT JOIN PAS_VEX_ANALYSIS VEX ON VEX.VULNERABILITY_ID_ = VER_VUL.VULNERABILITY_ID_ AND VEX.PROJECT_ID_ = {project_id} LEFT JOIN PSE_SUPPRESSED_VULNERABILITY SUP ON SUP.VULNERABILITY_ID_ = VER_VUL.VULNERABILITY_ID_ WHERE VER_VUL.COMPONENT_VERSION_ID_ = {component_version_id} AND (VEX.VULNERABILITY_ID_ IS NOT NULL OR SUP.VULNERABILITY_ID_ IS NOT NULL);"""
    return db_runner.run_query(sql)

def get_child_projects(project_id):
    project_ids = [project_id]
    subproject_ids_to_process = [project_id]
    logger.info("Entering get_child_projects (recursive)")
    while subproject_ids_to_process:
        current_project_id = subproject_ids_to_process.pop(0)
        sql = f"SELECT SUBPROJECT_ID_ as subProjectId FROM PAS_PROJECT_HIERARCHY WHERE PROJECT_ID_ = {current_project_id};"
        result = db_runner.run_query(sql)
        sub_ids = []
        if isinstance(result, list) and result:
            sub_ids = [row['subProjectId'] for row in result if 'subProjectId' in row and row['subProjectId'] is not None]
        elif result:
            logger.warning(f"Unexpected result format in get_child_projects for project {current_project_id}: {result}")
        if not sub_ids:
            logger.info(f"No subprojects found for project {current_project_id}")
        for sub_id in sub_ids:
            if sub_id not in project_ids:
                project_ids.append(sub_id)
                subproject_ids_to_process.append(sub_id)
    return project_ids

def get_inventory_files(project_id, inventory_id):
    sql = f"SELECT SCAN_FILE.PATH_ AS filePath, SCAN_FILE.MD5_ AS md5, SCAN_FILE.SHA1_ AS sha1 FROM PSE_INVENTORY_GROUP_FILES GRP_FILES JOIN PSE_SCANNED_FILES SCAN_FILE ON SCAN_FILE.ID_ = GRP_FILES.FILE_ID_  where PROJECT_ID_={project_id} and GRP_FILES.GROUP_ID_={inventory_id};"
    return db_runner.run_query(sql)

def get_custom_field_value(inventory_id, field_label="Archive Property"):
    # Step 1: Get the custom field column name for the given label
    sql_meta = f"SELECT FIELD_NAME_ FROM PAS_INVENTORY_FLEX_FIELDS_METADATA WHERE FIELD_LABEL_ = '{field_label}';"
    meta_result = db_runner.run_query(sql_meta)
    if not meta_result or not meta_result[0].get('FIELD_NAME_'):
        logger.warning(f"No custom field metadata found for '{field_label}'")
        return "N/A"
    field_name = meta_result[0]['FIELD_NAME_']
    # Step 2: Build and execute the value query using the column name
    sql_value = f"SELECT {field_name} AS CustomFieldValue FROM PAS_INVENTORY_FLEX_FIELDS WHERE INVENTORY_ID_={inventory_id};"
    result = db_runner.run_query(sql_value)
    if result and "CustomFieldValue" in result[0] and result[0]["CustomFieldValue"]:
        return result[0]["CustomFieldValue"]
    else:
        logger.warning(f"No custom field value found for inventory ID: {inventory_id} and label: {field_label}")
        return "N/A"



