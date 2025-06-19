"""
Copyright 2022 Flexera Software LLC
See LICENSE.TXT for full license text
SPDX-License-Identifier: MIT

Author : sgeary
Created On : Fri May 20 2022
Modified By : sarthak
Modified On: Thu Apr 24 2025
File : create_report.py
"""

import shutil
import sys, os, logging, argparse, json, re, zipfile
from datetime import datetime

import _version

import report_data
import report_artifacts
import report_errors
import upload_reports
import report_archive
import report_data_db

###################################################################################
# Test the version of python to make sure it's at least the version the script
# was tested on, otherwise there could be unexpected results
if sys.version_info < (3, 6):
    raise Exception(
        "The current version of Python is less than 3.6 which is unsupported.\n Script created/tested against python version 3.6.8. "
    )
else:
    pass

propertiesFile = "../server_properties.json"  # Created by installer or manually
propertiesFile = logfileName = (
    os.path.dirname(os.path.realpath(__file__)) + "/" + propertiesFile
)
logfileName = os.path.dirname(os.path.realpath(__file__)) + "/_cyclonedx_report.log"

###################################################################################
#  Set up logging handler to allow for different levels of logging to be capture
logging.basicConfig(
    format="%(asctime)s,%(msecs)-3d  %(levelname)-8s [%(filename)-30s:%(lineno)-4d]  %(message)s",
    datefmt="%Y-%m-%d:%H:%M:%S",
    filename=logfileName,
    filemode="w",
    level=logging.DEBUG,
)
logger = logging.getLogger(__name__)
logging.getLogger("urllib3").setLevel(logging.WARNING)  # Disable logging for requests module
####################################################################################
# Create command line argument options
parser = argparse.ArgumentParser(
    description="""Usage Examples:

Windows:
  python create_report.py -pid <projectID> -reportOpts "{\\"includeChildProjects\\": \\"True\\", \\"includeVEXReport\\": \\"True\\", \\"includeVDRReport\\": \\"True\\"}"   #####      

Linux:
  python3 create_report.py -pid <projectID> -reportOpts '{"includeChildProjects":"True","includeVEXReport":"True","includeVDRReport":"True"}'   #####      

Note:
  - The -pid flag is mandatory.
  - The -reportOpts flag is optional. If omitted, all values will default to "True".
  Example: python3 create_report.py -pid <projectID>
"""
)



parser.add_argument("-pid", "--projectID", help="Project ID")
parser.add_argument("-rid", "--reportID", help="Report ID(Optional)")
parser.add_argument(
    "-authToken", "--authToken", help="Code Insight Authorization Token(Optional)"
)
parser.add_argument(
    "-baseURL",
    "--baseURL",
    help="Code Insight Core Server Protocol/Domain Name/Port.(Optional)  i.e. http://localhost:8888 or https://sca.codeinsight.com:8443",
)
parser.add_argument(
    "-reportOpts", "--reportOptions", help="Options for report content(Optional)"
)
# ----------------------------------------------------------------------#
# Setting arguments for report to run independently without codeinsight(maintinance or Downtime)


# ----------------------------------------------------------------------#
def main():

    reportName = "CycloneDX Report"
    reportVersion = _version.__version__

    logger.info("Creating %s - %s" % (reportName, reportVersion))
    print("Creating %s - %s" % (reportName, reportVersion))
    print("    Logfile: %s" % (logfileName))

    #####################################################################################################
    if os.path.exists(propertiesFile):
        try:
            file_ptr = open(propertiesFile, "r")
            configData = json.load(file_ptr)
            baseURL = configData["core.server.url"]
            file_ptr.close()
            logger.info("Using baseURL from properties file: %s" % propertiesFile)
        except:
            logger.error("Unable to open properties file: %s" % propertiesFile)

        # Is there a self signed certificate to consider?
        try:
            certificatePath = configData["core.server.certificate"]
            os.environ["REQUESTS_CA_BUNDLE"] = certificatePath
            os.environ["SSL_CERT_FILE"] = certificatePath
            logger.info("Self signed certificate added to env")
        except:
            logger.info("No self signed certificate in properties file")

    else:
        baseURL = "http://localhost:8888"  # Required if the core.server.properties files is not used
        logger.info("Using baseURL from create_report.py")

    # See what if any arguments were provided

    args = parser.parse_args()
    projectID = (
        args.projectID
        if args.projectID is not None
        else sys.exit("Project ID -pid flag is mandatory")
    )
    reportID = (
        args.reportID
        if args.reportID is not None
        else print("Ignoring as -rid flag is not needed")
    )
    authToken = (
        args.authToken
        if args.authToken is not None
        else print("Ignoring as -authToken flag is not needed")
    )
    if args.reportOptions is not None:
        reportOptions = args.reportOptions
        if sys.platform.startswith("linux"):
            logger.info(f"Before Double Quote replacement: {reportOptions}")
            if '""' in reportOptions:
                reportOptions = reportOptions.replace('""', '"')[1:-1]
    else:
        reportOptions = '{"includeChildProjects": "True","includeVEXReport": "True","includeVDRReport": "True"}'
        if sys.platform.startswith("linux"):
            reportOptions = '{"includeChildProjects":"True","includeVEXReport":"True","includeVDRReport":"True"}'
    logger.info(f"Using default report options: {reportOptions}")

    fileNameTimeStamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    reportTimeStamp = datetime.strptime(fileNameTimeStamp, "%Y%m%d-%H%M%S").strftime("%B %d, %Y at %H:%M:%S")
    reportOptions = json.loads(reportOptions)
    reportOptions = verifyOptions(reportOptions)
    releaseDetails = {}
    releaseDetails["tool"] = "Revenera SCA - Code Insight"
    releaseDetails["releaseVersion"] = "N/A"
    releaseDetails["vendor"] = "Revenera"

    logger.debug("Code Insight Release: %s" % releaseDetails["releaseVersion"])
    logger.debug("Custom Report Provided Arguments:")
    logger.debug("    projectID:  %s" % projectID)
    logger.debug("    reportID:   %s" % reportID)
    logger.debug("    baseURL:  %s" % baseURL)
    logger.debug("    reportOptions:  %s" % reportOptions)

    reportData = {}
    reportData["projectID"] = projectID
    reportData["reportName"] = reportName
    reportData["reportVersion"] = reportVersion
    reportData["reportOptions"] = reportOptions
    reportData["releaseDetails"] = releaseDetails
    reportData["fileNameTimeStamp"] = fileNameTimeStamp
    reportData["reportTimeStamp"] = reportTimeStamp

    # Collect the data for the report
    if "errorMsg" in reportOptions.keys():

        reportFileNameBase = (
            reportName.replace(" ", "_") + "-Creation_Error-" + fileNameTimeStamp
        )

        reportData["errorMsg"] = reportOptions["errorMsg"]
        reportData["reportName"] = reportName
        reportData["reportFileNameBase"] = reportFileNameBase

        reports = report_errors.create_error_report(reportData)
        print("    *** ERROR  ***  Error found validating report options")
    else:
        reportData = report_data.gather_data_for_report(
            projectID, reportData, reportOptions
        )
        print("    Report data has been collected")
        report_data_db.db_runner.close()
        projectName = reportData["topLevelProjectName"]
        projectNameForFile = re.sub(
            r"[^a-zA-Z0-9]+", "-", projectName
        )  # Remove special characters from project name for artifacts

        # Are there child projects involved?  If so have the artifact file names reflect this fact
        if len(reportData["projectList"]) == 1:
            reportFileNameBase = (
                projectNameForFile
                + "-"
                + str(projectID)
                + "-"
                + reportName.replace(" ", "_")
                + "-"
                + fileNameTimeStamp
            )
        else:
            reportFileNameBase = (
                projectNameForFile
                + "-with-children-"
                + str(projectID)
                + "-"
                + reportName.replace(" ", "_")
                + "-"
                + fileNameTimeStamp
            )

        reportData["reportUTCTimeStamp"] = datetime.strptime(
            fileNameTimeStamp, "%Y%m%d-%H%M%S"
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        reportData["reportFileNameBase"] = reportFileNameBase

        if "errorMsg" in reportData.keys():
            reports = report_errors.create_error_report(reportData)
            print("    Error report artifacts have been created")
        else:
            reports = report_artifacts.create_report_artifacts(
                reportData, reportOptions
            )
            print("    Report artifacts have been created")
            for report in reports["allFormats"]:
                print("       - %s" % report)

    print("    Create report archive for upload")
    uploadZipfile = report_archive.create_report_zipfile(
        reports, reportFileNameBase
    )
    print("    Upload zip file creation completed")
    if authToken is not None:
        upload_reports.upload_project_report_data(
            baseURL, projectID, reportID, authToken, uploadZipfile
        )
        print("    Report uploaded to Code Insight")
        ########################################################
        # Remove the file since it has been uploaded to Code Insight
        try:
            os.remove(uploadZipfile)
        except OSError:
            logger.error("Error removing %s" % uploadZipfile)
            print("Error removing %s" % uploadZipfile)
    else:
        # Get the current path and directory
        current_path = os.path.abspath(__file__)
        current_directory = os.path.dirname(current_path)
        logger.info(f"Current directory: {current_directory}")

        # Define the DBReports directory path
        quickDBReports_dir = os.path.join(current_directory, "DBReports")

        # Check if quickDBReports directory exists, if not create it
        if not os.path.exists(quickDBReports_dir):
            os.makedirs(quickDBReports_dir)
            logger.info(f"Created directory: {quickDBReports_dir}")

        # Check if there are any previous reports in quickDBReports directory
        previous_reports = [
            f
            for f in os.listdir(quickDBReports_dir)
            if os.path.isfile(os.path.join(quickDBReports_dir, f))
        ]
        if previous_reports:
            # Create a Backup directory inside quickDBReports
            backup_dir = os.path.join(quickDBReports_dir, "Backup")
            if not os.path.exists(backup_dir):
                os.makedirs(backup_dir)
                logger.info(f"Created backup directory: {backup_dir}")

            # Create a timestamped backup directory inside Backup
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            timestamped_backup_dir = os.path.join(backup_dir, f"Backup_{timestamp}")
            os.makedirs(timestamped_backup_dir)
            logger.info(
                f"Created timestamped backup directory: {timestamped_backup_dir}"
            )

            # Move all previous reports to the timestamped backup directory
            for report in previous_reports:
                shutil.move(
                    os.path.join(quickDBReports_dir, report),
                    os.path.join(timestamped_backup_dir, report),
                )
                logger.info(f"Moved report {report} to backup directory")

        # Move new reports to the quickDBReports directory
        shutil.move(reportFileNameBase + ".xml", quickDBReports_dir)
        shutil.move(uploadZipfile, quickDBReports_dir)
        logger.info(f"Moved new report {uploadZipfile} to {quickDBReports_dir}")

    logger.info("Completed creating %s" % reportName)
    print("Completed creating %s" % reportName)


# ----------------------------------------------------------------------#
def verifyOptions(reportOptions):
    """
    Expected Options for report:
            includeChildProjects - True/False
    """
    reportOptions["errorMsg"] = []
    trueOptions = ["true", "t", "yes", "y"]
    falseOptions = ["false", "f", "no", "n"]

    includeChildProjects = reportOptions["includeChildProjects"]
    includeVDRReport = reportOptions["includeVDRReport"]
    includeVEXReport = reportOptions["includeVEXReport"]

    if includeChildProjects.lower() in trueOptions:
        reportOptions["includeChildProjects"] = True
    elif includeChildProjects.lower() in falseOptions:
        reportOptions["includeChildProjects"] = False
    else:
        reportOptions["errorMsg"].append(
            "Invalid option for including child projects: <b>%s</b>.  Valid options are <b>True/False</b>"
            % includeChildProjects
        )

    if includeVDRReport.lower() in trueOptions:
        reportOptions["includeVDRReport"] = True
    elif includeVDRReport.lower() in falseOptions:
        reportOptions["includeVDRReport"] = False
    else:
        reportOptions["errorMsg"].append(
            "Invalid option for including child projects: <b>%s</b>.  Valid options are <b>True/False</b>"
            % includeVDRReport
        )

    if includeVEXReport.lower() in trueOptions:
        reportOptions["includeVEXReport"] = True
    elif includeVEXReport.lower() in falseOptions:
        reportOptions["includeVEXReport"] = False
    else:
        reportOptions["errorMsg"].append(
            "Invalid option for including child projects: <b>%s</b>.  Valid options are <b>True/False</b>"
            % includeVEXReport
        )

    if not reportOptions["errorMsg"]:
        reportOptions.pop("errorMsg", None)

    return reportOptions


# ----------------------------------------------------------------------#
if __name__ == "__main__":
    main()
