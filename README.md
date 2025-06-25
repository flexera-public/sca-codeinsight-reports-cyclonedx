# This repo is the CycloneDX SBOM report for Code Insight.

The `sca-codeinsight-reports-cyclonedx` repository provides a report for Revenera's Code Insight product. This report enables users to generate a CycloneDX report representing the Software Bill of Materials (SBOM) for a specific project.

## Prerequisites

### Code Insight Release Requirements

|Repository Tag | Minimum Code Insight Release  |
|--|--|
|1.0.x |2021R4  |
|1.1.x |2022R1  |
|1.4.x |2024R3  |
|1.5.x |2024R3  |

**Repository Cloning**

This repository should be cloned directly into the **$CODEINSIGHT_INSTALLDIR/custom_report_scripts** directory. If no prior custom reports has been installed, this directory will need to be created prior to cloning.

### Java Requirements
To query data from the Code Insight database, the `<Install Location>\samples\customreport_helper\DBConnection.jar` file is required. Java is needed to run this JAR. You can specify the Java path in the `user_java_path` variable within `report_data_db.py`. If this variable is not set, the script will look for the `JAVA_HOME` environment variable. If neither is found, it will default to the Code Insight JRE located at `<Install Location>\jre`.

### Python Requirements

This repository requires the Requests module to interact with the Code Insight API's. Install the dependencies using the following command:

pip install -r requirements.txt

Offline Mode
The sca-codeinsight-reports-cyclonedx custom report can be used in offline mode, meaning the Code Insight server does not need to be running.

For Windows:
Open a command prompt at the location:
$CODEINSIGHT_INSTALLDIR/custom_report_scripts/sca-codeinsight-reports-cyclonedx
Run the following command
python create_report.py -pid <projectID> -reportOpts "{\"includeChildProjects\": \"True\", \"includeVEXReport\": \"True\", \"includeVDRReport\": \"True\"}"

For Linux:
Open a terminal at the location:
$CODEINSIGHT_INSTALLDIR/custom_report_scripts/sca-codeinsight-reports-cyclonedx
Run the following command:
python3 create_report.py -pid <projectID> -reportOpts '{"includeChildProjects":"True","includeVEXReport":"True","includeVDRReport":"True"}'

Notes:
The -pid flag is mandatory.
The -reportOpts flag is optional. If omitted, all values will default to "True".
Example: python3 create_report.py -pid <projectID>

Report Locations:
Recently Generated Reports:
$CODEINSIGHT_INSTALLDIR/custom_report_scripts/sca-codeinsight-reports-cyclonedx/DBReports
Older Reports:
$CODEINSIGHT_INSTALLDIR/custom_report_scripts/sca-codeinsight-reports-cyclonedx/DBReports/Backup


Configuration and Report Registration

It is optional but recommended to have the Code Insight server up and running if you intend to trigger this report from the Code Insight UI under the reports tab.
For registration purposes the file **server_properties.json** should be created and located in the **$CODEINSIGHT_INSTALLDIR/custom_report_scripts/** directory.  This file contains a json with information required to register the report within Code Insight as shown  here:

>     {
>         "core.server.url": "http://localhost:8888" ,
>         "core.server.token" : "Admin authorization token from Code Insight"
>     }

The value for core.server.url is also used within [create_report.py](create_report.py) for any project or inventory based links back to the Code Insight server within a generated report.

If the common **server_properties.json** files is not used then the information the the following files will need to be updated:

[registration.py](registration.py)  -  Update the **baseURL** and **adminAuthToken** values. These settings allow the report itself to be registered on the Code Insight server.

[create_report.py](create_report.py)  -  Update the **baseURL** value. This URL is used for links within the reports.

Report option default values can also be specified in [registration.py](registration.py) within the reportOptions dictionaries.

### Registering the Report

Prior to being able to call the script directly from within Code Insight it must be registered. The [registration.py](registration.py) file can be used to directly register the report once the contents of this repository have been added to the custom_report_script folder at the base Code Insight installation directory.

To register this report:

	python registration.py -reg

To unregister this report:
	
	python registration.py -unreg

To update this report configuration:
	
	python registration.py -update


## Usage

This report is executed directly from within Revenera's Code Insight product. From the project reports tab of each Code Insight project it is possible to *generate* the **CycloneDX Report** via the Report Framework.

The above values will be used in place of the **Project Name** for any project references within the generated artifacts to allow users the ability abstract the project name for the application SBOM report.


**Report Options**
- Including child projects (True/False) - Determine if child project data will be included or not.


The Code Insight Report Framework will provide the following to the report when initiated:

- Project ID
- Report ID
- Authorization Token
 
For this example report these three items are passed on to a batch or sh file which will in turn execute a python script. This script will then:

- Collect data for the report via REST API using the Project ID and Authorization Token
- Take this collected data and generate an xml CycloneDX document
- The xml file will be marked as the *"viewable"* file
    - If project hierachy is enabled a summary document will be created
- A zip file will be created containing the spdx which will be the *"downloadable"* file.
    - If project hierachy is enabled the report will contain information for all child projects recursively.
- Create a zip file with the viewable file and the downloadable file
- Upload this combined zip file to Code Insight via REST API
- Delete the report artifacts that were created as the script ran


## License

[MIT](LICENSE.TXT)


