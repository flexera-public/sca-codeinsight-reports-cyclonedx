'''
Copyright 2023 Flexera Software LLC
See LICENSE.TXT for full license text
SPDX-License-Identifier: MIT

Author : sgeary  
Created On : Wed Aug 16 2023
File : report_archive.py
'''
import logging, os, zipfile


logger = logging.getLogger(__name__)

#---------------------------------------------------------------------#
def create_report_zipfile(reportOutputs, reportFileNameBase):

    logger.info("Entering create_report_zipfile")
    allFormatZipFile = reportFileNameBase + ".zip"

    # create a ZipFile object
    allFormatsZip = zipfile.ZipFile(allFormatZipFile, 'w', zipfile.ZIP_DEFLATED)

    logger.debug("    Create downloadable archive: %s" %allFormatZipFile)
    print("        Create downloadable archive: %s" %allFormatZipFile)
    for format in reportOutputs["allFormats"]:
        print("            Adding %s to zip" %format)
        logger.debug("    Adding %s to zip" %format)
        allFormatsZip.write(format)

    allFormatsZip.close()
    logger.debug(    "Downloadable archive created")
    print("        Downloadable archive created")

    # Now create a temp zipfile of the zipfile along with the viewable file itself
    uploadZipflle = allFormatZipFile.replace(".zip", "_upload.zip")
    print("        Create zip archive containing viewable and downloadable archive for upload: %s" %uploadZipflle)
    logger.debug("    Create zip archive containing viewable and downloadable archive for upload: %s" %uploadZipflle)
    zipToUpload = zipfile.ZipFile(uploadZipflle, 'w', zipfile.ZIP_DEFLATED)
    zipToUpload.write(reportOutputs["viewable"])
    zipToUpload.write(allFormatZipFile)
    zipToUpload.close()
    logger.debug("    Archive zip file for upload has been created")
    print("        Archive zip file for upload has been created")

    # Clean up the items that were added to the zipfile
    try:
        os.remove(allFormatZipFile)
    except OSError:
        logger.error("Error removing %s" %allFormatZipFile)
        print("Error removing %s" %allFormatZipFile)
        return -1

    for fileName in reportOutputs["allFormats"]:
        try:
            os.remove(fileName)
        except OSError:
            logger.error("Error removing %s" %fileName)
            print("Error removing %s" %fileName)
            return -1    

    logger.info("Exiting create_report_zipfile")
    return uploadZipflle