"""
Main file for running and consolidating all data.
"""

import pandas as pd
import os
import logging
import boto3
import json
from datetime import date
from exploit_df_functions import *
from nvd_functions import *
from mitre_functions import *
from temporal_score_functions import *
from aws_functions import *


def main():
    try:
        # Configure logging, make sure log folder exists
        log_path = 'Logs/'
        if not os.path.exists(log_path):
            os.makedirs(log_path)
        log_file_path = log_path + f'{date.today()}.log'
        logging.basicConfig(filename=log_file_path, level=logging.DEBUG,
                            format='%(asctime)s - %(levelname)s - %(message)s')
        logging.getLogger().addHandler(logging.StreamHandler())

        # Establish AWS session
        # Set session for AWS
        logging.info("Getting AWS session")
        session = boto3.session.Session()

        # Add your client ID, client secret, token URL, and API endpoint URL
        # Get AWS Secret

        secret_name = "{ENTER SECRET HERE}"
        region_name = "{ENTER REGION HERE}"

        # Create a Secrets Manager client
        client = session.client(
            service_name='secretsmanager',
            region_name=region_name
        )

        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
        # Decrypts secret using the associated KMS key.
        secret = get_secret_value_response['SecretString']

        # Has to be formatted into dict
        secret = json.loads(secret)

        # Grab necessary secrets
        nvd_secret = secret['{SECRET NAME}']
        vulncheck_secret = secret['{SECRET NAME}']

        # Download NVD files
        download_bucket_files.download_nvd_file(session)

        """
        First process the MITRE file
        """

        logging.info("Creating MITRE File...")
        # Download mitre files
        logging.info("Downloading all MITRE files...")
        download_mitre.download_mitre_file()

        # Combine mitre json files
        logging.info("Combing all MITRE json files...")
        mitre_raw_json_files = 'Downloads/MitreCVE/cves'
        mitre_json_files = 'ProcessedFiles/Mitre CVE Json Year/'
        combine_json.combine_json_files_by_year(mitre_raw_json_files, mitre_json_files)

        # Process json files
        logging.info("Validating MITRE json files...")
        validate_json.parse_json_files(mitre_json_files)

        # Convert json to csv
        logging.info("Combining all json files into one dataframe...")
        mitre_df = merge_mitre_to_df.process_all_files()

        """
        Then process the NVD dataframe and combine the two
        """

        # Instantiate NVD DF class
        logging.info("Starting NVD file retrieval...")
        nvd_df_object = nvd_dataframe.NVDDataFrame(nvd_secret=nvd_secret)
        nvd_df = nvd_df_object.all_df_data()

        # Combine dataframes
        logging.info("Combining Dataframes...")

        # Merge the data on CVE ID with full outer join
        merged_data = pd.merge(nvd_df, mitre_df, left_on='NVD_CVE_ID', right_on='Mitre_CVE_ID',
                            how='outer')

        # Determine where the data is missing and create a new column 'CVE Trueup_Missing'
        merged_data['CVE_TrueUp_Missing'] = merged_data.apply(
            lambda row: 'MITRE' if pd.isnull(row['Mitre_CVE_ID']) else ('NVD' if pd.isnull(row['NVD_CVE_ID']) else ''),
            axis=1)

        # Now create a CVE_ID column, and remove NVD_CVE_ID and MITRE_CVE_ID columns
        merged_data["CVE_ID"] = merged_data["NVD_CVE_ID"].fillna(merged_data["Mitre_CVE_ID"])
        merged_data = merged_data.drop(columns=['NVD_CVE_ID', 'Mitre_CVE_ID'])

        # Put CVE_ID as first row
        col = merged_data.pop("CVE_ID")
        merged_data.insert(0, col.name, col)

        # Drop duplicates just in case
        merged_data.drop_duplicates(subset=['CVE_ID'], keep='first', inplace=True)

        """
        Now add all the Exploit Data
        """

        # Add all the KEV Data
        kev_df_object = exploit_dataframe_classes.KevDataFrame()
        kev_df = kev_df_object.all_df_data()
        merged_data = pd.merge(merged_data, kev_df, how='outer', on='CVE_ID')

        # Add all the Exploitdb Data
        exploitdb_df_object = exploit_dataframe_classes.ExploitDBDataFrame()
        exploitdb_df = exploitdb_df_object.all_df_data()
        merged_data = pd.merge(merged_data, exploitdb_df, on='CVE_ID', how='outer')

        # Add all the Metasploit data
        metasploit_df_object = exploit_dataframe_classes.MetasploitDataFrame()
        metasploit_df = metasploit_df_object.all_df_data()
        merged_data = pd.merge(merged_data, metasploit_df, on='CVE_ID', how='outer')

        # Add all the Github POC data
        github_df_object = exploit_dataframe_classes.GithubDataFrame()
        github_df = github_df_object.all_df_data()
        merged_data = pd.merge(merged_data, github_df, on='CVE_ID', how='outer')

        # Add all the Nuclei POC data
        nuclei_df_object = exploit_dataframe_classes.NucleiDataFrame()
        nuclei_df = nuclei_df_object.all_df_data()
        merged_data = pd.merge(merged_data, nuclei_df, on='CVE_ID', how='outer')

        # Add all the EPSS Data
        epss_df_object = exploit_dataframe_classes.EPSSDataFrame()
        epss_df = epss_df_object.all_df_data()
        merged_data = pd.merge(merged_data, epss_df, left_on='CVE_ID', right_on='CVE_ID', how='outer')

        # Add Google Project Zero
        google_df_object = exploit_dataframe_classes.GoogleProjectZero()
        google_df = google_df_object.all_df_data()
        merged_data = pd.merge(merged_data, google_df, on='CVE_ID', how='outer')

        # Add Vulncheck
        vulncheck_df_object = exploit_dataframe_classes.VulncheckDataFrame(vulncheck_secret=vulncheck_secret)
        vulncheck_df = vulncheck_df_object.all_df_data()
        merged_data = pd.merge(merged_data, vulncheck_df, on='CVE_ID', how='outer')

        """
        Calculate Temporal Scores
        """

        # Add all temporal vectors
        final_df = add_temporal_vector_v2.populate_temporal(merged_data)

        # Again, drop all duplicates just in case
        final_df.drop_duplicates(subset=['CVE_ID'], keep='first', inplace=True)

        # Save the merged data to a new xlsx file
        with pd.ExcelWriter(
                f'CVSSRescore/rescored_full_data_{date.today()}.xlsx',
                engine="xlsxwriter",
                engine_kwargs={'options': {'strings_to_formulas': False, 'strings_to_urls': False}}
        ) as writer:
            final_df.to_excel(writer, index=False)

        # Make a partial data DF for faster processing
        logging.info("Creating partial dataframe...")
        devsec_ops_df = final_df[[
            'CVE_ID', 
            'base_severity', 
            'base_score', 
            'temporal_severity', 
            'temporal_score',
            'exploit_maturity',
            'temporal_vector',
            'KEV',
            'Ransomware_Affiliation',
            'EPSS_Above_Threshold',
            'ExploitDB',
            'Metasploit_Module',
            'POC_In_Github',
            'Google_Project_Zero',
            'Nuclei',
            'Vulncheck_KEV',
            'Mitre_PacketStorm',
            'Sum_of_Flagging_Sources',
            'EPSS',
            'EPSS_Percentile',
            'cvss_version_used',
            'cvss_report_confidence',
            'cvss_has_reference',
            'NVD_Description',
            'Mitre_Description'
            ]]
        
        # Rename the column 'Mitre_PacketStorm' to 'PacketStorm'
        devsec_ops_df.rename(columns={'Mitre_PacketStorm': 'PacketStorm'}, inplace=True)
        
        # Save the merged data to a new xlsx file
        with pd.ExcelWriter(
                f'CVSSRescore/rescored_partial_data_{date.today()}.xlsx',
                engine="xlsxwriter",
                engine_kwargs={'options': {'strings_to_formulas': False, 'strings_to_urls': False}}
        ) as writer:
            devsec_ops_df.to_excel(writer, index=False)

        # Upload to AWS
        upload_to_bucket.upload_all_files(session)

        # Pass ARN
        account_id = session.client('sts').get_caller_identity().get('Account')
        client = session.client('sns')
        snsArn = f'arn:aws:sns:us-east-2:{account_id}:ENTER SNS NAME'
        message = f"Temporal Score Database v2 successfully ran."
        response = client.publish(
            TopicArn=snsArn,
            Message=message,
            Subject='Temporal Score Database v2'
        )

        # Give breakdown of severity change
        logging.info("Here is the breakdown of what has changed")
        logging.info(final_df.value_counts('base_severity'))
        logging.info(final_df.value_counts('temporal_severity'))

    except Exception as e:
        account_id = session.client('sts').get_caller_identity().get('Account')
        client = session.client('sns')
        snsArn = f'arn:aws:sns:us-east-2:{account_id}:ENTER SNS NAME'
        message = f"{e}: Temporal Score Database v2 did not upload files successfully. See log files."
        response = client.publish(
            TopicArn=snsArn,
            Message=message,
            Subject='Temporal Score Database v2'
        )


if __name__ == '__main__':
    main()
