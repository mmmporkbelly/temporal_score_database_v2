"""
Populate the temporal vector v2
New calculations treats everything with equal weight
"""

import numpy as np
import logging
from .calculate_temporal import calculate_temporal, calculate_base_severity


def populate_temporal(dataframe):
    df = dataframe

    # Edit df first to figure out which vector to use. NVD vectors will always be used if available
    df["cvss_vector_used"] = df["NVD_vectorString"].fillna(df["Mitre_vectorString"])
    df["cvss_version_used"] = df["NVD_version"].fillna(df["Mitre_version"])
    df["cvss_report_confidence"] = df["NVD_Vulnerability_Status"].fillna(df["Mitre_Report_State"])
    df["cvss_has_reference"] = df["NVD_has_reference"].fillna(df["Mitre_References"])

    # Replace all the True values of specified columns with 1 if True, 0 if not
    columns_to_check = [
        'KEV',
        'Ransomware_Affiliation',
        'EPSS_Above_Threshold',
        'ExploitDB',
        'Metasploit_Module',
        'POC_In_Github',
        'Google_Project_Zero',
        'Nuclei',
        'Vulncheck_KEV',
        'Mitre_PacketStorm'
    ]

    # Alter each column to fill with 1 if True, 0 if False
    for column in columns_to_check:
        df[column] = df[column].apply(lambda x: 0 if x != 1 else 1)

    # Create a new column that is the sum of all columns in columns_to_check
    df['Sum_of_Flagging_Sources'] = df[columns_to_check].sum(axis=1)

    # Remove exploit code provided by NVD (only a couple of use cases so far)
    df['cvss_vector_used'] = df['cvss_vector_used'].str.replace('E:', '')

    # Set up conditions. Note: Tilde (~) indicates is not, or ! in some languages
    # Conditions for Report Confidence. Only applicable to v2 and v3
    condition_rc_u = (df['cvss_report_confidence'] == 'REJECTED')
    condition_rc_r = ((df['cvss_report_confidence'] == 'Awaiting Analysis') |
                      (df['cvss_report_confidence'] == 'Undergoing Analysis') |
                      (df['cvss_report_confidence'] == 'Received')
                      )
    condition_rc_c = (~condition_rc_u & ~condition_rc_r)

    # Condition for patch level. If it has a reference, we can assume there is some sort of workaround.
    condition_rl_c = (df['NVD_Patch'] == True)
    condition_rl_w = (~condition_rl_c & (df['cvss_has_reference'].notna()))

    # Conditions for exploit code maturity
    condition_exploit_unconfirmed = (df['Sum_of_Flagging_Sources'].astype(int) == 0)
    condition_exploit_poc = ((df['Sum_of_Flagging_Sources'].astype(int) >= 1) & (df['Sum_of_Flagging_Sources'].astype(int) <= 3))
    condition_exploit_functional = ((df['Sum_of_Flagging_Sources'].astype(int) >= 4) & (df['Sum_of_Flagging_Sources'].astype(int) <= 6))
    condition_exploit_high = (df['Sum_of_Flagging_Sources'].astype(int) >= 7)

    # Set separate ones for v4 since it is a little different
    condition_exploit_unconfirmed_v4 = (df['Sum_of_Flagging_Sources'].astype(int) == 0)
    condition_exploit_poc_v4 = ((df['Sum_of_Flagging_Sources'].astype(int) >= 1) & (df['Sum_of_Flagging_Sources'].astype(int) <= 4))
    condition_exploit_attacked_v4 = (df['Sum_of_Flagging_Sources'].astype(int) >= 5)
    
    # Populate Temporal Vector
    logging.info("Populating temporal vectors...")

    # Check if 'exploit_maturity' column exists in the DataFrame
    if 'exploit_maturity' not in df.columns:
        # If 'exploit_maturity' column doesn't exist, create it with an empty string as its default value
        df['exploit_maturity'] = ''

    # Update via V2 Conditions for Exploit Code Maturity 
    condition_cvss_v2 = ((df['cvss_version_used'].astype(str) == '2') | (df['cvss_version_used'].astype(str) == '2.0'))
    df.loc[condition_cvss_v2 & condition_exploit_unconfirmed, 'exploit_maturity'] = 'E:U'
    df.loc[condition_cvss_v2 & condition_exploit_poc, 'exploit_maturity'] = 'E:POC'
    df.loc[condition_cvss_v2 & condition_exploit_functional, 'exploit_maturity'] = 'E:F'
    df.loc[condition_cvss_v2 & condition_exploit_high, 'exploit_maturity'] = 'E:H'
    
    # Add RL to vector 
    df.loc[condition_cvss_v2 & condition_rl_c, 'exploit_maturity'] += '/RL:OF'
    df.loc[condition_cvss_v2 & condition_rl_w, 'exploit_maturity'] += '/RL:TF'
    df.loc[condition_cvss_v2 & ~condition_rl_c & ~condition_rl_w, 'exploit_maturity'] += '/RL:U'
    
    # Add RC to vector
    df.loc[condition_cvss_v2 & condition_rc_c, 'exploit_maturity'] += '/RC:C'
    df.loc[condition_cvss_v2 & condition_rc_r, 'exploit_maturity'] += '/RC:UR'
    df.loc[condition_cvss_v2 & condition_rc_u, 'exploit_maturity'] += '/RC:UC'

    # Update via V3 Conditions for Exploit Code Maturity 
    condition_cvss_v3 = ((df['cvss_version_used'].astype(str) == '3.0') | (df['cvss_version_used'].astype(str) == '3.1') | (df['cvss_version_used'].astype(str) == '3'))
    df.loc[condition_cvss_v3 & condition_exploit_unconfirmed, 'exploit_maturity'] = 'E:U'
    df.loc[condition_cvss_v3 & condition_exploit_poc, 'exploit_maturity'] = 'E:P'
    df.loc[condition_cvss_v3 & condition_exploit_functional, 'exploit_maturity'] = 'E:F'
    df.loc[condition_cvss_v3 & condition_exploit_high, 'exploit_maturity'] = 'E:H'

    # Add RL to vector 
    df.loc[condition_cvss_v3 & condition_rl_c, 'exploit_maturity'] += '/RL:O'
    df.loc[condition_cvss_v3 & condition_rl_w, 'exploit_maturity'] += '/RL:T'
    df.loc[condition_cvss_v3 & ~condition_rl_c & ~condition_rl_w, 'exploit_maturity'] += '/RL:U'
    
    # Add RC to vector
    df.loc[condition_cvss_v3 & condition_rc_c, 'exploit_maturity'] += '/RC:C'
    df.loc[condition_cvss_v3 & condition_rc_r, 'exploit_maturity'] += '/RC:R'
    df.loc[condition_cvss_v3 & condition_rc_u, 'exploit_maturity'] += '/RC:U'

    # Update via V4 Conditions for Exploit Code Maturity. Make sure exploit maturity is not mentioned. 
    # condition_cvss_v4 = (((df['cvss_version_used'].astype(str) == '4') | (df['cvss_version_used'].astype(str) == '4.0')) & 'E:' not in df['cvss_vector_used'].astype(str))
    condition_cvss_v4 = (((df['cvss_version_used'].astype(str) == '4') | (df['cvss_version_used'].astype(str) == '4.0')) & ('E:' not in df['cvss_vector_used']))
    df.loc[condition_cvss_v4 & condition_exploit_attacked_v4, 'exploit_maturity'] = 'E:A'
    df.loc[condition_cvss_v4 & condition_exploit_poc_v4, 'exploit_maturity'] = 'E:P'
    df.loc[condition_cvss_v4 & condition_exploit_unconfirmed_v4, 'exploit_maturity'] = 'E:U'

    # Update vector with exploit maturity
    df['temporal_vector'] = np.where(df['cvss_vector_used'], df['cvss_vector_used'] + '/' + df['exploit_maturity'], False)

    # Extracting CVSS scores and severities
    logging.info('Computing temporal scores and severities')
    df[['base_score', 'base_severity']] = df.apply(calculate_base_severity, axis=1, result_type='expand')
    df[['temporal_score', 'temporal_severity']] = df.apply(calculate_temporal, axis=1, result_type='expand')

    # Write to excel
    return df
