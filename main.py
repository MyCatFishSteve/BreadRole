#!/usr/bin/env python3
import sys
import getopt
import json
import boto3
import pprint

usage_msg="""\
Usage: breadrole [options...]
Creates roles on Amazon Web Services that allow for easy traversal across accounts.
Your AWS must have access to the root
Options:
    -h, --help                  | Display this help message
    -n, --name STRING           | Role name for all accounts (must provide only 1)
    -p, --policy POLICY         | Policy file to attach to all roles created (at least 1 provided)
    -r, --root ACCOUNT          | Account ID that is the root to create from
    -a, --account ACCOUNT       | Account ID to create role and policy
"""
def usage():
    print(usage_msg)
    sys.exit(1)

# Array of account IDs to create roles in
child_accounts = []

root_account = ""
role_name = ""
role_policy_files = []

#
#
#
#
# def process_args(argv):
#     global root_account
#     global role_name
#     global role_accounts
#     global role_policy_files
#     try:
#         opts, args = getopt.getopt(argv, "hr:n:p:a:", ["help", "root=", "name=", "policy=", "account="])
#     except getopt.GetoptError:
#         usage()
#     for opt, arg in opts:
#         if opt in ('-h', '--help'):
#             usage()
#         elif opt in ('-r', '--root'):
#             if len(role_name) > 0:
#                 print("You must only specify one root account")
#                 usage()
#             root_account = arg
#         elif opt in ('-n', '--name'):
#             if len(role_name) > 0:
#                 print("You must only specify one role name")
#                 usage()
#             role_name = arg
#         elif opt in ('-p', '--policy'):
#             role_policy_files.append(arg)
#         elif opt in ('-a', '--account'):
#             child_accounts.append(arg)

#
#
#
#
def get_virtual_mfa_device(session, userid):
    response = session.client('iam').list_virtual_mfa_devices()
    virtual_mfa_devices = response['VirtualMFADevices']
    for entry in virtual_mfa_devices:
        try:
            if entry['User']['UserId'] == userid:
                return entry['SerialNumber']
        except:
            pass
    return

#
#
#
#
def main():
    # Process all arguments
    process_args(sys.argv[1:])

    # Create AWS session
    session = boto3.Session()

    # Create STS session
    sts = session.client('sts')


    # Obtain the user ID that we are logged in as
    try:
        caller_identity = sts.get_caller_identity()
        userid = caller_identity.get('UserId')
        account = caller_identity.get('Account')
    except Exception as e:
        print(e)
        sys.exit(1)

    # Print
    print(f'Effective UserID: {userid}')
    print(f'Effective Account: {account}')

    # Detect if MFA device required for authentication
    mfa_device_arn = get_virtual_mfa_device(session, userid)
    if mfa_device_arn:
        mfatoken = input('Enter your MFA token: ')

    # Get credentials for root account
    root_role_arn = f'arn:aws:iam::{root_account}:role/AdministratorAccess'
    try:
        root_credentials = sts.assume_role(
            RoleArn=root_role_arn,
            RoleSessionName='RootAccess',
            SerialNumber=mfa_device_arn,
            TokenCode=mfatoken
        )
    except Exception as e:
        print(e)
        sys.exit(1)

    # Array of sessions to interact with child accounts
    child_sessions = []

    # Create sessions for every child account
    for account in child_accounts:
        role_arn = f'arn:aws:iam::{account}:role/AdministratorAccess'
        try:
            credentials = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName='ChildAccess',
                SerialNumber=mfa_device_arn,
                TokenCode=mfatoken
            )
            child_sessions.append(boto3.Session(
                aws_access_key_id=credentials['Credentials']['AccessKeyId'],
                aws_secret_access_key=credentials['Credentials']['SecretAccessKey'],
                aws_session_token=credentials['Credentials']['SessionToken']
            ))
        except Exception as e:
            print(e)

    # Create root account session
    root_session = boto3.Session(
        aws_access_key_id=root_credentials['Credentials']['AccessKeyId'],
        aws_secret_access_key=root_credentials['Credentials']['SecretAccessKey'],
        aws_session_token=root_credentials['Credentials']['SessionToken']
    )

    iam = root_session.client('iam')
    print(iam.list_roles())

if __name__ == "__main__":
    main()
