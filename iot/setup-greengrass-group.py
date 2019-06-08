#!/usr/bin/env python2

# ---------------------------------------------------------------------------- #
# Copyright 2018-2019, OpenNebula Project, OpenNebula Systems                  #
#                                                                              #
# Licensed under the Apache License, Version 2.0 (the "License"); you may      #
# not use this file except in compliance with the License. You may obtain      #
# a copy of the License at                                                     #
#                                                                              #
# http://www.apache.org/licenses/LICENSE-2.0                                   #
#                                                                              #
# Unless required by applicable law or agreed to in writing, software          #
# distributed under the License is distributed on an "AS IS" BASIS,            #
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.     #
# See the License for the specific language governing permissions and          #
# limitations under the License.                                               #
# ---------------------------------------------------------------------------- #

import json
import yaml
import boto3
import re
import os
import sys
import argparse

def underscores(s):
    s = re.sub(r"[^\w\s\-_]", "", s)
    s = re.sub(r"\s+", "_", s)

    return s

def msg(s):
    print("AWS IoT: " + s)

def find_gg_group(gg, group_name):
    """ returns: greengrass group of the same name or None"""

    r = gg.list_groups(MaxResults="100")
    if "Groups" in r:
        while True:
            for group in r["Groups"]:
                if group["Name"] == group_name:
                    return group
            if "NextToken" in r and r["NextToken"] != "null":
                r = gg.list_groups(MaxResults="100", NextToken=r["NextToken"])
            else:
                break

    return None

def find_gg_policy(iot, policy_name):
    """ returns: Name, Arn or None x 2"""

    r = iot.list_policies(pageSize=100, ascendingOrder=True)
    if "policies" in r:
        while True:
            for policy in r["policies"]:
                if policy["policyName"] == policy_name:
                    return policy
            if "nextMarker" in r and r["nextMarker"] != "null":
                r = iot.list_policies(pageSize=100,
                                      ascendingOrder=True,
                                      nextMarker=r["nextMarker"])
            else:
                break

    return None

def create_gg_policy(iot, policy_name):
    core_policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["iot:Publish", "iot:Subscribe", "iot:Connect", "iot:Receive", "iot:GetThingShadow", "iot:DeleteThingShadow", "iot:UpdateThingShadow"],
                "Resource": ["arn:aws:iot:" + boto3.session.Session().region_name + ":*:*"]
            },
            {
                "Effect": "Allow",
                "Action": ["greengrass:AssumeRoleForGroup", "greengrass:CreateCertificate", "greengrass:GetConnectivityInfo", "greengrass:GetDeployment", "greengrass:GetDeploymentArtifacts", "greengrass:UpdateConnectivityInfo", "greengrass:UpdateCoreDeploymentStatus"],
                "Resource": ["*"]
            }
        ]
    }

    policy = iot.create_policy(
        policyName=policy_name,
        policyDocument=json.dumps(core_policy_doc))

    return policy

def run_as_user(username):
    import pwd

    # get the uid/gid from the username
    user_uid = pwd.getpwnam(username).pw_uid
    user_gid = pwd.getpwnam(username).pw_gid

    # remove group privileges
    os.setgroups([])

    # try setting the new uid/gid
    os.setgid(user_gid) # must be done first...
    os.setuid(user_uid)

    os.environ["HOME"] = pwd.getpwnam(username).pw_dir

# we expect three arguments: <username> <greengrass_group> <json_status_filename>
arg_parser = argparse.ArgumentParser()
arg_parser.add_argument("username", metavar="<username>", help="run this program as this user")
arg_parser.add_argument("gg_group", metavar="<greengrass_group>", help="name of the created aws greengrass group")
arg_parser.add_argument("status_filename", metavar="<status_filename>", help="filepath to the json where info will be stored")
args = arg_parser.parse_args()

try:
    run_as_user(args.username)
except Exception:
    msg("[!] We could not change our running uid/gid to this user: " + args.username)
    msg("[!] We will abort the configuration and do nothing")
    sys.exit(1)

# also we right away create other needed names:
GG_GROUP_NAME = args.gg_group
GG_STATUS_FILENAME = args.status_filename
GG_CORE_NAME = underscores(GG_GROUP_NAME) + "_Core"
GG_POLICY_NAME = GG_CORE_NAME + "-policy"
GG_CORE_DEFINITION_NAME = GG_CORE_NAME + "-definition"

# we test first that we can store all important info to the file:
try:
    with open(GG_STATUS_FILENAME, "w") as f:
        pass
except IOError:
    msg("[!] We cannot create and write to the status file: " + GG_STATUS_FILENAME)
    msg("[!] We will abort the configuration and do nothing")
    sys.exit(1)

# create iot and greengrass objects:
gg = boto3.client("greengrass")
iot = boto3.client("iot")

# return group if exists or None
gg_group = find_gg_group(gg, GG_GROUP_NAME)

# as of now we bail if the group of the same name exists
if gg_group is not None:
    msg("[!] The greengrass group of this name already exists: " + gg_group["Name"])
    msg("[!] We will abort the configuration and do nothing")
    sys.exit(1)

# we will also need a policy and for simplicity we will create one or reuse
# the one of the same name
#
# return policy if exists or None
gg_policy = find_gg_policy(iot, GG_POLICY_NAME)

# if policy does not exist yet - create it:
if gg_policy is None:
    msg("Create AWS IoT policy: " + GG_POLICY_NAME)
    gg_policy = create_gg_policy(iot, GG_POLICY_NAME)
else:
    msg("Reusing AWS IoT policy: " + gg_policy["policyName"])

# create keys and cert and core thing of our group
msg("Create AWS IoT keys and certificate")
gg_keys_cert = iot.create_keys_and_certificate(setAsActive=True)
msg("Create AWS IoT Thing: " + GG_CORE_NAME)
gg_core_thing = iot.create_thing(thingName=GG_CORE_NAME)

iot.attach_thing_principal(
    thingName=gg_core_thing["thingName"],
    principal=gg_keys_cert["certificateArn"])

# attach the previously obtained/created policy
iot.attach_principal_policy(
    policyName=gg_policy["policyName"],
    principal=gg_keys_cert["certificateArn"])

# prepare json doc for core definition
gg_core_initial_version = {"Cores": [
    {
        "Id": gg_core_thing["thingName"],
        "CertificateArn": gg_keys_cert["certificateArn"],
        "SyncShadow": False,
        "ThingArn": gg_core_thing["thingArn"]
    }
]}

msg("Create AWS Greengrass Core definition: " + GG_CORE_DEFINITION_NAME)
gg_core_definition = gg.create_core_definition(
    Name=GG_CORE_DEFINITION_NAME,
    InitialVersion=gg_core_initial_version)

# for some reasons we have to do this too
# https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/greengrass.html#Greengrass.Client.create_core_definition_version
# Quote: Greengrass groups must each contain exactly one Greengrass core.
# ...is that really true? So why is it list???

msg("Create AWS Greengrass Core definition version")
gg_core_definition_version = gg.create_core_definition_version(
    CoreDefinitionId=gg_core_definition["Id"],
    Cores=gg_core_initial_version["Cores"])

# create the greengrass group - we had to wait until a core definition was made
gg_group_initial_version = {
    #"ConnectorDefinitionVersionArn": "string",
    #"DeviceDefinitionVersionArn": "string",
    #"FunctionDefinitionVersionArn": "string",
    #"LoggerDefinitionVersionArn": "string",
    #"ResourceDefinitionVersionArn": "string",
    #"SubscriptionDefinitionVersionArn": "string",
    "CoreDefinitionVersionArn": gg_core_definition_version["Arn"]
}

msg("Create AWS Greengrass Group: " + GG_GROUP_NAME)
gg_group = gg.create_group(
    Name=GG_GROUP_NAME,
    InitialVersion=gg_group_initial_version)

# store everything so far created into the json status
gg_status = {
    "group": gg_group,
    "core_thing": gg_core_thing,
    "keys_cert": gg_keys_cert,
    "core_definition": gg_core_definition,
    "core_definition_version": gg_core_definition_version,
    "policy": gg_policy
}

msg("Store the whole setup into: " + GG_STATUS_FILENAME)
try:
    with open(GG_STATUS_FILENAME, "w") as f:
        json.dump(gg_status, f, indent=4)
except IOError:
    msg("[!] We could not write to the status file: " + GG_STATUS_FILENAME)
    msg("[!] Cloud setup was successful but we cannot provision this Core device")
    sys.exit(1)

# successfully finish
msg("SUCCESS")
sys.exit(0)

