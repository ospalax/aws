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

def find_iot_thing(iot, thing_name):
    """ returns: iot thing of the same name or None"""

    r = iot.list_things(maxResults=100)
    if "things" in r:
        while True:
            for thing in r["things"]:
                if thing["thingName"] == thing_name:
                    return thing
            if "nextToken" in r and r["nextToken"] != "null":
                r = iot.list_things(maxResults=100, nextToken=r["nextToken"])
            else:
                break

    return None

def find_iot_policy(iot, policy_name):
    """ returns: policy or None"""

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

def get_device_definition(gg, group_object):
    """ returns: dict with device definition for this group or None"""

    current_group_version = gg.get_group_version(
        GroupId=group_object["Id"],
        GroupVersionId=group_object["LatestVersion"])

    if not "DeviceDefinitionVersionArn" in current_group_version["Definition"]:
        return None

    definition_arn = current_group_version["Definition"]["DeviceDefinitionVersionArn"].split("/")

    if definition_arn[1:4] == ['greengrass', 'definition', 'devices']:
        return gg.get_device_definition(DeviceDefinitionId=definition_arn[4])

    return None

def get_devices(gg, group_object):
    """ returns: list of current devices from device definition version """

    current_group_version = gg.get_group_version(
        GroupId=group_object["Id"],
        GroupVersionId=group_object["LatestVersion"])

    if not "DeviceDefinitionVersionArn" in current_group_version["Definition"]:
        return []

    definition_arn = current_group_version["Definition"]["DeviceDefinitionVersionArn"].split("/")

    device_version = gg.get_device_definition_version(DeviceDefinitionId=definition_arn[4], DeviceDefinitionVersionId=definition_arn[6])

    return device_version["Definition"]["Devices"]

def update_group(gg, group_object, definitions):
    """ returns: group version """

    kwargs = {}

    current_group_version = gg.get_group_version(
        GroupId=group_object["Id"],
        GroupVersionId=group_object["LatestVersion"])

    kwargs.update(current_group_version["Definition"])
    kwargs.update(definitions)
    kwargs.update({"GroupId": group_object["Id"]})

    return gg.create_group_version(**kwargs)

def create_device_policy(iot, policy_name):
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["iot:Publish", "iot:Subscribe", "iot:Connect", "iot:Receive", "iot:GetThingShadow", "iot:DeleteThingShadow", "iot:UpdateThingShadow"],
                "Resource": ["arn:aws:iot:" + boto3.session.Session().region_name + ":*:*"]
            },
            {
                "Effect": "Allow",
                "Action": ["greengrass:*"],
                "Resource": ["*"]
            }
        ]
    }

    policy = iot.create_policy(
        policyName=policy_name,
        policyDocument=json.dumps(policy_doc))

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

# we expect three arguments: <username> <greengrass_group> <device_name> <json_status_filename>
arg_parser = argparse.ArgumentParser()
arg_parser.add_argument("username", metavar="<username>", help="run this program as this user")
arg_parser.add_argument("gg_group", metavar="<greengrass_group>", help="name of the created aws greengrass group")
arg_parser.add_argument("device_name", metavar="<device_name>", help="name of the created device in the defined greengrass group")
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
GG_DEVICE_NAME = underscores(args.device_name)
GG_STATUS_FILENAME = args.status_filename
GG_DEVICE_POLICY_NAME = GG_DEVICE_NAME + "-policy"
GG_DEVICE_DEFINITION_NAME = GG_DEVICE_NAME + "-definition"

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

# greengrass group of this name must exist already
if gg_group is None:
    msg("[!] The greengrass group of this name does not exist: " + gg_group["Name"])
    msg("[!] We will abort the configuration and do nothing")
    sys.exit(1)

# thing name must be unique - we abort if the name already exists
gg_thing = find_iot_thing(iot, GG_DEVICE_NAME)
if gg_thing is not None:
    msg("[!] The iot thing of this name already exists: " + gg_thing["thingName"])
    msg("[!] We will abort the configuration and do nothing")
    sys.exit(1)

# we will also need a policy and for simplicity we will create one or reuse
# the one of the same name
#
# return policy if exists or None
gg_device_policy = find_iot_policy(iot, GG_DEVICE_POLICY_NAME)

# if policy does not exist yet - create it:
if gg_device_policy is None:
    msg("Create AWS IoT policy: " + GG_DEVICE_POLICY_NAME)
    gg_device_policy = create_device_policy(iot, GG_DEVICE_POLICY_NAME)
else:
    msg("Reusing AWS IoT policy: " + gg_device_policy["policyName"])

# create keys and cert and core thing of our group
msg("Create AWS IoT keys and certificate")
gg_keys_cert = iot.create_keys_and_certificate(setAsActive=True)
msg("Create AWS IoT Thing: " + GG_DEVICE_NAME)
gg_device_thing = iot.create_thing(thingName=GG_DEVICE_NAME)

iot.attach_thing_principal(
    thingName=gg_device_thing["thingName"],
    principal=gg_keys_cert["certificateArn"])

# attach the previously obtained/created policy
iot.attach_principal_policy(
    policyName=gg_device_policy["policyName"],
    principal=gg_keys_cert["certificateArn"])

# store new device json doc
gg_new_device_doc = {
    "Id": gg_device_thing["thingName"],
    "CertificateArn": gg_keys_cert["certificateArn"],
    "SyncShadow": False,
    "ThingArn": gg_device_thing["thingArn"]
}

# prepare json doc for device definition
msg("Get the current device definition")
gg_device_definition = get_device_definition(gg, gg_group)

if gg_device_definition is None:
    gg_device_initial_version = {"Devices": [ gg_new_device_doc ]}

    msg("Create AWS Greengrass device definition: " + GG_DEVICE_DEFINITION_NAME)
    gg_device_definition = gg.create_device_definition(
        Name=GG_DEVICE_DEFINITION_NAME,
        InitialVersion=gg_device_initial_version)

msg("Prepare list of devices (updated with the new device)")
gg_device_list = get_devices(gg, gg_group)
if not gg_new_device_doc in gg_device_list:
    gg_device_list.append(gg_new_device_doc)

msg("Create AWS Greengrass device definition version")
gg_device_definition_version = gg.create_device_definition_version(
    DeviceDefinitionId=gg_device_definition["Id"],
    Devices=gg_device_list)

# update the greengrass group with the newly created device
msg("Update AWS Greengrass Group (with the new device): " + GG_GROUP_NAME)
gg_group_definitions = {
    "DeviceDefinitionVersionArn": gg_device_definition_version["Arn"]
}
gg_group_version = update_group(gg, gg_group, gg_group_definitions)

# store everything so far created into the json status
gg_status = {
    "group_version": gg_group_version,
    "device_thing": gg_device_thing,
    "keys_cert": gg_keys_cert,
    "device_definition": gg_device_definition,
    "device_definition_version": gg_device_definition_version,
    "policy": gg_device_policy
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

