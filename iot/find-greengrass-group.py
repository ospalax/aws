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
import boto3
import argparse
import sys
import os

def msg(s):
    print("AWS IoT: " + s)

def find_core_definition(gg, version_arn):
    """ returns: core definition with this core def. version arn or None"""

    r = gg.list_core_definitions(MaxResults="100")
    if "Definitions" in r:
        while True:
            for definition in r["Definitions"]:
                if definition["LatestVersionArn"] == version_arn:
                    return definition
            if "NextToken" in r and r["NextToken"] != "null":
                r = gg.list_core_definitions(MaxResults="100", NextToken=r["NextToken"])
            else:
                break

    return None

def find_gg_group_with_core(gg, core_arn):
    """ returns: greengrass group for this core thing or None"""

    r = gg.list_groups(MaxResults="100")
    if "Groups" in r:
        while True:
            for group in r["Groups"]:
                group_version = gg.get_group_version(GroupId=group['Id'],
                                                     GroupVersionId=group['LatestVersion'])
                #print(json.dumps(group_version, indent=4, sort_keys=True))
                # core definition arn
                cd_arn = group_version['Definition']['CoreDefinitionVersionArn']
                # core definition
                cd = find_core_definition(gg, cd_arn)
                # core definition version
                cd_version = gg.get_core_definition_version(CoreDefinitionId=cd['Id'],
                                                            CoreDefinitionVersionId=cd['LatestVersion'])
                #print(json.dumps(cd_version, indent=4, sort_keys=True))
                for core in cd_version["Definition"]["Cores"]:
                    if core["ThingArn"] == core_arn:
                        return group
            if "NextToken" in r and r["NextToken"] != "null":
                r = gg.list_groups(MaxResults="100", NextToken=r["NextToken"])
            else:
                break

    return None

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

# we expect two arguments: <username> <core thing arn>
arg_parser = argparse.ArgumentParser()
arg_parser.add_argument("username", metavar="<username>", help="run this program as this user")
arg_parser.add_argument("corething_arn", metavar="<core_thing_arn>", help="Arn of the core thing of the searched group")
args = arg_parser.parse_args()

try:
    run_as_user(args.username)
except Exception:
    msg("[!] We could not change our running uid/gid to this user: " + args.username)
    msg("[!] We will abort the configuration and do nothing")
    sys.exit(1)

# create iot and greengrass objects:
gg = boto3.client("greengrass")
iot = boto3.client("iot")

# return group if exists or None
gg_group = find_gg_group_with_core(gg, args.corething_arn)

# dump json with extracted group
print(json.dumps(gg_group, indent=4, sort_keys=True))

# successfully finish
sys.exit(0)

