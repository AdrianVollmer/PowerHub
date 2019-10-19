from powerhub.logging import log
from powerhub.sql import add_lsass, add_hive
from powerhub.upload import save_file
from powerhub.directories import LOOT_DIR
from powerhub.tools import unique, flatten
import re
import json


def get_loot_type(filename):
    """Determine the loot type

    Could be an LSA process dump or a registry hive.
    """
    if re.match(r".*lsass_[0-9]+.dmp(.[0-9]+)?", filename):
        return "DMP"
    elif re.match(r".*sam(.[0-9]+)?", filename):
        return "SAM"
    elif re.match(r".*security(.[0-9]+)?", filename):
        return "SECURITY"
    elif re.match(r".*system(.[0-9]+)?", filename):
        return "SYSTEM"
    elif re.match(r".*software(.[0-9]+)?", filename):
        return "SOFTWARE"


def store_minidump(loot_id, lsass, lass_file):
    """Write the results from parsing the lsass dmp file to the DB"""
    add_lsass(loot_id, lsass, lass_file)


def save_loot(file, loot_id):
    """Process the loot file"""

    filename = save_file(file, dir=LOOT_DIR)
    loot_type = get_loot_type(filename)
    try:
        if loot_type == "DMP":
            from pypykatz.pypykatz import pypykatz
            mimi = pypykatz.parse_minidump_file(filename)
            creds = [json.loads(v.to_json())
                     for _, v in mimi.logon_sessions.items()]
            print(creds)
            store_minidump(loot_id, json.dumps(creds), filename)
        else:  # registry hive
            add_hive(loot_id, loot_type, filename)
    except ImportError as e:
        log.error("You have unmet dependencies, loot could not be processed")
        log.exception(e)


def get_hive_goodies(hive):
    hive = json.loads(hive)
    # remove users with empty hashes, most likely disabled
    local_users = []
    if "SAM" in hive:
        local_users = [
            u for u in hive["SAM"]["local_users"]
            if not (
                u["lm_hash"] == "aad3b435b51404eeaad3b435b51404ee" and
                u["nt_hash"] == "31d6cfe0d16ae931b73c59d7e0c089c0"
            )
        ]
    dccs = []
    if "SECURITY" in hive:
        dccs = hive["SECURITY"]["dcc"]
    result = {
        "local_users": local_users,
        "dccs": dccs,
    }
    return result


def get_lsass_goodies(lsass):
    def get_creds(x):
        """recursive credential search"""
        if isinstance(x, dict):
            if "password" in x and x["password"]:
                return {
                    "domainname": x["domainname"],
                    "username": x["username"],
                    "password": x["password"],
                }
            elif "NThash" in x and x["NThash"]:
                return {
                    "domainname": x["domainname"],
                    "username": x["username"],
                    "NThash": x["NThash"],
                }
            elif "LMhash" in x and x["LMhash"]:
                return {
                    "domainname": x["domainname"],
                    "username": x["username"],
                    "LMGhash": x["LMGhash"],
                }
            else:
                result = [get_creds(y) for y in list(x.values())]
                result = [c for c in result if c]
                return result
        elif isinstance(x, list):
            result = [get_creds(y) for y in x]
            result = [c for c in result if c]
            return result
        else:
            return None

    result = json.loads(lsass)
    result = get_creds(result)
    result = flatten(result)
    result = [x[0] for x in result]
    result = unique(result)
    return result
