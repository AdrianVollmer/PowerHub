from powerhub.logging import log
from powerhub.upload import save_file
from powerhub.directories import LOOT_DIR

lootbox = [1, 2]


def get_loot_type(filename):
    """Determine the loot type

    Could be an LSA process dump or a registry hive.
    """
    pass


def store_minidump(creds):
    """Write the results from parsing the dmp file to the DB"""
    pass


def save_loot(file):
    loot_type = get_loot_type(file.filename)
    filename = save_file(file, dir=LOOT_DIR)
    try:
        if loot_type == "DMP":
            from pypykatz.pypykatz import pypykatz
            mimi = pypykatz.parse_minidump_file(filename)
            for _, v in mimi.logon_sessions.items():
                store_minidump(v.to_dict())
    except ImportError as e:
        log.error("You have unmet dependencies, loot could not be processed")
        log.exception(e)
