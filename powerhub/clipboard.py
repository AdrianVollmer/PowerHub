from powerhub.directories import XDG_DATA_HOME

import os
import logging
log = logging.getLogger(__name__)
try:
    import sqlalchemy as db
    _persistent = True
except ImportError:
    _persistent = False
    log.exception("You have unmet dependencies. The clipboard "
                  "won't be persistent. Consult the README.")


class Clipboard(object):
    def __init__(self):
        self.entries = []
        if _persistent:
            db_filename = os.path.join(XDG_DATA_HOME, "powerhub_db.sqlite")
            self.engine = db.create_engine('sqlite:///' + db_filename)
            connection = self.engine.connect()
            metadata = db.MetaData()
            self.create_table(metadata)
            self.load_entries(connection, metadata)

    def create_table(self, metadata):
        db.Table(
            'clipboard', metadata,
            db.Column('content', db.String(1024*8), nullable=False),
            db.Column('time', db.String(255), nullable=False),
            db.Column('IP', db.String(255), nullable=False),
        )
        metadata.create_all(self.engine)  # Creates the table

    def load_entries(self, connection, metadata):
        clipboard = db.Table('clipboard', metadata, autoload=True,
                             autoload_with=self.engine)
        query = db.select([clipboard])
        ResultProxy = connection.execute(query)
        entries = ResultProxy.fetchall()
        for e in entries:
            self.entries.append(Clipboard(*e))

    def __iter__(self):
        return iter(self.entries)

    def add(self, content, time, IP):
        e = ClipboardEntry(content, time, IP)
        self.entries.append(e)
        return e

    def delete(self, n):
        self.entries.pop(n)
        return

    def __len__(self):
        return len(self.entries)


class ClipboardEntry(object):
    def __init__(self, content, time, IP):
        self.content = content
        self.time = time
        self.IP = IP

    def __str__(self):
        return self.content


clipboard = Clipboard()
