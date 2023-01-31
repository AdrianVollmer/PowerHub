import logging

from sqlalchemy.exc import OperationalError
from sqlalchemy import text

_db = None
log = logging.getLogger(__name__)


def init_db(db):
    global _db
    _db = db
    init_settings()
    _db.create_all()
    _db.session.commit()
    try:
        upgrade_from_111_to_200(db)
    except OperationalError as e:
        msg = str(e)
        if not (
            'duplicate column name' in msg
            or 'no such table' in msg
        ):
            raise


def upgrade_from_111_to_200(db):
    """Add the `executable` column to the `Entry` table"""
    with db.engine.connect() as connection:
        connection.execute(text(
            'alter table Entry add column executable Boolean'
            ' not null default false'
        ))
        log.info("Schema upgrade successful (2.0)")


def get_setting(key):
    if not _db:
        return None
    setting = Setting.query.filter_by(key=key).first()
    if setting:
        return setting.value
    return None


def set_setting(key, value):
    if not _db:
        return None
    s = Setting(key=key, value=value)
    _db.session.add(s)
    _db.session.commit()


def init_settings():
    if not _db:
        return None
    global Setting

    class Setting(_db.Model):
        key = _db.Column(_db.String(255), primary_key=True)
        value = _db.Column(_db.String(1024), unique=False, nullable=False)


def get_clipboard():
    return get_clipboard_with_db(_db)


def get_clipboard_with_db(db):
    class Entry(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        content = db.Column(db.String(8*1024), unique=False, nullable=False)
        time = db.Column(db.String(120), unique=False, nullable=False)
        IP = db.Column(db.String(39), unique=False, nullable=False)
        # 39 because could be ipv6
        executable = db.Column(db.Boolean(), nullable=False, default=False)

        def __repr__(self):
            return '<Entry %r>' % self.time

        @property
        def timedelta(self):
            return get_timedelta(self.time)

    class Clipboard(object):
        def __init__(self):
            db.create_all()
            try:
                self.entries = {e.id: e for e in Entry.query.all()}
            except OperationalError:
                self.entries = {}
            # The entries dict needs to be kept in sync after all operations

        def __iter__(self):
            return iter(self.entries)

        def add(self, content, time, IP):
            e = Entry(content=content, time=time, IP=IP, executable=False)
            db.session.add(e)
            db.session.commit()
            self.entries[e.id] = e

        def edit(self, id, content):
            e = Entry.query.filter_by(id=id).first()
            e.content = content
            db.session.commit()
            self.entries[e.id] = e

        def set_executable(self, id, value):
            e = Entry.query.filter_by(id=id).first()
            e.executable = value
            db.session.commit()
            self.entries[e.id] = e

        def delete(self, id):
            e = self.entries[id]
            e_ = db.session.merge(e)
            db.session.delete(e_)
            db.session.commit()
            del self.entries[e.id]

        def __len__(self):
            return len(self.entries.keys())

    return Clipboard()


def get_clip_entry_list(clipboard):
    return [
        (
            c.id,
            '[%d] %s' % (
                c.id, c.content[:50] + ("..." if len(c.content) > 50 else "")
            ),
        ) for c in clipboard.entries.values() if c.executable
    ]


def get_timedelta(time):
    from datetime import datetime as dt
    result = dt.utcnow() - dt.fromisoformat(time)

    if result.total_seconds() < 60:
        result = "%ss" % result.seconds
    elif result.total_seconds() < 3600:
        result = "%sm" % (result.seconds // 60)
    elif result.total_seconds() < 86400:
        result = "%sh" % (result.seconds // 3600)
    else:
        result = "%sd" % result.days

    return result
