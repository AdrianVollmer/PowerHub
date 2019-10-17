try:
    from sqlalchemy.exc import OperationalError
except ImportError:
    pass

_db = None


def init_db(db):
    global _db
    _db = db
    init_settings()
    init_loot()
    _db.create_all()
    _db.session.commit()


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


def init_loot():
    global Loot

    if not _db:
        Loot = None
        return None

    class Loot(_db.Model):
        id = _db.Column(_db.String(8), primary_key=True)
        sysinfo = _db.Column(_db.String(1024*8), unique=False, nullable=False)
        lsass = _db.Column(_db.String(1024*16), unique=False, nullable=False)
        lsass_file = _db.Column(_db.String(1024), unique=False, nullable=False)
        system_file = _db.Column(_db.String(1024),
                                 unique=False,
                                 nullable=False)
        security_file = _db.Column(_db.String(1024),
                                   unique=False,
                                   nullable=False)
        sam_file = _db.Column(_db.String(1024), unique=False, nullable=False)
        sam = _db.Column(_db.String(1024*8), unique=False, nullable=False)
        security = _db.Column(_db.String(1024*8), unique=False, nullable=False)
        software_file = _db.Column(_db.String(1024),
                                   unique=False,
                                   nullable=False)
        software = _db.Column(_db.String(1024*8), unique=False, nullable=False)


def get_loot():
    return Loot


def get_clipboard():
    if _db:
        return get_clipboard_with_db(_db)
    else:
        return get_clipboard_without_db()


def get_clipboard_without_db():
    class Entry(object):
        def __init__(self, id=id, content=None, time=None, IP=None):
            self.id = id
            self.content = content
            self.time = time
            self.IP = IP

    class Clipboard(object):
        def __init__(self):
            self.next_id = 0
            self.entries = {}

        def __iter__(self):
            return iter(self.entries)

        def add(self, content, time, IP):
            e = Entry(id=self.next_id, content=content, time=time, IP=IP)
            self.entries[self.next_id] = e
            self.next_id += 1
            return e

        def delete(self, id):
            del self.entries[id]
            return

        def __len__(self):
            return len(self.entries.keys())

    return Clipboard()


def get_clipboard_with_db(db):
    class Entry(db.Model):
        id = db.Column(db.Integer, primary_key=True)
        content = db.Column(db.String(8*1024), unique=False, nullable=False)
        time = db.Column(db.String(120), unique=False, nullable=False)
        IP = db.Column(db.String(39), unique=False, nullable=False)
        # 39 because could be ipv6

        def __repr__(self):
            return '<Entry %r>' % self.time

    class Clipboard(object):
        def __init__(self):
            db.create_all()
            try:
                self.entries = {e.id: e for e in Entry.query.all()}
            except OperationalError:
                self.entries = {}

        def __iter__(self):
            return iter(self.entries)

        def add(self, content, time, IP):
            e = Entry(content=content, time=time, IP=IP)
            db.session.add(e)
            db.session.commit()
            self.entries[e.id] = e
            return None

        def delete(self, id):
            e = self.entries[id]
            e_ = db.session.merge(e)
            db.session.delete(e_)
            db.session.commit()
            del self.entries[e.id]
            return None

        def __len__(self):
            return len(self.entries.keys())

    return Clipboard()
