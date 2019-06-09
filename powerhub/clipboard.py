from sqlalchemy.exc import OperationalError
import logging
log = logging.getLogger(__name__)


def init_clipboard(db=None):
    if db:
        return init_clipboard_with_db(db)
    else:
        return init_clipboard_without_db()


def init_clipboard_without_db():
    class Entry(object):
        def __init__(self, content=None, time=None, IP=None):
            self.content = content
            self.time = time
            self.IP = IP

    class Clipboard(object):
        def __init__(self):
            self.entries = []

        def __iter__(self):
            return iter(self.entries)

        def add(self, content, time, IP):
            e = Entry(content=content, time=time, IP=IP)
            self.entries.append(e)
            return e

        def delete(self, n):
            self.entries.pop(n)
            return

        def __len__(self):
            return len(self.entries)

    return Clipboard()


def init_clipboard_with_db(db):
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
            self.update()

        def update(self):
            try:
                self.entries = Entry.query.all()
            except OperationalError:
                db.create_all()
                self.entries = []

        def __iter__(self):
            return iter(self.entries)

        def add(self, content, time, IP):
            e = Entry(content=content, time=time, IP=IP)
            db.session.add(e)
            db.session.commit()
            self.update()
            return e

        def delete(self, n):
            e = self.entries[n]
            db.session.delete(e)
            db.session.commit()
            self.entries = Entry.query.all()
            self.update()
            return

        def __len__(self):
            return len(self.entries)

    return Clipboard()
