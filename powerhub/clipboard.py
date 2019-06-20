from sqlalchemy.exc import OperationalError


def init_clipboard(db=None):
    if db:
        return init_clipboard_with_db(db)
    else:
        return init_clipboard_without_db()


def init_clipboard_without_db():
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
                self.entries = {e.id: e for e in Entry.query.all()}
            except OperationalError:
                db.create_all()
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
