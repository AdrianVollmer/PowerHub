
_db = None


def get_setting(key):
    setting = Setting.query.filter_by(key=key).first()
    if setting:
        return setting.value
    return None


def set_setting(key, value):
    s = Setting(key=key, value=value)
    _db.session.add(s)
    _db.session.commit()


def init_db(db):
    global Setting
    global _db
    _db = db

    class Setting(_db.Model):
        key = _db.Column(_db.String(255), primary_key=True)
        value = _db.Column(_db.String(1024), unique=False, nullable=False)

    _db.create_all()
