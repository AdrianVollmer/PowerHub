try:
    from flask_sqlalchemy import SQLAlchemy
except ImportError:
    print("You have unmet dependencies. The clipboard "
          "won't be persistent. Consult the README.")


def get_db(app):
    try:
        db = SQLAlchemy(app)
    except NameError:
        db = None
    return db
