import logging
import sys

import powerhub.env as env


DEBUG = (env.powerhub_app and env.powerhub_app.args.DEBUG)


class FlaskFilter(logging.Filter):
    """This removes a misleading logging message by Flask"""

    def filter(self, record):
        return "* Running on http://" not in record.getMessage()


if DEBUG:
    FORMAT = '%(levelname).1s %(asctime)-15s '
    FORMAT += '%(filename)s:%(lineno)d %(message)s'
else:
    FORMAT = '%(levelname).1s %(asctime)-15s %(message)s'


logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG if DEBUG else logging.INFO,
    format=FORMAT,
    datefmt="%Y-%m-%d %H:%M:%S",
)

log = logging.getLogger(__name__)

for h in logging.root.handlers:
    h.addFilter(FlaskFilter())
