import logging
import sys


class FlaskFilter(logging.Filter):
    """This removes a misleading logging message by Flask"""

    def filter(self, record):
        return "* Running on http://" not in record.getMessage()


def init_logging(debug, stream=sys.stdout):
    if debug:
        FORMAT = '%(levelname).1s %(asctime)-15s '
        FORMAT += '%(filename)s:%(lineno)d %(message)s'
    else:
        FORMAT = '%(levelname).1s %(asctime)-15s %(message)s'

    logging.basicConfig(
        stream=stream,
        level=logging.DEBUG if debug else logging.INFO,
        format=FORMAT,
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    for h in logging.root.handlers:
        h.addFilter(FlaskFilter())
