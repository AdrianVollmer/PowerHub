import logging
import sys

from powerhub.args import args


FORMAT = '%(levelname).1s %(asctime)-15s %(message)s'


logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG if args.DEBUG else logging.INFO,
    format=FORMAT,
    datefmt="%Y-%m-%d %H:%M:%S",
)

log = logging.getLogger(__name__)
