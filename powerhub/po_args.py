import argparse
from powerhub import __version__

parser = argparse.ArgumentParser(
    description="Leverage PowerHub's obfuscation mechanism to obfuscate"
    " PowerShell scripts and .NET binaries"
)

parser.add_argument(
    '-v', '--version', action='version', version='PowerHub ' + __version__
)

parser.add_argument(
    '-d', '--debug', default=False, action="store_true",
    help=("enable debug mode (disables a lot of obfuscation)"),
)

parser.add_argument(
    '-i', '--input',
    default='-',
    type=argparse.FileType(mode='rb'),
    help="path to input file (default: stdin)",
)

parser.add_argument(
    '-o', '--output',
    default='-',
    type=argparse.FileType(mode='w'),
    help="path to output file (default: stdin)",
)

parser.add_argument(
    '-e', '--epilogue',
    default=None,
    help="PowerShell code to execute after all scripts have been loaded",
)

parser.add_argument(
    '-n', '--natural', default=False, action="store_true",
    help=("use natural variable names"),
)


def parse_args():
    return parser.parse_args()
