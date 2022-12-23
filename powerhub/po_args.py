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
    '-i', '--input',
    default='-',
    type=argparse.FileType(mode='rb'),
    help="Path to input file (default: stdin)",
)

parser.add_argument(
    '-o', '--output',
    default='-',
    type=argparse.FileType(mode='w'),
    help="Path to output file (default: stdin)",
)


def parse_args():
    return parser.parse_args()
