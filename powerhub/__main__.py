#!/usr/bin/env python3
# -*- coding: utf-8 -*-


def main(background=False):
    from powerhub.args import parse_args
    args = parse_args()

    from powerhub.logging import init_logging
    init_logging(args.DEBUG)

    from powerhub.app import PowerHubApp
    PowerHubApp(args).run(background=background)


def power_obfuscate():
    from powerhub.po_args import parse_args
    args = parse_args()

    from powerhub.logging import init_logging
    import sys
    init_logging(args.debug, stream=sys.stderr)

    from powerhub.directories import init_directories
    init_directories(None, create_missing=False)

    from powerhub.stager import obfuscate_file
    obfuscate_file(
        args.input, args.output, epilogue=args.epilogue,
        slow_encryption=args.slow_encryption, decoy=args.decoy,
        debug=args.debug, natural=args.natural, name=args.name,
    )
