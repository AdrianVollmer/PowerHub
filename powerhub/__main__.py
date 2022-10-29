#!/usr/bin/env python3
# -*- coding: utf-8 -*-


def main(background=False):
    from powerhub.args import parse_args
    args = parse_args()

    from powerhub.app import PowerHubApp
    PowerHubApp(args).run(background=background)
