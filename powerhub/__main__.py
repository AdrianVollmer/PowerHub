#!/usr/bin/env python3
# -*- coding: utf-8 -*-


def main(background=False):
    from powerhub.app import PowerHubApp
    PowerHubApp().run(background=background)
