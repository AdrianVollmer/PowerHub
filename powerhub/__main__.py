#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from powerhub.app import PowerHubApp


def main(fully_threaded=False):
    PowerHubApp().run(fully_threaded=fully_threaded)
