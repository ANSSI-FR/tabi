# -*- coding: utf-8 -*-
# Copyright (C) 2016 ANSSI
# This file is part of the tabi project licensed under the MIT license.

from __future__ import print_function

import json
import logging

from tabi.emulator import detect_hijacks

logger = logging.getLogger(__name__)


def choose_input(input):
    if input == "mabo":
        from tabi.input.mabo import mabo_input
        return mabo_input

    elif input == "bgpreader":
        from tabi.input.bgpreader import bgpreader_input
        return bgpreader_input

    else:
        raise ValueError("unknown input type {}".format(input))


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("mrt_files", nargs="*", help="MRT files")
    parser.add_argument("-c", "--collector",
                        help="collector name from where the log files are",
                        default="none")
    parser.add_argument("-i", "--input",
                        help="MRT parser, e.g. 'mabo'",
                        default="mabo")
    parser.add_argument("-o", "--options",
                        help="extra options passed to the input method")
    parser.add_argument("--irr-ro-file",
                        help="CSV file containing IRR route objects")
    parser.add_argument("--irr-mnt-file",
                        help="CSV file containing IRR maintainer objects")
    parser.add_argument("--irr-org-file",
                        help="CSV file containing IRR organisation objects")
    parser.add_argument("--rpki-roa-file",
                        help="CSV file containing ROA")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="more logging")

    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    input_kwargs = {"files": args.mrt_files}
    if args.options is not None:
        try:
            input_kwargs.update(dict([w.split("=", 2) for w in
                                      args.options.split(",")]))
        except:
            raise ValueError("invalid input options (use format key=value)")

    input = choose_input(args.input)
    kwargs = input(args.collector, **input_kwargs)

    if args.irr_ro_file is not None:
        kwargs["irr_ro_file"] = args.irr_ro_file

    if args.rpki_roa_file is not None:
        kwargs["rpki_roa_file"] = args.rpki_roa_file

    if args.irr_org_file is not None:
        kwargs["irr_org_file"] = args.irr_org_file

    if args.irr_mnt_file is not None:
        kwargs["irr_mnt_file"] = args.irr_mnt_file

    # detect the conflicts and print them
    for conflict in detect_hijacks(**kwargs):
        if conflict["type"] == "ABNORMAL":
            print(json.dumps(conflict))
