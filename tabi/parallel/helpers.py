# -*- coding: utf-8 -*-
# Copyright (C) 2016 ANSSI
# This file is part of the tabi project licensed under the MIT license.

import os
import re
import sys
import logging
import subprocess
import math

from tabi.helpers import *

############################################
# Directories management


def create_directory(directoryname):
    """Create the directoryname directory."""

    if not os.path.exists(directoryname):
        try:
            os.mkdir(directoryname)
            logging.debug("'%s' directory created", directoryname)
        except:
            message = "create_directory() could not create"
            message += " '%s' directory" % directoryname
            critical_error(message)


def get_directoryname(options, args):
    """Extract a directory name from the first filenames in args."""

    if options.disable_checks is False and len(args) > 0:
        re_str = "(updates|bview)\.([0-9]{4})([0-9]{2})[0-9]*\.[0-9]*"
        matching = re.search(re_str, args[0])
        if not matching:
            message = "get_directoryname() '%s' does not seems to use the correct" \
                      " RIS filenames' format !" % args[0]
            critical_error(message)

        return "%s.%s" % (matching.group(2), matching.group(3))

    else:
        return "no_name"


def create_results_directory(output_directory, directory):
    """Manage the creation of the results directory."""

    # Create the "results" directory
    directoryname = "%s/%s" % (output_directory, directory)
    create_directory(output_directory)
    create_directory(directoryname)


############################################
# Configuration management


def parse_ases_ini(filename):
    """Retrieve a list of AS numbers from filename."""

    # Open the file
    try:
        fdases = open(filename, 'r')
    except:
        message = "parse_ases_ini(): could not open %s !" % filename
        raise CriticalException(message)

    # Get the file's content
    ases = fdases.readlines()
    fdases.close()

    # Check if ases contains valid integers
    as_list = []
    for str_as in ases:
        try:
            as_list += [int(str_as.strip())]
        except ValueError:
            message = "parse_ases_ini(): '%s' is not a "\
                      "valid integer !" % str_as.strip()
            raise CriticalException(message)

    return as_list


def split_ases_list(asn_list, num):
    """Returns 'num' lists of AS numbers."""

    # Do not split
    if num <= 1 or len(asn_list) == 0:
        return [asn_list]

    # Compute the number of AS per slice
    asn_number = int(math.ceil(len(asn_list)/float(num)))

    # Split the asn_list in 'num' lists
    ret_list = []
    for i in range(num):
        ret_list += [asn_list[:asn_number]]
        asn_list = asn_list[asn_number:]

    return ret_list
