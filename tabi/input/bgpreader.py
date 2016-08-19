# -*- coding: utf-8 -*-
# Copyright (C) 2016 ANSSI
# This file is part of the tabi project licensed under the MIT license.

import os
import sys
import logging
import subprocess

from contextlib import contextmanager

from tabi.core import InternalMessage
from tabi.helpers import check_ris_filenames, get_as_origin, \
    critical_error, process_iterator, gzip_opener

logger = logging.getLogger(__name__)


def bgpreader_format_bview(collector, data):
    """
    Transform an bgpreader bview line to the internal representation.
    """
    as_path = data[8]
    if len(as_path) > 0:
        try:
            origin = frozenset(get_as_origin(as_path))
        except:
            logger.warning("invalid AS_PATH %s", as_path)
        else:
            if len(origin) == 1:
                origin = iter(origin).next()
            yield InternalMessage("F",
                                  data[1],
                                  data[3],
                                  int(data[4]),
                                  data[5],
                                  data[6],
                                  origin,
                                  as_path)


def bgpreader_format_update(collector, data):
    """
    Transform an bgpreader update message to the internal representation.
    """
    if data[0] == "W":
        yield InternalMessage("W",
                              data[1],
                              data[3],
                              int(data[4]),
                              data[5],
                              data[6],
                              None,
                              None)
    elif data[0] == "A":
        as_path = data[8]
        if len(as_path) > 0:
            try:
                origin = frozenset(get_as_origin(as_path))
            except:
                logger.warning("invalid AS_PATH %s", as_path)
            else:
                if len(origin) == 1:
                    origin = iter(origin).next()
                yield InternalMessage("U",
                                      data[1],
                                      data[3],
                                      int(data[4]),
                                      data[5],
                                      data[6],
                                      origin,
                                      as_path)


def bgpreader_format(collector, message):
    """
    Get the internal representation associated with `message'.

    :param collector: Name of the collector the message comes from
    :param message: Raw BGP message parsed with bgpreader
    :return: iterator of InternalMessage
    """

    data = message.split("|")
    dump_type = data[0]
    elem_type = data[1]

    if dump_type == "R" and elem_type == "R":
        return bgpreader_format_bview(collector, data[1:])
    elif dump_type == "U" and elem_type in {"W", "A"}:
        return bgpreader_format_update(collector, message[1:])
    else:
        logger.warning("unknown document type %s, %s", dump_type, elem_type)
        return []


def bgpreader_fork(filename, output=None):
    """
    Call BGPREADER_PATH on a given MRT dump.
    Return the subprocess handle.
    """
    BGPREADER_PATH = os.getenv(
        "BGPREADER_PATH", os.path.join(os.path.dirname(sys.argv[0]),
                                       "./bgpreader"))

    # Check if files exists
    if not os.path.exists(filename):
        message = "bgpreader_fork(): MRT file does not exist: %s" % filename
        critical_error(message)

    # Call the external command
    try:
        if output is None:
            output = subprocess.PIPE
        else:
            output = open(output, "w")
        if "bview" in filename:
            opts = "rib-file,{}".format(filename)
        else:
            opts = "upd-file,{}".format(filename)
        sp = subprocess.Popen([BGPREADER_PATH, "-d", "singlefile", "-o", opts,
                               "-w", "0,{}".format(0x7FFFFFFF - 1)],
                              stdout=output, stderr=subprocess.PIPE)
    except OSError, e:
        critical_error("bgpreader_fork() %s: %s" % (BGPREADER_PATH, e))
    finally:
        if output != subprocess.PIPE:
            output.close()
    return sp


@contextmanager
def bgpreader_opener(mrt_file, tmp_file=None):
    """
    Give an iterator on the content of 'mrt_file'.

    :param tmp_file: optionaly store the parsed content in this file.
    """
    # MRT file, fork bgpreader
    sp = bgpreader_fork(mrt_file, output=tmp_file)
    try:
        if tmp_file is None:
            yield process_iterator(sp, sp.stdout)
        else:
            with open(tmp_file, "r") as inp:
                yield process_iterator(sp, inp)
    except:
        # kill bgpreader if it is still running
        sp.poll()
        if sp.returncode is None:
            sp.kill()
        raise
    finally:
        sp.wait()
        for line in sp.stderr:
            logger.error("mrt_opener: bgpreader: %s", line.strip())


def bgpreader_input(collector, **options):
    """
    Prepare arguments for `detect_conflits' using already parsed data.
    """

    files = options.pop("files", [])

    if collector.startswith("rrc"):
        # this is a RIS collector, prepare the file list
        files, remain = check_ris_filenames(files)
        if len(remain):
            raise ValueError("cannot sort the files")

    # detect if it is required to open the files using bgpreader or just gunzip
    if str(options.get("mrt", True)).lower() == "true":
        opener = bgpreader_opener
    else:
        opener = gzip_opener

    return {"collector": collector, "files": files, "opener": opener,
            "format": bgpreader_format}
