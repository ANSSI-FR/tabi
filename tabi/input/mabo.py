# -*- coding: utf-8 -*-
# Copyright (C) 2016 ANSSI
# This file is part of the tabi project licensed under the MIT license.

import json
import logging

from contextlib import contextmanager

from tabi.core import InternalMessage
from tabi.helpers import check_ris_filenames, get_as_origin, \
    process_iterator, gzip_opener, mabo_fork

logger = logging.getLogger(__name__)


def mabo_format_td2(collector, data):
    """
    Transform an mabo table dump v2 message to the internal representation.
    """
    for entry in data.get("entries", []):
        as_path = entry["as_path"]
        if len(as_path) == 0:
            # skip announces from IGP
            continue
        try:
            origin = frozenset(get_as_origin(as_path))
        except:
            logger.warning("invalid AS_PATH %s", as_path)
        else:
            if len(origin) == 1:
                origin = iter(origin).next()
            yield InternalMessage("F",
                                  data["timestamp"],
                                  collector,
                                  int(entry["peer_as"]),
                                  entry["peer_ip"],
                                  data["prefix"],
                                  origin,
                                  as_path)


def mabo_format_update(collector, data):
    """
    Transform an mabo update message to the internal representation.
    """
    for entry in data.get("withdraw", []):
        yield InternalMessage("W",
                              data["timestamp"],
                              collector,
                              int(data["peer_as"]),
                              data["peer_ip"],
                              entry,
                              None,
                              None)

    as_path = data.get("as_path", "")
    if len(as_path) != 0:
        try:
            origin = frozenset(get_as_origin(as_path))
        except:
            logger.warning("invalid AS_PATH %s", as_path)
        else:
            if len(origin) == 1:
                origin = iter(origin).next()
            for entry in data.get("announce", []):
                yield InternalMessage("U",
                                      data["timestamp"],
                                      collector,
                                      int(data["peer_as"]),
                                      data["peer_ip"],
                                      entry,
                                      origin,
                                      as_path)


def mabo_format(collector, message):
    """
    Get the internal representation associated with `message'.

    :param collector: Name of the collector the message comes from
    :param message: Raw BGP message parsed with mabo
    :return: iterator of InternalMessage
    """

    data = json.loads(message)
    typ_ = data["type"]
    if typ_ == "table_dump_v2":
        return mabo_format_td2(collector, data)
    elif typ_ == "update":
        return mabo_format_update(collector, data)
    else:
        logger.warning("unsupported message type %s", typ_)
        return []


@contextmanager
def mrt_opener(mrt_file, tmp_file=None):
    """
    Give an iterator on the content of 'mrt_file'.

    :param tmp_file: optionaly store the parsed content in this file.
    """
    # MRT file, fork mabo
    sp = mabo_fork(mrt_file, output=tmp_file)
    try:
        if tmp_file is None:
            yield process_iterator(sp, sp.stdout)
        else:
            with open(tmp_file, "r") as inp:
                yield process_iterator(sp, inp)
    except:
        # kill mabo if it is still running
        sp.poll()
        if sp.returncode is None:
            sp.kill()
        raise
    finally:
        sp.wait()
        for line in sp.stderr:
            logger.error("mrt_opener: mabo: %s", line.strip())


def mabo_input(collector, **options):
    """
    Prepare arguments for `detect_conflits' using already parsed data.
    """

    files = options.pop("files", [])

    if collector.startswith("rrc"):
        # this is a RIS collector, prepare the file list
        files, remain = check_ris_filenames(files)
        if len(remain):
            raise ValueError("cannot sort the files")

    # detect if it is required to open the files using mabo or just gunzip
    if str(options.get("mrt", True)).lower() == "true":
        opener = mrt_opener
    else:
        opener = gzip_opener

    return {"collector": collector, "files": files, "opener": opener,
            "format": mabo_format}
