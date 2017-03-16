# -*- coding: utf-8 -*-
# Copyright (C) 2016 ANSSI
# This file is part of the tabi project licensed under the MIT license.

import logging

from functools import partial
from itertools import chain
from collections import deque

from tabi.rib import EmulatedRIB, Radix
from tabi.core import default_route, route, withdraw, hijack
from tabi.input.mabo import mabo_format
from tabi.annotate import annotate_if_relation, annotate_if_route_objects, \
    annotate_if_roa, annotate_if_direct, annotate_with_type, \
    fill_relation_struct, fill_ro_struct, fill_roa_struct
from tabi.helpers import default_opener


logger = logging.getLogger(__name__)


def process_message(rib, collector, message, is_watched=None, data=None):
    """
    Modify the RIB according to the BGP `message'.
    """
    default = list(default_route(message))
    if len(default) > 0:
        # XXX replace with a filter function
        # we ignore default routes
        return default, [], []

    conflicts = list(hijack(rib, message))
    if message.as_path is None or message.origin is None:
        routes = withdraw(rib, message)
    elif len(conflicts) > 0 \
            or is_watched is None or is_watched(message) is True:
        routes = route(rib, message, data)
    else:
        routes = []
    return default, routes, conflicts


def detect_conflicts(collector, files, opener=default_opener,
                     format=mabo_format, is_watched=None):
    """
    Get a list of conflicts (hijacks without annotation) from the BGP files
    (bviews and updates).

    :param collector: Name of the collector the files come from
    :param files: List of files to process
    :param opener: Function to use in order to open the files
    :param format: Format of the BGP data in the files
    :param is_watched: Function returning True if the BGP update must be followed
    :return: Generator of conflicts
    """
    rib = EmulatedRIB()
    queue = deque(files)

    # insert initial bview in the RIB
    bviews = []
    while len(queue):
        try:
            bview_file = queue.popleft()
            with opener(bview_file) as f:
                for data in f:
                    for msg in format(collector, data):
                        if msg.type != "F":
                            raise ValueError
                        if len(list(default_route(msg))) > 0:
                            logger.warning("got a default route %s", msg)
                            continue
                        if is_watched is None or is_watched(msg):
                            route(rib, msg, data)
        except ValueError:
            # this file is not a bview, stop right now
            queue.appendleft(bview_file)
            break
        else:
            bviews.append(bview_file)

    if len(bviews) == 0:
        raise ValueError("no bviews were loaded")

    # play all BGP updates to detect BGP conflicts
    for file in chain(bviews, queue):
        with opener(file) as f:
            for data in f:
                for msg in format(collector, data):
                    default, _, conflicts = process_message(
                        rib, collector, msg, is_watched)
                    if len(default) > 0:
                        logger.warning("got a default route %s", msg)
                    for conflict in conflicts:
                        yield conflict


def detect_hijacks(collector, files,
                   irr_org_file=None,
                   irr_mnt_file=None,
                   irr_ro_file=None,
                   rpki_roa_file=None,
                   opener=default_opener,
                   format=mabo_format, is_watched=None):
    """
    Detect BGP hijacks from `files' and annotate them using metadata.

    :param collector: Name of the collector the BGP files come from
    :param files: List of BGP files to process
    :param irr_org_file: CSV file containing irr,organisation,asn
    :param irr_mrt_file: CSV file containing irr,maintainer,asn
    :param irr_ro_file: CSV file containing irr,prefix,asn
    :param rpki_roa_file: CSV file containing asn,prefix,max_length,valid
    :param opener: Function to use in order to open the files
    :param format: Format of the BGP data in the files
    :return: Generator of hijacks (conflicts with annotation)
    """

    logger.info("loading metadata...")
    funcs = [annotate_if_direct]
    if irr_org_file is not None and irr_mnt_file is not None:
        relations_dict = dict()
        fill_relation_struct(irr_org_file, relations_dict,
                             "organisations")
        fill_relation_struct(irr_mnt_file, relations_dict, "maintainers")
        funcs.append(partial(annotate_if_relation, relations_dict))

    if irr_ro_file is not None:
        ro_rad_tree = Radix()
        fill_ro_struct(irr_ro_file, ro_rad_tree)
        funcs.append(partial(annotate_if_route_objects, ro_rad_tree))

    if rpki_roa_file is not None:
        roa_rad_tree = Radix()
        fill_roa_struct(rpki_roa_file, roa_rad_tree)
        funcs.append(partial(annotate_if_roa, roa_rad_tree))

    funcs.append(annotate_with_type)
    logger.info("starting hijacks detection...")
    for conflict in detect_conflicts(collector, files,
                                     opener=opener, format=format,
                                     is_watched=is_watched):
        for f in funcs:
            f(conflict)
        yield conflict
