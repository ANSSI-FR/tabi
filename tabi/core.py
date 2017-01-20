# -*- coding: utf-8 -*-
# Copyright (C) 2016 ANSSI
# This file is part of the tabi project licensed under the MIT license.

import logging

from itertools import chain
from collections import namedtuple, OrderedDict

logger = logging.getLogger(__name__)

InternalMessage = namedtuple("InternalMessage",
                             ["type",
                              "timestamp",
                              "collector",
                              "peer_as", "peer_ip",
                              "prefix", "origin",
                              "as_path"
                              ])


PeerInformation = namedtuple("PeerInformation",
                             ["peer_as", "peer_ip"])
RouteInformation = namedtuple("RouteInformation",
                              ["origin", "data"])


def iter_origin(origin):
    """
    Return a list of ASN according to `origin'.
    """
    if isinstance(origin, int):
        yield origin
    elif origin is not None:
        for asn in origin:
            yield asn


def default_route(update):
    """Function that handles the processing of UPDATEs containing
    the default prefixes (where mask length is lower than 8 bits).
    """

    try:
        _, masklen = update.prefix.split("/")
        if int(masklen) < 8:
            for asn in iter_origin(update.origin):
                tmp_announce = OrderedDict([("prefix", update.prefix),
                                            ("asn", asn),
                                            ("as_path", update.as_path)])
                default_info = OrderedDict([("timestamp", update.timestamp),
                                            ("collector", update.collector),
                                            ("peer_as", update.peer_as),
                                            ("peer_ip", update.peer_ip),
                                            ("announce", tmp_announce)])
                yield default_info
    except ValueError:
        pass


def format_route(update, num_routes):
    for asn in iter_origin(update.origin):
        yield OrderedDict([("timestamp", update.timestamp),
                           ("collector", update.collector),
                           ("peer_as", update.peer_as),
                           ("peer_ip", update.peer_ip),
                           ("type", update.type),
                           ("prefix", update.prefix),
                           ("as_path", update.as_path),
                           ("asn", asn),
                           ("num_routes", num_routes)])


def route(rib, update, data=None):
    """Function that handles the processing of UPDATEs."""

    # Update the RIB with this route information
    peer_info = PeerInformation(update.peer_as, update.peer_ip)
    route_info = RouteInformation(update.origin, data)
    node = rib.update(update.prefix, peer_info, route_info)
    return format_route(update, len(node.data))


def format_hijack(update, origin, conflict_prefix, conflict_asn):
    """Prepare and return an ordered dictionary, that could be
    logged or manipulated.
    """

    tmp_conflict_with = OrderedDict([("prefix", conflict_prefix),
                                     ("asn", conflict_asn)])

    for asn in iter_origin(origin):
        if update.as_path is None:
            announce_key = "withdraw"
            tmp_announce = OrderedDict([("type", update.type),
                                        ("prefix", update.prefix),
                                        ("asn", asn)])
        else:
            announce_key = "announce"
            tmp_announce = OrderedDict([("type", update.type),
                                        ("prefix", update.prefix),
                                        ("asn", asn),
                                        ("as_path", update.as_path)])

        yield OrderedDict([("timestamp", update.timestamp),
                           ("collector", update.collector),
                           ("peer_as", update.peer_as),
                           ("peer_ip", update.peer_ip),
                           (announce_key, tmp_announce),
                           ("conflict_with", tmp_conflict_with),
                           ("asn", conflict_asn)])


def same_origin(origin1, origin2):
    """
    Return True if these two origins have at least one common ASN.
    """
    if isinstance(origin1, int):
        if isinstance(origin2, int):
            return origin1 == origin2
        return origin1 in origin2
    if isinstance(origin2, int):
        return origin2 in origin1
    return len(origin1.intersection(origin2)) > 0


def hijack(rib, update):
    """Function that handles the processing of UPDATEs and WITHDRAWs in conflict."""

    # List that holds the messages that will be returned
    messages = []

    # Same prefix (first) then less specific hijacks
    origin = update.origin
    for node in rib.search_all_containing(update.prefix):
        if origin is None:
            # if we process a withdraw, we do not know the originating ASN
            # instead we get it from RouteInformation stored in the RIB
            # as it should always be in the first Radix node returned by
            # search_all_containing.
            ri = node.data.get(PeerInformation(update.peer_as, update.peer_ip))
            if ri is None:
                # if we don't find the originating ASN we cannot process
                # further
                return []
            origin = ri.origin

        # Find conflicting ASN origin
        tmp_origins = set()
        for ri_origin, _ in node.data.itervalues():
            if not same_origin(origin, ri_origin):
                tmp_origins.update(iter_origin(ri_origin))

        for asn in tmp_origins:
            messages.append(format_hijack(update, origin, node.prefix, asn))

    return chain.from_iterable(messages)


def format_withdraw(withdraw, origin, num_routes):
    for asn in iter_origin(origin):
        yield OrderedDict([("timestamp", withdraw.timestamp),
                           ("collector", withdraw.collector),
                           ("peer_as", withdraw.peer_as),
                           ("peer_ip", withdraw.peer_ip),
                           ("type", withdraw.type),
                           ("prefix", withdraw.prefix),
                           ("asn", asn),
                           ("num_routes", num_routes)])


def withdraw(rib, withdraw):
    """Function that handles the processing of WITHDRAWs."""

    # Withdrawal of routes
    peer_info = PeerInformation(withdraw.peer_as, withdraw.peer_ip)

    node = rib.search_exact(withdraw.prefix)
    if node is not None:
        ri = node.data.pop(peer_info, None)
        num_routes = len(node.data)
        if num_routes == 0:
            rib.delete(withdraw.prefix)
        if ri is not None:
            return format_withdraw(withdraw, ri.origin, num_routes)
    return []
