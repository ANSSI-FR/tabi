# -*- coding: utf-8 -*-
# Copyright (C) 2016 ANSSI
# This file is part of the tabi project licensed under the MIT license.

import collections
import json
import radix


InternalMessage = collections.namedtuple("InternalMessage",
                                         ["timestamp",
                                          "collector",
                                          "peer_as", "peer_ip",
                                          "prefix", "asn",
                                          "as_path"
                                          ])


RouteInformation = collections.namedtuple("RouteInformation",
                                          ["origin_asn",
                                           "peer_as",
                                           "peer_ip"
                                           ])
HijackInformation = collections.namedtuple("HijackInformation",
                                           ["origin_asn",
                                            "hijacker_asn",
                                            "peer_as",
                                            "peer_ip"
                                            ])


class DefaultRoute:
    """Object that handles the processing of UPDATEs containing
    the default prefixes.
    """

    def process(self, update):
        """Process a default route, i.e. return a message or do nothing."""

        if update.prefix == "0.0.0.0/0" or update.prefix == "::/0":
            return [self.message(update)]
        else:
            return []

    def message(self, update):
        """Prepare and return an ordered dictionary, that could
        be logged or manipulated.
        """

        u = update
        tmp_announce = collections.OrderedDict([("prefix", u.prefix),
                                                ("asn", u.asn),
                                                ("as_path", u.as_path)])
        default_info = collections.OrderedDict([("timestamp", u.timestamp),
                                                ("collector", u.collector),
                                                ("peer_as", u.peer_as),
                                                ("peer_ip", u.peer_ip),
                                                ("announce", tmp_announce)])
        return default_info


class Route:
    """Object that handles the processing of UPDATEs."""

    def __init__(self, rib):
        self.rib = rib

    def process(self, update):
        """Process a regular prefix annoucement."""

        # Update the RIB with this route information
        route_info = RouteInformation(update.asn, update.peer_as,
                                      update.peer_ip)
        self.rib.update(update.prefix, route_info, "routes_information")

        return [self.message(update)]

    def message(self, update):
        """Prepare and return an ordered dictionary, that could be
        logged or manipulated.
        """

        u = update
        route_info = collections.OrderedDict([("timestamp", u.timestamp),
                                              ("collector", u.collector),
                                              ("peer_as", u.peer_as),
                                              ("peer_ip", u.peer_ip),
                                              ("action", "A"),
                                              ("prefix", u.prefix),
                                              ("as_path", u.as_path),
                                              ("asn", u.asn)])

        return route_info


class Hijack:
    """Object that handles the processing of UPDATEs in conflict."""

    def __init__(self, rib, datatype):
        self.rib = rib
        self.datatype = datatype

    def process(self, update):
        """Process a possible conflicting annoucement."""

        # List that holds the messages that will be returned
        messages = []

        # Same prefix & more specific hijacks
        for node in self.rib.search_all_containing(update.prefix):

            tmp_origin_asn = map(lambda (asn, y, z): asn,
                                 node.data.get("routes_information", []))
            for origin_asn in set(tmp_origin_asn):

                # An AS can't hijack itself
                if origin_asn == update.asn:
                    continue

                # Store the hijacks information
                hijack_info = HijackInformation(origin_asn, update.asn,
                                                update.peer_as, update.peer_ip)
                self.rib.update(update.prefix, hijack_info,
                                "hijacks_information")

                messages += [self.message(update, node.prefix, origin_asn)]

        return messages

    def message(self, update, conflict_prefix, conflict_asn):
        """Prepare and return an ordered dictionary, that could be
        logged or manipulated.
        """

        u = update
        tmp_conflict_with = collections.OrderedDict([("prefix",
                                                      conflict_prefix),
                                                     ("asn", conflict_asn)])

        tmp_announce = collections.OrderedDict([("prefix", u.prefix),
                                                ("asn", u.asn),
                                                ("as_path", u.as_path)])

        hijack_info = collections.OrderedDict([("timestamp", u.timestamp),
                                               ("collector", u.collector),
                                               ("peer_as", u.peer_as),
                                               ("peer_ip", u.peer_ip),
                                               ("type", self.datatype),
                                               ("announce", tmp_announce),
                                               ("conflict_with",
                                                tmp_conflict_with),
                                               ("asn", conflict_asn)])

        return hijack_info


class Withdraw:
    """Object that handles the processing of WITHDRAWs."""

    def __init__(self, rib, datatype="W"):
        self.rib = rib
        self.datatype = datatype

    def process(self, withdraw):
        """Process a regular prefix withdrawal."""

        # Lists that holds the messages that will be returned
        route_messages = []
        hijack_messages = []

        # Withdrawal of routes & hijacks
        node = self.rib.search_exact(withdraw.prefix)
        if node:
            route_messages += self.perform_withdraw(node,
                                                    "routes_information",
                                                    withdraw)
            hijack_messages += self.perform_withdraw(node,
                                                     "hijacks_information",
                                                     withdraw)

        # Finally delete the node if there is no associated data
        if node and not len(node.data.keys()):
            self.rib.delete(withdraw.prefix)

        return route_messages, hijack_messages

    def perform_withdraw(self, node, information_key, withdraw):
        """Remove an information key from the radix tree."""

        # Return messages
        messages = []

        # Store the informations that will be removed
        to_be_removed = collections.OrderedDict()

        for information in node.data.get(information_key, []):
            # Retrieve the AS number and log the message
            information_tuple = (information.peer_as, information.peer_ip)
            withdraw_tuple = (withdraw.peer_as, withdraw.peer_ip)
            if information_tuple == withdraw_tuple:

                # Store the route that will be removed
                to_be_removed[information] = None

                # Log the WITHDRAW
                messages += [self.message(withdraw, information)]

        # Remove the information
        for information in to_be_removed.keys():
            del(node.data[information_key][information])
        if len(node.data.get(information_key, [None])) == 0:
            del(node.data[information_key])

        return messages

    def message(self, withdraw, information):
        """Prepare and return an ordered dictionary, that could be logged
        or manipulated.
        """

        withdraw_info = []

        if isinstance(information, RouteInformation):
            w = withdraw
            ordererdict_data = [("timestamp", w.timestamp),
                                ("collector", w.collector),
                                ("peer_as", w.peer_as),
                                ("peer_ip", w.peer_ip),
                                ("action", self.datatype),
                                ("prefix", w.prefix),
                                ("asn", information.origin_asn)]
            withdraw_info = collections.OrderedDict(ordererdict_data)

        elif isinstance(information, HijackInformation):
            w = withdraw
            tmp_withdraw = collections.OrderedDict([("prefix", w.prefix),
                                                    ("asn",
                                                     information.hijacker_asn)
                                                    ])
            ordererdict_data = [("timestamp", w.timestamp),
                                ("collector", w.collector),
                                ("peer_as", w.peer_as),
                                ("peer_ip", w.peer_ip),
                                ("type", self.datatype),
                                ("withdraw", tmp_withdraw),
                                # XXX: must add confict_with to
                                # known which (prefix, asn)
                                # tuple is concerned
                                ("asn", information.origin_asn)]

            withdraw_info = collections.OrderedDict(ordererdict_data)

        return withdraw_info


def process_message(rib, message, keep_asn=lambda asn: True):
    # XXX: - access_time could be an internal function wrapping time.time()
    #      - OR access_time could be set with the message timestamp, if older
    #      than 8 hours, delete it, or check with the date of the last bview...
    #      - OR count the number of processes bview !
    """Parse abstracted BGP messages."""

    # Lists that holds the messages that will be returned
    default_messages = []
    route_messages = []
    hijack_messages = []

    # Instanciate objects that process abstracted BGP messages
    default_route = DefaultRoute()
    route = Route(rib)
    hijack = Hijack(rib, message.datatype)
    withdraw = Withdraw(rib)

    # Process WITHDRAW messages
    for update in message.withdraws():
        withdraw_routes, withdraw_hijacks = withdraw.process(update)
        route_messages += withdraw_routes
        hijack_messages += withdraw_hijacks

    # Process UPDATE messages
    for update in message.announces():
        # Default routes are processed separately, then skipped.
        # If inserted in the radix tree, they will be in conflict
        # with every prefix !

        if update.prefix == "0.0.0.0/0" or update.prefix == "::/0":
            # Process the default prefix
            default_messages += default_route.process(update)

            # Always skip a default
            continue

        elif keep_asn(update.asn):
            # Process the UPDATE if the corresponding ASN is monitored
            route_messages += route.process(update)

        # Detect if the UPDATE is in conflict
        for message in hijack.process(update):
            if keep_asn(message["asn"]):
                hijack_messages += [message]

    return default_messages, route_messages, hijack_messages


def bview_fake_withdraw(rib, collector_id, current_time, timestamp):
    """Function that fakes withdraw if RIB elements where not
    modified by a bview.
    """

    # List prefixes that need to be withdrawn
    to_withdraw = set()
    # Enumerate all nodes in the RIB
    for node in rib.nodes():
        # Get all keys
        for key in node.data.keys():
            # Remember elements that were not "recently" accessed.
            for information_key, access_time in node.data[key].iteritems():
                if access_time < current_time:
                    to_withdraw.add((node.prefix, information_key))

    # Really withdraw messages
    withdraw = Withdraw(rib, datatype="FW")

    route_messages = []
    hijack_messages = []

    for prefix, information_key in to_withdraw:
        # Prepare a fake iternal message
        internal = InternalMessage(timestamp,
                                   collector_id,
                                   information_key.peer_as,
                                   information_key.peer_ip,
                                   prefix,
                                   None,
                                   None)
        withdraw_routes, withdraw_hijacks = withdraw.process(internal)
        route_messages += withdraw_routes
        hijack_messages += withdraw_hijacks

    return route_messages, hijack_messages
