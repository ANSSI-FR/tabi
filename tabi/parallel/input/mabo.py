# -*- coding: utf-8 -*-
# Copyright (C) 2016 ANSSI
# This file is part of the tabi project licensed under the MIT license.

import collections

import tabi.parallel.helpers
from tabi.parallel.core import InternalMessage


# Internal element
TableDumpV2Element = collections.namedtuple("TableDumpV2Element",
                                            ["asn",
                                             "as_path",
                                             "peer_as", "peer_ip"
                                             ])


class MaboTableDumpV2Document:
    """Abstract a Table Dump v2 document from mabo."""

    def __init__(self, collector, message):
        self.collector = collector
        self.message = message
        self.datatype = "F"

    def elements(self):
        """Parse the message and return a list of elements that
        will be used to build internal BGP messages.
        """

        extracted_elements = collections.OrderedDict()  # XXX: list !

        for entry in self.message.get("entries", []):

            as_path = entry.get("as_path", [])
            if len(as_path):
                # Extract AS origins from the AS PATH
                as_origins = tabi.parallel.helpers.get_as_origin(as_path)
            else:
                # Do not process empty AS PATH - aka data coming from an IGP
                continue

            # Build an element per AS origin
            for as_origin in as_origins:
                element = TableDumpV2Element(as_origin,
                                             entry.get("as_path", None),
                                             int(entry.get("peer_as", None)),
                                             entry.get("peer_ip", None))
                extracted_elements[element] = None

        return extracted_elements.keys()

    def timestamp(self):
        """Get the abtracted message timestamp."""
        return self.message["timestamp"]

    def withdraws(self):
        """Return abstracted withdraws, i.e an empty list."""

        return []

    def announces(self):
        """Return abstracted announces, i.e an empty list."""

        for element in self.elements():
            internal = InternalMessage(self.message["timestamp"],
                                       self.collector,
                                       element.peer_as,
                                       element.peer_ip,
                                       self.message["prefix"],
                                       element.asn,
                                       element.as_path)
            yield internal


class MaboUpdateDocument:
    """Abstract an UPDATE document from mabo."""

    def __init__(self, collector, message):
        self.collector = collector
        self.message = message
        self.datatype = "U"

    def get_as_origins(self):
        """Return the list of AS origins."""

        as_path = self.message.get("as_path", [])

        if len(as_path):
            # Extract AS origins from the AS PATH
            return tabi.parallel.helpers.get_as_origin(as_path)
        else:
            # Do not process empty AS PATH - aka data coming from an IGP
            return []

    def timestamp(self):
        """Get the abtracted message timestamp."""
        return self.message["timestamp"]

    def withdraws(self):
        """Return abstracted withdraws, i.e an empty list."""
        for prefix in self.message.get("withdraw", []):
            internal = InternalMessage(self.message["timestamp"],
                                       self.collector,
                                       int(self.message.get("peer_as", None)),
                                       self.message.get("peer_ip", None),
                                       prefix,
                                       None,
                                       None)
            yield internal

    def announces(self):
        """Return abstracted announces, i.e an empty list."""

        for prefix in self.message.get("announce", []):
            for asn in self.get_as_origins():
                internal = InternalMessage(self.message["timestamp"],
                                           self.collector,
                                           int(self.message.get("peer_as", None)),
                                           self.message.get("peer_ip", None),
                                           prefix,
                                           asn,
                                           self.message.get("as_path", None))
                yield internal
