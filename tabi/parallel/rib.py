 # -*- coding: utf-8 -*-
# Copyright (C) 2016 ANSSI
# This file is part of the tabi project licensed under the MIT license.

import radix
import time
import collections


class EmulatedRIB(object):
    """Emulated RIB using a Radix object."""

    def __init__(self):
        self.radix = radix.Radix()
        self.access_time = time.time()

    def set_access_time(self, access_time):
        """Set the new access time."""
        self.access_time = access_time

    def update_data(self, node, value, information_key):
        """Update the information stored in a radix node."""

        if not node.data.get(information_key, None):
            # The node was created

            # The OrderedDict() keeps a consistent order and
            # helps comparing results.
            node.data[information_key] = collections.OrderedDict()

        # The node already exist
        node.data[information_key][value] = self.access_time

    def update(self, prefix, value, information_key):
        """Update the information stored concerning a specific prefix."""

        # Check if the entry exists
        node = self.radix.add(prefix)
        if node:
            self.update_data(node, value, information_key)

    def delete(self, prefix):
        self.radix.delete(prefix)

    def search_all_containing(self, prefix):
        tmp_node = self.radix.search_covering(prefix)
        if tmp_node is None:
            return []
        else:
            return tmp_node

    def search_exact(self, prefix):
        tmp_node = self.radix.search_exact(prefix)
        return tmp_node

    def nodes(self):
        return self.radix.nodes()

    def prefixes(self):
        return self.radix.prefixes()
