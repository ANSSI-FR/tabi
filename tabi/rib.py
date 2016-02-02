# -*- coding: utf-8 -*-
# Copyright (C) 2016 ANSSI
# This file is part of the tabi project licensed under the MIT license.

from radix import Radix


class EmulatedRIB(object):
    """Emulated RIB using a Radix object."""

    def __init__(self):
        self.radix = Radix()
        self.peers = dict()

    def update(self, prefix, peer, value):
        """Update the information stored concerning a specific prefix."""
        peer_sym = self.peers.get(peer, None)
        if peer_sym is None:
            peer_sym = self.peers[peer] = peer
        node = self.radix.add(prefix)
        node.data[peer_sym] = value
        return node

    def lookup(self, prefix, peer):
        peer_sym = self.peers.get(peer, None)
        if peer_sym is not None:
            node = self.radix.search_exact(prefix)
            if node is not None:
                return node.data.get(peer_sym, None)

    def pop(self, prefix, peer):
        node = self.radix.search_exact(prefix)
        if node is not None:
            val = node.data.pop(peer, None)
            if len(node.data) == 0:
                self.radix.delete(prefix)
            return val

    def delete(self, prefix):
        return self.radix.delete(prefix)

    def search_all_containing(self, prefix):
        tmp_node = self.radix.search_covering(prefix)
        if tmp_node is None:
            return []
        return tmp_node

    def search_all_contained(self, prefix):
        tmp_node = self.radix.search_covered(prefix)
        if tmp_node is None:
            return []
        return tmp_node

    def search_exact(self, prefix):
        return self.radix.search_exact(prefix)

    def nodes(self):
        return self.radix.nodes()

    def prefixes(self):
        return self.radix.prefixes()
