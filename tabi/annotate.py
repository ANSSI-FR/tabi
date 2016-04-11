# -*- coding: utf-8 -*-
# Copyright (C) 2016 ANSSI
# This file is part of the tabi project licensed under the MIT license.

from csv import reader
from itertools import chain
from collections import defaultdict

from tabi.helpers import default_opener

fake_maintainers = ["RIPE-NCC-END-MNT", "AFRINIC-HM-MNT"]


def fill_relation_struct(input, relations_dicts, relation_type,
                         opener=default_opener):
    """
    Copy organisations or maintainers file into relations_dicts.

    relations_dict["organisations"][organisation] = set(asn)
    relations_dict["organisations_reverse"][asn] = set(organisations)
    relations_dict["maintainers"][maintainer] = set(asn)
    relations_dict["maintainers_reverse"][asn] = set(organisations)

    :param input: CSV file containing relations with columns:
        authority, maintainer, asn
    :param relations_dicts: empty dictionary are partly filled (by this method) relations_dict
    :param relation_type: 'organisations' or 'maintainers'
    :return: Nothing
    """
    direct = relations_dicts[relation_type] = relations_dicts.get(relation_type, defaultdict(set))
    reverse = relations_dicts["{}_reverse".format(relation_type)] = relations_dicts.get(
        "{}_reverse".format(relation_type), defaultdict(set))
    with opener(input) as relations_file:
        relations_reader = reader(relations_file, delimiter=',')
        for line in relations_reader:  # line : [authority, maintainer, asn]
            if line[1] in fake_maintainers:
                continue
            reverse[int(line[2])].add(line[1])
            direct[line[1]].add(int(line[2]))


def fill_ro_struct(input, rad_tree, opener=default_opener):
    """
    Copy routes file into rad_tree.

    :param input: CSV file containing route objects with columns:
        authority, prefix, asn
    :param rad_tree: Radix tree
    :return: Nothing
    """
    with opener(input) as ro_file:
        ro_reader = reader(ro_file, delimiter=',')
        for ro in ro_reader:  # ro : [authority, prefix, asn]
            new_node = rad_tree.add(ro[1])
            new_node.data[int(ro[2])] = new_node.data.get(int(ro[2]), set())
            new_node.data[int(ro[2])].add(ro[0])


def fill_roa_struct(input, rad_tree, opener=default_opener):
    """
    Copy roa file into rad_tree.

    Max lenght is stored in data[asn]

    :param input: CSV file containing roa entries with columns:
        asn, prefix, max_length, validity
    :param rad_tree: Radix tree
    :return: Nothing
    """
    with opener(input) as roa_file:
        roa_reader = reader(roa_file, delimiter=',')
        for roa in roa_reader:  # roa : [asn, prefix, max_length, validity]
            if roa[3].lower() == "true":
                asn = int(roa[0])
                new_node = rad_tree.add(roa[1])
                new_node.data[asn] = max(new_node.data.get(asn, 0), int(roa[2]))


def annotate_if_relation(relations_dicts, conflict):
    """
    Add "relation": list(relations) to conflict if ASes in conflict have the
    same organisations, maintainers or administrative contacts.

    :param conflict: conflict dictionary to annotate
    :param relations_dicts: dict from DetectBGPConflicts.fill_relation_struct
            relations_dicts["organisations"][organisation] = set(asn)
            relations_dicts["organisations_reverse"][asn] = set(organisations)
            relations_dicts["maintainers"][maintainer] = set(asn)
            relations_dicts["maintainers_reverse"][asn] = set(organisations)
            relations_dicts["contacts"][contact] = set(asn)
            relations_dicts["contacts_reverse"][asn] = set(contacts)
    :return: `conflict'
    """

    announce = conflict.get("announce", None)
    if announce is None:
        return conflict

    conflict_with = conflict.get("conflict_with", None)
    if conflict_with is None:
        return conflict

    as1 = announce["asn"]
    as2 = conflict_with["asn"]

    orgs = relations_dicts.get("organisations", {})
    orgs_reverse = relations_dicts.get("organisations_reverse", {})
    mnts_reverse = relations_dicts.get("maintainers_reverse", {})
    contacts_reverse = relations_dicts.get("contacts_reverse", {})

    as1_org = orgs_reverse.get(as1, None)
    as2_org = orgs_reverse.get(as2, None)

    if as1_org is not None and as2_org is not None:
        if as1_org & as2_org:
            conflict["relation"] = conflict.get("relation", list())
            conflict["relation"].append("org")

    as1_siblings = {as1}
    if as1_org is not None:
        as1_siblings.update(chain.from_iterable([orgs.get(org, list())
                                                 for org in as1_org]))
    as2_siblings = {as2}
    if as2_org is not None:
        as2_siblings.update(chain.from_iterable([orgs.get(org, list())
                                                 for org in as2_org]))

    as1_contacts = set()
    for asn in as1_siblings:
        as1_contacts.update(contacts_reverse.get(asn, set()))

    as2_contacts = set()
    for asn in as2_siblings:
        as2_contacts.update(contacts_reverse.get(asn, set()))

    if as1_contacts & as2_contacts:
        conflict["relation"] = conflict.get("relation", list())
        conflict["relation"].append("contact")

    as1_mnts = set()
    for asn in as1_siblings:
        as1_mnts.update(mnts_reverse.get(asn, set()))

    as2_mnts = set()
    for asn in as2_siblings:
        as2_mnts.update(mnts_reverse.get(asn, set()))

    if as1_mnts & as2_mnts:
        conflict["relation"] = conflict.get("relation", list())
        conflict["relation"].append("mnt")

    return conflict


def annotate_if_roa(roa_rad_tree, conflict):
    announce = conflict.get("announce", None)
    if announce is None:
        return conflict
    conflict_with = conflict.get("conflict_with", None)
    if conflict_with is None:
        return conflict
    annotate_roa_announce(announce, roa_rad_tree)
    annotate_roa_announce(conflict_with, roa_rad_tree)
    return conflict


def annotate_if_route_objects(ro_rad_tree, conflict):
    """
    Check the `conflict' for valid route objects from the "announce" and
    "conflict_with" fields.

    :param conflict: conflict dictionnary to annotate
    :param ro_rad_tree: radix tree containing route objects, AS nb in data["asn"]
    :return: `conflict'
    """

    announce = conflict.get("announce", None)
    if announce is None:
        return conflict
    conflict_with = conflict.get("conflict_with", None)
    if conflict_with is None:
        return conflict
    annotate_route_announce(announce, ro_rad_tree)
    annotate_route_announce(conflict_with, ro_rad_tree)
    return conflict


def annotate_route_announce(announce, ro_rad_tree):
    """
    Add a list of IRR containing valid route objects for this `announce' in "valid".

    :param announce: dictionary to annotate containing "asn" and "prefix" fields
    :param ro_rad_tree: radix tree containing route objects, AS nb in data["asn"]
    :return: `announce'
    """
    prefix = announce["prefix"]
    asn = announce["asn"]
    ro_declared = ro_rad_tree.search_covering(prefix)

    valid = set(announce.get("valid", set()))
    for node in ro_declared:
        bases = node.data.get(asn, None)
        if bases is not None:
            valid.update(bases)
    if len(valid) > 0:
        announce["valid"] = list(valid)
    return announce


def annotate_roa_announce(announce, roa_rad_tree):
    """
    Add "roa" in the "valid" field of `announce' if it is covered by a valid ROA.

    :param announce: dictionary to annotate containing "asn" and "prefix" fields
    :param roa_rad_tree: radix tree containing ROA
    :return: `announce'
    """
    prefix = announce["prefix"]
    asn = announce["asn"]
    roa_declared = roa_rad_tree.search_covering(prefix)
    for node in roa_declared:
        if asn in node.data and int(prefix.split("/")[1]) <= node.data[asn]:
            announce["valid"] = announce.get("valid", list())
            announce["valid"].append("roa")
            break
    return announce


def canonical_as_path(as_path):
    """
    Transform an AS_PATH from a string to a list without prepending and
    handling correctly AS_SETs.
    """
    new_as_path = []
    segments = as_path.split()
    for i, segment in enumerate(segments):
        if not segment.startswith("{"):
            asn = int(segment)
            if len(new_as_path) == 0 or new_as_path[-1][0] != asn:
                new_as_path.append([asn])
        else:
            if i == 0:
                raise ValueError("as set in the first segment is illegal")
            as_set = {int(asn) for asn in segment[1:-1].split(",")}
            new_as_path.append(list(as_set))
    return new_as_path


def annotate_if_direct(conflict):
    """
    Add "direct": False to `conflict' if "as_path" from `conflict'
    contains the other AS or True if it is directly connected to it

    :param conflict: conflict dictionary to annotate
    :return: `conflict'
    """

    announce = conflict.get("announce", None)
    if announce is None:
        return conflict

    conflict_with = conflict.get("conflict_with", None)
    if conflict_with is None:
        return conflict

    as_path = announce["as_path"]
    asn = conflict_with["asn"]
    ases = canonical_as_path(as_path)
    if len(ases) > 1 and asn in ases[-2]:
        conflict["direct"] = True
    elif len(ases) > 2 and asn in chain.from_iterable(ases[:-2]):
        conflict["direct"] = False
    return conflict


def annotate_with_type(conflict):
    """
    Annotate conflict with VALID/RELATION/DIRECT/NODIRECT/ABNORMAL depending on
    previous annotations.

    :param conflict: one line of output from `detect_conflicts' task
    :return: `conflict'
    """
    announce = conflict.get("announce", None)
    if announce is None:
        announce = conflict["conflict_with"]

    if "valid" in announce:
        conflict["type"] = "VALID"
    elif "relation" in conflict:
        conflict["type"] = "RELATION"
    elif "direct" in conflict:
        if conflict["direct"]:
            conflict["type"] = "DIRECT"
        else:
            conflict["type"] = "NODIRECT"
    else:
        conflict["type"] = "ABNORMAL"
    return conflict


def annotate_directly_with_type(conflict, relations_dict, ro_rad_tree,
                                roa_rad_tree):
    annotate_if_route_objects(ro_rad_tree, conflict)
    annotate_if_roa(roa_rad_tree, conflict)
    annotate_if_relation(relations_dict, conflict)
    annotate_if_direct(conflict)
    annotate_with_type(conflict)
    return conflict
