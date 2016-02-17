# -*- coding: utf-8 -*-
import os

from radix import Radix
from collections import defaultdict

from tabi.annotate import fill_relation_struct, fill_ro_struct, \
    fill_roa_struct
from tabi.annotate import annotate_if_roa, annotate_if_route_objects, annotate_if_direct, annotate_if_relation
from tabi.annotate import annotate_with_type

PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resources")


def test_fill_ro_struct():
    file = os.path.join(PATH, "conflict_annotation", "inputs", "ro_file")
    rad_tree = Radix()
    fill_ro_struct(file, rad_tree)
    res = list()
    for node in rad_tree:
        res.append((node.prefix, node.data))
    assert res == [('60.136.0.0/16', {17676: {'jpnic'}}), ('60.145.0.0/16', {17676: {'jpnic'}}),
                   ('60.145.0.0/24', {17676: {'jpnic'}}), ('192.0.0.0/16', {17: {'jpnic'}})]


def test_fill_roa_struct():
    file = os.path.join(PATH, "conflict_annotation", "inputs", "roa_file")
    rad_tree = Radix()
    fill_roa_struct(file, rad_tree)
    res = list()
    for node in rad_tree:
        res.append((node.prefix, node.data))
    assert res == [('86.63.224.0/19', {35238: 19}),
                   ('91.91.0.0/16', {35238: 16}),
                   ('192.113.0.0/16', {16074: 16}),
                   ('194.209.159.0/24', {16079: 32}),
                   ('212.234.194.0/24', {16071: 28, 16072: 24})]


def test_fill_relation_struct():
    file = os.path.join(PATH, "conflict_annotation", "inputs", "maintainers_file")
    relations_dict = defaultdict(set)
    fill_relation_struct(file, relations_dict, "maintainers")
    assert relations_dict == {"maintainers": {'AFRINIC-FAKE': {37554, 202214}},
                              "maintainers_reverse": {37554: {'AFRINIC-FAKE'}, 202214: {'AFRINIC-FAKE'}}}
    file = os.path.join(PATH, "conflict_annotation", "inputs", "organisations_file")
    relations_dict = defaultdict(set)
    fill_relation_struct(file, relations_dict, "organisations")
    assert relations_dict == {"organisations_reverse": {30896: {'ORG-ACL2-AFRINIC', 'ORG-ACL1-AFRINIC'},
                                                        21242: {'ORG-AC5-AFRINIC'},
                                                        37572: {'ORG-ACFC1-AFRINIC'},
                                                        17676: {'FAKE'}, 9737: {'FAKE'}},
                              "organisations": {'ORG-ACL2-AFRINIC': {30896}, 'ORG-ACL1-AFRINIC': {30896},
                                                'ORG-AC5-AFRINIC': {21242}, 'ORG-ACFC1-AFRINIC': {37572},
                                                'FAKE': {17676, 9737}}}
    file = os.path.join(PATH, "conflict_annotation", "inputs", "maintainers_file")
    fill_relation_struct(file, relations_dict, "maintainers")
    assert relations_dict == {"maintainers": {'AFRINIC-FAKE': {37554, 202214}},
                              "maintainers_reverse": {37554: {'AFRINIC-FAKE'}, 202214: {'AFRINIC-FAKE'}},
                              "organisations_reverse": {30896: {'ORG-ACL2-AFRINIC', 'ORG-ACL1-AFRINIC'},
                                                        21242: {'ORG-AC5-AFRINIC'},
                                                        37572: {'ORG-ACFC1-AFRINIC'},
                                                        17676: {'FAKE'}, 9737: {'FAKE'}},
                              "organisations": {'ORG-ACL2-AFRINIC': {30896}, 'ORG-ACL1-AFRINIC': {30896},
                                                'ORG-AC5-AFRINIC': {21242}, 'ORG-ACFC1-AFRINIC': {37572},
                                                'FAKE': {17676, 9737}}}


def test_annotate_if_valid_ok():
    file = os.path.join(PATH, "conflict_annotation", "inputs", "ro_file")
    ro_rad_tree = Radix()
    fill_ro_struct(file, ro_rad_tree)
    input_dict = {"timestamp": 1445817600.0,
                  "collector": "rrc01",
                  "peer_as": 13030,
                  "peer_ip": "195.66.224.175",
                  "type": "F",
                  "announce": {"prefix": "60.145.0.0/28",
                               "asn": 17676,
                               "as_path": "13030 3491 4651 9737 23969"},
                  "conflict_with": {"prefix": "1.0.128.0/17",
                                    "asn": 9737},
                  "asn": 9737}
    expected = {"timestamp": 1445817600.0,
                "collector": "rrc01",
                "peer_as": 13030,
                "peer_ip": "195.66.224.175",
                "type": "F",
                "announce": {"prefix": "60.145.0.0/28",
                             "asn": 17676, "valid": ['jpnic'],
                             "as_path": "13030 3491 4651 9737 23969"},
                "conflict_with": {"prefix": "1.0.128.0/17",
                                  "asn": 9737},
                "asn": 9737}
    annotate_if_route_objects(ro_rad_tree, input_dict)
    assert input_dict == expected


def test_annotate_if_valid_rpki_ok1():
    file = os.path.join(PATH, "conflict_annotation", "inputs", "roa_file")
    rpki_rad_tree = Radix()
    fill_roa_struct(file, rpki_rad_tree)
    input_dict = {"timestamp": 1445817600.0,
                  "collector": "rrc01",
                  "peer_as": 13030,
                  "peer_ip": "195.66.224.175",
                  "type": "F",
                  "announce": {"prefix": "212.234.194.0/24",
                               "asn": 16071,
                               "as_path": "13030 3491 4651 9737 23969"},
                  "conflict_with": {"prefix": "212.234.194.0/24",
                                    "asn": 16072},
                  "asn": 16072}
    expected = {"timestamp": 1445817600.0,
                "collector": "rrc01",
                "peer_as": 13030,
                "peer_ip": "195.66.224.175",
                "type": "F",
                "announce": {"prefix": "212.234.194.0/24",
                             "asn": 16071, "valid": ["roa"],
                             "as_path": "13030 3491 4651 9737 23969"},
                "conflict_with": {"prefix": "212.234.194.0/24",
                                  "asn": 16072, "valid": ["roa"]},
                "asn": 16072}
    annotate_if_roa(rpki_rad_tree, input_dict)
    assert input_dict == expected


def test_annotate_if_valid_rpki_ok2():
    file = os.path.join(PATH, "conflict_annotation", "inputs", "roa_file")
    rpki_rad_tree = Radix()
    fill_roa_struct(file, rpki_rad_tree)
    input_dict = {"timestamp": 1445817600.0,
                  "collector": "rrc01",
                  "peer_as": 13030,
                  "peer_ip": "195.66.224.175",
                  "type": "F",
                  "announce": {"prefix": "212.234.194.0/24",
                               "asn": 16070,
                               "as_path": "13030 3491 4651 9737 23969"},
                  "conflict_with": {"prefix": "212.234.194.0/24",
                                    "asn": 16072},
                  "asn": 16072}
    expected = {"timestamp": 1445817600.0,
                "collector": "rrc01",
                "peer_as": 13030,
                "peer_ip": "195.66.224.175",
                "type": "F",
                "announce": {"prefix": "212.234.194.0/24",
                             "asn": 16070,
                             "as_path": "13030 3491 4651 9737 23969"},
                "conflict_with": {"prefix": "212.234.194.0/24",
                                  "asn": 16072, "valid": ["roa"]},
                "asn": 16072}
    annotate_if_roa(rpki_rad_tree, input_dict)
    assert input_dict == expected


def test_annotate_if_valid_conflict_with():
    file = os.path.join(PATH, "conflict_annotation", "inputs", "ro_file")
    ro_rad_tree = Radix()
    fill_ro_struct(file, ro_rad_tree)
    input_dict = {"timestamp": 1445817600.0,
                  "collector": "rrc01",
                  "peer_as": 13030,
                  "peer_ip": "195.66.224.175",
                  "type": "F",
                  "announce": {"prefix": "1.0.128.0/17",
                               "asn": 9737,
                               "as_path": "13030 3491 4651 9737 23969"},
                  "conflict_with": {"prefix": "60.145.0.0/28",
                                    "asn": 17676},
                  "asn": 17676}
    expected = {"timestamp": 1445817600.0,
                "collector": "rrc01",
                "peer_as": 13030,
                "peer_ip": "195.66.224.175",
                "type": "F",
                "announce": {"prefix": "1.0.128.0/17",
                             "asn": 9737,
                             "as_path": "13030 3491 4651 9737 23969"},
                "conflict_with": {"prefix": "60.145.0.0/28",
                                  "asn": 17676, "valid": ['jpnic']},
                "asn": 17676}
    annotate_if_route_objects(ro_rad_tree, input_dict)
    assert input_dict == expected


def test_annotate_if_valid_both():
    file = os.path.join(PATH, "conflict_annotation", "inputs", "ro_file")
    ro_rad_tree = Radix()
    fill_ro_struct(file, ro_rad_tree)
    input_dict = {"timestamp": 1445817600.0,
                  "collector": "rrc01",
                  "peer_as": 13030,
                  "peer_ip": "195.66.224.175",
                  "type": "F",
                  "announce": {"prefix": "60.145.0.0/28",
                               "asn": 17676,
                               "as_path": "13030 3491 4651 9737 23969"},
                  "conflict_with": {"prefix": "192.0.0.0",
                                    "asn": 17},
                  "asn": 17676}
    expected = {"timestamp": 1445817600.0,
                "collector": "rrc01",
                "peer_as": 13030,
                "peer_ip": "195.66.224.175",
                "type": "F",
                "announce": {"prefix": "60.145.0.0/28",
                             "asn": 17676, "valid": ['jpnic'],
                             "as_path": "13030 3491 4651 9737 23969"},
                "conflict_with": {"prefix": "192.0.0.0",
                                  "asn": 17, "valid": ['jpnic']},
                "asn": 17676}
    annotate_if_route_objects(ro_rad_tree, input_dict)
    assert input_dict == expected


def test_annotate_if_valid_ko():
    file = os.path.join(PATH, "conflict_annotation", "inputs", "ro_file")
    ro_rad_tree = Radix()
    fill_ro_struct(file, ro_rad_tree)
    input_dict = {"timestamp": 1445817600.0,
                  "collector": "rrc01",
                  "peer_as": 13030,
                  "peer_ip": "195.66.224.175",
                  "type": "F",
                  "announce": {"prefix": "60.145.0.0/28",
                               "asn": 202214,
                               "as_path": "13030 3491 4651 9737 23969"},
                  "conflict_with": {"prefix": "1.0.128.0/17",
                                    "asn": 9737},
                  "asn": 9737}
    expected = {"timestamp": 1445817600.0,
                "collector": "rrc01",
                "peer_as": 13030,
                "peer_ip": "195.66.224.175",
                "type": "F",
                "announce": {"prefix": "60.145.0.0/28",
                             "asn": 202214,
                             "as_path": "13030 3491 4651 9737 23969"},
                "conflict_with": {"prefix": "1.0.128.0/17",
                                  "asn": 9737},
                "asn": 9737}
    annotate_if_route_objects(ro_rad_tree, input_dict)
    assert input_dict == expected


def test_annotate_if_relation_ok():
    relations_dict = defaultdict(set)
    file = os.path.join(PATH, "conflict_annotation", "inputs", "maintainers_file")
    fill_relation_struct(file, relations_dict, "maintainers")
    file = os.path.join(PATH, "conflict_annotation", "inputs", "organisations_file")
    fill_relation_struct(file, relations_dict, "organisations")
    input_dict = {"timestamp": 1445817600.0,
                  "collector": "rrc01",
                  "peer_as": 13030,
                  "peer_ip": "195.66.224.175",
                  "type": "F",
                  "announce": {"prefix": "60.145.0.0/28",
                               "asn": 37554,
                               "as_path": "13030 3491 4651 9737 23969"},
                  "conflict_with": {"prefix": "1.0.128.0/17",
                                    "asn": 12322},
                  "asn": 12322}
    annotate_if_relation(relations_dict, input_dict)
    expected = {"timestamp": 1445817600.0,
                "collector": "rrc01",
                "peer_as": 13030,
                "peer_ip": "195.66.224.175",
                "type": "F",
                "announce": {"prefix": "60.145.0.0/28",
                             "asn": 37554,
                             "as_path": "13030 3491 4651 9737 23969"},
                "conflict_with": {"prefix": "1.0.128.0/17",
                                  "asn": 12322},
                "asn": 12322}
    assert input_dict == expected
    input_dict = {"timestamp": 1445817600.0,
                  "collector": "rrc01",
                  "peer_as": 13030,
                  "peer_ip": "195.66.224.175",
                  "type": "F",
                  "announce": {"prefix": "60.145.0.0/28",
                               "asn": 37554,
                               "as_path": "13030 3491 4651 9737 23969"},
                  "conflict_with": {"prefix": "1.0.128.0/17",
                                    "asn": 202214},
                  "asn": 202214}
    annotate_if_relation(relations_dict, input_dict)
    expected = {"timestamp": 1445817600.0,
                "collector": "rrc01",
                "peer_as": 13030,
                "peer_ip": "195.66.224.175",
                "type": "F",
                "announce": {"prefix": "60.145.0.0/28",
                             "asn": 37554,
                             "as_path": "13030 3491 4651 9737 23969"},
                "conflict_with": {"prefix": "1.0.128.0/17",
                                  "asn": 202214},
                "asn": 202214,
                "relation": ["mnt"]}
    assert input_dict == expected


def test_annotate_if_relation_ko():
    relations_dict = defaultdict(set)
    file = os.path.join(PATH, "conflict_annotation", "inputs", "maintainers_file")
    fill_relation_struct(file, relations_dict, "maintainers")
    file = os.path.join(PATH, "conflict_annotation", "inputs", "organisations_file")
    fill_relation_struct(file, relations_dict, "organisations")
    input_dict = {"timestamp": 1445817600.0,
                  "collector": "rrc01",
                  "peer_as": 13030,
                  "peer_ip": "195.66.224.175",
                  "type": "F",
                  "announce": {"prefix": "60.145.0.0/28",
                               "asn": 202214,
                               "as_path": "13030 3491 4651 9737 23969"},
                  "conflict_with": {"prefix": "1.0.128.0/17",
                                    "asn": 12322},
                  "asn": 12322}
    annotate_if_relation(relations_dict, input_dict)
    expected = {"timestamp": 1445817600.0,
                "collector": "rrc01",
                "peer_as": 13030,
                "peer_ip": "195.66.224.175",
                "type": "F",
                "announce": {"prefix": "60.145.0.0/28",
                             "asn": 202214,
                             "as_path": "13030 3491 4651 9737 23969"},
                "conflict_with": {"prefix": "1.0.128.0/17",
                                  "asn": 12322},
                "asn": 12322}
    assert input_dict == expected


def test_annotate_if_direct_ok():
    input_dict = {"timestamp": 1445817600.0,
                  "collector": "rrc01",
                  "peer_as": 13030,
                  "peer_ip": "195.66.224.175",
                  "type": "F",
                  "announce": {"prefix": "60.145.0.0/28",
                               "asn": 37554,
                               "as_path": "13030 3491 9737 12322 37554"},
                  "conflict_with": {"prefix": "1.0.128.0/17",
                                    "asn": 12322},
                  "asn": 12322}
    annotate_if_direct(input_dict)
    expected = {"timestamp": 1445817600.0,
                "collector": "rrc01",
                "peer_as": 13030,
                "peer_ip": "195.66.224.175",
                "type": "F",
                "announce": {"prefix": "60.145.0.0/28",
                             "asn": 37554,
                             "as_path": "13030 3491 9737 12322 37554"},
                "conflict_with": {"prefix": "1.0.128.0/17",
                                  "asn": 12322},
                "asn": 12322,
                "direct": True}
    assert input_dict == expected


def test_annotate_if_nodirect():
    #pytest.skip()   # not implemented yet - tests to develop
    input_dict = {"timestamp": 1445817600.0,
                  "collector": "rrc01",
                  "peer_as": 13030,
                  "peer_ip": "195.66.224.175",
                  "type": "F",
                  "announce": {"prefix": "60.145.0.0/28",
                               "asn": 37554,
                               "as_path": "13030 3491 12322 9737 23969"},
                  "conflict_with": {"prefix": "1.0.128.0/17",
                                    "asn": 12322},
                  "asn": 12322}
    annotate_if_direct(input_dict)
    expected = {"timestamp": 1445817600.0,
                "collector": "rrc01",
                "peer_as": 13030,
                "peer_ip": "195.66.224.175",
                "type": "F",
                "announce": {"prefix": "60.145.0.0/28",
                             "asn": 37554,
                             "as_path": "13030 3491 12322 9737 23969"},
                "conflict_with": {"prefix": "1.0.128.0/17",
                                  "asn": 12322},
                "asn": 12322,
                "direct": False}
    assert input_dict == expected


def test_annotate_if_direct_ko():
    input_dict = {"timestamp": 1445817600.0,
                  "collector": "rrc01",
                  "peer_as": 13030,
                  "peer_ip": "195.66.224.175",
                  "type": "F",
                  "announce": {"prefix": "60.145.0.0/28",
                               "asn": 37554,
                               "as_path": "13030 3491 4651 9737 23969"},
                  "conflict_with": {"prefix": "1.0.128.0/17",
                                    "asn": 12322},
                  "asn": 12322}
    annotate_if_direct(input_dict)
    expected = {"timestamp": 1445817600.0,
                "collector": "rrc01",
                "peer_as": 13030,
                "peer_ip": "195.66.224.175",
                "type": "F",
                "announce": {"prefix": "60.145.0.0/28",
                             "asn": 37554,
                             "as_path": "13030 3491 4651 9737 23969"},
                "conflict_with": {"prefix": "1.0.128.0/17",
                                  "asn": 12322},
                "asn": 12322}
    assert input_dict == expected


def test_annotate_with_type_abnormal():
    inp_dict = {"timestamp": 1445817600.0, "collector": "rrc01", "peer_as": 13030, "peer_ip": "195.66.224.175",
                "type": "F",
                "announce": {"prefix": "1.0.128.0/24", "asn": 23969, "as_path": "13030 3491 4651 9737 23969"},
                "conflict_with": {"prefix": "1.0.128.0/17", "asn": 9737}, "asn": 9737, "valid": ["ro"]}
    annotate_with_type(inp_dict)
    assert inp_dict["type"] == "ABNORMAL"


def test_annotate_with_type_direct():
    inp_dict = {"timestamp": 1445817600.0, "collector": "rrc01", "peer_as": 13030, "peer_ip": "195.66.224.175",
                "type": "F",
                "announce": {"prefix": "1.0.128.0/24", "asn": 23969, "as_path": "13030 3491 4651 9737 23969"},
                "conflict_with": {"prefix": "1.0.128.0/17", "asn": 9737}, "asn": 9737, "direct": True, "valid": ["ro"]}
    annotate_with_type(inp_dict)
    assert inp_dict["type"] == "DIRECT"


def test_annotate_with_type_nodirect():
    inp_dict = {"timestamp": 1445817600.0, "collector": "rrc01", "peer_as": 13030, "peer_ip": "195.66.224.175",
                "type": "F",
                "announce": {"prefix": "1.0.128.0/24", "asn": 23969, "as_path": "13030 3491 4651 9737 23969"},
                "conflict_with": {"prefix": "1.0.128.0/17", "asn": 9737}, "asn": 9737, "direct": False}
    annotate_with_type(inp_dict)
    assert inp_dict["type"] == "NODIRECT"


def test_annotate_with_type_relation():
    inp_dict = {"timestamp": 1445817600.0, "collector": "rrc01", "peer_as": 13030, "peer_ip": "195.66.224.175",
                "type": "F", "relation": ["ripe"],
                "announce": {"prefix": "1.0.128.0/24", "asn": 23969, "as_path": "13030 3491 4651 9737 23969"},
                "conflict_with": {"prefix": "1.0.128.0/17", "asn": 9737}, "asn": 9737, "direct": True, "valid": ["ro"]}
    annotate_with_type(inp_dict)
    assert inp_dict["type"] == "RELATION"


def test_annotate_with_type_valid():
    inp_dict = {"timestamp": 1445817600.0, "collector": "rrc01", "peer_as": 13030, "peer_ip": "195.66.224.175",
                "type": "F", "relation": ["ripe"],
                "announce": {"prefix": "1.0.128.0/24", "asn": 23969, "as_path": "13030 3491 4651 9737 23969",
                             "valid": ["ro"]},
                "conflict_with": {"prefix": "1.0.128.0/17", "asn": 9737}, "asn": 9737, "direct": True}
    annotate_with_type(inp_dict)
    assert inp_dict["type"] == "VALID"
