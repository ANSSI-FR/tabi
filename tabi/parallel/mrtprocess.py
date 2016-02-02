# -*- coding: utf-8 -*-
# Copyright (C) 2016 ANSSI
# This file is part of the tabi project licensed under the MIT license.

import logging
import multiprocessing
import cProfile
import os
import time
import json
import select
import sys
import traceback

import tabi.parallel.rib
import tabi.parallel.core
import tabi.parallel.helpers


logger = logging.getLogger(__name__)

############################################
# Helper functions

def is_ready(fileno, timeout=0):
    """Check if there is data to read from fileno."""
    p = select.poll()
    p.register(fileno, select.POLLIN)
    events = p.poll(timeout)
    return len(events) != 0


def is_watched_asn(parameters, asn):
    """Is this process responsible for the given AS ?"""

    if parameters["ases"] is not None:
        # if there is an ases file we check against it
        if asn in parameters["ases"]:
            return True
    else:
        # otherwise the AS are distributed between processes according
        # to there job id
        if asn % parameters["num_jobs"] == parameters["job_id"]:
            return True
    return False


# Tags used to identify results
ROUTES = 1
HIJACKS = 2
DEFAULTS = 3


class MRTProcess(multiprocessing.Process):
    """Process that parses MRT dumps."""

    def __init__(self, pipe, parameters):
        multiprocessing.Process.__init__(self)

        # Prepare variables
        self.pipe = pipe
        self.parameters = parameters
        self.access_time = None
        self.timestamp = None

        # Create the RIB
        self.parameters["rib"] = tabi.parallel.rib.EmulatedRIB()

    def _process_line(self, tmp):
        """Process lines from mabo."""

        from tabi.parallel.input.mabo import MaboTableDumpV2Document
        from tabi.parallel.input.mabo import MaboUpdateDocument

        document = json.loads(tmp)

        if document.get("type", None) == "table_dump_v2":
            abstracted_message = MaboTableDumpV2Document(self.parameters["collector_id"], document)

        elif document.get("type", None) == "update":
            abstracted_message = MaboUpdateDocument(self.parameters["collector_id"], document)

        else:
            self.parameters["logger"].warning("_process_line(): unknown type %s", document.get("type", None))
            return

        import functools
        keep_asn = functools.partial(is_watched_asn, self.parameters)

        self.parameters["rib"].set_access_time(self.access_time)
        default_messages, route_messages, hijack_messages = tabi.parallel.core.process_message(self.parameters["rib"], abstracted_message, keep_asn)
        self.timestamp = abstracted_message.timestamp()

        for message in default_messages:
            self.parameters["results_pipe"].send((DEFAULTS, None, json.dumps(message)))

        for message in route_messages:
            self.parameters["results_pipe"].send((ROUTES, message["asn"], json.dumps(message)))

        for message in hijack_messages:
            if "withdraw" in message:  # XXX: format must be the same !
                asn = message["withdraw"]["asn"]
            else:
                asn = message["conflict_with"]["asn"]
            self.parameters["results_pipe"].send((HIJACKS, asn, json.dumps(message)))

    def _process_file(self, filename):
        try:
            fh = open(filename, "r")

            while True:
                line = fh.readline()

                # If nothing was read and there is a command waiting on
                # the socket then we reached End Of File.
                if not line:
                    if is_ready(self.pipe.fileno()):
                        break
                    # Otherwise wait a bit for the file to be filled
                    time.sleep(0.01)
                    continue

                # readline() usually returns a full line (with \n), if not,
                # seek at the beginning of the line and try again.
                if line[-1] != "\n":
                    fh.seek(- len(line), os.SEEK_CUR)
                    time.sleep(0.01)
                    continue
                self._process_line(line)
        except Exception, e:
            # Report exceptions and the corresponding trace
            etype, evalue, etrace = sys.exc_info()
            traceback_str = traceback.format_exception(etype, evalue, etrace)
            message = "MRTProcess(%d): something went wrong when reading '%s':"
            message = message % (self.parameters["job_id"], filename)
            message += " %s" % e
            message += " %s" % traceback_str
            tabi.parallel.helpers.critical_error(message)

    def run(self):
        """The main code of the process."""

        # Start the code profiling in the worker if enabled in the main process
        stats = None
        if self.parameters["stats"]:
            stats = cProfile.Profile()
            stats.enable()

        while True:
            tmp = self.pipe.recv()

            # Do things according to commands
            if tmp == "STOP":
                # Stop & get the number of prefixes stored in the tree
                self.pipe.send(self.parameters["rib"].prefixes())  # XXX: false as routes & hijacks are merged
                self.parameters["results_pipe"].send("DONE")
                break

            elif tmp[:6] == "ACCESS":
                # Store the access time
                self.access_time = float(tmp[7:])
                continue

            elif tmp == "BVIEW_END":
                # Remove prefixes that were not accessed by the bview
                route_messages, hijack_messages = tabi.parallel.core.bview_fake_withdraw(self.parameters["rib"],
                                                                                    self.parameters["collector_id"],
                                                                                    self.access_time, self.timestamp)
                for message in route_messages:
                    self.parameters["results_pipe"].send((ROUTES, message["asn"], json.dumps(message)))

                for message in hijack_messages:
                    if "withdraw" in message:  # XXX: format must be the same !
                        asn = message["withdraw"]["asn"]
                    else:
                        asn = message["conflict_with"]["asn"]
                    self.parameters["results_pipe"].send((HIJACKS, asn, json.dumps(message)))
                continue

            elif tmp == "SYNC_PING":
                self.pipe.send("SYNC_PONG")
                continue

            elif tmp[:7] == "PROCESS":
                # Process the output of mabo and send the number of routes
                self._process_file(tmp[8:])

            else:
                message = "Process(%d).run(): unknown command: %s" % (self.parameters["job_id"], tmp)
                tabi.parallel.helpers.critical_error(message)

        # Dump the profiling data
        if stats is not None:
            stats.disable()
            filename = "worker.{}.pstats".format(os.getpid())
            self.parameters["logger"].info("Dump worker profiling stats in %s", filename)
            stats.dump_stats(filename)
