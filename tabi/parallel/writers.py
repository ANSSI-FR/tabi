# -*- coding: utf-8 -*-
# Copyright (C) 2016 ANSSI
# This file is part of the tabi project licensed under the MIT license.

import multiprocessing
import select
import sys
import gzip
import os

import tabi.helpers
import tabi.parallel.helpers
import tabi.parallel.mrtprocess


class BaseWriterProcess(multiprocessing.Process):
    """Base class for the processes that write the results to the disk."""

    def __init__(self, results_pipes, parameters):
        multiprocessing.Process.__init__(self)

        # Prepare variables
        self.results_pipes = results_pipes
        self.parameters = parameters

    def get_fd(self, str_key, asn):
        raise NotImplementedError

    def close_fds(self):
        raise NotImplementedError

    def run(self):
        """The main code of the process."""

        # Map a file descriptor to a pipe
        fd2pipe = {}

        try:
            # Register file descriptors that will be polled
            p = select.poll()
            for pipe in self.results_pipes:
                tmp_fd = pipe.fileno()
                fd2pipe[tmp_fd] = pipe
                p.register(tmp_fd, select.POLLIN)

            # Iterate until all pipes are closed
            go = len(self.results_pipes)
            while go:
                for (fd, _) in p.poll():
                    try:
                        tmp = fd2pipe[fd].recv()
                    except Exception:
                        message = "WriterProcess.run() - exception catched"
                        self.parameters["logger"].exception(message)
                        sys.exit()

                    # No more results will be received, close the pipe
                    if tmp == "DONE":
                        p.unregister(fd)
                        fd2pipe[fd].close()
                        go -= 1
                    else:
                        self._write(tmp)
        finally:
            # Close file descriptors
            self.close_fds()

    def _write(self, tmp):
        data_type, asn, str_json = tmp
        if data_type == tabi.parallel.mrtprocess.ROUTES:
            self.get_fd("routes_fd", asn).write("%s\n" % str_json)
        elif data_type == tabi.parallel.mrtprocess.HIJACKS:
            self.get_fd("hijacks_fd", asn).write("%s\n" % str_json)
        elif data_type == tabi.parallel.mrtprocess.DEFAULTS:
            self.get_fd("defaults_fd", asn).write("%s\n" % str_json)


class CombinedWriterProcess(BaseWriterProcess):
    """
    Combined mode writer writes results into two gziped files.
    """

    def __init__(self, results_pipes, parameters):
        super(CombinedWriterProcess, self).__init__(results_pipes, parameters)

        # Create the directory structure
        directoryname = "%s/%s" % (self.parameters["output_directory"],
                                   self.parameters["directory"])

        tabi.parallel.helpers.create_results_directory(
            self.parameters["output_directory"],
            self.parameters["directory"])
        tabi.parallel.helpers.create_directory(directoryname)

        routes_filename = "%s/all.routes.json.gz" % directoryname
        self.parameters["routes_fd"] = gzip.GzipFile(routes_filename,
                                                     mode="w", mtime=0)
        hijacks_filename = "%s/all.hijacks.json.gz" % directoryname
        self.parameters["hijacks_fd"] = gzip.GzipFile(hijacks_filename,
                                                      mode="w", mtime=0)
        defaults_filename = "%s/all.defaults.json.gz" % directoryname
        self.parameters["defaults_fd"] = gzip.GzipFile(defaults_filename,
                                                       mode="w", mtime=0)

    def get_fd(self, str_key, asn):
        """Open or return the file descriptor that will be use
        to write results.
        """

        # Combined file descriptors are already opened
        return self.parameters[str_key]

    def close_fds(self):
        """Close file descriptors."""

        self.parameters["routes_fd"].close()
        self.parameters["hijacks_fd"].close()
        self.parameters["defaults_fd"].close()


class LegacyWriterProcess(BaseWriterProcess):
    """
    Legacy mode writer is also called split mode.
    """

    def __init__(self, results_pipes, parameters):
        super(LegacyWriterProcess, self).__init__(results_pipes, parameters)

        # Create the directory structure
        directoryname = "results/%s/%s" % (self.parameters["output_directory"],
                                           self.parameters["directory"])

        tabi.parallel.helpers.create_results_directory(
            self.parameters["output_directory"],
            self.parameters["directory"])
        tabi.parallel.helpers.create_directory(directoryname)

        self.parameters["routes_fd"] = {}
        self.parameters["hijacks_fd"] = {}
        self.parameters["defaults_fd"] = None

    def get_fd(self, str_key, asn):
        """Open or return the file descriptor that will be used
        to write results.
        """

        # Return the file descriptor
        if str_key == "defaults_fd":
            if self.parameters[str_key] is not None:
                return self.parameters["defaults_fd"]

        elif self.parameters[str_key].get(asn, None) is not None:
            return self.parameters[str_key][asn]

        # Create directories that will store the files
        directoryname = "results/%s/%s/%s/" % (self.parameters["output_directory"],
                                               self.parameters["directory"],
                                               asn)
        tabi.parallel.helpers.create_directory(directoryname)

        # Open the routes and hijacks files
        if str_key == "routes_fd":
            fd = gzip.GzipFile("%s/routes.json.gz" % directoryname,
                               mode="w", mtime=0)
            self.parameters[str_key][asn] = fd

        elif str_key == "hijacks_fd":
            fd = gzip.GzipFile("%s/hijacks.json.gz" % directoryname,
                               mode="w", mtime=0)
            self.parameters[str_key][asn] = fd

        else:
            directoryname = "results/%s/%s/" % (self.parameters["output_directory"],
                                                self.parameters["directory"])
            fd = gzip.GzipFile("%s/all.defaults.json.gz" % directoryname,
                               mode="w", mtime=0)
            self.parameters["defaults_fd"] = fd

        return fd

    def close_fds(self):
        """Close file descriptors."""
        for fd in self.parameters["routes_fd"].itervalues():
            fd.close()
        for fd in self.parameters["hijacks_fd"].itervalues():
            fd.close()
        if self.parameters["defaults_fd"] is not None:
            self.parameters["defaults_fd"].close()


class LiveWriterProcess(BaseWriterProcess):
    """
    Live mode writer writes hijack results to stdout.
    """

    def __init__(self, results_pipes, parameters):
        super(LiveWriterProcess, self).__init__(results_pipes, parameters)

        self.parameters["routes_fd"] = open(os.devnull, "w")
        self.parameters["hijacks_fd"] = sys.stdout
        self.parameters["defaults_fd"] = sys.stderr

    def get_fd(self, str_key, asn):
        """Open or return the file descriptor that will be used
        to write results.
        """

        # Combined file descriptors are already opened
        return self.parameters[str_key]

    def close_fds(self):
        """Close file descriptors."""

        self.parameters["routes_fd"].close()
        self.parameters["hijacks_fd"].close()
        self.parameters["defaults_fd"].close()
