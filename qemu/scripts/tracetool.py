#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Command-line wrapper for the tracetool machinery.
"""

__author__     = "Lluís Vilanova <vilanova@ac.upc.edu>"
__copyright__  = "Copyright 2012, Lluís Vilanova <vilanova@ac.upc.edu>"
__license__    = "GPL version 2 or (at your option) any later version"

__maintainer__ = "Stefan Hajnoczi"
__email__      = "stefanha@linux.vnet.ibm.com"


import sys
import getopt

from tracetool import error_write, out
import tracetool.backend
import tracetool.format


_SCRIPT = ""

def error_opt(msg = None):
    if msg is not None:
        error_write("Error: " + msg + "\n")

    backend_descr = "\n".join([ "    %-15s %s" % (n, d)
                                for n,d in tracetool.backend.get_list() ])
    format_descr = "\n".join([ "    %-15s %s" % (n, d)
                               for n,d in tracetool.format.get_list() ])
    error_write("""\
Usage: %(script)s --format=<format> --backend=<backend> [<options>]

Backends:
%(backends)s

Formats:
%(formats)s

Options:
    --help                   This help message.
    --list-backends          Print list of available backends.
    --check-backend          Check if the given backend is valid.
    --binary <path>          Full path to QEMU binary.
    --target-type <type>     QEMU emulator target type ('system' or 'user').
    --target-arch <arch>     QEMU emulator target arch.
    --probe-prefix <prefix>  Prefix for dtrace probe names
                             (default: qemu-<target-type>-<target-arch>).\
""" % {
            "script" : _SCRIPT,
            "backends" : backend_descr,
            "formats" : format_descr,
            })

    if msg is None:
        sys.exit(0)
    else:
        sys.exit(1)


def main(args):
    global _SCRIPT
    _SCRIPT = args[0]

    long_opts  = [ "backend=", "format=", "help", "list-backends", "check-backend" ]
    long_opts += [ "binary=", "target-type=", "target-arch=", "probe-prefix=" ]

    try:
        opts, args = getopt.getopt(args[1:], "", long_opts)
    except getopt.GetoptError, err:
        error_opt(str(err))

    check_backend = False
    arg_backend = ""
    arg_format = ""
    binary = None
    target_type = None
    target_arch = None
    probe_prefix = None
    for opt, arg in opts:
        if opt == "--help":
            error_opt()

        elif opt == "--backend":
            arg_backend = arg
        elif opt == "--format":
            arg_format = arg

        elif opt == "--list-backends":
            backends = tracetool.backend.get_list()
            out(", ".join([ b for b,_ in backends ]))
            sys.exit(0)
        elif opt == "--check-backend":
            check_backend = True

        elif opt == "--binary":
            binary = arg
        elif opt == '--target-type':
            target_type = arg
        elif opt == '--target-arch':
            target_arch = arg
        elif opt == '--probe-prefix':
            probe_prefix = arg

        else:
            error_opt("unhandled option: %s" % opt)

    if arg_backend is None:
        error_opt("backend not set")

    if check_backend:
        if tracetool.backend.exists(arg_backend):
            sys.exit(0)
        else:
            sys.exit(1)

    if arg_format == "stap":
        if binary is None:
            error_opt("--binary is required for SystemTAP tapset generator")
        if probe_prefix is None and target_type is None:
            error_opt("--target-type is required for SystemTAP tapset generator")
        if probe_prefix is None and target_arch is None:
            error_opt("--target-arch is required for SystemTAP tapset generator")

        if probe_prefix is None:
            probe_prefix = ".".join([ "qemu", target_type, target_arch ])

    try:
        tracetool.generate(sys.stdin, arg_format, arg_backend,
                           binary = binary, probe_prefix = probe_prefix)
    except tracetool.TracetoolError, e:
        error_opt(str(e))

if __name__ == "__main__":
    main(sys.argv)
