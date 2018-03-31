# maybe - see what a program does before deciding whether you really want it to happen
#
# Copyright (c) 2016-2017 Philipp Emanuel Weidmann <pew@worldwidemann.com>
#
# Nemo vir est qui mundum non reddat meliorem.
#
# Released under the terms of the GNU General Public License, version 3
# (https://gnu.org/licenses/gpl.html)


from acidsh import register_filter


def filter_create_directory(path):
    return "create directory", [path], 0


register_filter("mkdir", lambda process, args:
                filter_create_directory(process.full_path(args[0])))
register_filter("mkdirat", lambda process, args:
                filter_create_directory(process.full_path(args[1], args[0])))
