#
# Description:  Binary Ninja plugin to decompile all the codebase in Pseudo C
# and dump it into a given directory, though File -> Export would also work for some
# cases instead of using this plugin, depending on what you are trying to achieve.
#
# Author: Asher Davila (@asher_davila)
# https://github.com/AsherDLL/PCDump-bn
#

import calendar
import ntpath
import os
import platform
import re
import time
import argparse
import json

from binaryninja.binaryview import BinaryView
from binaryninja.enums import DisassemblyOption, FunctionAnalysisSkipOverride
from binaryninja.function import DisassemblySettings, Function
from binaryninja.interaction import get_directory_name_input, get_text_line_input
from binaryninja.lineardisassembly import LinearViewCursor, LinearViewObject
from binaryninja.log import log_alert, log_error, log_info, log_warn
from binaryninja.plugin import BackgroundTaskThread, PluginCommand
from binaryninja import TypePrinter
# print everything with print(TypePrinter.default.print_all_types(bv.types.items(), bv))
from binaryninja import HighLevelILOperation

from util import log_epcdump, get_callee_datavars, recurse_append_callee, log_wpcdump
from util import JSON_STATS_FILE
from util import functionlist_g
from pseudoc_dump import PseudoCDump

def dump_pseudo_c(bv: BinaryView) -> None:
    """
    Receives path and instantiates PseudoCDump, and calls PseudoCDump 
    to start the thread in the background.

    Args:
        bv: A Binary Ninja BinaryView instance which is a view on binary data,
            and presents a queryable interface of a binary file.
        function: None.
    """
    global functionlist_g
    functionlist_g = []
    allfuncs = False
    aliaslist = {}
    blacklist = {}

    args = get_text_line_input("argument list", "args")
    argparser = argparse.ArgumentParser('pcdump')
    argparser.add_argument('--func', '-f', help="functions name or address to parse")
    argparser.add_argument("--range", help="range, specified as a string separated by a -")
    argparser.add_argument("--recursive", "-r", action='store_true', help="recursive, if the function has a call pull that too")
    argparser.add_argument('--write_location', '-w', help='location to write the output to')
    argparser.add_argument('--dirless', '-d', action='store_true', help="write and don\'t create directory")
    argparser.add_argument('-s', '--solo', action='store_true', help='location to write the output to')

    if args != None:
        args = args.decode("utf-8")
    else:
        return
    # print(args)
    args = re.sub(r"[ ]+", " ", args)
    # print(args)
    args = argparser.parse_args(str(args).split(' '))
    # if args == []:
    #     log_epcdump(''
    #               'PCDUMP- Try again if you change your mind!')
    #     return
        
    destination_path = args.write_location
    if (destination_path == None) or (destination_path == 'dialog'):
        destination_path = get_directory_name_input('Destination')
    
    if os.path.exists(destination_path) == False:
        log_epcdump(''
                  'No directory was provided to save the decompiled Pseudo C')
        return

    # pull dump stats if there are any
    # dump stats has
        # functions
        # includes
        # objects
    jsstatfile = os.path.join(destination_path, JSON_STATS_FILE)
    crashdict = {}
    if os.path.exists(jsstatfile):
        with open(jsstatfile, "r") as statfile:
            crashdict = json.loads(statfile.read())
            aliaslist = crashdict.aliaslist
            blacklist = crashdict.blacklist
            funclist = crashdict.funclist
    funclist_old = []
    for func_i in crashdict.functions:
        func_tmp = self.bv.get_function_at(func_i)
        # if function is in the functionlist, i'll remove it
        if func_tmp in self.functionlist:
            self.functionlist.remove(func_tmp)
    for inc_i in crashdict.includes:
        if inc_tmp in self.includelist:
            self.includelist.remove(inc_tmp)
    for obj_i in crashdict.objects:
        if obj_tmp in self.objectlist:
            self.objectlist.remove(obj_tmp)
    for alias_i in crashdict.aliases:
        alias_i
    for black_i in crashdict.blacklist:
        black_i


    if args.func != None:
        targfuncs = bv.get_functions_by_name(args.func)
        if targfuncs == []:
            targfuncs = bv.get_functions_containing(int(args.func, 0x10))
        if targfuncs == []:
            log_wpcdump('could not find the func {}'.format(args.func))
        functionlist_g = targfuncs

    if args.range != None:
        targstart = int(args.range.split('-')[0], 0x10)
        targend = int(args.range.split('-')[1], 0x10)
        for eachfunc in bv.functions:
            if (eachfunc.start >= targstart) and (eachfunc.start < targend):
                functionlist_g.append(eachfunc)

    if (args.func == None) and (args.range == None):
        functionlist_g = bv.functions
        allfuncs = True

    # if we are getting some resursive stuff
    if (args.recursive == True) and (allfuncs == False):
        functionlist_g_tmp = functionlist_g
        for func in functionlist_g_tmp:
            recurse_append_callee(func)
        functionlist_g += get_callee_datavars(bv, functionlist_g)

    dump = PseudoCDump(bv, 'Starting the Pseudo C Dump...', functionlist_g, destination_path, args)
    dump.start()

"""Register the plugin that will be called with an address argument.
"""
PluginCommand.register('Pseudo C Dump',
                                   'Dumps Pseudo C for the whole code base',
                                   dump_pseudo_c)
