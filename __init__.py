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
from types import SimpleNamespace

from binaryninja.binaryview import BinaryView
from binaryninja.enums import DisassemblyOption, FunctionAnalysisSkipOverride
from binaryninja.function import DisassemblySettings, Function
from binaryninja.interaction import get_directory_name_input, get_text_line_input, IntegerField, TextLineField, ChoiceField, get_form_input, SeparatorField, OpenFileNameField, CheckboxField, AddressField
from binaryninja.lineardisassembly import LinearViewCursor, LinearViewObject
from binaryninja.log import log_alert, log_error, log_info, log_warn
from binaryninja.plugin import BackgroundTaskThread, PluginCommand
from binaryninja import TypePrinter
# print everything with print(TypePrinter.default.print_all_types(bv.types.items(), bv))
from binaryninja import HighLevelILOperation

from .util import functionlist_append, get_callee_datavars, log_epcdump, log_wpcdump, recurse_append_callee_p
from .util import BN_AL, BN_BL, BN_FL, JSON_STATS_FILE
from .util import functionlist_g
from .pseudoc_dump import PseudoCDump

def cmdline_getargs(bv: BinaryView):
    args = get_text_line_input("PseudoCDump argument list", "args")
    argparser = argparse.ArgumentParser('pcdump')
    argparser.add_argument('--func', '-f', help="functions name or address to parse")
    argparser.add_argument("--range", help="range, specified as a string separated by a -")
    argparser.add_argument("--recursive", "-r", type=int, help="recursive, if the function has a call pull that too"\
                           "recursion depth 0 means keep going down")
    argparser.add_argument('--write_location', '-w', help='location to write the output to')
    argparser.add_argument('--dirless', '-d', action='store_true', help="write and don\'t create directory")
    argparser.add_argument('--solo', '-s', action='store_true', help='location to write the output to')
    argparser.add_argument('--nooverwrite', '-n', action='store_true', help="default action" \
                           "is to overwrite the function files. if this flag is set, do not" \
                            "overwrite those files")
    argparser.add_argument('--cmake', action='store_true', help='generate a cmake file with the sources')
    argparser.add_argument('--cpp', action='store_true', help='make cpp')

    if args != None:
        args = args.decode("utf-8")
    else:
        return
    # print(args)
    args = re.sub(r"[ ]+", " ", args)
    # print(args)
    args = argparser.parse_args(str(args).split(' '))
    return args

def gui_getargs(bv: BinaryView, addr: int) -> None:
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
    blacklist = []
    funclistold = []

    # if args == []:
    #     log_epcdump(''
    #               'PCDUMP- Try again if you change your mind!')
    #     return

    input_list = []
    funcfield = CheckboxField(f'Pull just function {hex(addr)}', default=False)
    input_list.append(funcfield)
    range_field = TextLineField('range field delineated by -', default=None)
    input_list.append(range_field)
    recurse_depth = IntegerField('recurse depth', default=-1)
    input_list.append(recurse_depth)
    pcdump_out = OpenFileNameField('location to write')
    input_list.append(pcdump_out)
    dirless_arg = CheckboxField("write to dirty directory", default=False)
    input_list.append(dirless_arg)
    soloprocess = CheckboxField("solo, don't accumulate deps", default=False)
    input_list.append(soloprocess)
    nooverwrite = CheckboxField("do not overwrite function files", default=False)
    input_list.append(nooverwrite)
    gencmake = CheckboxField("generate cmake file", default=False)
    input_list.append(gencmake)
    makecpp = CheckboxField("generate as cpp files", default=False)
    input_list.append(makecpp)
    get_form_input(input_list, "pcdump")

    if funcfield.result == True:
        funcout = addr
    else:
        funcout = None

    args = SimpleNamespace(func=funcout, range=range_field.result, recursive=recurse_depth.result, write_location=pcdump_out.result, dirless=dirless_arg.result, solo=soloprocess.result, nooverwrite=nooverwrite.result, cmake=gencmake.result, cpp=makecpp.result)
    return args

def dump_pseudo_c(bv: BinaryView, addr: int) -> None:
    args = gui_getargs(bv, addr)
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
            if BN_AL in crashdict:
                aliaslist = crashdict[BN_AL]
            if BN_BL in crashdict:
                blacklist = crashdict[BN_BL]
            if BN_FL in crashdict:
                funclistold = crashdict[BN_FL]
    # for func_i in crashdict.functions:
    #     func_tmp = self.bv.get_function_at(func_i)
    #     # if function is in the functionlist, i'll remove it
    #     if func_tmp in self.functionlist:
    #         self.functionlist.remove(func_tmp)
    # for inc_i in crashdict.includes:
    #     if inc_tmp in self.includelist:
    #         self.includelist.remove(inc_tmp)
    # for obj_i in crashdict.objects:
    #     if obj_tmp in self.objectlist:
    #         self.objectlist.remove(obj_tmp)
    # for alias_i in crashdict.aliases:
    #     alias_i
    # for black_i in crashdict.blacklist:
    #     black_i


    if args.func != None:
        targfuncs = bv.get_functions_by_name(args.func)
        if targfuncs == []:
            targfuncs = bv.get_functions_containing(int(args.func, 0x10))
        if targfuncs == []:
            log_wpcdump('could not find the func {}'.format(args.func))
        functionlist_g = targfuncs

    if args.range != -1:
        targstart = int(args.range.split('-')[0], 0x10)
        targend = int(args.range.split('-')[1], 0x10)
        for eachfunc in bv.functions:
            if (eachfunc.start >= targstart) and (eachfunc.start < targend):
                functionlist_g, _ = functionlist_append(eachfunc, functionlist_g, aliaslist, blacklist)
                # functionlist_g.append(eachfunc)

    if (args.func == None) and (args.range == -1):
        functionlist_g = bv.functions
        allfuncs = True

    # if we are getting some resursive stuff
    if (args.recursive != None) and (allfuncs == False):
        functionlist_g_tmp = functionlist_g.copy()
        for func in functionlist_g_tmp:
            print("recursing on ", func)
            functionlist_g = recurse_append_callee_p(functionlist_g, args.recursive, 0, bv, func, aliaslist, blacklist)
    
    fex = 'c'
    if args.cpp == True:
        fex='cpp'

    dump = PseudoCDump(bv, 'Starting the Pseudo C Dump...', functionlist_g, destination_path, args,
                       funclistold, aliaslist, blacklist, fex)
    dump.start()

"""Register the plugin that will be called with an address argument.
"""
PluginCommand.register_for_address('Pseudo C Dump',
                                   'Dumps Pseudo C for the whole code base',
                                   dump_pseudo_c)
