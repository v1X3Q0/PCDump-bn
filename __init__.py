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

def log_wpcdump(toprint):
    log_warn('PCDUMP- {}'.format(toprint))

def log_epcdump(toprint):
    log_error('PCDUMP- {}'.format(toprint))

def post_pcode_format(pcode_in, externlist=[]):
    pcode_out = pcode_in

    prefix = "#include <stdint.h>\n" \
    "#include <stdio.h>\n" \
    "#include \"pseudoc_routines.h\"\n" \
    "#include \"types_file.h\"\n" \
    "#define nullptr NULL\n" \
    "#define bool int\n" \
    "\n"

    # pcode_out = pcode_out.replace('void* ', 'void** ')
    pcode_out = pcode_out.replace('cond:', 'cond_')

    pcode_out = prefix + ''.join(externlist) + pcode_out

    return pcode_out

def get_callee_datavars(bv, functionlist):
    funcl = []
    for func_i in functionlist:
        xref_list = bv.get_code_refs_from(func_i.start, func_i, func_i.arch, func_i.total_bytes)
        for unfilt_ref in xref_list:
            # is a function, continue
            df = bv.get_function_at(unfilt_ref)
            if df == None:
                continue
            if df not in funcl:
                funcl.append(df)
    return funcl

def mark_all_functions_analyzed(bv, functionlist):
    for func_i in functionlist:
        func_i.analysis_skip_override = (FunctionAnalysisSkipOverride.NeverSkipFunctionAnalysis)
    bv.update_analysis_and_wait()
    wait_counter = 0
    for func_i in functionlist:
        function_pc = function.pseudo_c_if_available
        while function_pc == None:
            time.sleep(1)
            log_info(f'waiting for analysis to finish {wait_counter}')
            wait_counter += 1
            # detault wait counter, 600 seconds
            if wait_counter > 600:
                break
    return

class PseudoCDump(BackgroundTaskThread):
    """PseudoCDump class definition.

    Attributes:
        bv: A Binary Ninja BinaryView instance which is a view on binary data,
            and presents a queryable interface of a binary file.

        msg: A string containing the message displayed when started.
        destination_path: A string containing the path of the folder where
            the Pseudo C code will be dumped.
    Class constants:
        FILE_SUFFIX: The suffix of the filenames where the content of the
            functions will be written. In this case, is a constant string 'c'
            (file extension .c).

        MAX_PATH: Maximum path length (255).            
    """
    FILE_SUFFIX = 'c'
    MAX_PATH = 255

    def __init__(self, bv: BinaryView, msg: str, functionlist_a: list, destination_path: str, args):
        """Inits PseudoCDump class"""
        BackgroundTaskThread.__init__(self, msg, can_cancel=True)
        self.bv = bv
        self.destination_path = destination_path
        self.functionlist = functionlist_a
        self.functionlist_externdict = {}
        self.args = args

    def __get_function_name(self, function: Function) -> str:
        """This private method is used to normalize the name of the function
        being dumped. It tries to use the symbol of the function if it exists
        and if the length of the destination path plus the length of the
        symbol doesn't exceed MAX_PATH. Otherwise, it uses the address at the
        start of the function. Again, it checks that the length of the
        destination path plus the length of the address(sub_<address>) doesn't
        exceed MAX_PATH. If the still exceeds MAX_PATH, it raises an exception.

        Args:
            function: A Binary Ninja Function instance containing
                the current function to be dumped.
        
        Returns:
            The string containing the normalized function name.

        Raises:
            File name too long for function <function> 
            Try using a different path.
        """
        function_symbol = self.bv.get_symbol_at(function.start)

        if hasattr(function_symbol,
                   'short_name') and (len(self.destination_path) + len(
                       function_symbol.short_name)) <= self.MAX_PATH:
            return function_symbol.short_name
        elif len(self.destination_path) + len(
                'sub_%x' % (function.start)) <= self.MAX_PATH:
            return 'sub_%x' % (function.start)
        else:
            if hasattr(function_symbol, 'short_name'):
                raise ValueError('File name too long for function: '
                                 f'{function_symbol.short_name!r}\n'
                                 'Try using a different path')
            else:
                raise ValueError('File name too long for function: '
                                 f'sub_{function.start:x}\n'
                                 'Try using a different path')

    def __create_directory(self) -> str:
        """This function creates a new directory with a name that is based on
        the name of the file that is being processed and the current time, and
        returns the path of the new directory.
        """
        directory_name = ''.join(
            (f'PseudoCDump_{ntpath.basename(self.bv.file.filename)}_',
             str(calendar.timegm(time.gmtime()))))
        new_directory = os.path.join(self.destination_path, directory_name)
        os.mkdir(new_directory)

        return new_directory

    def accumulate_data_refs(self):
        global_var_dict = {}
        for func_i in self.functionlist:
            extern_list = []
            xref_list = self.bv.get_code_refs_from(func_i.start, func_i, func_i.arch, func_i.total_bytes)
            for unfilt_ref in xref_list:
                # already have this ref
                if unfilt_ref in global_var_dict.keys():
                    continue
                # not a data ref, continue
                data_ref = self.bv.get_data_var_at(unfilt_ref)
                if data_ref == None:
                    continue
                # is a function, continue
                if self.bv.get_function_at(unfilt_ref) != None:
                    continue
                # this is the filtration step, clean the name up if it has one that would
                # otherwise be illegal
                if data_ref.name != None:
                    badname = re.match(r'@([1-9]+)', data_ref.name)
                    if badname != None:
                        data_ref.name = 'global_{}'.format(badname.group(1))
                type_prefix = str(data_ref.type)
                array_count = ''
                m = re.search(r'(\[0x[0-9a-fA-F]+\])', str(data_ref.type))
                if m != None:
                    array_count = m.group(0)
                    type_prefix = re.sub(r'(\[0x[0-9a-fA-F]+\])', "", str(data_ref.type))
                name_out = data_ref.name
                if name_out == None:
                    name_out = f"data_{hex(unfilt_ref)[2:]}"
                # have function pointer, function pointer mutation
                if type_prefix.count('(') > 1:
                    type_prefix = type_prefix.replace('(*)', f'(*{name_out})')
                # not a function pointer, do a simple replacement of dangling
                # asterix
                else:
                    type_prefix = type_prefix.replace('(*)', '*')
                object_line = '{} {}{}'.format(type_prefix, name_out, array_count)
                global_var_dict[unfilt_ref] = object_line
                extern_list.append(f"extern {object_line};\n")
            # lastly, we need to save this functions externs
            self.functionlist_externdict[func_i] = extern_list
        destination = os.path.join(
            self.destination_path,
            normalize_destination_file("pcdump_c_object_file", self.FILE_SUFFIX))
        linelist = []
        for unfilt_ref in global_var_dict.keys():
            linelist.append(f'{global_var_dict[unfilt_ref]};\n')
        pcode_out = post_pcode_format(''.join(linelist))
        with open(destination, 'wb') as file:
            file.write(bytes(pcode_out, 'utf-8'))
        return
    
    def accumulate_types(self):
        types_file = TypePrinter.default.print_all_types(self.bv.types.items(), self.bv)
        destination = os.path.join(
            self.destination_path,
            normalize_destination_file("types_file", "h"))
        with open(destination, 'wb') as file:
            file.write(bytes(types_file, 'utf-8'))
        return

    def accumulate_callees(self):
        linelist = []
        callee_list = []
        if (self.functionlist != self.bv.functions) or (self.args.recursive == False):
            # first we have to do a deep copy just in case, so that we don't get
            # any reference issues
            for func_i in self.functionlist:
                callee_list.append(func_i)
            # straight append all the callees out
            for func_i in self.functionlist:
                for callee in func_i.callees:
                    if callee not in callee_list:
                        callee_list.append(callee)
            datavar_list = get_callee_datavars(self.bv, self.functionlist)
            # deep copy results
            for datavar in datavar_list:
                if datavar not in callee_list:
                    callee_list.append(datavar)
        else:
            callee_list = self.bv.functions
        for func_i in callee_list:
            header = f"{func_i.type.get_string_before_name()} {func_i.name}{func_i.type.get_string_after_name()}"
            linelist.append(f'{str(header)};\n')
        destination = os.path.join(
            self.destination_path,
            normalize_destination_file("pseudoc_routines", "h"))
        routines_out = "#pragma once\n\n"
        routines_out += "#include \"types_file.h\"\n\n"
        routines_out += ''.join(linelist)
        with open(destination, 'wb') as file:
            file.write(bytes(routines_out, 'utf-8'))
        return
    
    def run(self) -> None:
        """Method representing the thread's activity. It invokes the callable
        object passed to the object's constructor as the target argument.
        Additionally, writes the content of each function into a <function_name>.c
        file in the provided destination folder.
        """
        if self.args.solo !=  True:
            self.destination_path = self.__create_directory()
        log_info(f'Number of functions we are dumping: {len(self.functionlist)}')
        log_info(f'Number of functions we could potentially dump: {len(self.bv.functions)}')
        count = 1
        if self.args.solo == False:
            # get globals, output is objects in a c file
            self.accumulate_data_refs()
            # get types, output is types in a header file
            self.accumulate_types()
            # get callees to header file, output is includes in a header file
            self.accumulate_callees()
        # Mark all functions to be ready
        mark_all_functions_analyzed(self.bv, self.functionlist)
        # get functions
        for function in self.functionlist:
            function_name = self.__get_function_name(function)
            log_info(f'Dumping function {function_name}')
            self.progress = "Dumping Pseudo C: %d/%d" % (
                count, len(self.bv.functions))
            force_analysis(self.bv, function)
            pcode = get_pseudo_c2(self.bv, function)
            if pcode == None:
                log_epcdump(f"couldn't get pcode for {function.name}")
                return 
            pcode = post_pcode_format(pcode, self.functionlist_externdict[function])
            destination = os.path.join(
                self.destination_path,
                normalize_destination_file(function_name, self.FILE_SUFFIX))
            with open(destination, 'wb') as file:
                file.write(bytes(pcode, 'utf-8'))
            count += 1
        log_alert(f'Done \nFiles saved in {self.destination_path}')


def normalize_destination_file(destination_file: str,
                               filename_suffix: str) -> str:
    """Normalizes the file name depending on the platform being run.
    It will replace reserved characters with an underscore '_'

    Args:
        destination_file: A string containing the file name.

        filename_suffix:  A string containing the file suffix
            (file extension).
    
    Return:
        The string containing the normalized file name.
    """
    if 'Windows' in platform.system():
        normalized_destination_file = '.'.join(
            (re.sub(r'[><:"/\\|\?\*]', '_',
                    destination_file), filename_suffix))
        return normalized_destination_file
    else:
        normalized_destination_file = '.'.join(
            (re.sub(r'/', '_', destination_file), filename_suffix))
        return normalized_destination_file


def force_analysis(bv: BinaryView, function: Function) -> None:
    """Binary Ninja may have skipped the analysis of the function being dumped.
    It forces the analysis of the function if Binary ninja skipped it.
    
    Args:
        bv: A Binary Ninja BinaryView instance which is a view on binary data,
            and presents a queryable interface of a binary file.
        function: A Binary Ninja Function instance containing
            the current function to be dumped.
    """
    if function is not None and function.analysis_skipped:
        log_wpcdump(
            ''
            f'Analyzing the skipped function {bv.get_symbol_at(function.start)}'
        )
        function.analysis_skip_override = (
            FunctionAnalysisSkipOverride.NeverSkipFunctionAnalysis)
        bv.update_analysis_and_wait()

def get_pseudo_c2(bv: BinaryView, function: Function) -> str:
    # function_l = bv.get_function_at(function_base)
    attempts = 0
    function_pc = function.pseudo_c_if_available
    while function_pc == None:
        print("function {} reanalysis, try: {}".format(function.name, attempts + 1))
        # works, but is async
        # function.reanalyze()
        
        # maybe sync?
        function.analysis_skipped = False
        function.mark_updates_required()
        bv.update_analysis_and_wait()

        function_pc = function.pseudo_c_if_available
        if attempts == 10:
            return None
        time.sleep(1)
        attempts+=1
    linelist = []
    header = f"{function.type.get_string_before_name()} {function.name}{function.type.get_string_after_name()}"
    linelist.append(f'{str(header)}\n')
    for hlil_i in function_pc.get_linear_lines(function.hlil.root):
        linelist.append(f'{str(hlil_i)}\n')

    lines_of_code = ''.join(linelist)
    return (lines_of_code)


def get_pseudo_c(bv: BinaryView, function: Function) -> str:
    """Gets the Pseudo C of the function being dumped. It stores every
    line of the function (header and body) into a list while the function
    is being traversed. Finally, it returns the entire function Pseudo C
    dump.

    Args:
        bv: A Binary Ninja BinaryView instance which is a view on binary data,
            and presents a queryable interface of a binary file.
        function: A Binary Ninja Function instance containing
            the current function to be dumped.

    Return:
        lines_of_code: A single string containing the entire Pseudo C code of
            the function.
    """
    lines = []
    settings = DisassemblySettings()
    settings.set_option(DisassemblyOption.ShowAddress, False)
    settings.set_option(DisassemblyOption.WaitForIL, True)
    obj = LinearViewObject.language_representation(bv, settings)
    cursor_end = LinearViewCursor(obj)
    cursor_end.seek_to_address(function.highest_address)
    body = bv.get_next_linear_disassembly_lines(cursor_end)
    cursor_end.seek_to_address(function.highest_address)
    header = bv.get_previous_linear_disassembly_lines(cursor_end)

    for line in header:
        lines.append(f'{str(line)}\n')

    for line in body:
        lines.append(f'{str(line)}\n')

    lines_of_code = ''.join(lines)
    return (lines_of_code)

functionlist_g = []

def recurse_append_callee(func):
    global functionlist_g
    callees = func.callees
    for callee in callees:
        if callee not in functionlist_g:
            functionlist_g.append(callee)
            recurse_append_callee(func)
    return

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

    args = get_text_line_input("argument list", "args")
    argparser = argparse.ArgumentParser('pcdump')
    argparser.add_argument('--func', '-f', help="functions name or address to parse")
    argparser.add_argument("--range", help="range, specified as a string separated by a -")
    argparser.add_argument("--recursive", "-r", action='store_true', help="recursive, if the function has a call pull that too")
    argparser.add_argument('--write_location', '-d', help='location to write the output to')
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

    functionlist_g = []

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
