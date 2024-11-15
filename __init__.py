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

def log_wpcdump(toprint):
    log_warn('PCDUMP- {}'.format(toprint))

def log_epcdump(toprint):
    log_error('PCDUMP- {}'.format(toprint))

def post_pcode_format(pcode_in):
    pcode_out = pcode_in

    prefix = "#include <stdint.h>\n" \
    "#include <stdio.h>\n" \
    "#define nullptr NULL\n" \
    "#define bool int\n" \
    "\n"

    # pcode_out = pcode_out.replace('void* ', 'void** ')
    pcode_out = pcode_out.replace('cond:', 'cond_')

    pcode_out = prefix + pcode_out

    return pcode_out

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

    def __init__(self, bv: BinaryView, msg: str, functionlist_a: list, destination_path: str):
        """Inits PseudoCDump class"""
        BackgroundTaskThread.__init__(self, msg, can_cancel=True)
        self.bv = bv
        self.destination_path = destination_path
        self.functionlist = functionlist_a

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

    def run(self) -> None:
        """Method representing the thread's activity. It invokes the callable
        object passed to the object's constructor as the target argument.
        Additionally, writes the content of each function into a <function_name>.c
        file in the provided destination folder.
        """
        self.destination_path = self.__create_directory()
        log_info(f'Number of functions to dump: {len(self.bv.functions)}')
        count = 1
        for function in self.functionlist:
            function_name = self.__get_function_name(function)
            log_info(f'Dumping function {function_name}')
            self.progress = "Dumping Pseudo C: %d/%d" % (
                count, len(self.bv.functions))
            force_analysis(self.bv, function)
            pcode = get_pseudo_c2(self.bv, function)
            pcode = post_pcode_format(pcode)
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
    function_pc = function.pseudo_c_if_available
    linelist = []
    for i in function.hlil.instructions:
        distext_list = function_pc.get_linear_lines(i)
        for j in distext_list:
            distext = distext_list[0]
            distext_str = str(distext)
            linelist.append(f'{str(distext_str)}\n')
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


def dump_pseudo_c(bv: BinaryView) -> None:
    """
    Receives path and instantiates PseudoCDump, and calls PseudoCDump 
    to start the thread in the background.

    Args:
        bv: A Binary Ninja BinaryView instance which is a view on binary data,
            and presents a queryable interface of a binary file.
        function: None.
    """
    
    args = get_text_line_input("argument list", "args")
    argparser = argparse.ArgumentParser('pcdump')
    argparser.add_argument('--func', '-f', help="functions name or address to parse")
    argparser.add_argument("--range", help="range, specified as a string separated by a -")
    argparser.add_argument("-r", help="recursive, if the function has a call pull that too")
    argparser.add_argument('--write_location', '-d', help='location to write the output to')

    if args != None:
        args = args.decode("utf-8")
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

    functionlist = []

    if args.func != None:
        targfuncs = bv.get_functions_by_name(args.func)
        if targfuncs == []:
            targfuncs = bv.get_functions_containing(int(args.func, 0x10))
        if targfuncs == []:
            log_wpcdump('could not find the func {}'.format(args.func))
        functionlist = targfuncs

    if args.range != None:
        targstart = int(args.range.split('-')[0], 0x10)
        targend = int(args.range.split('-')[1], 0x10)
        for eachfunc in bv.functions:
            if (eachfunc.start >= targstart) and (eachfunc.start < targend):
                functionlist.append(eachfunc)

    if (args.func == None) and (args.range == None):
        functionlist = bv.functions

    dump = PseudoCDump(bv, 'Starting the Pseudo C Dump...', functionlist, destination_path)
    dump.start()


"""Register the plugin that will be called with an address argument.
"""
PluginCommand.register('Pseudo C Dump',
                                   'Dumps Pseudo C for the whole code base',
                                   dump_pseudo_c)
