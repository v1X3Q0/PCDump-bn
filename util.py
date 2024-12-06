import re
import time
import platform
import os

from binaryninja.binaryview import BinaryView
from binaryninja.log import log_alert, log_error, log_info, log_warn
from binaryninja.function import DisassemblySettings, Function
from binaryninja.lineardisassembly import LinearViewCursor, LinearViewObject
from binaryninja.enums import DisassemblyOption, FunctionAnalysisSkipOverride

from cmake_dummy import cmake_dummy

JSON_STATS_FILE="pc_dumpstats.json"
BN_TYPES_FILE="types_file.h"
BN_PCFUNC_FILE="pseudoc_routines.h"
BN_PCOBJ_FILE="pcdump_c_object_file.c"
BN_PALIAS_FILE="pseudoc_aliases.h"

BN_AL="aliaslist"
BN_BL="blacklist"
BN_FL="funclist"

functionlist_g = []

def fix_bad_datavars(bv):
    for datavar_key in bv.data_vars.keys():
        datavar = bv.data_vars[datavar_key]
        if datavar.name != None:
            badname = re.match(r'@([1-9]+)', datavar.name)
            if badname != None:
                datavar.name = 'global_{}'.format(badname.group(1))

def log_wpcdump(toprint):
    log_warn('PCDUMP- {}'.format(toprint))

def log_epcdump(toprint):
    log_error('PCDUMP- {}'.format(toprint))

def key_in_funcdict(funcname_in, funcdict_a):
    for funcregex in funcdict_a.keys():
        fmatch = re.match(funcregex, funcname_in)
        if fmatch != None:
            return [funcname_in, funcdict_a[funcregex]]
    return None

def functionlist_append(funcname_in, functionlist_a, aliaslist_a=None, blacklist_a=None):
    # false cases, it is in the aliaslist, blacklist or the functionlist
    if (aliaslist_a != None) and (key_in_funcdict(funcname_in, aliaslist_a) != None):
        return functionlist_a
    if (blacklist_a != None) and (funcname_in in blacklist_a):
        return functionlist_a
    # true case, its not in any so add the function
    return functionlist_a.append(funcname_in)

def post_pcode_format(pcode_in, externlist=[]):
    pcode_out = pcode_in

    prefix = "#include <stdint.h>\n" \
    "#include <stdio.h>\n" \
    "#include <string.h>\n" \
    "#include \"" + BN_PCFUNC_FILE + "\"\n" \
    "#include \"" + BN_TYPES_FILE + "\"\n" \
    "#define nullptr NULL\n" \
    "#define bool int\n" \
    "#define true 1\n"\
    "#define false 0\n"\
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
        # func_i.analysis_skip_override = (FunctionAnalysisSkipOverride.NeverSkipFunctionAnalysis)
        func_i.analysis_skipped = False
        func_i.mark_updates_required()
    bv.update_analysis_and_wait()
    for func_i in functionlist:
        wait_counter = 0
        function_pc = func_i.pseudo_c
        while function_pc == None:
            time.sleep(1)
            function_pc = func_i.pseudo_c
            log_info(f'waiting for analysis to finish {wait_counter}')
            wait_counter += 1
            # detault wait counter, 600 seconds
            if wait_counter > 600:
                break
    return

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

def recurse_append_callee(bv, func, aliaslist_a, blacklist_a):
    global functionlist_g
    # first iterate blatant callees
    callees = func.callees
    for callee in callees:
        if callee not in functionlist_g:
            functionlist_g = functionlist_append(callee, functionlist_g, aliaslist_a, blacklist_a)
            recurse_append_callee(bv, func, aliaslist_a, blacklist_a)
    # then do dataref callees
    datareflist = get_callee_datavars(bv, [func])
    for callee in datareflist:
        if callee not in functionlist_g:
            functionlist_g = functionlist_append(callee, functionlist_g, aliaslist_a, blacklist_a)
            recurse_append_callee(bv, func, aliaslist_a, blacklist_a)
    return

def generate_cmake(path: str, objlist: list):
    cmake_current = cmake_dummy.format(os.path.basename(path), ' '.join(objlist))
    f = open(os.path.join(path, 'CMakeLists.txt'), 'w')
    f.write(cmake_current)
    f.close()