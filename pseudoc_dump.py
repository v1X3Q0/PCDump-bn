import calendar
import ntpath
import os
import time
import re
import json

from binaryninja.plugin import BackgroundTaskThread, PluginCommand
from binaryninja.binaryview import BinaryView
from binaryninja.function import DisassemblySettings, Function
from binaryninja.log import log_alert, log_error, log_info, log_warn
from binaryninja import TypePrinter, TypeClass

from .util import force_analysis, generate_cmake, get_callee_datavars, get_pseudo_c2, key_in_funcdict, log_epcdump, mark_all_functions_analyzed, normalize_destination_file, post_pcode_format, recursive_grab_types_p
from .util import BN_AL, BN_BL, BN_FL, BN_PALIAS_FILE, BN_PCFUNC_FILE, BN_PCOBJ_FILE, BN_TYPES_FILE, JSON_STATS_FILE
from .util import functionlist_g

from .file_dummy import types_macroprefix

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
    MAX_PATH = 255

    def __init__(self, bv: BinaryView, msg: str, functionlist_a: list, destination_path: str, args, funclistold_a: dict, aliaslist_a: dict, blacklist_a: dict, file_extension_a='c'):
        """Inits PseudoCDump class"""
        BackgroundTaskThread.__init__(self, msg, can_cancel=True)
        self.bv = bv
        self.destination_path = destination_path
        self.functionlist = functionlist_a
        self.functionlist_externdict = {}
        self.args = args
        self.funclistold = funclistold_a
        self.aliaslist = aliaslist_a
        self.blacklist = blacklist_a
        self.FILE_SUFFIX = file_extension_a

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

    # obtain the data refs, globals and such from the routines.
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
                    elif '$' in str(data_ref.name):
                        data_ref.name = str(data_ref.name).replace('$', '_')
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
            self.destination_path, BN_PCOBJ_FILE + '.' + self.FILE_SUFFIX)
        linelist = []
        for unfilt_ref in global_var_dict.keys():
            linelist.append(f'{global_var_dict[unfilt_ref]};\n')
        pcode_out = post_pcode_format(''.join(linelist))
        with open(destination, 'wb') as file:
            file.write(bytes(pcode_out, 'utf-8'))
        return
    
    def accumulate_types(self):
        # types_file = TypePrinter.default.print_all_types(self.bv.types.items(), self.bv)
                
        typelist_l = []
        types_file = types_macroprefix
        # push macros and binja typedefs, as of 4.2

        # first pass, pull enums
        for eachtype in self.bv.types:
            eachtype_t = eachtype[1]
            if eachtype_t.type_class == TypeClass.EnumerationTypeClass:
                typelist_l.append(eachtype)
        
        # second pass, pull structs
        structlist_l = []
        for eachtype in self.bv.types:
            eachtype_t = eachtype[1]
            thistype = self.bv.get_type_by_name(eachtype[0])
            if eachtype_t.type_class == TypeClass.StructureTypeClass:
                structlist_l = recursive_grab_types_p(self.bv, thistype, structlist_l)

        # finally, append all the enums
        for eachtype in typelist_l:
            linestmp=TypePrinter.default.get_type_lines(eachtype[1], self.bv.type_container, eachtype[0])
            linesstr=[]
            # combine the lines
            for line in linestmp:
                badline = re.match(r'(enum [a-zA-Z_][a-zA-Z0-9_]+) \:.*', str(line))
                if badline != None:
                    line = badline.group(1)
                linesstr.append(str(line))
            types_file += '\n'.join(linesstr)
            types_file += '\n\n'
        
        # then the structures
        for eachtype in structlist_l:
            eachtype_t = self.bv.get_type_by_name(eachtype)
            linestmp=TypePrinter.default.get_type_lines(eachtype_t, self.bv.type_container, eachtype)
            linesstr=[]
            # combine the lines
            for index in range(0, len(linestmp)):
                line = linestmp[index]

                if (re.search(r'__offset\(0x[0-9a-fA-F]+\)', str(line)) != None) or (str(line) == ''):
                    curoff = line.offset
                    nextoff = linestmp[index + 1].offset
                    if curoff == nextoff:
                        continue
                    line = f'\tchar __padding{str(curoff)}[{nextoff - curoff}];'
                linesstr.append(str(line))
            types_file += '\n'.join(linesstr)
            types_file += '\n\n'

        destination = os.path.join(
            self.destination_path, BN_TYPES_FILE)
        with open(destination, 'wb') as file:
            file.write(bytes(types_file, 'utf-8'))
        return

    # this routine will create our include file with all the subroutines
    # functions in the function list need
    def accumulate_callees(self):
        linelist = []
        callee_list = []
        alias_list = []
        # if we are just doing one function, or we are not pulling recursively.
        # cause if we are pulling recursively, we likely already have all the includes
        # from the recursive pull
        if (self.functionlist != self.bv.functions) or (self.args.recursive == None):
            # first we have to do a DEEP COPY just in case, so that we don't get
            # any reference issues
            callee_list = self.functionlist.copy()
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
        elif self.functionlist == self.bv.functions:
            callee_list = self.bv.functions
        # remove the aliases and blacklisted entries
        for func in callee_list:
            aliastmp = key_in_funcdict(func.name, self.aliaslist)
            if aliastmp != None:
                callee_list.remove(func)
                alias_list.append(aliastmp)
            elif func.name in self.blacklist:
                callee_list.remove(func)
        for aliastmp in alias_list:
            macro_i = f"#define {aliastmp[0]} {aliastmp[1]}"
            linelist.append(f'{str(macro_i)}\n')
        for func_i in callee_list:
            header = f"{func_i.type.get_string_before_name()} {func_i.name}{func_i.type.get_string_after_name()}"
            linelist.append(f'{str(header)};\n')
        destination = os.path.join(
            self.destination_path, BN_PCFUNC_FILE)
        routines_out = "#pragma once\n\n"
        routines_out += "#include \"" + BN_TYPES_FILE + "\"\n\n"
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
        crashdict = {}
        if (self.args.solo == False) and (self.args.dirless == False):
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
            if (self.args.nooverwrite == True) and (function.start in self.funclistold):
                continue
            elif (function.start not in self.funclistold):
                self.funclistold.append(function.start)
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
        crashdict[BN_AL] = self.aliaslist
        crashdict[BN_BL] = self.blacklist
        crashdict[BN_FL] = self.funclistold
        cmakesouces = []
        if self.args.cmake == True:
            for function_addr in self.funclistold:
                cmakesouces.append(self.bv.get_function_at(function_addr).name + self.FILE_SUFFIX)
            cmakesouces.append(BN_PCOBJ_FILE)
            generate_cmake(self.destination_path, cmakesouces)
        jsstatfile = os.path.join(self.destination_path, JSON_STATS_FILE)
        with open(jsstatfile, "w") as statfile:
            json.dump(crashdict, statfile)
        log_alert(f'Done \nFiles saved in {self.destination_path}')

