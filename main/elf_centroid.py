import os, sys
from capstone import *
from capstone.arm import *
import subprocess

###########################################################

blacklisted_functions = [
    "__udivsi3",
    "__restore_core_regs",
    "__div0",
    "__divsi3"]

DEMANGLER = 'arm-linux-androideabi-c++filt'


def demangle(names, parameters):
    try:
        args = [DEMANGLER, '-i']
        if parameters:
            args.append('-p')
        args.extend(names)
        pipe = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        stdout, _ = pipe.communicate()
        demangled = stdout.split("\n")
        # Each line ends with a newline, so the final entry of the split output
        # will always be ''.
        assert len(demangled) == len(names) + 1
        return demangled[:-1]
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print "[%s, %s, %s] failed to demangle C++ names: %s" % (exc_type, fname, exc_tb.tb_lineno, str(e))
        return None


def disassemble_function(md, name, address, offset, code):
    if address - offset > len(code) or address < 0:
        print "invalid address", address, ".text section size", len(code)
        return
    if address and 0x1:
        md.mode = CS_MODE_THUMB
        address -= 1
    else:
        md.mode = CS_MODE_ARM
    try:
        demangled_name = demangle([name], False)
        if demangled_name and demangled_name != name:
            name = demangled_name
        print name, "(", hex(address), "):"
        # for i in md.disasm(code[address - offset:-1], address):
        #    print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        #    if i.id in (ARM_INS_BL,):
        #        break
    except Exception as e:
        print "Failed to disassemble function ", name, "at address ", hex(address), ":", str(e)
        return


def disassemble_functions(functions, offset, code):
    try:
        md = Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN)
        if not md:
            print "failed to disassemble"
            return
        md.detail = False
        md.skipdata = True
        for name, address in functions.items():
            # if name != "X509_check_purpose":
            #    continue
            disassemble_function(md, name, address, offset, code)
    except Exception as e:
        print "Failed to disassemble functions", str(e)
        return


def scan_section(functions, elffile, lib_path, section):
    try:
        from elftools.elf.sections import SymbolTableSection
        from elftools.common.exceptions import ELFError

        if not section or not isinstance(section, SymbolTableSection) or section['sh_entsize'] == 0:
            return 0

        print "symbol table '%s' contains %s entries" % (section.name, section.num_symbols())

        count = 0
        for nsym, symbol in enumerate(section.iter_symbols()):

            # iterate over all functions
            if (symbol['st_info']['type'] == 'STT_FUNC' and symbol['st_shndx'] != 'SHN_UNDEF' and
                    symbol.name not in blacklisted_functions and
                    not symbol.name.startswith(('__gnu_Unwind_', '___Unwind_', '__aeabi_', '__gnu_unwind_', '_Unwind_',
                                                '__aeabi_unwind_'))):
                # functions from .text section
                section = elffile.get_section(symbol['st_shndx'])
                if section.name != '.text':
                    continue

                # bookeeping function names
                func = symbol.name
                if not func in functions:
                    functions[func] = symbol['st_value']

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print "[%s, %s, %s] Error extracting functions: %s" % (exc_type, fname, exc_tb.tb_lineno, str(e))


def get_functions(lib_path):
    functions = {}
    data = None
    offset = None
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.common.exceptions import ELFError

        with open(lib_path, 'rb') as stream:
            elffile = ELFFile(stream)

            if not elffile.has_dwarf_info():
                print('file has no DWARF info')

            scan_section(functions, elffile, lib_path, elffile.get_section_by_name('.symtab'))
            scan_section(functions, elffile, lib_path, elffile.get_section_by_name('.dynsym'))

            # .text section hex dump
            section = elffile.get_section_by_name('.text')
            if section:
                data = section.data()
                offset = section['sh_offset']

        return functions, offset, data

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print "[%s, %s, %s] Error extracting functions: %s" % (exc_type, fname, exc_tb.tb_lineno, str(e))


if __name__ == "__main__":
    functions, offset, data = get_functions(sys.argv[1])
    if not functions:
        print "No functions found"
        exit(1)

    print ".text size", len(data), "offset", offset, "functions", len(functions)
    disassemble_functions(functions, offset, data)
