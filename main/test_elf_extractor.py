import os, sys


# build a map of function names and their count
def scan_section(functions, lib_path, section):
    """
    Function to extract function names from a shared library file.
    """
    try:
        from elftools.elf.sections import SymbolTableSection

        if not section or not isinstance(section, SymbolTableSection) or section['sh_entsize'] == 0:
            return 0

        print "symbol table '%s' contains %s entries" % (section.name, section.num_symbols())

        count = 0
        for nsym, symbol in enumerate(section.iter_symbols()):

            if symbol['st_info']['type'] == 'STT_FUNC' and symbol['st_shndx'] != 'SHN_UNDEF':

                # bookeeping function names
                func = symbol.name
                if not func in functions:
                    functions[func] = 1
                else:
                    functions[func] += 1
                count += 1
        return count
    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print "[%s, %s, %s] Error extracting functions: %s" % (exc_type, fname, exc_tb.tb_lineno, str(e))
        return 0


def get_functions(lib_path):
    from elftools.elf.elffile import ELFFile
    from elftools.common.exceptions import ELFError

    count = 0
    functions = {}
    try:
        with open(lib_path, 'rb') as stream:
            elffile = ELFFile(stream)
            count += scan_section(functions, lib_path, elffile.get_section_by_name('.symtab'))
            count += scan_section(functions, lib_path, elffile.get_section_by_name('.dynsym'))
        return count, functions
    except e as Exception:
        print "error: ", str(e)
        return 0, None


def get_functions_old(lib_path):
    try:
        from elftools.elf.elffile import ELFFile
        from elftools.common.exceptions import ELFError
        from elftools.elf.sections import SymbolTableSection

        nosymtab = True
        with open(lib_path, 'rb') as stream:
            elffile = ELFFile(stream)
            if not elffile:
                return 0, None

            # build a map of function names and their count
            functions = {}
            count = 0

            for section in elffile.iter_sections():
                if not isinstance(section, SymbolTableSection):
                    continue

                if section['sh_entsize'] == 0:
                    continue

                nosymtab = False
                print "symbol table '%s' contains %s entries" % (section.name, section.num_symbols())

                for nsym, symbol in enumerate(section.iter_symbols()):
                    if symbol['st_info']['type'] == 'STT_FUNC' and symbol['st_shndx'] != 'SHN_UNDEF':

                        # bookeeping function names
                        func = symbol.name
                        if not func in functions:
                            functions[func] = 1
                        else:
                            functions[func] += 1
                        count += 1

                return count, functions

            if nosymtab:
                print "no symbols found in lib %s" % (lib_path)
                return 0, None

    except Exception as e:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
        print "[%s, %s, %s] Error extracting functions: %s" % (exc_type, fname, exc_tb.tb_lineno, str(e))
        return 0, None


if __name__ == "__main__":
    print get_functions(sys.argv[1])
