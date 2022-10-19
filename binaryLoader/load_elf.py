from elftools.elf.elffile import ELFFile
import exceptions.exceptions
from elftools.elf.constants import SH_FLAGS
from capstone import *
import numpy

class ELF:
    def __init__(self, name):
        self._name = name
        try:
            self._elf = ELFFile(open(name, 'rb'))
        except:
            raise exceptions.exceptions.ELFFormatException("Error while opening the file " + self._name)
        self._arch = None
        self._arch_mode = None
        self._entry_point = None
        self.load()

    def load(self):
        self._arch = self._elf.get_machine_arch() #stringa x86 oppure x64
        if self._arch == 'x86':
            self._arch_mode = CS_MODE_32
            self._arch = CS_ARCH_X86
        elif self._arch == 'x64':
            self._arch_mode = CS_MODE_64
            self._arch = CS_ARCH_X86
        else:
            raise exceptions.exceptions.BadArchitecture("Architecture not supported!")
        #TODO calcolo entry point


    def parse_symtab_for_call_address(self):
        address = []
        for s in self._elf.iter_sections():
            if s.name == '.symtab':
                for entry in s.iter_symbols():
                    if entry['st_info'].__getitem__('type') == 'STT_FUNC':
                        if entry['st_value'] != 0:
                            address.append('0x'+str(numpy.base_repr(entry['st_value'], base=16)).lower())
        return address


    def getExecutableSections(self): #memorizza anche l'indirizzo di partenza
        self.parse_symtab_for_call_address()
        ret = {}
        for s in self._elf.iter_sections():
            if s.header['sh_flags'] & SH_FLAGS.SHF_EXECINSTR: #0x4
                ret[s['sh_addr']] = s.data()
        return ret

    @property
    def arch(self):
        return self._arch

    @property
    def arch_mode(self):
        return self._arch_mode





