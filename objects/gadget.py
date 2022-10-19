import numpy
from capstone import CS_MODE_32


class Gadget:
    def __init__(self):
        self.instructions = []
        self.address = 0
        self.arch = None

    def is_rop(self):
        return self.instructions[-1].mnemonic == 'ret'

    def is_jop(self):
        return self.instructions[-1].mnemonic == 'jmp'

    def is_sys(self):
        return self.instructions[-1].mnemonic.__contains__('sys')

    def __str__(self) -> str:
        s = ''
        if self.arch == CS_MODE_32:
            s += '0x00'
        else:
            s += '0x0000'
        s += str(numpy.base_repr(self.address, base=16)).lower() + ': '
        for i in self.instructions:
            s += i.__str__()
        return s

    def __eq__(self, o: object) -> bool:
        assert type(o) == Gadget
        if len(self.instructions) != len(o.instructions):
            return False
        for i, inst in enumerate(self.instructions):
            if not inst.__eq__(o.instructions[i]):
                return False
        return True

    def __hash__(self) -> int:
        return hash(tuple(self.instructions))


class Instruction:
    def __init__(self, mnemonic, operands):
        self.mnemonic = mnemonic
        self.operands = operands

    def __str__(self) -> str:
        return self.mnemonic + ' ' + self.operands + ' ; '

    def __eq__(self, o: object) -> bool:
        assert type(o) == Instruction
        if self.mnemonic == o.mnemonic and self.operands == o.operands:
            return True
        return False

    def __hash__(self) -> int:
        return hash(self.__str__())
