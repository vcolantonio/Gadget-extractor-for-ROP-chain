import re
import time

from binaryLoader.load_elf import ELF
from objects.gadget import Gadget, Instruction
import capstone.x86_const as const
from capstone import *

args = None


def finder(section, md, arch, direct_call_address):
    gadgets = backward(section, md, arch, direct_call_address)

    ok_gadgets = []
    stop_inst = ["ret", "retf", "jmp", "call", "sysenter", "syscall"]

    for g in gadgets:
        if g.instructions[-1].mnemonic not in stop_inst:
            continue
        for i in g.instructions:
            if 'ret' in i.mnemonic:
                continue

        ok_gadgets += [g]

    return ok_gadgets


def is_stop_instruction(inst):
    return inst.id == const.X86_INS_RET or inst.id == const.X86_INS_JMP  \
           or inst.id == const.X86_INS_SYSCALL or inst.id == const.X86_INS_RETF or inst.id == const.X86_INS_SYSENTER


def backward(section, md, arch, direct_call_address):
    max_gadget_len = args.length
    max_inst_bytes = 15  # for x86 arch
    max_offset = max_inst_bytes * max_gadget_len

    found = []
    stop_bytes = [
        b"\xc3",  # ret
        b"\xc2[\x00-\xff]{2}"  # ret <imm>
        b"\xff[\x20\x21\x22\x23\x26\x27]{1}",  # jmp  [reg]
        b"\xff[\xe0\xe1\xe2\xe3\xe4\xe6\xe7]{1}",  # jmp  [reg]
        b"\xff[\x10\x11\x12\x13\x16\x17]{1}",  # jmp  [reg]
        #b"\xff[\xd0\xd1\xd2\xd3\xd4\xd6\xd7]{1}"  # call [reg]
        b"\x0f\x34", #sysenter
        b"\x0f\x05", #syscall
        b"\xcd\x80" #int 0x80
    ]

    for stop in stop_bytes:
        stop_found = [s.end() for s in re.finditer(stop, section[1])]
        for s in stop_found:
            for offset in range(1, max_offset + 1):
                gadget = Gadget()
                gadget.arch = arch
                to_disass = section[1][s - offset:s]
                for inst in md.disasm(to_disass, section[0] + s - offset):
                    if inst.id != const.X86_INS_INVALID:
                        gadget.address = section[0] + s - offset
                        if inst.id == const.X86_INS_CALL or inst.id == const.X86_INS_JMP:

                            if inst.op_str[0] == '0' and not inst.op_str in direct_call_address:  # is an address and not a register
                                break
                            if inst.id == const.X86_INS_CALL and not (inst.op_str[0] == 'r' or 'e'):
                                break
                            #if inst.mnemonic == 'jmp' and inst.op_str in ['r8','r9','r10','r11','r12','r13','r14','r15']:
                            #    break

                        if is_stop_instruction(inst) and len(gadget.instructions) <= max_gadget_len:
                            gadget.instructions.append(Instruction(inst.mnemonic, inst.op_str))
                            break
                        # istruzione valida ma non terminale
                        gadget.instructions.append(Instruction(inst.mnemonic, inst.op_str))
                    else:
                        break

                if 0 < len(gadget.instructions) <= max_gadget_len:  # gadget della lunghezza desiderata
                    #if len(gadget.instructions) > 1:
                    found.append(gadget)

    return found


def order(gadgets):
    return sorted(gadgets, key=lambda g: g.instructions[0].__str__())


def duplicate_removal(gadgets):
    return list(set(gadgets))


def get_direct_call_address(disassembler, sections_data):
    direct_call_address = set()
    for d in sections_data.items():
        disass = disassembler.disasm_lite(d[1], d[0])
        for (address, size, mnemonic, op_str) in disass:
            if mnemonic == 'call':
                if op_str[0] == '0':  # non si tratta di un registro
                    direct_call_address.add(op_str)

    return direct_call_address


def init_elf_and_disassembler(file):
    elf = ELF(file)
    elf.load()
    sections_data = elf.getExecutableSections()

    md = Cs(elf.arch, elf.arch_mode)
    md.detail = True
    md.syntax = CS_OPT_SYNTAX_INTEL
    # md.skipdata_setup = ("db", None, None)
    md.skipdata = True
    #direct_call_address = elf.parse_symtab_for_call_address()
    direct_call_address = get_direct_call_address(md, sections_data)
    search(sections_data, md, elf, direct_call_address)


def search(sections_data, md, elf, direct_call_address):
    result = []

    for t in sections_data.items():
        result += finder(t, md, elf.arch_mode, direct_call_address)



    result = duplicate_removal(result)
    ordered = order(result)

    if args.type == '' and args.instruction == '':
        print_gadgets(ordered)
    elif args.type == '':
        print_gadgets(get_gadget_from_instruction(ordered,args.instruction))
    elif args.instruction == '':
        if args.type == 'rop':
            print_gadgets(get_rop_gadget(ordered))
        elif args.type == 'jop':
            print_gadgets(get_jop_gadget(ordered))
        elif args.type == 'sys':
            print_gadgets(get_sys_gadget(ordered))
        else:
            print_gadgets(ordered)
    else:
        if args.type == 'rop':
            print_gadgets(get_rop_gadget(get_gadget_from_instruction(ordered, args.instruction)))
        elif args.type == 'jop':
            print_gadgets(get_jop_gadget(get_gadget_from_instruction(ordered, args.instruction)))
        else:
            print_gadgets(get_sys_gadget(get_gadget_from_instruction(ordered, args.instruction)))


def get_rop_gadget(gadgets):
    ris = []
    for g in gadgets:
        if g.is_rop():
            ris.append(g)
    return ris


def get_jop_gadget(gadgets):
    ris = []
    for g in gadgets:
        if g.is_jop():
            ris.append(g)
    return ris


def get_sys_gadget(gadgets):
    ris = []
    for g in gadgets:
        if g.is_sys():
            ris.append(g)
    return ris


def get_gadget_from_instruction(gadgets, inst):
    ris = []
    for g in gadgets:
        for i in g.instructions:
            if inst in i.__str__():
                ris.append(g)
                break
    return ris

def print_gadgets(gadgets):
    for g in gadgets:
        print(g.__str__())
    print()
    print('Total gadgets found: ', len(gadgets))


# random_data = b"\xed\x00\x00\x00\x00\x1a\x5a\x0f\x1f\xff\xc2\x09\x80\x00\x00\x00\x07\xf7\xeb\x2a\xff\xff\x7f\x57\xe3\x01\xff\xff\x7f\x57\xeb\x00\xf0\x00\x00\x24\xb2\x4f\x00\x78"

def main(options):
    global args
    args = options
    init_elf_and_disassembler(args.file_path)



