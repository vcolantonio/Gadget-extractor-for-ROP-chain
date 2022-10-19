import argparse
import gadgetsFinder.search as search

parser = argparse.ArgumentParser("Description")
parser.add_argument("-f", "--file_path", action='store', type=str, help="File path to analyze", required=True)
parser.add_argument("-l", "--length", action='store', type=int, default=5, help="Max number of instructions for gadget (default 5)")
parser.add_argument("-t", "--type", action='store', type=str, default='', help="Gadget type: rop, jop or sys")
parser.add_argument("-i", "--instruction", action='store', type=str, default='', help="Print all gadgets that contains this instruction mnemonic")

args = parser.parse_args()
search.main(args)


