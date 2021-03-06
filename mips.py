#!/usr/bin/python3 -OO
'''
Intelligently disassemble and reassemble MIPS binaries
'''
from __future__ import print_function
import sys, os, struct, ctypes, re, logging, pdb
from collections import OrderedDict, defaultdict
from ctypes import c_byte, c_int16, c_int32, c_int64

logging.basicConfig(level=logging.DEBUG if __debug__ else logging.WARN)

try:
    EXECUTABLE, COMMAND, *ARGV = sys.argv
    EXEC = os.path.splitext(os.path.basename(EXECUTABLE))[0]
    if EXEC == 'doctest':
        DOCTESTDEBUG = logging.debug
    else:
        DOCTESTDEBUG = lambda *args, **kwargs: None
except ValueError:
    logging.error('sys.argv: %s', sys.argv)
    if len(sys.argv) == 1 and sys.argv[0] == '':
        logging.info('module being imported, not a problem')
    else:
        raise ValueError('Must specify command and args for that function')
MATCH_OBJDUMP_DISASSEMBLY = bool(os.getenv('MATCH_OBJDUMP_DISASSEMBLY'))

# labels will cause objdump -D output and mips disassemble output to differ
# same if instructions with bad args are turned into .word 0xNNNNNNNN
USE_LABELS = AGGRESSIVE_WORDING = not MATCH_OBJDUMP_DISASSEMBLY
INTCTLVS = os.getenv('MIPS_INTCTLVS', '00100')  # IntCtlVS
VECTORS = os.getenv('VECTORS', 32)  # 64 on 64 bit machines (?)
logging.warning('USE_LABELS = %s, AGGRESSIVE_WORDING=%s', USE_LABELS,
                AGGRESSIVE_WORDING)

LABELS = {}  # filled in by init()

STATE = OrderedDict()  # filled in by init()

MEMORY = bytearray()

REGISTER = [
    '$' + registername for registername in [
        'zero',
        'at',
        'v0', 'v1',
        'a0', 'a1', 'a2', 'a3',
        't0', 't1', 't2', 't3', 't4', 't5', 't6', 't7',
        's0', 's1', 's2', 's3', 's4', 's5', 's6', 's7',
        't8', 't9',
        'k0', 'k1',
        'gp',  # global area pointer, base of global data segment
        'sp',  # stack pointer
        'fp',  # frame pointer
        'ra',  # return address
    ]
]

ALTREG = [
    # for swc[2-3] and possibly other instructions
    '$' + str(n) for n in range(32)
]

FLOATREG = [
    # for swc1 and possibly other instructions
    '$f' + str(n) for n in range(32)
]

# pattern for reading assembly language
LINEPATTERN = r'^(?:(?P<label>[a-z0-9.]+):)?\s*'  # match label
LINEPATTERN += r'(?:(?P<mnemonic>[a-z0-9.]+)\s+)?'  # match mnemonic
LINEPATTERN += r'(?:(?P<args>[a-z0-9$()._,-]+)?\s*)?'  # match args
# assembler leaves a hint at the end of a comment when it turns
# a machine instruction into a macro/pseudoop. we use these to
# create identical images to original from unedited disassemblies.
LINEPATTERN += r"(?:#.*?(?:[(]from '(?P<was>[a-z0-9.]+)'[)])?)?\s*$"

# patterns for assembly language output
LABEL = '%(label)s'
MNEMONIC = '\t%(mnemonic)s'
ARGS = {
    'dst': '\t%(rd)s,%(rs)s,%(rt)s',
    'st': '\t%(rs)s,%(rt)s',
    'dt': '\t%(rd)s,%(rt)s',
    'dta': '\t%(rd)s,%(rt)s,%(amount)d',
    'dtx': '\t%(rd)s,%(rt)s,0x%(amount)x',
    'dts': '\t%(rd)s,%(rt)s,%(rs)s',
    'ds': '\t%(rd)s,%(rs)s',
    's': '\t%(rs)s',
    'd': '\t%(rd)s',
    't': '\t%(rt)s',
    'cc': '\t0x%(codehigh)x,0x%(code)x',
    'tsx': '\t%(rt)s,%(rs)s,0x%(immediate)x',
    'stc': '\t%(rs)s,%(rt)s,0x%(code)x',
    'tsi': '\t%(rt)s,%(rs)s,%(immediate)d',
    'si': '\t%(rs)s,%(immediate)d',
    'tx': '\t%(rt)s,0x%(immediate)x',
    'ti': '\t%(rt)s,%(immediate)d',
    'stl': '\t%(rs)s,%(rt)s,%(destination)s',
    'sl': '\t%(rs)s,%(destination)s',
    'txs': '\t%(rt)s,0x%(immediate)x(%(rs)s)',
    'tis': '\t%(rt)s,%(immediate)d(%(rs)s)',
    'ftis': '\t%(floatrt)s,%(immediate)d(%(rs)s)',
    'cvt': '\t%(floatrd)s,%(floatrs)s',
    'alttis': '\t%(altrt)s,%(immediate)d(%(rs)s)',
    'Tis': '\t0x%(target)x,%(immediate)d(%(rs)s)',
    'l': '\t%(destination)s',
    'i': '\t%(immediate)d',
    'x': '\t0x%(immediate)x',
    'X': '\t0x%(longimmediate)x',
    'jalx': '\t0x%(jalximmediate)x',
    'tC': '\t%(rt)s,%(coregister)s',
    'tC$': '\t%(rt)s,%(coregister)s,0x%(sel)x',
    'S': '\t0x%(longcode)x',
    'sync': '\t0x%(amount)x',
}
COMMENT = '\t# %(index)x: %(chunkstring)s %(comment)s'

PATTERN = {
    'arithlog': LABEL + MNEMONIC + ARGS['dst'] + COMMENT,
    'arithlogz': LABEL + MNEMONIC + ARGS['dt'] + COMMENT,
    'divmult': LABEL + MNEMONIC + ARGS['st'] + COMMENT,
    'shift': LABEL + MNEMONIC + ARGS['dtx'] + COMMENT,
    'shiftv': LABEL + MNEMONIC + ARGS['dts'] + COMMENT,
    'jumpr': LABEL + MNEMONIC + ARGS['s'] + COMMENT,
    'jumpr2': LABEL + MNEMONIC + ARGS['ds'] + COMMENT,
    'movefrom': LABEL + MNEMONIC + ARGS['d'] + COMMENT,
    'moveto': LABEL + MNEMONIC + ARGS['s'] + COMMENT,
    'arithlogi': LABEL + MNEMONIC + ARGS['tsi'] + COMMENT,
    'arithlogx': LABEL + MNEMONIC + ARGS['tsx'] + COMMENT,
    'loadi': LABEL + MNEMONIC + ARGS['ti'] + COMMENT,
    'loadx': LABEL + MNEMONIC + ARGS['tx'] + COMMENT,
    'branch': LABEL + MNEMONIC + ARGS['stl'] + COMMENT,
    'branchz': LABEL + MNEMONIC + ARGS['sl'] + COMMENT,
    'loadstore': LABEL + MNEMONIC + ARGS['tis'] + COMMENT,
    'floadstore': LABEL + MNEMONIC + ARGS['ftis'] + COMMENT,
    'altloadstore': LABEL + MNEMONIC + ARGS['alttis'] + COMMENT,
    'cache': LABEL + MNEMONIC + ARGS['Tis'] + COMMENT,
    'jump': LABEL + MNEMONIC + ARGS['l'] + COMMENT,
    'trap': LABEL + MNEMONIC + ARGS['x'] + COMMENT,
    'trap2': LABEL + MNEMONIC + ARGS['st'] + COMMENT,
    'trap3': LABEL + MNEMONIC + ARGS['stc'] + COMMENT,
    'trapi': LABEL + MNEMONIC + ARGS['si'] + COMMENT,
    'simple': LABEL + MNEMONIC + '\t' + COMMENT,
    'coprocessor': LABEL + MNEMONIC + ARGS['X'] + COMMENT,
    'jalx': LABEL + MNEMONIC + ARGS['jalx'] + COMMENT,
    'coproc_move': LABEL + MNEMONIC + ARGS['tC'] + COMMENT,
    'coproc_move3': LABEL + MNEMONIC + ARGS['tC$'] + COMMENT,
    'word': LABEL + MNEMONIC + '\t0x%(instruction)x' + COMMENT,
    'break': LABEL + MNEMONIC + ARGS['cc'] + COMMENT,
    'syscall': LABEL + MNEMONIC + ARGS['S'] + COMMENT,
    'cvt': LABEL + MNEMONIC + ARGS['cvt'] + COMMENT,
    'sync': LABEL + MNEMONIC + ARGS['sync'] + COMMENT,
}

ARGSEP = r'[,()]\s*'

PACKFORMAT = {
    # for Register.bytevalue
    32: '<L',
    64: '<Q',
}

INSTRUCTION = [
    # mnemonic, print pattern, save branch label, condition, signed, index
    # 'condition' is an expression to be `eval`d, and if false, '.word'
    # is used instead.
    # use of 'index' instead of writing out a complete list allows the
    # programmer to build incrementally
    # 'signed' is how the 16-bit 'immediate' or branch value is used
    # by the instruction.
    # values shown in hex are never signed in objdump disassembly.
    # use 'None' for 'save branch label' for instructions that have no
    #  branch calculation
    # use 'None' for 'signed' if there is no immediate value
    ['SPECIAL', 'shift', False, 'True', False, 0],
    ['REGIMM', 'branchz', False, 'True', False, 1],
    ['j', 'coprocessor', True, 'True', True, 2],
    ['jal', 'coprocessor', True, 'True', True, 3],
    ['beq', 'branch', True, 'True', True, 4],
    ['bne', 'branch', True, 'True', True, 5],
    ['blez', 'branchz', True, 'target == 0', True, 6],
    ['bgtz', 'branchz', True, 'target == 0', True, 7],
    ['addi', 'arithlogi', False, 'True', True, 8],
    # 'addiu' and some others, although called, 'unsigned', actually use signed
    #  arithmetic, but disregard overflow, as in the C language.
    ['addiu', 'arithlogi', False, 'True', True, 9],
    ['slti', 'arithlogi', False, 'True', True, 10],
    ['sltiu', 'arithlogi', False, 'True', True, 11],
    ['andi', 'arithlogx', False, 'True', False, 12],
    ['ori', 'arithlogx', False, 'True', False, 13],
    ['xori', 'arithlogx', False, 'True', True, 14],
    ['lui', 'loadx', False, 'source == 0', False, 15],
    ['COP0', 'coprocessor', False, 'True', False, 16],
    ['COP1', 'coprocessor', False, 'True', False, 17],
    ['COP2', 'coprocessor', False, 'True', False, 18],
    ['COP3', 'coprocessor', False, 'True', False, 19],
    ['beql', 'branch', True, 'True', True, 20],
    ['bnel', 'branch', True, 'True', True, 21],
    ['blezl', 'branchz', True, 'target == 0', True, 22],
    ['bgtzl', 'branchz', True, 'target == 0', True, 23],
    ['daddi', 'arithlogi', False, 'True', True, 24],
    ['daddiu', 'arithlogi', False, 'True', True, 25],
    ['ldl', 'loadstore', True, 'True', True, 26],
    ['ldr', 'loadstore', True, 'True', True, 27],
    ['SPECIAL2', 'arithlog', True, 'True', True, 28],
    ['jalx', 'jalx', True, 'True', True, 29],
    ['lb', 'loadstore', True, 'True', True, 32],
    ['lh', 'loadstore', True, 'True', True, 33],
    ['lwl', 'loadstore', True, 'True', True, 34],
    ['lw', 'loadstore', True, 'True', True, 35],
    ['lbu', 'loadstore', True, 'True', True, 36],
    ['lhu', 'loadstore', True, 'True', True, 37],
    ['lwr', 'loadstore', True, 'True', True, 38],
    ['lwu', 'loadstore', True, 'True', True, 39],
    ['sb', 'loadstore', True, 'True', True, 40],
    ['sh', 'loadstore', True, 'True', True, 41],
    ['swl', 'loadstore', True, 'True', True, 42],
    ['sw', 'loadstore', True, 'True', True, 43],
    ['sdl', 'loadstore', True, 'True', True, 44],
    ['sdr', 'loadstore', True, 'True', True, 45],
    ['swr', 'loadstore', True, 'True', True, 46],
    ['cache', 'cache', True, 'True', True, 47],
    ['ll', 'loadstore', True, 'True', True, 48],
    ['lwc1', 'floadstore', False, 'True', True, 49],
    ['lwc2', 'altloadstore', False, 'True', True, 50],
    ['lwc3', 'altloadstore', False, 'True', True, 51],
    ['lld', 'loadstore', False, 'True', True, 52], # there is no 'lcd0'
    ['ldc1', 'floadstore', False, 'True', True, 53],
    ['ldc2', 'altloadstore', False, 'True', True, 54],
    ['ld', 'loadstore', False, 'True', True, 55],  # there is no 'ldc3'
    ['sc', 'loadstore', False, 'True', True, 56],
    ['swc1', 'floadstore', False, 'True', True, 57],
    ['swc2', 'altloadstore', False, 'True', True, 58],
    ['swc3', 'altloadstore', False, 'True', True, 59],
    ['scd', 'loadstore', False, 'True', True, 60],
    ['sdc1', 'floadstore', False, 'True', True, 61],
    ['sdc2', 'altloadstore', False, 'True', True, 62],
    ['sd', 'loadstore', True, 'True', True, 63]
]

# .word is used where no legal instruction exists
WORD = ['.word', 'word', False, 'True', False]
# also used during development of this script for unimplemented instructions

REGIMM = [
    ['bltz', 'branchz', True, 'True', True, 0],
    ['bgez', 'branchz', True, 'True', True, 1],
    ['bltzl', 'branchz', True, 'True', True, 2],
    ['bgezl', 'branchz', True, 'True', True, 3],
    ['tgei', 'trapi', False, 'True', False, 8],
    ['tgeiu', 'trapi', False, 'True', False, 9],
    ['tlti', 'trapi', False, 'True', True, 10],
    ['tltiu', 'trapi', False, 'True', True, 11],
    ['teqi', 'trapi', False, 'True', True, 12],
    ['tnei', 'trap', False, 'True', False, 14],
    ['bltzal', 'branchz', True, 'True', True, 16],
    ['bgezal', 'branchz', True, 'True', True, 17],
    ['bltzall', 'branchz', True, 'True', True, 18],
    ['bgezall', 'branchz', True, 'True', True, 19],
]

SPECIAL = [
    ['sll', 'shift', False, 'source == 0', True, 0],
    ['srl', 'shift', False, 'source == 0', True, 2],
    ['sra', 'shift', False, 'source == 0', None, 3],
    ['sllv', 'shiftv', None, 'amount == 0', None, 4],
    ['srlv', 'shiftv', None, 'amount == 0', None, 6],
    ['srav', 'shiftv', None, 'amount == 0', None, 7],
    ['jr', 'jumpr', True, 'target == dest == amount == 0', True, 8],
    ['jalr', 'jumpr2', True, 'target == amount == 0', True, 9],
    ['movz', 'arithlog', None, 'amount == 0', None, 10],
    ['movn', 'arithlog', None, 'amount == 0', None, 11],
    ['syscall', 'syscall', False, 'True', False, 12],
    ['break', 'simple', False, 'True', False, 13],
    ['sync', 'sync', False, 'source == target == dest == 0', False, 15],
    ['mfhi', 'movefrom', False, 'source == target == amount == 0', False, 16],
    ['mthi', 'moveto', False, 'target == dest == amount == 0', False, 17],
    ['mflo', 'movefrom', False, 'source == target == amount == 0', False, 18],
    ['mtlo', 'moveto', False, 'target == dest == amount == 0', False, 19],
    ['dsllv', 'shiftv', False, 'amount == 0', False, 20],
    ['dsrlv', 'shiftv', False, 'amount == 0', False, 22],
    ['dsrav', 'arithlog', False, 'amount == 0', True, 23],
    ['mult', 'divmult', None, 'dest == amount == 0', None, 24],
    ['multu', 'divmult', None, 'dest == amount == 0', None, 25],
    ['div', 'divmult', False, 'dest == amount == 0', True, 26],
    ['divu', 'divmult', False, 'dest == amount == 0', True, 27],
    ['dmult', 'arithlog', False, 'dest == amount == 0', True, 28],
    ['dmultu', 'arithlog', False, 'dest == amount == 0', True, 29],
    ['ddiv', 'divmult', False, 'dest == amount == 0', True, 30],
    ['ddivu', 'divmult', False, 'dest == amount == 0', True, 31],
    ['add', 'arithlog', False, 'amount == 0', True, 32],
    ['addu', 'arithlog', False, 'amount == 0', True, 33],
    ['sub', 'arithlog', False, 'amount == 0', True, 34],
    ['subu', 'arithlog', False, 'amount == 0', False, 35],
    ['and', 'arithlog', False, 'amount == 0', False, 36],
    ['or', 'arithlog', False, 'amount == 0', False, 37],
    ['xor', 'arithlog', False, 'amount == 0', False, 38],
    ['nor', 'arithlog', False, 'amount == 0', False, 39],
    ['slt', 'arithlog', None, 'amount == 0', None, 42],
    ['sltu', 'arithlog', None, 'amount == 0', None, 43],
    ['dadd', 'arithlog', False, 'amount == 0', True, 44],
    ['daddu', 'arithlog', False, 'amount == 0', True, 45],
    ['dsub', 'arithlog', False, 'amount == 0', True, 46],
    ['dsubu', 'arithlog', False, 'amount == 0', True, 47],
    ['tge', 'divmult', False, 'True', False, 48],
    ['tgeu', 'divmult', False, 'True', False, 49],
    ['tlt', 'divmult', False, 'True', False, 50],
    ['tltu', 'trap3', False, 'True', False, 51],
    ['teq', 'divmult', False, 'True', False, 52],
    ['tne', 'trap3', False, 'True', False, 54],
    ['dsll', 'shift', False, 'source == 0', False, 56],
    ['dsrl', 'shift', False, 'source == 0', False, 58],
    ['dsra', 'shift', False, 'source == 0', True, 59],
    ['dsll32', 'shift', False, 'source == 0', False, 60],
    ['dsrl32', 'shift', False, 'source == 0', False, 62],
    ['dsra32', 'shift', False, 'source == 0', True, 63]
]

SPECIAL2 = [
    ['mul', 'arithlog', None, 'amount == 0', None, 2],
]

COP0 = [
    ['mfc0', 'coproc_move', False, 'mtzero == 0', False, 0],
    ['mtc0', 'coproc_move', False, 'mtzero == 0', False, 4],
    ['c0', 'coprocessor', False, 'True', False, 16],
    ['c0', 'coprocessor', False, 'True', False, 17],
    ['c0', 'coprocessor', False, 'True', False, 18],
    ['c0', 'coprocessor', False, 'True', False, 19],
    ['c0', 'coprocessor', False, 'True', False, 20],
    ['c0', 'coprocessor', False, 'True', False, 21],
    ['c0', 'coprocessor', False, 'True', False, 22],
    ['c0', 'coprocessor', False, 'True', False, 23],
    ['c0', 'coprocessor', False, 'True', False, 24],
    ['c0', 'coprocessor', False, 'True', False, 25],
    ['c0', 'coprocessor', False, 'True', False, 26],
    ['c0', 'coprocessor', False, 'True', False, 27],
    ['c0', 'coprocessor', False, 'True', False, 28],
    ['c0', 'coprocessor', False, 'True', False, 29],
    ['c0', 'coprocessor', False, 'True', False, 30],
    ['c0', 'coprocessor', False, 'True', False, 31],
]

COP1 = [
    ['c1', 'coprocessor', False, 'True', False, 16],
    ['c1', 'coprocessor', False, 'True', False, 17],
    ['c1', 'coprocessor', False, 'True', False, 18],
    ['c1', 'coprocessor', False, 'True', False, 19],
    ['c1', 'coprocessor', False, 'True', False, 20],
    ['c1', 'coprocessor', False, 'True', False, 21],
    ['c1', 'coprocessor', False, 'True', False, 22],
    ['c1', 'coprocessor', False, 'True', False, 23],
    ['c1', 'coprocessor', False, 'True', False, 24],
    ['c1', 'coprocessor', False, 'True', False, 25],
    ['c1', 'coprocessor', False, 'True', False, 26],
    ['c1', 'coprocessor', False, 'True', False, 27],
    ['c1', 'coprocessor', False, 'True', False, 28],
    ['c1', 'coprocessor', False, 'True', False, 29],
    ['c1', 'coprocessor', False, 'True', False, 30],
    ['c1', 'coprocessor', False, 'True', False, 31],
]

COP2 = [
    ['c2', 'coprocessor', False, 'True', False, 16],
    ['c2', 'coprocessor', False, 'True', False, 17],
    ['c2', 'coprocessor', False, 'True', False, 18],
    ['c2', 'coprocessor', False, 'True', False, 19],
    ['c2', 'coprocessor', False, 'True', False, 20],
    ['c2', 'coprocessor', False, 'True', False, 21],
    ['c2', 'coprocessor', False, 'True', False, 22],
    ['c2', 'coprocessor', False, 'True', False, 23],
    ['c2', 'coprocessor', False, 'True', False, 24],
    ['c2', 'coprocessor', False, 'True', False, 25],
    ['c2', 'coprocessor', False, 'True', False, 26],
    ['c2', 'coprocessor', False, 'True', False, 27],
    ['c2', 'coprocessor', False, 'True', False, 28],
    ['c2', 'coprocessor', False, 'True', False, 29],
    ['c2', 'coprocessor', False, 'True', False, 30],
    ['c2', 'coprocessor', False, 'True', False, 31],
]

COP3 = [
    ['c3', 'coprocessor', False, 'True', False, 16],
    ['c3', 'coprocessor', False, 'True', False, 17],
    ['c3', 'coprocessor', False, 'True', False, 18],
    ['c3', 'coprocessor', False, 'True', False, 19],
    ['c3', 'coprocessor', False, 'True', False, 20],
    ['c3', 'coprocessor', False, 'True', False, 21],
    ['c3', 'coprocessor', False, 'True', False, 22],
    ['c3', 'coprocessor', False, 'True', False, 23],
    ['c3', 'coprocessor', False, 'True', False, 24],
    ['c3', 'coprocessor', False, 'True', False, 25],
    ['c3', 'coprocessor', False, 'True', False, 26],
    ['c3', 'coprocessor', False, 'True', False, 27],
    ['c3', 'coprocessor', False, 'True', False, 28],
    ['c3', 'coprocessor', False, 'True', False, 29],
    ['c3', 'coprocessor', False, 'True', False, 30],
    ['c3', 'coprocessor', False, 'True', False, 31],
]

COREGISTER = {
    # see https://en.wikichip.org/wiki/mips/coprocessor_0
    0b00000: 'c0_index',
    0b00001: 'c0_random',
    0b00010: 'c0_entrylo0',
    0b00011: 'c0_entrylo1',
    0b00100: 'c0_context',
    0b00101: 'c0_pagemask',
    0b00110: 'c0_wired',
    0b00111: 'c0_hwrena',
    0b01000: 'c0_badvaddr',
    0b01001: 'c0_count',
    0b01010: 'c0_entryhi',
    0b01011: 'c0_compare',
    0b01100: 'c0_sr',  # selector 0
    # with selector 1: intctl, interrupt vector setup
    # with selector 2: srsctl, shadow register control
    # with selector 3: srsmap, shadow register map
    0b01101: 'c0_cause',
    0b01110: 'c0_epc',
    0b01111: 'c0_prid',  # selector 0
    # with selector 1: ebase, exception entry point base address
    0b10000: 'c0_config',
    # with selector 1, 2, 3: config1, config2, config3
    0b10001: 'c0_lladdr',
    0b10010: 'c0_watchlo',
    0b10011: 'c0_watchhi',
    # 20, 21, 22 unused(?)
    0b10111: 'c0_debug',
    0b11000: 'c0_depc',
    0b11001: 'c0_perfctl', # selector 0
    # with selector 1: perfcnt
    0b11010: 'c0_ecc',
    0b11011: 'c0_cacheerr',
    0b11100: 'c0_taglo', # selector 0
    # with selector 1: datalo
    0b11101: 'c0_taghi', # selector 0
    # with selector 1: datahi
}

INSTRUCTIONS = {
    'SPECIAL': SPECIAL,
    'SPECIAL2': SPECIAL2,
    'REGIMM': REGIMM,
    'COP0': COP0,
    'COP1': COP1,
    'COP2': COP2,
    'COP3': COP3,
}

REFERENCE = {
    # This is primarily for assembly, whereas other tables were made
    # for disassembly. Ideally we will come up with a format that suits
    # both purposes well, and possibly emulation too.
    # from https://s3-eu-west-1.amazonaws.com/downloads-mips/documents/
    # MD00086-2B-MIPS32BIS-AFP-05.04.pdf starting page 45, and
    # https://www.cs.cmu.edu/afs/cs/academic/class/15740-f97/public/doc/
    # mips-isa.pdf starting page A-28.
    'fmt': {  # 5-bit field for floating point instructions
        # from http://hades.mech.northwestern.edu/images/a/af/
        # MIPS32_Architecture_Volume_I-A_Introduction.pdf, table 7.20
        'docs': [
            ['0-15', 'reserved'],
            ['S', '10000', 'single precision, 32 bits'],
            ['D', '10001', 'double precision, 64 bits'],
            ['18-19', 'reserved'],
            ['W', '10100', 'fixed-point word, 32 bits'],
            ['L', '10101', 'fixed-point long, 64 bits'],
            ['PS', '10110', 'paired single, 32 bits each'],  # removed rel. 6
            ['23-31', 'reserved'],
        ],
    },
    'fmt3': {  # 3-bit field for floating point instructions
        # from http://hades.mech.northwestern.edu/images/a/af/
        # MIPS32_Architecture_Volume_I-A_Introduction.pdf, table 7.20
        'docs': [
            ['S', '000', 'single precision, 32 bits'],
            ['D', '001', 'double precision, 64 bits'],
            ['2-3', 'reserved'],
            ['W', '100', 'fixed-point word, 32 bits'],
            ['L', '101', 'fixed-point long, 64 bits'],
            ['PS', '110', 'paired single, 32 bits each'],  # removed rel. 6
            ['7', 'reserved'],
        ],
    },
    '.set': {
        'type': 'assembler directive',
        'action': 'logging.debug("Nothing to do for %r", mnemonic)',
    },
    '.word': {
        'type': 'assembler directive',
        'fields': [
            ['immediate', 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'],
        ],
        'args': ['immediate'],
        'emulation': [
            'raise Exception("%s not executable code", hex(immediate))',
        ],
    },
    'abs.s': {
        'fields': [
            ['COP1', '010001'],
            ['fmt', '10000'],  # fmt for single is 16, 0x10
            ['0', '00000'],
            ['fs', 'bbbbb'],
            ['fd', 'bbbbb'],
            ['ABS', '000101'],
        ],
        'args': ['fd,fs'],
        'emulation': ['fd.value = abs(fs)'],
    },
    'abs.d': {
        'fields': [
            ['COP1', '010001'],
            ['fmt', '10001'],  # fmt for double is 17, 0x11
            ['0', '00000'],
            ['fs', 'bbbbb'],
            ['fd', 'bbbbb'],
            ['ABS', '000101'],
        ],
        'args': ['fd,fs'],
        'emulation': ['fd.value = abs(fs)'],
    },
    'abs.ps': {
        'fields': [
            ['COP1', '010001'],
            ['fmt', '10110'],  # fmt for paired-single is 22, 0x16
            ['0', '00000'],
            ['fs', 'bbbbb'],
            ['fd', 'bbbbb'],
            ['ABS', '000101'],
        ],
        'args': ['fd,fs'],
        'emulation': ['fd.value = abs(fs)'],
    },
    'add': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['ADD', '100000'],
        ],
        'args': ['rd,rs,rt'],
        'emulation': ['rd.value = mips_add(rs, rt, 32, False)'],
    },
    'addi': {
        'fields': [
            ['ADDI', '001000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,rs,immediate'],
        'emulation': ['arg = c_int16(immediate).value',
                      'rt.value = mips_add(rs, arg, 32, False)']
    },
    'addiu': {
        'fields': [
            ['ADDIU', '001001'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,rs,immediate'],
        'emulation': ['arg = c_int16(immediate).value',  # sign-extend it
                      'rt.value = mips_add(rs, rt, 32, True)'],
    },
    'addu': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['ADDU', '100001'],
        ],
        'args': ['rd,rs,rt'],
        'emulation': ['rd.value = mips_add(rs, rt, 32, True)'],
    },
    'and': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['AND', '100100'],
        ],
        'args': ['rd,rs,rt'],
        'emulation': ['rd.value = rs & rt'],
    },
    'andi': {
        'fields': [
            ['ANDI', '001100'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,rs,immediate'],
        'emulation': ['rt.value = rs & immediate'],
    },
    'b': {
        'alias_of': [['beq', '$zero,$zero,offset']],
        'args': 'offset',
    },
    'bal': {
        'alias_of': [['bgezal', '$zero,offset']],
        'args': 'offset',
    },
    'beq': {
        'fields': [
            ['BEQ', '000100'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,rt,offset'],
        'emulation': ['if rs == rt: address = (offset << 2) + pc; '
                     'do_next(); jump(address)'],
    },
    'beql': {
        'fields': [
            ['BEQ', '010100'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,rt,offset'],
        'emulation': ['if rs == rt: mips_branch(offset, likely=True)'],
    },
    'beqz': {
        'alias_of': [['beq', 'rs,$zero,offset']],
        'args': 'rs,offset',
    },
    'beqzl': {
        'alias_of': [['beql', 'rs,$zero,offset']],
        'args': 'rs,offset',
    },
    'bgez': {
        'fields': [
            ['REGIMM', '000001'],
            ['rs', 'bbbbb'],
            ['BGEZ', '00001'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,offset'],
        'emulation': ['if rs >= 0: mips_jump(offset)'],
    },
    'bgezal': {
        'fields': [
            ['REGIMM', '000001'],
            ['rs', 'bbbbb'],
            ['BGEZAL', '10001'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,offset'],
        'emulation': ['if rs >= 0: mips_jump(offset)'],
    },
    'bgezall': {
        'fields': [
            ['REGIMM', '000001'],
            ['rs', 'bbbbb'],
            ['BGEZAL', '10011'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,offset'],
        'emulation': ['if rs >= 0: mips_jump(offset, likely=True)'],
    },
    'bgezl': {
        'fields': [
            ['REGIMM', '000001'],
            ['rs', 'bbbbb'],
            ['BGEZL', '00011'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,offset'],
        'emulation': ['if rs >= 0: mips_jump(offset, likely=True)'],
    },
    'bgtz': {
        'fields': [
            ['BGTZ', '000111'],
            ['rs', 'bbbbb'],
            ['0', '00000'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,offset'],
        'emulation': ['if mips_signed(rs.value, rs.size) > 0: '
                     'do_next(); mips_jump(offset)'],
    },
    'bgtzl': {
        'fields': [
            ['BGTZL', '010111'],
            ['rs', 'bbbbb'],
            ['0', '00000'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,offset'],
        'emulation': ['if rs > 0: mips_jump(offset, likely=True)'],
    },
    'blez': {
        'fields': [
            ['BLEZ', '000110'],
            ['rs', 'bbbbb'],
            ['0', '00000'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,offset'],
        'emulation': ['if mips_signed(rs.value, rs.size) < 0: '
                     'do_next(); mips_jump(offset)'],
    },
    'blezl': {
        'fields': [
            ['BLEZL', '010110'],
            ['rs', 'bbbbb'],
            ['0', '00000'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,offset'],
        'emulation': ['if rs < 0: mips_jump(offset)'],
    },
    'bltz': {
        'fields': [
            ['REGIMM', '000001'],
            ['rs', 'bbbbb'],
            ['BLTZ', '00000'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,offset'],
        'emulation': ['if mips_signed(rs.value, rs.size) < 0: '
                     'do_next(); mips_jump(offset)'],
    },
    'bltzal': {
        'fields': [
            ['REGIMM', '000001'],
            ['rs', 'bbbbb'],
            ['BLTZALL', '10000'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,offset'],
        'emulation': ['if rs < 0: mips_jump(offset)'],
    },
    'bltzall': {
        'fields': [
            ['REGIMM', '000001'],
            ['rs', 'bbbbb'],
            ['BLTZALL', '10010'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,offset'],
        'emulation': ['if rs < 0: mips_jump(offset, likely=True)'],
    },
    'bltzl': {
        'fields': [
            ['REGIMM', '000001'],
            ['rs', 'bbbbb'],
            ['BLTZ', '00010'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,offset'],
        'emulation': ['if rs < 0: mips_jump(offset, likely=True)'],
    },
    'bne': {
        'fields': [
            ['BNE', '000101'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,rt,offset'],
        'emulation': ['if rs.value != rt.value: address = (offset << 2) + pc; '
                     'do_next(); mips_jump(address)'],
    },
    'bnel': {
        'fields': [
            ['BNEL', '010101'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,rt,offset'],
        'emulation': ['if rs != rt: mips_jump(offset, likely=True)'],
    },
    'bnez': {
        'alias_of': [['bne', 'rs,$zero,offset']],
        'args': 'rs,offset',
    },
    'bnezl': {
        'alias_of': [['bnel', 'rs,$zero,offset']],
        'args': 'rs,offset',
    },
    'break': {
        'fields': [
            ['SPECIAL', '000000'],
            ['codehi', 'bbbbbbbbbb'],
            ['codelo', 'bbbbbbbbbb'],
            ['BREAK', '001101'],
        ],
        'args': ['codehi,codelo', [None, '0,0']],
        'emulation': ['mips_break()'],
    },
    'c0': {
        'fields': [
            ['COP0', '010000'],
            ['CO', '1'],
            ['immediate', 'bbbbbbbbbbbbbbbbbbbbbbbbb'],
        ],
        'args': ['immediate'],
        'emulation': ['logging.debug("ignoring c0 %s", hex(immediate))'],
    },
    'c1': {
        'fields': [
            ['COP1', '010001'],
            ['CO', '1'],
            ['immediate', 'bbbbbbbbbbbbbbbbbbbbbbbbb'],
        ],
        'args': ['immediate'],
        'emulation': ['logging.debug("ignoring c1 %s", hex(immediate))'],
    },
    'c2': {
        'fields': [
            ['COP2', '010010'],
            ['CO', '1'],
            ['immediate', 'bbbbbbbbbbbbbbbbbbbbbbbbb'],
        ],
        'args': ['immediate'],
        'emulation': ['logging.debug("ignoring c2 %s", hex(immediate))'],
    },
    'c3': {
        'fields': [
            ['COP3', '010011'],
            ['CO', '1'],
            ['immediate', 'bbbbbbbbbbbbbbbbbbbbbbbbb'],
        ],
        'args': ['immediate'],
        'emulation': ['logging.debug("ignoring c3 %s", hex(immediate))'],
    },
    'cache': {
        'fields': [
            ['CACHE', '101111'],
            ['base', 'bbbbb'],
            ['op', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['op,offset(base)'],
        'emulation': ['mips_cache(op, base, offset)'],
    },
    'cvt.s.d': {
        'fields': [
            ['COP1', '010001'],
            ['fmt', '10001'],  # 'D', doubleword
            ['0', '00000'],
            ['fs', 'bbbbb'],
            ['fd', 'bbbbb'],
            ['CVT.S', '100000'],
        ],
        'args': ['fd,fs'],
        'emulation': ['mips_cvt("s", "d", fs, fd)'],
    },
    'dadd': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['DADD', '101100'],
        ],
        'args': ['rd,rs,rt'],
        'emulation': ['rd.value = mips_add(rs, rt, 64, False)'],
    },
    'daddi': {
        'fields': [
            ['DADDI', '011000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,rs,immediate'],
        'emulation': ['arg = c_int16(immediate).value',  # sign-extend it
                      'rt.value = mips_add(rs, arg, 64, False)'],
    },
    'daddiu': {
        'fields': [
            ['DADDIU', '011001'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,rs,immediate'],
        'emulation': ['arg = c_int16(immediate).value',  # sign-extend it
                      'rt.value = mips_add(rs, arg, 64, True)'],
    },
    'daddu': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['DADDU', '101101'],
        ],
        'args': ['rd,rs,rt'],
        'emulation': ['rd.value = mips_add(rs, rt, 64, True)'],
    },
    'ddiv': {
        # obdjump incorrectly dumps ddiv as arithlog
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            #['0', '0000000000'], # correct, but replaced by following 2 lines
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['DDIV', '011110'],
        ],
        'args': ['rd,rs,rt', ['rs,rt', '$zero,rs,rt']],
        'emulation': ['lo.value, hi.value = mips_div(rs, rt, 64, False)'],
    },
    'ddivu': {
        # obdjump incorrectly dumps ddivu as arithlog
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            #['0', '0000000000'], # correct, but replaced by following 2 lines
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['DDIVU', '011111'],
        ],
        'args': ['rd,rs,rt', ['rs,rt', '$zero,rs,rt']],
        'emulation': ['lo.value, hi.value = mips_div(rs, rt, 64, True)'],
    },
    'deret': {
        'fields': [
            ['COP0', '010000'],
            ['CO', '1'],
            ['0', '0000000000000000000'],
            ['DERET', '011111'],
        ],
        'args': [None],
        'emulation': ['mips_deret()'],
    },
    'div': {
        # obdjump incorrectly dumps ddiv as arithlog
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            #['0', '0000000000'], # correct, but replaced by following 2 lines
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['DIV', '011010'],
        ],
        'args': ['rd,rs,rt', ['rs,rt', '$zero,rs,rt']],
        'emulation': ['lo.value, hi.value = mips_div(rs, rt, 32, False)'],
    },
    'divu': {
        # obdjump incorrectly dumps ddiv as arithlog
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            #['0', '0000000000'], # correct, but replaced by following 2 lines
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['DIVU', '011011'],
        ],
        'args': ['rd,rs,rt', ['rs,rt', '$zero,rs,rt']],
        'emulation': ['lo.value, hi.value = mips_div(rs, rt, 32, True)'],
    },
    'dmult': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['0', '0000000000'],
            ['DMULT', '011100'],
        ],
        'args': ['rs, rt'],
        'emulation': ['mips_mult(rs, rt, 64, False)'],
    },
    'dmultu': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['0', '0000000000'],
            ['DMULTU', '011101'],
        ],
        'args': ['rs, rt'],
        'emulation': ['mips_mult(rs, rt, 64, True)'],
    },
    'dneg': {
        'alias_of': [['dsub', 'rd,$zero,rt']],
        'args': 'rd,rt',
    },
    'dnegu': {
        'alias_of': [['dsubu', 'rd,$zero,rt']],
        'args': 'rd,rt',
    },
    'dsll': {
        'fields': [
            ['SPECIAL', '000000'],
            ['0', '00000'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['sa', 'bbbbb'],
            ['DSLL', '111000'],
        ],
        'args': ['rd,rt,sa'],
        'emulation': ['rd.value = rt << sa'],
    },
    'dsll32': {
        'fields': [
            ['SPECIAL', '000000'],
            ['0', '00000'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['sa', 'bbbbb'],
            ['DSLL32', '111100'],
        ],
        'args': ['rd,rt,sa'],
        'emulation': ['rd.value = rt << (sa + 32)'],
    },
    'dsllv': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['DSLLV', '010100'],
        ],
        'args': ['rd,rt,rs'],
        'emulation': ['rd.value = rt << rs & 0b11111'],
    },
    'dsra': {
        'fields': [
            ['SPECIAL', '000000'],
            ['0', '00000'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['sa', 'bbbbb'],
            ['DSRA', '111011'],
        ],
        'args': ['rd,rt,sa'],
        'emulation': ['rd.value = rt >> sa'],
    },
    'dsra32': {
        'fields': [
            ['SPECIAL', '000000'],
            ['0', '00000'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['sa', 'bbbbb'],
            ['DSRA32', '111111'],
        ],
        'args': ['rd,rt,sa'],
        'emulation': ['rd.value = rt >> (sa + 32)'],
    },
    'dsrav': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['DSRAV', '010111'],
        ],
        'args': ['rd,rt,rs'],
        'emulation': ['rd.value = rt >> rs'],
    },
    'dsrl': {
        'fields': [
            ['SPECIAL', '000000'],
            ['0', '00000'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['sa', 'bbbbb'],
            ['DSRL', '111010'],
        ],
        'args': ['rd,rt,sa'],
        'emulation': ['rd.uvalue = rt.uvalue >> sa'],
    },
    'dsrl32': {
        'fields': [
            ['SPECIAL', '000000'],
            ['0', '00000'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['sa', 'bbbbb'],
            ['DSRL', '111110'],
        ],
        'args': ['rd,rt,sa'],
        'emulation': ['rd.uvalue = rt.uvalue >> (sa + 32)'],
    },
    'dsrlv': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['DSRLV', '010110'],
        ],
        'args': ['rd,rt,rs'],
        'emulation': ['rd.uvalue = rt.uvalue >> (rs & 0b11111)'],
    },
    'dsub': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['DSUB', '101110'],
        ],
        'args': ['rd,rs,rt'],
        'emulation': ['rd.value = mips_sub(rs, rt, 64, False)'],
    },
    'dsubu': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['DSUB', '101111'],
        ],
        'args': ['rd,rs,rt'],
        'emulation': ['rd.value = mips_sub(rs, rt, 64, True)'],
    },
    'ehb': {
        'alias_of': [['sll', '$zero,$zero,3']],
        'args': None,
    },
    'eret': {
        'fields': [
            ['COP0', '010000'],
            ['CO', '1'],
            ['0', '0000000000000000000'],
            ['ERET', '011000'],
        ],
        'args': [None],
        'emulation': ['mips_eret()'],
    },
    'j': {
        'fields': [
            ['J', '000010'],
            ['target', 'bbbbbbbbbbbbbbbbbbbbbbbbbb'],
        ],
        'args': ['target'],
        'emulation': ['mips_jump(target)'],
    },
    'jal': {
        'fields': [
            ['JAL', '000011'],
            ['target', 'bbbbbbbbbbbbbbbbbbbbbbbbbb'],
        ],
        'args': ['target'],
        'emulation': ['mips_jump(target)'],
    },
    'jalr': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['', '00000'],
            ['rd', 'bbbbb'],
            ['', '00000'],
            ['JALR', '001001'],
        ],
        'args': ['rd,rs', ['rs', '$ra,rs']],
        'emulation': ['rd.value = pc + 4; do_next(); jump(rs.value)'],
    },
    'jalx': {
        'fields': [
            ['JALX', '011101'],
            ['target', 'bbbbbbbbbbbbbbbbbbbbbbbbbb'],
        ],
        'args': ['target'],
        'emulation': ['ra = (pc + 2) | isa_mode; address = target << 2; '
                     'do_next(); isa_mode ^= 1; jump(address)'],
    },
    'lb': {
        'fields': [
            ['LB', '100000'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['rt.value = c_byte(MEMORY[base + offset]).value'],
    },
    'ld': {
        'fields': [
            ['LD', '110111'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['rt.value = mips_load(base, offset, "d")'],
    },
    'ldc1': {
        'fields': [
            ['LDC1', '110101'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['mips_coprocessor_load(1, rt, base, offset)'],
    },
    'ldc2': {
        'fields': [
            ['LDC2', '110110'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['mips_coprocessor_load(2, rt, base, offset)'],
    },
    'lh': {
        'fields': [
            ['LB', '100001'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['mips_load(rt, base, offset, "h")'],
    },
    'll': {
        'fields': [
            ['LL', '110000'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['rt.value = mips_load(base, offset)'],
    },
    'lld': {
        'fields': [
            ['LLD', '110100'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['rt.value = mips_load(base, offset, bits=64)'],
    },
    'jr': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['', '000000000000000'],
            ['JR', '001000'],
        ],
        'args': ['rs'],
        'emulation': ['mips_jump(rs.value)'],
    },
    'lbu': {
        'fields': [
            ['LBU', '100100'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['rt.value = mips_load(base, offset, "b", signed=False)'],
    },
    'ldl': {
        'fields': [
            ['LDL', '011010'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['mips_ldl(rt, base, offset)'],
    },
    'ldr': {
        'fields': [
            ['LDR', '011011'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['mips_ldr(rt, base, offset)'],
    },
    'lhu': {
        'fields': [
            ['LHU', '100101'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['rt.uvalue = mips_load(offset, base, "h")'],
    },
    'li': {
        'alias_of': [['addiu', 'rt,$zero,offset'], ['ori', 'rt,$zero,offset']],
        'args': 'rt,offset',
    },
    'lui': {
        'fields': [
            ['LUI', '001111'],
            ['0', '00000'],
            ['rt', 'bbbbb'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,immediate'],
        'emulation': ['rt.value = c_int16(immediate).value'],
    },
    'lw': {
        'fields': [
            ['LW', '100011'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['mips_lw(rt, offset, base)'],
    },
    'lwc1': {
        'fields': [
            ['LWC1', '110001'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['mips_coprocessor_load(1, rt, offset, base, "w")'],
    },
    'lwc2': {
        'fields': [
            ['LWC2', '110010'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['mips_coprocessor_load(2, rt, offset, base, "w")'],
    },
    'lwc3': {
        'fields': [
            ['LWC3', '110011'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['mips_coprocessor_load(3, rt, offset, base, "w")'],
    },
    'lwl': {
        'fields': [
            ['LWL', '100010'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['mips_lw(rt, offset, base, "left")'],
    },
    'lwr': {
        'fields': [
            ['LWR', '100110'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['mips_lw(rt, offset, base, "right")'],
    },
    'lwu': {
        'fields': [
            ['LWU', '100111'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['rt.uvalue = mips_load(offset, base)'],
    },
    'mfc0': {
        'fields': [
            ['COP0', '010000'],
            ['MF', '00000'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['0', '00000000'],
            ['sel', 'bbb'],
        ],
        'args': ['rt,rd,sel', ['rt,rd', 'rt,rd,0']],
        'emulation': ['rt.value = mips_mfc0(rd, sel)'],
    },
    'mfhi': {
        'fields': [
            ['SPECIAL', '000000'],
            ['0', '0000000000'],
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['MFHI', '010000'],
        ],
        'args': ['rd'],
        'emulation': ['rd.value = hi.value'],
    },
    'mflo': {
        'fields': [
            ['SPECIAL', '000000'],
            ['0', '0000000000'],
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['MFLO', '010010'],
        ],
        'args': ['rd'],
        'emulation': ['rd.value = lo.value'],
    },
    'move': {
        'alias_of': [
            ['addu', 'rd,rs,$zero'],
            ['daddu', 'rd,rs,$zero'],
            ['or', 'rd,rs,$zero'],
        ],
        'args': 'rd,rs',
        'emulation': ['rd.value = rs.value'],
    },
    'movn': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['MOVN', '001011'],
        ],
        'args': ['rd,rs,rt'],
        'emulation': ['if rt != 0: rd.value = rs'],
    },
    'movz': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['MOVZ', '001010'],
        ],
        'args': ['rd,rs,rt'],
        'emulation': ['if rt == 0: rd.value = rs'],
    },
    'mtc0': {
        'fields': [
            ['COP0', '010000'],
            ['MT', '00100'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['0', '00000000'],
            ['sel', 'bbb'],
        ],
        'args': ['rt,rd,sel', ['rt,rd', 'rt,rd,0']],
        'emulation': ['mips_mtc(0, rd, sel, rt.value)'],
    },
    'mthi': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['0', '000000000000000'],
            ['MTHI', '010001'],
        ],
        'args': ['rs'],
        'emulation': ['mips_mthi(rs.value)'],
    },
    'mtlo': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['0', '000000000000000'],
            ['MTLO', '010011'],
        ],
        'args': ['rs'],
        'emulation': ['mips_mtlo(rs.value)'],
    },
    'mul': {
        'fields': [
            ['SPECIAL2', '011100'],
            ['rs', 'nnnnn'],
            ['rt', 'nnnnn'],
            ['rd', 'nnnnn'],
            ['0', '00000'],
            ['MUL', '000010'],
        ],
        'args': ['rd,rs,rt'],
        'emulation': ['rd.value = mips_mult(rs, rt, 32, False, True)'],
    },
    'mult': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['0', '0000000000'],
            ['MULT', '011000'],
        ],
        'args': ['rs, rt'],
        'emulation': ['mips_mult(rs, rt, 32, False)'],
    },
    'multu': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['0', '0000000000'],
            ['MULTU', '011001'],
        ],
        'args': ['rs, rt'],
        'emulation': ['mips_mult(rs, rt, 32, True)'],
    },
    'neg': {
        'alias_of': [['sub', 'rd,$zero,rt']],
        'args': 'rd,rt',
    },
    'negu': {
        'alias_of': [['subu', 'rd,$zero,rt']],
        'args': 'rd,rt',
    },
    'nop': {
        'alias_of': [['sll', '$zero,$zero,0']],
        'args': None,
    },
    'nor': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['NOR', '100111'],
        ],
        'args': ['rd,rs,rt'],
        'emulation': ['rd.value = (rs.value | rt.value) ^ -1'],
    },
    'or': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['OR', '100101'],
        ],
        'args': ['rd,rs,rt'],
        'emulation': ['rd.value = rs.value | rt.value'],
    },
    'ori': {
        'fields': [
            ['ORI', '001101'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,rs,immediate'],
        'emulation': ['rt.value = rs | immediate'],
    },
    'sb': {
        'fields': [
            ['SB', '101000'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['mips_store(offset, base, value, "b")'],
    },
    'sc': {
        'fields': [
            ['SC', '111000'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['mips_store(rt, base, offset, atomic=True)'],
    },
    'scd': {
        'fields': [
            ['SC', '111100'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['mips_store(rt, base, offset, "d", atomic=True)'],
    },
    'sd': {
        'fields': [
            ['SD', '111111'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['mips_store(offset + contents(base), contents(rt))'],
    },
    'sdc1': {
        'fields': [
            ['SDC1', '111101'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['mips_coprocessor_store(1, rt, offset, base, rt, "d")'],
    },
    'sdc2': {
        'fields': [
            ['SDC2', '111110'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['mips_coprocessor_store(2, rt, offset, base, rt, "d")'],
    },
    'sdl': {
        'fields': [
            ['SDL', '101100'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['mips_store(offset, base, rt, "d", "left")'],
    },
    'sdr': {
        'fields': [
            ['SDR', '101101'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['mips_store(offset, base, rt, "d", "right")'],
    },
    'sh': {
        'fields': [
            ['SH', '101001'],
            ['base', 'bbbbb'],
            ['rt','bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['mips_store(rt, offset, base, "h")'],
    },
    'sll': {
        'fields': [
            ['SPECIAL', '000000'],
            ['0', '00000'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['sa', 'bbbbb'],
            ['SLL', '000000'],
        ],
        'args': ['rd,rt,sa'],
        'emulation': ['rd.value = rt.value << sa'],
    },
    'sllv': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['SLLV', '000100'],
        ],
        'args': ['rd,rt,rs'],
        'emulation': ['rd.value = rt.value << rs.value & 0b11111'],
    },
    'slt': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['SLT', '101010'],
        ],
        'args': ['rd,rs,rt'],
        'emulation': ['rd.value = c_int32(rs).value < c_int32(rt).value'],
    },
    'slti': {
        'fields': [
            ['SLTI', '001010'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,rs,immediate'],
        'emulation': ['rt.value = mips_signed(rs.value, rs.size) < '
                     'mips_signed(immediate, 16)'],
    },
    'sltiu': {
        'fields': [
            ['SLTIU', '001011'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,rs,immediate'],
        'emulation': ['rt.value = rs.value < immediate'],
    },
    'sltu': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['SLTU', '101011'],
        ],
        'args': ['rd,rs,rt'],
        'emulation': ['rd.value = rs < rt'],
    },
    'sra': {
        'fields': [
            ['SPECIAL', '000000'],
            ['0', '00000'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['sa', 'bbbbb'],
            ['SRA', '000011'],
        ],
        'args': ['rd,rt,sa'],
        'emulation': ['rd.value = mips_sra(rt.value, sa)'],
    },
    'srav': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['SRAV', '000111'],
        ],
        'args': ['rd,rt,rs'],
        'emulation': ['rd.value = rt >> rs'],
    },
    'srl': {
        'fields': [
            ['SPECIAL', '000000'],
            ['0', '00000'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['sa', 'bbbbb'],
            ['SRL', '000010'],
        ],
        'args': ['rd,rt,sa'],
        'emulation': ['rd.value = mips_srl(rt.value, sa)'],
    },
    'srlv': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['SRLV', '000110'],
        ],
        'args': ['rd,rt,rs'],
        'emulation': ['rd.value = mips_srl(rt, rs)'],
    },
    'ssnop': {
        'alias_of': [['sll', '$zero,$zero,1']],
        'args': None,
    },
    'sub': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['SUB', '100010'],
        ],
        'args': ['rd,rs,rt'],
        'emulation': ['rd.value = mips_subtract(rs, rt, 32, False)'],
    },
    'subu': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['SUBU', '100011'],
        ],
        'args': ['rd,rs,rt'],
        'emulation': ['rd.value = mips_subtract(rs, rt, 32, True)'],
    },
    'sw': {
        'fields': [
            ['SW', '101011'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': [
            'shadow = c_int32(base)',
            'shadow.value += offset',
            'value = struct.pack("<L", rt.value)',
            'logging.debug("memory before SW: %s", MEMORY[shadow.value:][:4])',
            'MEMORY[shadow.value:shadow.value + 4] = list(value)',
            'logging.debug("memory after SW: %s", MEMORY[shadow.value:][:4])',
        ],
    },
    'swc1': {
        'fields': [
            ['SWC1', '111001'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['mips_coprocessor_store(1, offset, base, rt)'],
    },
    'swc2': {
        'fields': [
            ['SWC2', '111010'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['mips_coprocessor_store(2, offset, base, rt)'],
    },
    'swc3': {
        'fields': [
            ['SWC3', '111011'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['mips_coprocessor_store(3, offset, base, rt)'],
    },
    'swl': {
        'fields': [
            ['SWL', '101010'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['mips_store(rt, offset, base, "w", "left")'],
    },
    'swr': {
        'fields': [
            ['SWR', '101110'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': ['mips_store(rt, offset, base, "w", "right")'],
    },
    'sync': {
        'fields': [
            ['SPECIAL', '000000'],
            ['0', '000000000000000'],
            ['stype', 'bbbbb'],
            ['SYNC', '001111'],
        ],
        'args': ['stype', [None, '0']],
        'emulation': ['mips_sync(stype)'],
    },
    'syscall': {
        'fields': [
            ['SPECIAL', '000000'],
            ['code', 'bbbbbbbbbbbbbbbbbbbb'],
            ['SYSCALL', '001100'],
        ],
        'args': ['code', [None, '0']],
        'emulation': ['mips_syscall()'],
    },
    'teq': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['code', 'bbbbbbbbbb'],
            ['TEQ', '110100'],
        ],
        'args': ['rs,rt,code', ['rs,rt', 'rs,rt,0']],
        'emulation': ['if rs.value == rt.value: mips_trap(code)'],
    },
    'teqi': {
        'fields': [
            ['REGIMM', '000001'],
            ['rs', 'bbbbb'],
            ['TEQI', '01100'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,immediate'],
        'emulation': ['if rs == immediate: mips_trap(code)'],
    },
    'tge': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['code', 'bbbbbbbbbb'],
            ['TGE', '110000'],
        ],
        'args': ['rs,rt,code', ['rs,rt', 'rs,rt,0']],
        'emulation': ['if mips_signed(rs) > mips_signed(rt): mips_trap(code)'],
    },
    'tgei': {
        'fields': [
            ['REGIMM', '000001'],
            ['rs', 'bbbbb'],
            ['TGEI', '01000'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,immediate'],
        'emulation': ['if rs.value >= c_int16(immediate).value: mips_trap()'],
    },
    'tgeiu': {
        'fields': [
            ['REGIMM', '000001'],
            ['rs', 'bbbbb'],
            ['TGEIU', '01001'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,immediate'],
        'emulation': ['if rs.uvalue >= c_int16(immediate).value & 0xffffffff): '
                     'mips_trap(0)'],
    },
    'tgeu': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['code', 'bbbbbbbbbb'],
            ['TGEU', '110001'],
        ],
        'args': ['rs,rt,code', ['rs,rt', 'rs,rt,0']],
        'emulation': ['if rs > rt: mips_trap(code)'],
    },
    'tlbwi': {
        'fields': [
            ['COP0', '010000'],
            ['CO', '1'],
            ['0', '0000000000000000000'],
            ['TLBWI', '000010'],
        ],
        'args': [None],
        'emulation': ['mips_tlbwi()'],
    },
    'tlbwr': {
        'fields': [
            ['COP0', '010000'],
            ['CO', '1'],
            ['0', '0000000000000000000'],
            ['TLBWR', '000110'],
        ],
        'args': [None],
        'emulation': ['mips_tlbwr()'],
    },
    'tlt': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['code', 'bbbbbbbbbb'],
            ['TLT', '110010'],
        ],
        'args': ['rs,rt,code', ['rs,rt', 'rs,rt,0']],
        'emulation': ['if mips_signed(rs.value, rs.size) < '
                     'mips_signed(rt.value, rt.size): mips_trap()'],
    },
    'tlti': {
        'fields': [
            ['REGIMM', '000001'],
            ['rs', 'bbbbb'],
            ['TLTI', '01010'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,immediate'],
        'emulation': ['if rs < c_int16(immediate).value: mips_trap()'],
    },
    'tltiu': {
        'fields': [
            ['REGIMM', '000001'],
            ['rs', 'bbbbb'],
            ['TLTIU', '01011'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,immediate'],
        'emulation': ['if rs.uvalue < c_int16(immediate).value & 0xffffffff):'
        ' mips_trap()'],
    },
    'tltu': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['code', 'bbbbbbbbbb'],
            ['TLTU', '110011'],
        ],
        'args': ['rs,rt,code', ['rs,rt', 'rs,rt,0']],
        'emulation': ['if rs.value < rt.value: mips_trap()'],
    },
    'tne': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['code', 'bbbbbbbbbb'],
            ['TNE', '110110'],
        ],
        'args': ['rs,rt,code', ['rs,rt', 'rs,rt,0']],
        'emulation': ['if rs.value != rt.value: mips_trap(code)'],
    },
    'wait': {
        'fields': [
            ['COP0', '010000'],
            ['CO', '1'],
            ['code', 'bbbbbbbbbbbbbbbbbbb'],
            ['WAIT', '100000'],
        ],
        'args': ['code', [None, '0']],
        'emulation': ['mips_wait(code)'],
    },
    'xor': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['XOR', '100110'],
        ],
        'args': ['rd,rs,rt'],
        'emulation': ['rd.value = rs ^ rt'],
    },
    'xori': {
        'fields': [
            ['XORI', '001110'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,rs,immediate'],
        'emulation': ['rt.value = rs ^ immediate'],
    },
}

REGISTER_REFERENCE = {}  # filled in by init()

CONVERSION = {
    # NOTE: put the most restrictive conditions FIRST, because the conversion
    # process is not a loop; for example, 'b' should come before 'beqz'
    # mnemonic: [[condition, result]...]
    'beq': [
        ['source == target == 0', ['b', 'jump', True, 'True', False]],
        ['target == 0', ['beqz', 'branchz', True, 'True', False]],
    ],
    'sll': [
        ['instruction == 0', ['nop', 'simple', None, 'True', None]],
        ['dest == target == 0 and amount == 3',
         ['ehb', 'simple', None, 'True', False],
        ],
        ['dest == target == 0 and amount == 1',
         ['ssnop', 'simple', None, 'True', False],
        ],
    ],
    'or': [['target == 0', ['move', 'jumpr2', None, 'True', None]]],
    'addiu': [['source == 0', ['li', 'loadi', None, 'True', False]]],
    'addu': [['target == 0', ['move', 'jumpr2', None, 'True', None]]],
    'daddu': [['target == 0', ['move', 'jumpr2', None, 'True', None]]],
    'bgezal': [['source == 0', ['bal', 'jump', True, 'True', False]]],
    'bne': [['target == 0', ['bnez', 'branchz', True, 'True', None]]],
    'beql': [['target == 0', ['beqzl', 'branchz', True, 'True', None]]],
    'bnel': [['target == 0', ['bnezl', 'branchz', True, 'True', None]]],
    'tge': [['code != 0', ['tge', 'trap3', True, 'True', None]]],
    'tlt': [['code != 0', ['tlt', 'trap3', True, 'True', None]]],
    'tne': [['code == 0', ['tne', 'trap2', False, 'True', None]]],
    'tltu': [['code == 0', ['tltu', 'trap2', True, 'True', None]]],
    'tgeu': [['code != 0', ['tgeu', 'trap3', True, 'True', None]]],
    'teq': [['code != 0', ['teq', 'trap3', True, 'True', None]]],
    'ori': [['source == 0', ['li', 'loadx', False, 'True', True]]],  # or dli
    'c0': [
        ['longimmediate >> 6 == 0 and function == 0b011111',
         ['deret', 'simple', False, 'True', None]],
        ['longimmediate == 0x2',
         ['tlbwi', 'simple', False, 'True', None]],
        ['longimmediate == 0x6',
         ['tlbwr', 'simple', False, 'True', None]],
        ['longimmediate == 0x18',
         ['eret', 'simple', False, 'True', None]],
        ['longimmediate == 0x20',
         ['wait', 'simple', False, 'True', None]],
    ],
    'c1': [
        ['target == 0 and function == 0b100000 and source == 0b10001',
         ['cvt.s.d', 'cvt', None, 'True', None]],
    ],
    'break': [['code != 0', ['break', 'break', False, 'True', False]]],
    'subu': [['source == 0', ['negu', 'arithlogz', None, 'True', None]]],
    'dsub': [['source == 0', ['dneg', 'arithlogz', None, 'True', None]]],
    'dsubu': [['source == 0', ['dnegu', 'arithlogz', None, 'True', None]]],
    'sub': [['source == 0', ['neg', 'arithlogz', None, 'True', None]]],
    'dmult': [['source == 0', ['dmult', 'arithlogz', None, 'True', None]]],
    'dmultu': [['source == 0', ['dmultu', 'arithlogz', None, 'True', None]]],
    'mtc0': [['sel != 0', ['mtc0', 'coproc_move3', None, 'True', None]]],
    'mfc0': [['sel != 0', ['mfc0', 'coproc_move3', None, 'True', None]]],
    'jalr': [['dest == 31', ['jalr', 'jumpr', True, 'True', True]]],
    'syscall': [['longcode == 0', ['syscall', 'simple', None, 'True', None]]],
}

class Register(object):
    r'''
    Represent a MIPS general register for emulation

    >>> logging.debug('All registers should have been created by now!')
    >>> Register('$zero').value = 2
    >>> register = Register('$at')
    >>> logging.debug('setting $at to 0xffffffff')
    >>> register.value = 0xffffffff
    >>> logging.warning('setting $at register bytevalue')
    >>> register.bytevalue = (b'\x55\x44\x33', 1)
    >>> '0x%08x' % register.value
    '0x334455ff'
    '''
    registers = {}
    def __new__(cls, *args, **kwargs):
        name = args[0]
        if name[1:].isdigit():
            number = int(name[1:])
            if number in cls.registers:
                register = cls.registers[number]
                logging.debug('returning existing register %s', register)
            else:
                raise ValueError('Cannot create register with numeric name')
        elif name in cls.registers:
            register = cls.registers[name]
            logging.debug('returning already existing register %s', register)
            return register
        else:
            logging.debug('creating new Register(%s)', name)
            return super().__new__(cls)

    def __init__(self, name, number=None, value=0): 
        logging.debug('initializing register %s', name)
        if not name in self.registers:
            self.name = name
            if number is None:
                number = REGISTER_REFERENCE[name]
            self.number = number
            self.registers[name] = self
            self.registers[number] = self
            self.value = value

    def __index__(self):
        return self.value

    def __int__(self):
        return self.value

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<%s(%d)=%d>' % (self.name, self.number, self.value)

    @property
    def bytevalue(self):
        '''
        Return 32-bit register contents as bytes
        '''
        array = struct.pack(PACKFORMAT[32], self.value)
        DOCTESTDEBUG('Register.bytevalue returning bytes %s', array)
        return array

    @bytevalue.setter
    def bytevalue(self, args):
        '''
        Store bytes in 32-bit register
        '''
        DOCTESTDEBUG('Register.bytevalue setter args: %s', args)
        databytes, start = args
        array = bytearray(self.bytevalue)
        DOCTESTDEBUG('setting bytevalue at offset %d to %r', start, databytes)
        array[start:start + len(databytes)] = databytes
        value = struct.unpack(PACKFORMAT[32], array)[0]
        DOCTESTDEBUG('Storing updated value 0x%08x in register %s', value, self)
        self.value = value

class ZeroRegister(Register):
    '''
    Special case for $zero
    '''
    def _warn(self, value):
        if value != 0:
            logging.info('Attempt to set zero register to %r', value)

    # This subclass has a fixed value
    value = property(lambda *args: 0, _warn)

    def __repr__(self):
        return '<$zr(0)=0>'

class CoprocessorRegister(object):
    '''
    Separate from general registers.

    Each coprocessor 0 register number has up to 4 actual registers,
    determined by a 3-bit selector.
    '''
    registers = {0: {}, 1: {}, 2: {}, 3: {}}

    def __new__(cls, coprocessor, name, number=0, selector=None):
        if name[1:].isdigit():  # register in $28 form
            number = int(name[1:])
            if number in cls.registers[coprocessor]:
                register = cls.registers[coprocessor][number]
                logging.debug('returning existing register %s', register)
        elif name in cls.registers:
            register = cls.registers[coprocessor][name]
            logging.debug('returning already existing register %s', register)
            return register
        else:
            logging.debug('creating new CoprocessorRegister(%s)', name)
            return super().__new__(cls)

    def __init__(self, coprocessor, name, number=None, selector=None): 
        logging.debug('initializing coprocessor register %s', name)
        if not name in self.registers[coprocessor]:
            self.name = name
            if number is None:
                if coprocessor == 0:
                    number = COREGISTER.index(name)
                elif name[1:].isdigit():  # '$11' form
                    number = int(name[1:])
                else:
                    number = int(name[2:])  # '$f12' form
            self.number = number
            self.registers[name] = self
            self.registers[number] = self
            self.value = 0

    def __index__(self):
        return self.value

    def __int__(self):
        return self.value

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<%s(%d)=%d>' % (self.name, self.number, self.value)
        pass

def disassemble(filespec):
    '''
    primitive disassembler
    '''
    print('.set noat')  # get rid of warnings for using $at register
    with open(filespec, 'rb') as infile:
        filedata = infile.read()
        # store labels of b, j, etc. instruction targets, to print later
    for loop in [0, 1]:
        for index in range(0, len(filedata), 4):
            chunk = filedata[index:index + 4]
            disassemble_chunk(loop, index, chunk, len(filedata))

def assemble(filespec):
    '''
    primitive assembler
    '''
    outfile = None
    with open(filespec, 'r') as infile:
        filedata = infile.read().splitlines()
    # first pass, just build labels
    for loop in range(2):
        if loop == 1:
            outfile = sys.stdout.buffer
            debug = logging.debug
            logging.debug('labels at start of 2nd pass: %s', LABELS)
        else:
            debug = lambda *args, **kwargs: None
        offset = 0
        for line in filedata:
            label = None
            match = re.match(LINEPATTERN, line)
            if match:
                label = match.group('label')
            else:
                raise ValueError('No match for regex %r to line %r' %
                                 (LINEPATTERN, line))
            #logging.debug('match: %s', match.groupdict())
            instruction, emulation = assemble_instruction(
                loop, offset,
                **{key: value for key, value
                    in match.groupdict().items() if key != 'label'})
            if instruction is not None:
                if outfile is not None:
                    debug('assembled instruction: 0x%08x', instruction)
                    try:
                        outfile.write(struct.pack('<L', instruction))
                    except TypeError:
                        raise(TypeError('Cannot write bytes to %s' % outfile))
                elif label:
                    if label in LABELS:
                        raise ValueError('Label %r already in LABELS as %r' %
                                         (label, LABELS[label]))
                    LABELS[label] = offset
                offset += 4
                debug('offset now: %s', hex(offset))

def disassemble_chunk(loop, index, chunk, maxoffset):
    '''
    build labels dict in first loop, output assembly language in second
    '''
    instruction = struct.unpack('<L', chunk)[0]
    chunkstring = repr(chunk)[1:]  # to make assembly output match python2
    logging.debug('chunk: %r, instruction: 0x%08x', chunk, instruction)
    label = LABELS.get(index, '')
    label += ':' if label else ''
    comment = ''
    opcode = instruction >> 26  # high 6 bits
    mnemonic, style, labeled, condition, signed = INSTRUCTION[opcode][:5]
    source = (instruction & 0x03e00000) >> 21  # 5 bits, 0-31
    rs = REGISTER[source]
    target = (instruction & 0x001f0000) >> 16  # next 5 bits
    rt = REGISTER[target]
    floatrt = FLOATREG[target]
    altrt = ALTREG[target]
    dest = (instruction & 0x0000f800) >> 11  # next 5 bits
    rd = REGISTER[dest]
    floatrs = FLOATREG[dest]
    amount = (instruction & 0x000007c0) >> 6  # next 5 bits
    floatrd = FLOATREG[amount]
    code = (instruction & 0x0000ffc0) >> 6 # dest and amount combined
    longcode = (instruction & 0x03ffffc0) >> 6  # 20 bit code for syscall
    codehigh = longcode >> 10  # for breakpoints
    function = instruction & 0x0000003f  # low 6 bits
    immediate = instruction & 0x0000ffff  # low 16 bits
    longimmediate = ((instruction & 0x03ffffff) << 2)  # low 26 bits
    # longimmediate for jal[x] is shifted by 2
    # and low bit is set to 1 for jalx but can't find that in documentation
    jalximmediate = longimmediate | 1
    co = (instruction & 0x02000000) >> 25  # coprocessor control bit
    jump = instruction & 0x03ffffff
    sel = instruction & 0b111  # selector bits for m[ft]b[0-3]
    mtzero = instruction & 0b11111111000 # coprocessor moveto requires zero
    if mnemonic == 'SPECIAL':
        mnemonic, style, labeled, condition, signed = SPECIAL[function][:5]
    if mnemonic == 'SPECIAL2':
        mnemonic, style, labeled, condition, signed = SPECIAL2[function][:5]
    elif mnemonic == 'REGIMM':
        mnemonic, style, labeled, condition, signed = REGIMM[target][:5]
    elif mnemonic.startswith('COP'):
        coprocessor = int(mnemonic[-1:])
        coregister = (
            COREGISTER.get(dest, '$%d' % dest),
            '$f%d' % dest,
            '$%d' % dest,
            '$%d' % dest
        )[coprocessor]
        listing = INSTRUCTIONS[mnemonic]
        longimmediate = (instruction & 0x1ffffff)  # low 25 bits
        mnemonic, style, labeled, condition, signed = listing[source][:5]
    if not eval(condition):
        logging.debug("failed condition %s, converting %r to '.word': %s",
                      condition, mnemonic, shorten(locals()))
        mnemonic, style, labeled, condition, signed = WORD
    if signed and not style.endswith('x'):
        immediate = ctypes.c_short(immediate).value
    # the jump offset is immediate * 4 added to the *following* instruction
    offset = index + 4 + (immediate << 2)
    # don't use labels until we've ascertained that output is like objdump
    if USE_LABELS:
        destination = LABELS.get(offset, hex(offset))
    else:
        destination = hex(offset)
    if mnemonic in CONVERSION:
        try:
            for condition, result in CONVERSION[mnemonic]:
                if eval(condition):
                    comment += ' (from %r)' % mnemonic
                    mnemonic, style, labeled, condition, signed = result
                    break
                else:
                    logging.debug('eval %r failed in %s', condition,
                                  shorten(locals()))
        except ValueError:
            raise ValueError('CONVERSION[%r] improperly formatted: %s' %
                             (mnemonic, CONVERSION[mnemonic]))
    if USE_LABELS and labeled and offset not in LABELS and offset <= maxoffset:
        LABELS[offset] = 's%s' % hex(offset).lstrip('0x')
        #logging.debug('LABELS: %s', LABELS)
    pattern = PATTERN[style]
    line = pattern % locals()
    if loop == 1:
        print(line)
    return line

def init():
    '''
    Fill in some missing info in global structures
    
    Also make some "corrections" to match objdump disassembly,
    and catch some errors in entering instruction parameters
    '''
    for listing, size in ([INSTRUCTION, 64], [REGIMM, 32], [SPECIAL, 64],
            [SPECIAL2, 64], [COP0, 32], [COP1, 32], [COP2, 32], [COP3, 32]):
        for item in list(listing):
            while item[-1] != listing.index(item):
                logging.debug('%s expected at %d, found at %d',
                              item[0], item[-1], listing.index(item))
                listing.insert(listing.index(item), WORD)
        while len(listing) < size:
            listing.append(WORD)
    # fill in missing coprocessor 0 registers
    for index in range(32):
        if index not in COREGISTER.keys():
            COREGISTER[index] = '$%d' % index
    if USE_LABELS:
        LABELS[0] = 'start'
        # see //s3-eu-west-1.amazonaws.com/downloads-mips/I7200/
        #  I7200+product+launch/MIPS_I7200_Programmers_Guide_01_20_MD01232.pdf
        # table 44, but note that the 'general equation' below it is wrong.
        vectorlength = int(INTCTLVS, 2) * 0x20
        for index in range(VECTORS):
            # add vector labels for disassembly only.
            # it's up to the assembly coder to put them into the code.
            LABELS[(index * vectorlength) + 0x200] = 'intvec%d' % index
    if MATCH_OBJDUMP_DISASSEMBLY:
        # objdump sync becomes .word if stype set in amount field, and
        # simple "sync" if amount is zero
        CONVERSION['sync'] = [
            [ 'amount == 0', ['sync', 'simple', False, 'True', False]],
            ['amount != 0', WORD]
        ]
        # objdump disassembly returns .word for sel != 0
        CONVERSION['mtc0'] = [['sel != 0', WORD]]
        CONVERSION['mfc0'] = [['sel != 0', WORD]]
        # objdump disassembly always returns just the .word for movz and movn
        CONVERSION['movz'] = [['True', WORD]]
        CONVERSION['movn'] = [['True', WORD]]
        # objdump has no 'deret' nor 'mul'
        CONVERSION['c0'][0][1] = ['c0', 'coprocessor', False, 'True', False]
        CONVERSION['mul'] = [['True', WORD]]
        # objdump doesn't show register $s8 as frame pointer
        REGISTER_REFERENCE['$fp'] = REGISTER.index('$fp')
        REGISTER[REGISTER.index('$fp')] = '$s8'
        # objdump dumps div, ddiv, divu, and ddivu as arithlog
        for item in SPECIAL:
            if item[0] in ('div', 'divu', 'ddiv', 'ddivu'):
                logging.warning('Making %r incorrectly dump as "arithlog"'
                                ' to match objdump disassembly',
                                item[0])
                item[1] = 'arithlog'
    else:
        # need to be able to interpret register $s8 when assembling
        REGISTER_REFERENCE['$s8'] = REGISTER.index('$fp')
    REGISTER_REFERENCE.update({value: key for key, value
                               in COREGISTER.items()
                               if value.startswith('c')
                             })
    for listing in REGISTER, ALTREG, FLOATREG:
        hashtable = zip(listing, range(len(listing)))
        REGISTER_REFERENCE.update(hashtable)
    for key, item in REFERENCE.items():
        if 'fields' in item:
            length = 0
            for name, value in item['fields']:
                length += len(value)
            if length != 32:
                raise ValueError(
                    'REFERENCE[%r] fields are incorrect: %d != 32' %
                    (key, length))
    # STATE is used only by emulator, but initialize it anyway because it
    # makes sure all the registers are created correctly and in order
    STATE[REGISTER[0]] = ZeroRegister('$zero', 0)
    for index in range(1, len(REGISTER)):
        STATE[REGISTER[index]] = Register(REGISTER[index], index)
        logging.debug('Creating COP0 register %s (%d)',
                      COREGISTER[index], index)
        STATE[COREGISTER[index]] = CoprocessorRegister(0,
                                                       COREGISTER[index],
                                                       index)

def shorten(hashtable):
    '''
    Get rid of anything huge in locals(), for debugging purposes
    '''
    for key in hashtable.keys():
        try:
            if len(hashtable[key]) > 256:
                hashtable.pop(key)
                logging.debug('got rid of key %s', key)
        except TypeError:  # ignore len(int)
            pass
    return hashtable

def buildargs(provided, expected):
    '''
    build a dict of expected args to those provided
    '''
    index = 0
    given = argsplit(provided)
    wanted = argsplit(expected[index])
    desired = list(wanted)
    logging.debug('buildargs: given: %s, wanted: %s', given, wanted)
    # insert any default args where needed
    # this only works left-to-right, if a different order is needed,
    # priority will need to be specified and used.
    while len(given) < len(desired):
        index += 1
        try:
            desired = argsplit(expected[index][0])
        except IndexError:
            raise(IndexError('No index [%d][0] in %s' % (index, expected)))
        logging.debug('buildargs calling rebuildargs: %s', expected[index])
        provided = rebuildargs(provided, *expected[index])
        given = argsplit(provided)
        logging.debug('buildargs loop: given: %s, wanted: %s', given, wanted)
    return dict(zip(wanted, given))
    
    return OrderedDict(zip(wanted, given))

def rebuildargs(args, pseudoop_args, newargs):
    '''
    rebuild argstring from pseudoop to original instruction

    example 'b' has a single arg 'offset', but aliases to
    'beq $zero,$zero,offset'. so if 'offset' is 's209c',
    '$zero,$zero,s209c' must be provided to assemble_instruction,
    which will match the expected 'rs,rt,offset'.
    >>> rebuildargs('0x3456', 'offset', 'rs,rt,offset')
    'rs,rt,0x3456'
    >>> rebuildargs('', '', '0,0')
    '0,0'
    '''
    logging.debug('rebuildargs args: %s', locals())
    argslist = [argsplit(string) for string in (args, pseudoop_args, newargs)]
    logging.debug('argslist before rebuild: %s', argslist)
    if len(argslist[0]) != len(argslist[1]):
        raise ValueError('Length mismatch: %s' % argslist[:2])
    for index in range(len(argslist[2])):
        arg = argslist[2][index]
        if arg in argslist[1]:
            argslist[2][index] = argslist[0][argslist[1].index(arg)]
    logging.debug('argslist after rebuild: %s', argslist)
    return ','.join(argslist[2])

def argsplit(args):
    '''
    split string using ARGSEP.

    special case for None, return empty list
    '''
    try:
        return re.compile(ARGSEP).split(args)
    except TypeError:
        return []

def smart_mask(number, name, offset, argsdict, maskbits):
    '''
    Calculate branch targets/offsets differently
    '''
    logging.debug('smart_mask(%s, %r, %s, %r)',
                  hex(number), name, argsdict, maskbits)
    if number < 0:
        number = (1 << 32) + number  # two's complement
        logging.debug('negative number now %s', hex(number))
    if name  == 'offset' and not 'base' in argsdict:
        number = (number - offset - 4) >> 2
        logging.debug('branch offset now %s', hex(number))
    elif name == 'target':
        number >>= 2  # jump targets are *not* PC-relative
        logging.debug('jump target now %s', hex(number))
    number = number & maskbits
    logging.debug('number after mask operation: %s', hex(number))
    return number & maskbits

def assemble_instruction(loop, offset, mnemonic=None, args=None, was=''):
    '''
    Assemble an instruction given the assembly source line

    Return both the assembled instruction and the emulation info to emulator
    '''
    logging.debug('processing: %s', locals())
    instruction = 0
    reference = REFERENCE.get(mnemonic)
    zero = ('$zero','$0','$f0')
    if reference:
        fieldsdict = {}
        if {'fields', 'args'}.issubset(reference.keys()):
            argsdict = buildargs(args, reference['args'])
            fieldsdict = {key: value for key, value in reference['fields']
                          if re.compile('[A-Za-z_][A-Za-z0-9_]+').match(key)}
            for name, value in reference['fields']:
                logging.debug('assemble_instruction: name %r, value %r',
                              name, value)
                fieldlength = len(value)
                instruction <<= fieldlength
                mask = (1 << fieldlength) - 1
                if value.isdigit():
                    instruction |= int(value, 2)
                    if name in fieldsdict:
                        fieldsdict[name] = int(value, 2)
                else:  # typically 'bbbbb'
                    try:
                        arg = argsdict[name]
                        fieldsdict[name] = arg
                    except KeyError:
                        raise KeyError('%r not found in %s' % (name, argsdict))
                    if arg[:1].startswith(tuple('-0123456789')):
                        number = eval(arg)
                        if name in fieldsdict:
                            fieldsdict[name] = number
                        logging.debug('before merging number %r: %s',
                                      arg, hex(instruction))
                        instruction |= smart_mask(number, name, offset,
                                                  argsdict, mask)
                        logging.debug('after merging number %r: %s',
                                      arg, hex(instruction))
                    elif arg in LABELS:
                        if name in fieldsdict:
                            fieldsdict[name] = LABELS[arg]
                        logging.debug('before merging label %r (%s): %s',
                                      arg, hex(LABELS[arg]), hex(instruction))
                        instruction |= smart_mask(LABELS[arg], name, offset,
                                                  argsdict, mask)
                        logging.debug('after merging label %r (%s): %s',
                                      arg, hex(LABELS[arg]), hex(instruction))
                    else:
                        # check for coprocessor register special names
                        if '_' in arg:
                            logging.debug('coregister before replacement: %r',
                                          arg)
                            arg = arg.replace(arg[arg.index('_') - 1], '%d', 1)
                            logging.debug('coregister after: %s', arg)
                        if arg in REGISTER_REFERENCE:
                            if name in fieldsdict:
                                fieldsdict[name] = Register(arg)
                            logging.debug('before %r: %s',
                                          arg, hex(instruction))
                            instruction |= REGISTER_REFERENCE[arg]
                            logging.debug('after %r: %s', arg, hex(instruction))
                        elif loop == 0:
                            instruction = 'pending label list completion'
                            break
                        else:
                            logging.error('%r not in REGISTER_REFERENCE %s',
                                          arg, REGISTER_REFERENCE)
                            raise ValueError('Cannot process arg %r' % arg)
        elif reference.get('action') is not None:
            logging.warning('exec %r', reference['action'])
            try:
                exec(reference['action'], globals(), locals())
                instruction = None
            except (TypeError, ValueError):
                raise ValueError('Cannot exec %s action' % reference)
        elif reference.get('alias_of') is not None:
            aliases = reference['alias_of']
            expected = reference['args']
            logging.debug('expected args of aliased parent: %r', expected)
            logging.debug('dict(aliases): %s', dict(aliases))
            if was in dict(aliases):
                newargs = dict(aliases)[was]
                mnemonic = was
                logging.debug('found args %s from de-aliased %r', newargs, was)
            else:
                mnemonic, newargs = aliases[0]
                logging.debug('newargs from default %s', newargs)
            logging.debug('assemble_instruction calling itself with new args')
            return assemble_instruction(loop, offset, mnemonic,
                                        rebuildargs(args, expected, newargs),
                                        None)
        else:
            raise NotImplementedError('No action found for %s' % mnemonic)
        return instruction, (reference.get('emulation'), fieldsdict)
    else:
        raise NotImplementedError('%s not in REFERENCE' % mnemonic)

def emulate(filespec):
    '''
    primitive MIPS emulator
    '''
    with open(filespec, 'rb') as infile:
        filedata = infile.read()
    MEMORY.extend(filedata)  # mutable copy of filedata, byte-addressable
    MEMORY.extend(bytes(4096))  # add room for stack (enough?)
    program = [filedata[i:i + 4] for i in range(0, len(filedata), 4)]
    pc = 0x8c000000  # program counter on reset
    index = 0
    run = False  # setting to True below will run code until error or ^C
    while True:
        instruction = disassemble_chunk(0, index, program[index], len(filedata))
        logging.debug('executing %s', instruction)
        parts = re.compile(LINEPATTERN).match(instruction)
        if not parts:
            raise NotImplementedError('No known way to execute %s', instruction)
        executable, emulation = assemble_instruction(0, pc,
                                                     parts.group('mnemonic'),
                                                     parts.group('args'),
                                                     parts.group('was'))
        locals().update(emulation[1])
        index += 1
        pc += 4
        print(STATE.values(), emulation, file=sys.stderr)
        for code in emulation[0]:
            exec(code, globals(), locals())
        if __debug__:
            pdb.set_trace()
        elif not run:
            run = bool(input('Continue -> '))
            logging.warning('`run` set to %r', run)

def mips_add(augend, addend, bits=32, ignore_overflow=False):
    '''
    Add a number to a MIPS register

    MIPS always uses 32 or 64 bit integers.

    Its "unsigned" operations are actually signed, but simply ignore
    arithmetic overflow.
    '''
    c_int = c_int32 if bits == 32 else c_int64
    adder = c_int(augend)
    adder.value += int(addend)
    total = adder.value  # I'd use `sum` but it's bad practice
    if not ignore_overflow:
        check_sum = augend.value + addend  # check using Python's bignums
        if total != check_sum:
            raise ArithmeticOverflow('MIPS sum %s != Python sum %s' %
                                     (hex(total), hex(check_sum)))
    return total
 
def mips_subtract(subtrahend, minuend, bits=32, ignore_overflow=False):
    '''
    Subtract a number from a MIPS register
    
    MIPS always uses 32 or 64 bit integers.

    Its "unsigned" operations are actually signed, but simply ignore
    arithmetic overflow.
    '''
    return mips_add(subtrahend, -minuend, bits, ignore_overflow)

def mips_multiply(multiplicand, multiplier, bits=32, unsigned=False,
        return_as_int=False):
    '''
    Multiply a number to a MIPS register

    MIPS always uses 32 or 64 bit integers.

    Most of its "unsigned" operations are actually signed, but simply ignore
    arithmetic overflow. MIPS multiplication always ignores overflow, but has
    signed and unsigned variants.

    When `return` is True, the product is returned as a single 32-bit integer.
    Otherwise, it's still returned, but as a tuple for the (hi, lo) special
    registers.

    See https://devblogs.microsoft.com/oldnewthing/20180404-00/?p=98435
    '''
    c_int = eval('c_int%du' % bits) if unsigned else eval('c_int%d' % bits)
    register = c_int(multiplicand)
    register.value *= multiplier
    product = register.value
    return product if return_as_int else divmod(product, 1 << bits)
 
def mips_div(dividend, divisor, bits=32, ignore_overflow=False):
    '''
    Divide a MIPS register by a number

    MIPS always uses 32 or 64 bit integers.

    Most of its "unsigned" operations are actually signed, but simply ignore
    arithmetic overflow. Division is exceptional because it cannot overflow.

    See https://devblogs.microsoft.com/oldnewthing/20180404-00/?p=98435
    '''
    c_int = c_uint32 if bits == 32 else c_uint64
    register = c_int(dividend)
    quotient, remainder = divmod(register.value, divisor)
    return quotient, remainder
 
def mips_lw(rt, offset, base, half='both'):
    '''
    Load 32-bit register 'rt' from memory. Supports 'lw', 'lwl', and 'lwr'.
    '''
    register = c_int32(base)
    register.value += offset
    loadoffset = register.value % 4
    length = 4 - loadoffset
    if half == 'left':
        rt.bytevalue = (MEMORY[offset:offset + length + 1], 0)
    elif half == 'right':
        rt.bytevalue = (MEMORY[offset + length:offset + 4], length)
    else:  # both
        rt.bytevalue = (MEMORY[offset:offset + 4], 0)

def mips_mfc0(rd, selector):
    '''
    Return contents of coprocessor 0 register rd with selector
    '''

if __name__ == '__main__':
    init()
    eval(COMMAND)(*ARGV)
else:
    init()
