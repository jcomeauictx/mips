#!/usr/bin/python -OO
'''
Intelligently disassemble and reassemble MIPS binaries
'''
import sys, os, struct, ctypes, re, logging
from collections import OrderedDict

logging.basicConfig(level=logging.DEBUG if __debug__ else logging.WARN)

MATCH_OBJDUMP_DISASSEMBLY = bool(os.getenv('MATCH_OBJDUMP_DISASSEMBLY'))
# labels will cause objdump -D output and mips disassemble output to differ
# same if instructions with bad args are turned into .word 0xNNNNNNNN
USE_LABELS = AGGRESSIVE_WORDING = not MATCH_OBJDUMP_DISASSEMBLY
INTCTLVS = os.getenv('MIPS_INTCTLVS', '00100')  # IntCtlVS
VECTORS = os.getenv('VECTORS', 32)  # 64 on 64 bit machines (?)
logging.warn('USE_LABELS = %s, AGGRESSIVE_WORDING=%s', USE_LABELS,
             AGGRESSIVE_WORDING)

LABELS = {}  # filled in by init()

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
COMMENT = '\t# %(index)x: %(chunk)r %(comment)s'

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
    0b00000: 'c%d_index',
    0b00010: 'c%d_entrylo0',
    0b00011: 'c%d_entrylo1',
    0b00100: 'c%d_context',
    0b00101: 'c%d_pagemask',
    0b01000: 'c%d_badvaddr',
    0b01001: 'c%d_count',
    0b01010: 'c%d_entryhi',
    0b01011: 'c%d_compare',
    0b01100: 'c%d_sr',
    0b01101: 'c%d_cause',
    0b01110: 'c%d_epc',
    0b01111: 'c%d_prid',
    0b10000: 'c%d_config',
    0b10010: 'c%d_watchlo',
    0b10011: 'c%d_watchhi',
    0b10110: '$22',
    0b11100: 'c%d_taglo',
    0b11101: 'c%d_taghi',
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
        'emulation': 'raise Exception("0x%x not executable code", immediate)',
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
        'emulation': 'fd = abs(fs)'
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
        'emulation': 'fd = abs(fs)'
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
        'emulation': 'fd = abs(fs)'
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
        'emulation': 'rd = rs + rt',
    },
    'addi': {
        'fields': [
            ['ADDI', '001000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,rs,immediate'],
        'emulation': 'rt.value = rs + immediate',
    },
    'addiu': {
        'fields': [
            ['ADDIU', '001001'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,rs,immediate'],
        'emulation': 'disable(MipsOverflow); rt.value = rs + immediate'
                     'enable(MipsOverflow)',
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
        'emulation': 'rd.value = rs.value + rt.value',
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
        'emulation': 'rd.value = rs.value & rt.value',
    },
    'andi': {
        'fields': [
            ['ANDI', '001100'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,rs,immediate'],
        'emulation': 'rt.value = rs & immediate',
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
        'emulation': 'if rs == rt: address = (offset << 2) + pc; '
                     'do_next(); jump(address)',
    },
    'beql': {
        'fields': [
            ['BEQ', '010100'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,rt,offset'],
        'emulation': 'if rs == rt: mips_branch(offset, likely=True)'
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
        'emulation': 'if rs >= 0: mips_jump(offset)',
    },
    'bgezal': {
        'fields': [
            ['REGIMM', '000001'],
            ['rs', 'bbbbb'],
            ['BGEZAL', '10001'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,offset'],
        'emulation': 'if rs.value() >= 0: mips_jump(offset)',
    },
    'bgezall': {
        'fields': [
            ['REGIMM', '000001'],
            ['rs', 'bbbbb'],
            ['BGEZAL', '10011'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,offset'],
        'emulation': 'if rs.value() >= 0: mips_jump(offset, likely=True)',
    },
    'bgezl': {
        'fields': [
            ['REGIMM', '000001'],
            ['rs', 'bbbbb'],
            ['BGEZL', '00011'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,offset'],
        'emulation': 'if rs >= 0: mips_jump(offset, likely=True)',
    },
    'bgtz': {
        'fields': [
            ['BGTZ', '000111'],
            ['rs', 'bbbbb'],
            ['0', '00000'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,offset'],
        'emulation': 'if mips_signed(rs.value, rs.size) > 0: '
                     'do_next(); mips_jump(offset)',
    },
    'bgtzl': {
        'fields': [
            ['BGTZL', '010111'],
            ['rs', 'bbbbb'],
            ['0', '00000'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,offset'],
        'emulation': 'if rs > 0: mips_jump(offset, likely=True)'
    },
    'blez': {
        'fields': [
            ['BLEZ', '000110'],
            ['rs', 'bbbbb'],
            ['0', '00000'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,offset'],
        'emulation': 'if mips_signed(rs.value, rs.size) < 0: '
                     'do_next(); mips_jump(offset)',
    },
    'blezl': {
        'fields': [
            ['BLEZL', '010110'],
            ['rs', 'bbbbb'],
            ['0', '00000'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,offset'],
        'emulation': 'if rs < 0: mips_jump(offset)',
    },
    'bltz': {
        'fields': [
            ['REGIMM', '000001'],
            ['rs', 'bbbbb'],
            ['BLTZ', '00000'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,offset'],
        'emulation': 'if mips_signed(rs.value, rs.size) < 0: '
                     'do_next(); mips_jump(offset)',
    },
    'bltzal': {
        'fields': [
            ['REGIMM', '000001'],
            ['rs', 'bbbbb'],
            ['BLTZALL', '10000'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,offset'],
        'emulation': 'if rs < 0: mips_jump(offset)',
    },
    'bltzall': {
        'fields': [
            ['REGIMM', '000001'],
            ['rs', 'bbbbb'],
            ['BLTZALL', '10010'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,offset'],
        'emulation': 'if rs < 0: mips_jump(offset, likely=True)',
    },
    'bltzl': {
        'fields': [
            ['REGIMM', '000001'],
            ['rs', 'bbbbb'],
            ['BLTZ', '00010'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,offset'],
        'emulation': 'if rs < 0: mips_jump(offset, likely=True)',
    },
    'bne': {
        'fields': [
            ['BNE', '000101'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,rt,offset'],
        'emulation': 'if rs.value != rt.value: address = (offset << 2) + pc; '
                     'do_next(); mips_jump(address)',
    },
    'bnel': {
        'fields': [
            ['BNEL', '010101'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,rt,offset'],
        'emulation': 'if rs.value != rt.value: '
                     'mips_jump(offset, likely=True)',
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
        'emulation': 'mips_break()',
    },
    'c0': {
        'fields': [
            ['COP0', '010000'],
            ['CO', '1'],
            ['immediate', 'bbbbbbbbbbbbbbbbbbbbbbbbb'],
        ],
        'args': ['immediate'],
        'emulation': 'logging.debug("ignoring c0 0x%x", immediate)',
    },
    'c1': {
        'fields': [
            ['COP1', '010001'],
            ['CO', '1'],
            ['immediate', 'bbbbbbbbbbbbbbbbbbbbbbbbb'],
        ],
        'args': ['immediate'],
        'emulation': 'logging.debug("ignoring c1 0x%x", immediate)',
    },
    'c2': {
        'fields': [
            ['COP2', '010010'],
            ['CO', '1'],
            ['immediate', 'bbbbbbbbbbbbbbbbbbbbbbbbb'],
        ],
        'args': ['immediate'],
        'emulation': 'logging.debug("ignoring c2 0x%x", immediate)',
    },
    'c3': {
        'fields': [
            ['COP3', '010011'],
            ['CO', '1'],
            ['immediate', 'bbbbbbbbbbbbbbbbbbbbbbbbb'],
        ],
        'args': ['immediate'],
        'emulation': 'logging.debug("ignoring c3 0x%x", immediate)',
    },
    'cache': {
        'fields': [
            ['CACHE', '101111'],
            ['base', 'bbbbb'],
            ['op', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['op,offset(base)'],
        'emulation': 'mips_cache(op, base, offset)',
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
        'emulation': 'mips_cvt("s", "d", fs, fd)',
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
        'emulation': 'rd = rs + rt',
    },
    'daddi': {
        'fields': [
            ['DADDI', '011000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,rs,immediate'],
        'emulation': 'pushbits(32); rt.value = rs + immediate; popbits()',
    },
    'daddiu': {
        'fields': [
            ['DADDIU', '011001'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,rs,immediate'],
        'emulation': 'disable(MipsOverflow); rt.value = rs + immediate; '
                     'enable(MipsOverflow)',
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
        'emulation': 'disable(MipsOverflow); rd = rs + rt; '
                     'enable(MipsOverflow)',
    },
    'ddiv': {
        # obdjump incorrectly dumps ddiv as arithlog
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            # ['0', '0000000000'], # correct, but replaced by following 2 lines
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['DDIV', '011110'],
        ],
        'args': ['rd,rs,rt', ['rs,rt', '$zero,rs,rt']],
        'emulation': 'mips_div(rs, rt, bits=64)',
    },
    'ddivu': {
        # obdjump incorrectly dumps ddivu as arithlog
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            # ['0', '0000000000'], # correct, but replaced by following 2 lines
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['DDIVU', '011111'],
        ],
        'args': ['rd,rs,rt', ['rs,rt', '$zero,rs,rt']],
        'emulation': 'mips_div(rs, rt, bits=64, signed=False)',
    },
    'deret': {
        'fields': [
            ['COP0', '010000'],
            ['CO', '1'],
            ['0', '0000000000000000000'],
            ['DERET', '011111'],
        ],
        'args': [None],
        'emulation': 'mips_deret()',
    },
    'div': {
        # obdjump incorrectly dumps ddiv as arithlog
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            # ['0', '0000000000'], # correct, but replaced by following 2 lines
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['DIV', '011010'],
        ],
        'args': ['rd,rs,rt', ['rs,rt', '$zero,rs,rt']],
        'emulation': 'mips_div(rs, rt)',
    },
    'divu': {
        # obdjump incorrectly dumps ddiv as arithlog
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            # ['0', '0000000000'], # correct, but replaced by following 2 lines
            ['rd', 'bbbbb'],
            ['0', '00000'],
            ['DIVU', '011011'],
        ],
        'args': ['rd,rs,rt', ['rs,rt', '$zero,rs,rt']],
        'emulation': 'mips_div(rs, rt, unsigned=True)',
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
        'emulation': 'mips_mult(rs, rt, bits=64)',
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
        'emulation': 'mips_mult(rs, rt, bits=64, signed=False)',
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
        'emulation': 'rd.value = rt << sa',
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
        'emulation': 'rd.value = rt << (sa + 32)',
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
        'emulation': 'rd.value = rt.value << rs.value & 0b11111',
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
        'emulation': 'rd.value = rt >> sa',
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
        'emulation': 'rd.value = rt >> (sa + 32)',
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
        'emulation': 'rd.value = rt >> rs',
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
        'emulation': 'rd.uvalue = rt.uvalue >> sa',
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
        'emulation': 'rd.uvalue = rt.uvalue >> (sa + 32)',
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
        'emulation': 'rd.uvalue = rt.uvalue >> (rs & 0b11111)',
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
        'emulation': 'rd.value = mips_sub(rs, rt)',
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
        'emulation': 'rd.value = mips_sub(rs, rt, overflow=False)',
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
        'emulation': 'mips_eret()',
    },
    'j': {
        'fields': [
            ['J', '000010'],
            ['target', 'bbbbbbbbbbbbbbbbbbbbbbbbbb'],
        ],
        'args': ['target'],
        'emulation': 'mips_jump(target)',
    },
    'jal': {
        'fields': [
            ['JAL', '000011'],
            ['target', 'bbbbbbbbbbbbbbbbbbbbbbbbbb'],
        ],
        'args': ['target'],
        'emulation': 'mips_jump(target)',
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
        'emulation': 'rd.value = pc + 4; do_next(); jump(rs.value)',
    },
    'jalx': {
        'fields': [
            ['JALX', '011101'],
            ['target', 'bbbbbbbbbbbbbbbbbbbbbbbbbb'],
        ],
        'args': ['target'],
        'emulation': 'ra = (pc + 2) | isa_mode; address = target << 2; '
                     'do_next(); isa_mode ^= 1; jump(address)',
    },
    'lb': {
        'fields': [
            ['LB', '100000'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'rt.value = sign_extend(byte_contents(base + offset))',
    },
    'ld': {
        'fields': [
            ['LD', '110111'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'rt.value = mips_load(base, offset, "d")',
    },
    'ldc1': {
        'fields': [
            ['LDC1', '110101'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'mips_coprocessor_load(1, rt, base, offset)',
    },
    'ldc2': {
        'fields': [
            ['LDC2', '110110'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'mips_coprocessor_load(2, rt, base, offset)',
    },
    'lh': {
        'fields': [
            ['LB', '100001'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'mips_load(rt, base, offset, "h")',
    },
    'll': {
        'fields': [
            ['LL', '110000'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'rt.value = mips_load(base, offset)',
    },
    'lld': {
        'fields': [
            ['LLD', '110100'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'rt.value = mips_load(base, offset, bits=64)',
    },
    'jr': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['', '000000000000000'],
            ['JR', '001000'],
        ],
        'args': ['rs'],
        'emulation': 'mips_jump(rs.value)',
    },
    'lbu': {
        'fields': [
            ['LBU', '100100'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'rt.value = mips_load(base, offset, "b", signed=False)',
    },
    'ldl': {
        'fields': [
            ['LDL', '011010'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'mips_ldl(rt, base, offset)',
    },
    'ldr': {
        'fields': [
            ['LDR', '011011'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'mips_ldr(rt, base, offset)',
    },
    'lhu': {
        'fields': [
            ['LHU', '100101'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'rt.uvalue = mips_load(offset, base, "h")',
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
        'emulation': 'rt.value = sign_extend(immediate << 16)',
    },
    'lw': {
        'fields': [
            ['LW', '100011'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'rt.value = mips_lw(offset, base)',
    },
    'lwc1': {
        'fields': [
            ['LWC1', '110001'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'mips_coprocessor_load(1, rt, offset, base, "w")',
    },
    'lwc2': {
        'fields': [
            ['LWC2', '110010'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'mips_coprocessor_load(2, rt, offset, base, "w")',
    },
    'lwc3': {
        'fields': [
            ['LWC3', '110011'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'mips_coprocessor_load(3, rt, offset, base, "w")',
    },
    'lwl': {
        'fields': [
            ['LWL', '100010'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'rt.value = mips_lw(offset, base, "left")',
    },
    'lwr': {
        'fields': [
            ['LWR', '100110'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'rt.value = mips_lw(offset, base, "right")',
    },
    'lwu': {
        'fields': [
            ['LWU', '100111'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'rt.uvalue = mips_load(offset, base)',
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
        'emulation': 'rt.value = mips_mfc(0, rd, sel)',
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
        'emulation': 'rd.value = hi.value',
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
        'emulation': 'rd.value = lo.value',
    },
    'move': {
        'alias_of': [
            ['addu', 'rd,rs,$zero'],
            ['daddu', 'rd,rs,$zero'],
            ['or', 'rd,rs,$zero'],
        ],
        'args': 'rd,rs',
        'emulation': 'rd.value = rs.value',
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
        'emulation': 'if rt != 0: rd.value = rs',
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
        'emulation': 'if rt == 0: rd.value = rs',
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
        'emulation': 'mips_mtc(0, rd, sel, rt.value)',
    },
    'mthi': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['0', '000000000000000'],
            ['MTHI', '010001'],
        ],
        'args': ['rs'],
        'emulation': 'mips_mthi(rs.value)',
    },
    'mtlo': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'bbbbb'],
            ['0', '000000000000000'],
            ['MTLO', '010011'],
        ],
        'args': ['rs'],
        'emulation': 'mips_mtlo(rs.value)',
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
        'emulation': 'rd.value = rs * rt',
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
        'emulation': 'mips_mult(rs.value, rt.value)',
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
        'emulation': 'mips_mult(rs.value, rt.value, ignore_overflow=True)',
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
        'emulation': 'rd.value = (rs.value | rt.value) ^ -1',
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
        'emulation': 'rd.value = rs.value | rt.value',
    },
    'ori': {
        'fields': [
            ['ORI', '001101'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,rs,immediate'],
        'emulation': 'rt.value = rs | immediate',
    },
    'sb': {
        'fields': [
            ['SB', '101000'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'mips_store(offset, base, value, "b")',
    },
    'sc': {
        'fields': [
            ['SC', '111000'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'mips_store(rt, base, offset, atomic=True)'
    },
    'scd': {
        'fields': [
            ['SC', '111100'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'mips_store(rt, base, offset, "d", atomic=True)'
    },
    'sd': {
        'fields': [
            ['SD', '111111'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'mips_store(offset + contents(base), contents(rt))',
    },
    'sdc1': {
        'fields': [
            ['SDC1', '111101'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'mips_coprocessor_store(1, rt, offset, base, rt, "d")',
    },
    'sdc2': {
        'fields': [
            ['SDC2', '111110'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'mips_coprocessor_store(2, rt, offset, base, rt, "d")',
    },
    'sdl': {
        'fields': [
            ['SDL', '101100'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'mips_store(offset, base, rt, "d", "left")',
    },
    'sdr': {
        'fields': [
            ['SDR', '101101'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'mips_store(offset, base, rt, "d", "right")',
    },
    'sh': {
        'fields': [
            ['SH', '101001'],
            ['base', 'bbbbb'],
            ['rt','bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'mips_store(rt, offset, base, "h")',
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
        'emulation': 'rd.value = rt.value << sa',
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
        'emulation': 'rd.value = rt.value << rs.value & 0b11111',
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
        'emulation': 'rd.value = mips_signed(rs.value, rs.size) < '
                     'mips_signed(rt.value, rt.size)',
    },
    'slti': {
        'fields': [
            ['SLTI', '001010'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,rs,immediate'],
        'emulation': 'rt.value = mips_signed(rs.value, rs.size) < '
                     'mips_signed(immediate, 16)',
    },
    'sltiu': {
        'fields': [
            ['SLTIU', '001011'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,rs,immediate'],
        'emulation': 'rt.value = rs.value < immediate',
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
        'emulation': 'rd.value = rs < rt',
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
        'emulation': 'rd.value = mips_sra(rt.value, sa)',
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
        'emulation': 'rd.value = rt >> rs',
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
        'emulation': 'rd.value = mips_srl(rt.value, sa)',
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
        'emulation': 'rd.value = mips_srl(rt, rs)',
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
        'emulation': 'rd.value = rs.value - rt.value',
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
        'emulation': 'rd.value = rs.value - rt.value',
    },
    'sw': {
        'fields': [
            ['SW', '101011'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'mips_sw(offset, base, rt.value)',
    },
    'swc1': {
        'fields': [
            ['SWC1', '111001'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'mips_coprocessor_store(1, offset, base, rt)',
    },
    'swc2': {
        'fields': [
            ['SWC2', '111010'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'mips_coprocessor_store(2, offset, base, rt)',
    },
    'swc3': {
        'fields': [
            ['SWC3', '111011'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'mips_coprocessor_store(3, offset, base, rt)',
    },
    'swl': {
        'fields': [
            ['SWL', '101010'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'mips_store(rt, offset, base, "w", "left")',
    },
    'swr': {
        'fields': [
            ['SWR', '101110'],
            ['base', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['offset', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,offset(base)'],
        'emulation': 'mips_store(rt, offset, base, "w", "right")',
    },
    'sync': {
        'fields': [
            ['SPECIAL', '000000'],
            ['0', '000000000000000'],
            ['stype', 'bbbbb'],
            ['SYNC', '001111'],
        ],
        'args': ['stype', [None, '0']],
        'emulation': 'mips_sync(stype)',
    },
    'syscall': {
        'fields': [
            ['SPECIAL', '000000'],
            ['code', 'bbbbbbbbbbbbbbbbbbbb'],
            ['SYSCALL', '001100'],
        ],
        'args': ['code', [None, '0']],
        'emulation': 'mips_syscall()',
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
        'emulation': 'if rs.value == rt.value: mips_trap(code)',
    },
    'teqi': {
        'fields': [
            ['REGIMM', '000001'],
            ['rs', 'bbbbb'],
            ['TEQI', '01100'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,immediate'],
        'emulation': 'if rs == immediate: mips_trap(code)',
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
        'emulation': 'if mips_signed(rs) > mips_signed(rt): mips_trap(code)',
    },
    'tgei': {
        'fields': [
            ['REGIMM', '000001'],
            ['rs', 'bbbbb'],
            ['TGEI', '01000'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,immediate'],
        'emulation': 'if rs.value >= sign_extend(immediate): mips_trap()',
    },
    'tgeiu': {
        'fields': [
            ['REGIMM', '000001'],
            ['rs', 'bbbbb'],
            ['TGEIU', '01001'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,immediate'],
        'emulation': 'if rs.uvalue >= unsigned(sign_extend(immediate)): '
                     'mips_trap(0)',
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
        'emulation': 'if rs > rt: mips_trap(code)',
    },
    'tlbwi': {
        'fields': [
            ['COP0', '010000'],
            ['CO', '1'],
            ['0', '0000000000000000000'],
            ['TLBWI', '000010'],
        ],
        'args': [None],
        'emulation': 'mips_tlbwi()',
    },
    'tlbwr': {
        'fields': [
            ['COP0', '010000'],
            ['CO', '1'],
            ['0', '0000000000000000000'],
            ['TLBWR', '000110'],
        ],
        'args': [None],
        'emulation': 'mips_tlbwr()',
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
        'emulation': 'if mips_signed(rs.value, rs.size) < '
                     'mips_signed(rt.value, rt.size): mips_trap()',
    },
    'tlti': {
        'fields': [
            ['REGIMM', '000001'],
            ['rs', 'bbbbb'],
            ['TLTI', '01010'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,immediate'],
        'emulation': 'if rs < sign_extend(immediate): mips_trap()',
    },
    'tltiu': {
        'fields': [
            ['REGIMM', '000001'],
            ['rs', 'bbbbb'],
            ['TLTIU', '01011'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rs,immediate'],
        'emulation': 'if rs.uvalue < unsigned(sign_extend(immediate)):'
        ' mips_trap()',
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
        'emulation': 'if rs.value < rt.value: mips_trap()',
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
        'emulation': 'if rs.value != rt.value: mips_trap(code)',
    },
    'wait': {
        'fields': [
            ['COP0', '010000'],
            ['CO', '1'],
            ['code', 'bbbbbbbbbbbbbbbbbbb'],
            ['WAIT', '100000'],
        ],
        'args': ['code', [None, '0']],
        'emulation': 'mips_wait(code)',
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
        'emulation': 'rd.value = rs ^ rt',
    },
    'xori': {
        'fields': [
            ['XORI', '001110'],
            ['rs', 'bbbbb'],
            ['rt', 'bbbbb'],
            ['immediate', 'bbbbbbbbbbbbbbbb'],
        ],
        'args': ['rt,rs,immediate'],
        'emulation': 'rt.value = rs ^ immediate',
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
    '''
    Represent a MIPS general register
    '''
    registers = {}
    def __new__(cls, *args, **kwargs):
        name = args[0]
        if name in cls.registers:
            logging.debug('returning already existing register %s', name)
            return cls.registers[name]
        else:
            logging.debug('creating new Register(%s)', name)
            return super(Register, cls).__new__(cls, *args, **kwargs)
    def __init__(self, name, number=None, value=0): 
        self.name = name
        if number is None:
            number = REGISTER_REFERENCE[name]
        self.number = number
        self.value = value
        self.registers[name] = self
        self.registers[number] = self

    def __index__(self):
        return self.value

    def __int__(self):
        return self.value

    def __add__(self, other):
        return self.value + int(other)

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<Register_%s(%d) value=%d>' % (self.name, self.number,
                                               self.value)

def disassemble(filespec):
    '''
    primitive disassembler
    '''
    print '.set noat'  # get rid of warnings for using $at register
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
            outfile = sys.stdout
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
                    outfile.write(struct.pack('<L', instruction))
                elif label:
                    if label in LABELS:
                        raise ValueError('Label %r already in LABELS as %r' %
                                         (label, LABELS[label]))
                    LABELS[label] = offset
                offset += 4
                debug('offset now: 0x%x', offset)

def disassemble_chunk(loop, index, chunk, maxoffset):
    '''
    build labels dict in first loop, output assembly language in second
    '''
    instruction = struct.unpack('<L', chunk)[0]
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
        coprocessor = int(mnemonic[-1])
        coregister = COREGISTER.get(dest, 'c%d_unknown')
        if '%d' in coregister:
            coregister = coregister % coprocessor
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
        destination = LABELS.get(offset, '0x%x' % offset)
    else:
        destination = '0x%x' % offset
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
        LABELS[offset] = 's%x' % offset
        #logging.debug('LABELS: %s', LABELS)
    pattern = PATTERN[style]
    line = pattern % locals()
    if loop == 1:
        print line
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
        CONVERSION['sync'] = [[
            'amount == 0',
            ['sync', 'simple', False, 'True', False],
        ]]
        CONVERSION['sync'] = [['amount != 0', WORD]]
        # objdump disassembly returns .word for sel != 0
        CONVERSION['mtc0'] = [['sel != 0', WORD]]
        CONVERSION['mfc0'] = [['sel != 0', WORD]]
        # objdump disassembly always returns just the .word for movz and movn
        CONVERSION['movz'] = [['True', WORD]]
        CONVERSION['movn'] = [['True', WORD]]
        # objdump has no 'deret'
        CONVERSION['c0'][0][1] = ['c0', 'coprocessor', False, 'True', False]
        # objdump doesn't show register $s8 as frame pointer
        REGISTER_REFERENCE['$fp'] = REGISTER.index('$fp')
        REGISTER[REGISTER.index('$fp')] = '$s8'
        # objdump dumps div, ddiv, divu, and ddivu as arithlog
        for item in SPECIAL:
            if item[0] in ('div', 'divu', 'ddiv', 'ddivu'):
                logging.warn('Making %r incorrectly dump as "arithlog"'
                             ' to match objdump disassembly',
                             item[0])
                item[1] = 'arithlog'
    else:
        # need to be able to interpret register $s8 when assembling
        REGISTER_REFERENCE['$s8'] = REGISTER.index('$fp')
    REGISTER_REFERENCE.update({value: key for key, value in COREGISTER.items()})
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
    argslist = [argsplit(string) for string in args, pseudoop_args, newargs]
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
        logging.debug('negative number now 0x%x', number)
    if name  == 'offset' and not 'base' in argsdict:
        number = (number - offset - 4) >> 2
        logging.debug('branch offset now 0x%x', number)
    elif name == 'target':
        number >>= 2  # jump targets are *not* PC-relative
        logging.debug('jump target now 0x%x', number)
    number = number & maskbits
    logging.debug('number after mask operation: 0x%x', number)
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
                        logging.debug('before merging number %r: 0x%x',
                                      arg, instruction)
                        instruction |= smart_mask(number, name, offset,
                                                  argsdict, mask)
                        logging.debug('after merging number %r: 0x%x',
                                      arg, instruction)
                    elif arg in LABELS:
                        if name in fieldsdict:
                            fieldsdict[name] = LABELS[arg]
                        logging.debug('before merging label %r (0x%x): 0x%x',
                                      arg, LABELS[arg], instruction)
                        instruction |= smart_mask(LABELS[arg], name, offset,
                                                  argsdict, mask)
                        logging.debug('after merging label %r (0x%x): 0x%x',
                                      arg, LABELS[arg], instruction)
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
                            logging.debug('before %r: 0x%x', arg, instruction)
                            instruction |= REGISTER_REFERENCE[arg]
                            logging.debug('after %r: 0x%x', arg, instruction)
                        elif loop == 0:
                            instruction = 'pending label list completion'
                            break
                        else:
                            logging.error('%r not in REGISTER_REFERENCE %s',
                                          arg, REGISTER_REFERENCE)
                            raise ValueError('Cannot process arg %r' % arg)
        elif reference.get('action') is not None:
            exec reference['action'] in globals(), locals()
            instruction = None
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
        return instruction, (reference['emulation'], fieldsdict)
    else:
        raise NotImplementedError('%s not in REFERENCE' % mnemonic)

def emulate(filespec):
    '''
    primitive MIPS emulator
    '''
    with open(filespec) as infile:
        filedata = infile.read()
    program = [filedata[i:i + 4] for i in range(0, len(filedata), 4)]
    pc = 0x8c000000  # program counter on reset
    index = 0
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
        logging.info('executing: %s', emulation)
        locals().update(emulation[1])
        index += 1
        pc += 4
        exec(emulation[0])
        raw_input('%s Continue> ' % Register.registers)
        
if __name__ == '__main__':
    init()
    eval(sys.argv[1])(*sys.argv[2:])
