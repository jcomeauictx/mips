#!/usr/bin/python
'''
Intelligently disassemble and reassemble MIPS binaries
'''
import sys, os, struct, ctypes, re, logging

logging.basicConfig(level=logging.DEBUG if __debug__ else logging.WARN)

MATCH_OBJDUMP_DISASSEMBLE = bool(os.getenv('MATCH_OBJDUMP_DISASSEMBLE'))
# labels will cause objdump -D output and mips disassemble output to differ
# same if instructions with bad args are turned into .word 0xNNNNNNNN
USE_LABELS = AGGRESSIVE_WORDING = not MATCH_OBJDUMP_DISASSEMBLE

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
        's8',  # frame pointer (but fp not output by objdump)
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
    # objdump disassembly always returns just the word for movz and movn
    #['movz', 'arithlog', None, 'amount == 0', None, 10],
    #['movn', 'arithlog', None, 'amount == 0', None, 11],
    ['syscall', 'syscall', False, 'True', False, 12],
    ['break', 'simple', False, 'True', False, 13],
    ['sync', 'simple', False, 'source == target == dest == 0', False, 15],
    ['mfhi', 'movefrom', False, 'source == target == amount == 0', False, 16],
    ['mthi', 'moveto', False, 'target == dest == amount == 0', False, 17],
    ['mflo', 'movefrom', False, 'source == target == amount == 0', False, 18],
    ['mtlo', 'moveto', False, 'target == dest == amount == 0', False, 19],
    ['dsllv', 'shiftv', False, 'amount == 0', False, 20],
    ['dsrlv', 'shiftv', False, 'amount == 0', False, 22],
    ['dsrav', 'arithlog', False, 'amount == 0', True, 23],
    ['mult', 'divmult', None, 'dest == amount == 0', None, 24],
    ['multu', 'divmult', None, 'dest == amount == 0', None, 25],
    ['div', 'arithlog', False, 'dest == amount == 0', True, 26],
    ['divu', 'arithlog', False, 'dest == amount == 0', True, 27],
    ['dmult', 'arithlog', False, 'dest == amount == 0', True, 28],
    ['dmultu', 'arithlog', False, 'dest == amount == 0', True, 29],
    ['ddiv', 'arithlog', False, 'dest == amount == 0', True, 30],
    ['ddivu', 'arithlog', False, 'dest == amount == 0', True, 31],
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
    # MD00086-2B-MIPS32BIS-AFP-05.04.pdf starting page 45
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
    'abs.s': {
        'fields': [
            ['COP1', '010001'],
            ['fmt', '10000'],  # fmt for single is 16, 0x10
            ['0', '00000'],
            ['fs', 'nnnnn'],
            ['fd', 'nnnnn'],
            ['ABS', '000101'],
        ],
        'args': 'fd,fs',
        'emulation': 'fd = abs(fs)'
    },
    'abs.d': {
        'fields': [
            ['COP1', '010001'],
            ['fmt', '10001'],  # fmt for double is 17, 0x11
            ['0', '00000'],
            ['fs', 'nnnnn'],
            ['fd', 'nnnnn'],
            ['ABS', '000101'],
        ],
        'args': 'fd,fs',
        'emulation': 'fd = abs(fs)'
    },
    'abs.ps': {
        'fields': [
            ['COP1', '10001'],
            ['fmt', '10110'],  # fmt for paired-single is 22, 0x16
            ['0', '00000'],
            ['fs', 'nnnnn'],
            ['fd', 'nnnnn'],
            ['ABS', '000101'],
        ],
        'args': 'fd,fs',
        'emulation': 'fd = abs(fs)'
    },
    'add': {
        'fields': [
            ['SPECIAL', '000000'],
            ['rs', 'nnnnn'],
            ['rt', 'nnnnn'],
            ['rd', 'nnnnn'],
            ['0', '00000'],
            ['ADD', '100000'],
        ],
        'args': 'rd,rs,rt',
        'emulation': 'rd = rs + rt',
    },
    'beq': {
        'fields': [
            ['BEQ', '000100'],
            ['rs', 'nnnnn'],
            ['rt', 'nnnnn'],
            ['offset', 'nnnnnnnnnnnnnnnn'],
        ],
        'args': 'rs,rt,offset',
        'emulation': 'if rs == rt: jump(offset << 2 + pc)',
    },
    'b': {
        'alias_of': [['beq', '$zero,$zero,offset']],
        'args': 'offset'
    },
    'beqz': {
        'alias_of': [['beq', 'rs,$zero,offset']],
        'args': 'rs,offset'
    },
    '.set': {
        'type': 'assembler directive',
        'action': 'logging.debug("Nothing to do for %r", mnemonic)',
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
         #['deret', 'simple', False, 'True', None]],  # objdump has no deret
         ['c0', 'coprocessor', False, 'True', False]],
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
    # objdump disassembly returns .word for sel != 0
    #'mtc0': [['sel != 0', ['mtc0', 'coproc_move3', None, 'True', None]]],
    #'mfc0': [['sel != 0', ['mfc0', 'coproc_move3', None, 'True', None]]],
    'mtc0': [['sel != 0', WORD]],
    'mfc0': [['sel != 0', WORD]],
    'jalr': [['dest == 31', ['jalr', 'jumpr', True, 'True', True]]],
    # objdump sync becomes .word if sync type set in amount field
    'sync': [['amount != 0', WORD]],
    'syscall': [['longcode == 0', ['syscall', 'simple', None, 'True', None]]],
}

def disassemble(filespec):
    '''
    primitive disassembler
    '''
    init()
    print '.set noat'  # get rid of warnings for using $at register
    with open(filespec, 'rb') as infile:
        filedata = infile.read()
        # store labels of b, j, etc. instruction targets, to print later
    labels = {0: 'start'}
    for loop in [0, 1]:
        for index in range(0, len(filedata), 4):
            chunk = filedata[index:index + 4]
            process(loop, index, chunk, labels)

def assemble(filespec):
    '''
    primitive assembler
    '''
    linepattern = r'^(?:(?P<label>[a-z0-9.]+):)?\s*'  # match label
    linepattern += r'(?:(?P<mnemonic>[a-z0-9.]+)\s+)?'  # match mnemonic
    linepattern += r'(?:(?P<args>[a-z0-9$()._,-]+)?\s*)?'  # match args
    # assembler leaves a hint at the end of a comment when it turns
    # a machine instruction into a macro/pseudoop. we use these to
    # create identical images to original from unedited disassemblies.
    linepattern += r"(?:#.*?(?:[(]from '(?P<previous>[a-z0-9.]+)'[)])?)?\s*$"
    with open(filespec, 'r') as infile:
        filedata = infile.read().splitlines()
    # first pass, just build labels
    labels = {}
    for loop in range(2):
        offset = 0
        for line in filedata:
            label = None
            match = re.match(linepattern, line)
            if match:
                label = match.group('label')
            else:
                raise ValueError('No match for regex %r to line %r' %
                                 (linepattern, line))
            instruction = assemble_instruction(loop, labels,
                                               **match.groupdict())
            if instruction is not None:
                if loop == 1:
                    outfile.write(struct.pack('<L', instruction))
                elif label is not None:
                    labels[label] = offset
                offset += 4

def process(loop, index, chunk, labels):
    '''
    build labels dict in first loop, output assembly language in second
    '''
    instruction = struct.unpack('<L', chunk)[0]
    logging.debug('chunk: %r, instruction: 0x%08x', chunk, instruction)
    label = labels.get(index, '')
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
    offset = index + 4 + (immediate << 2)
    # don't use labels until we've ascertained that output is like objdump
    if USE_LABELS:
        destination = labels.get(offset, '0x%x' % offset)
    else:
        destination = '0x%x' % offset
    if mnemonic in CONVERSION:
        for condition, result in CONVERSION[mnemonic]:
            if eval(condition):
                comment += ' (from %r)' % mnemonic
                mnemonic, style, labeled, condition, signed = result
                break
            else:
                logging.debug('eval %r failed in %s', condition,
                              shorten(locals()))
    if USE_LABELS and labeled and offset not in labels:
        labels[offset] = 's%x' % offset
        #logging.debug('labels: %s', labels)
    pattern = PATTERN[style]
    line = pattern % locals()
    if loop == 1:
        print line

def init():
    '''
    Fill in some missing info in global structures
    '''
    for listing, size in ([INSTRUCTION, 64], [REGIMM, 32], [SPECIAL, 64],
            [COP0, 32], [COP1, 32], [COP2, 32], [COP3, 32]):
        for item in list(listing):
            while item[-1] != listing.index(item):
                logging.debug('%s expected at %d, found at %d',
                              item[0], item[-1], listing.index(item))
                listing.insert(listing.index(item), WORD)
        while len(listing) < size:
            listing.append(WORD)
    REGISTER_REFERENCE.update({value: key for key, value in COREGISTER.items()})
    for listing in REGISTER, ALTREG, FLOATREG:
        hashtable = zip(listing, range(len(listing)))
        REGISTER_REFERENCE.update(hashtable)

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

def assemble_instruction(loop, labels, mnemonic='', label='', args='',
        previous=''):
    '''
    Assemble an instruction given the assembly source line
    '''
    logging.debug('processing: %s', locals())
    instruction = 0
    if mnemonic in REFERENCE:
        args = args.split(',')
        if 'fields' in REFERENCE[mnemonic]:
            for name, value in REFERENCE[mnemonic]['fields']:
                instruction <<= len(value)
                if value.isdigit():
                    instruction |= int(value, 2)
                else:
                    arg = args.pop(0)
                    if arg[0].isdigit():
                        instruction |= eval(args[0])
                    elif arg in labels:
                        instruction |= labels[arg]
                    else:
                        # check for coprocessor register special names
                        if '_' in arg:
                            arg = arg.replace(arg[arg.index('_') - 1], '%d')
                        if arg in REGISTER_REFERENCE:
                            instruction |= REGISTER_REFERENCE[arg]
                        elif loop == 0:
                            instruction = 'pending label list completion'
                            break
        elif REFERENCE[mnemonic].get('action') is not None:
            exec(REFERENCE[mnemonic]['action'])
            instruction = None
        elif REFERENCE[mnemonic].get('alias_of') is not None:
            aliases = REFERENCE[mnemonic]['alias_of']
            logging.debug('dict(aliases): %s', dict(aliases))
            if previous in dict(aliases):
                args = dict(aliases)[previous]
                mnemonic = previous
            else:
                mnemonic, args = aliases[0]
            return assemble_instruction(loop, labels, mnemonic,
                                        label, args, None)
        else:
            raise NotImplementedError('No action found for %s' % mnemonic)
    else:
        raise NotImplementedError('%s not in REFERENCE' % mnemonic)
    return instruction

if __name__ == '__main__':
    eval(sys.argv[1])(*sys.argv[2:])
