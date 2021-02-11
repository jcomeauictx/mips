#!/usr/bin/python3 -OO
'''
Tiny replacement for Heffner/Collake FMK, just for TRX version 1 images

Tested only with an older OpenWrt CFE partition image.
Using Python3 for native lzma support
'''
import sys, os, re, subprocess, logging, lzma, gzip, zlib
from socket import ntohl

logging.basicConfig(level=logging.DEBUG if __debug__ else logging.WARN)

OFFSETS = re.compile(r', ([\w\s]+?) offset: (0x[0-9a-fA-F]+)')

DECOMPRESSOR = {
    'LZMA compressed data': 'lzma',
    'gzip compressed data': 'gzip',
    'Zlib compressed data': 'zlib',
}

def split(filespec, outdir=None):
    '''
    Run binwalk on the file and extract the various parts
    '''
    logging.warning('Running binwalk, this may take a while...')
    binwalk = subprocess.check_output(['/usr/bin/binwalk', filespec])
    logging.debug('binwalk output: %s', binwalk)
    parts = [lineinfo(line.decode()) for line in binwalk.splitlines()[3:]
              if len(line)]
    warning = False
    offsets = {'header': 0}
    if not parts:
        raise ValueError('File %s was not recognized by binwalk' % filespec)
    if outdir is None:
        outdir = os.path.dirname(filespec)
        warning = True  # may be unexpected, so let user know
    logging.debug('outdir: %s, filespec: %s', outdir, filespec)
    dirname = os.path.join(outdir, os.path.basename(filespec) + '.parts')
    if warning:
        logging.warning('Output goes to %s', dirname)
    os.mkdir(dirname)  # raises OSError if already exists
    with open(filespec, 'rb') as infile:
        filedata = infile.read()
    parts.append([str(len(filedata))])
    logging.debug('parts: %s', parts)
    for index in range(len(parts) - 1):
        hexoffset, description = parts[index]
        size = int(parts[index + 1][0], 16)
        writefile(dirname, hexoffset, '.raw', 'wb', size, filedata, offsets)
        writefile(dirname, hexoffset, '.info', 'w', 0, description, offsets)
        if description.startswith(tuple(DECOMPRESSOR)):
            data = decompress(description, filedata, hexoffset, size)
            writefile(dirname, hexoffset, '.dat', 'wb', 0, data, offsets)
        elif description.startswith('TRX firmware header'):
            trx_header = description.split()
            crc32 = trx_header[trx_header.index('CRC32:') + 1].rstrip(',')
            trxsize = int(trx_header[trx_header.index('size:') + 1].rstrip(','))
            logging.debug('calculating CRC32 on %d (0x%x) bytes of data',
                          len(filedata[12:trxsize]), len(filedata[12:trxsize]))
            crc32_check = zlib.crc32(filedata[12:trxsize])
            if int(crc32, 16) != crc32_check ^ 0xffffffff:
                raise ValueError('Nonmatching CRCs 0x%x != %s' %
                                 (crc32_check, crc32.lower()))
            offsets.update({key.replace(' ', '_'): int(value, 16) for key, value
                            in OFFSETS.findall(description)})
            # make it convertible both ways
            offsets.update({value: key for key, value in offsets.items()})
            logging.debug('offsets: %s', offsets)

def lineinfo(line):
    '''
    Return offset and info for each line of binwalk
    '''
    logging.debug('lineinfo: line=%r', line)
    try:
        decimal, hexadecimal, info = line.split(None, 2)
    except (ValueError, AttributeError):
        raise ValueError('Line %s expected to have 3 elements' % repr(line))
    if int(decimal) != int(hexadecimal, 16):
        raise ValueError('Bad offset: %s != %s' % (decimal, hexadecimal))
    return '0x%08x' % int(decimal), info

def decompress(compression, filedata, hexoffset, size):
    '''
    Return decompressed data for specified compression method
    '''
    prefix = compression.split(',')[0]
    module = DECOMPRESSOR[prefix]
    offset = int(hexoffset, 16)
    return eval(module).decompress(filedata[offset:offset + size])

def writefile(dirname, hexoffset, extension, mode, size, filedata, offsets):
    '''
    Write data to file, and optionally symlink it to a name
    '''
    basename = hexoffset  # use hexadecimal offset as the root name
    pathroot = os.path.join(dirname, basename)
    offset = int(hexoffset, 16)
    if not size:  # no offset being used
        data = filedata
    else:
        data = filedata[offset:offset + size]
    with open(pathroot + extension, mode) as outfile:
        outfile.write(data)
    if offset in offsets:
        oldpwd = os.getcwd()
        os.chdir(dirname)
        os.symlink(basename + extension, offsets[offset] + extension)
        os.chdir(oldpwd)

if __name__ == '__main__':
    COMMAND = sys.argv[1]
    eval(COMMAND)(*sys.argv[2:])
