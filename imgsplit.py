#!/usr/bin/python3 -OO
'''
Tiny replacement for Heffner/Collake FMK

Using Python3 for native lzma support
'''
import sys, os, subprocess, logging, lzma, gzip, zlib
from socket import ntohl

logging.basicConfig(level=logging.DEBUG if __debug__ else logging.WARN)


DECOMPRESSOR = {
    'LZMA compressed data': 'lzma',
    'gzip compressed data': 'gzip',
    'Zlib compressed data': 'zlib',
}

def split(filespec, outdir=None):
    '''
    Run binwalk on the file and extract the various pieces
    '''
    binwalk = subprocess.check_output(['/usr/bin/binwalk', filespec])
    logging.debug('binwalk output: %s', binwalk)
    pieces = [lineinfo(line.decode()) for line in binwalk.splitlines()[3:]
              if len(line)]
    warning = False
    if not pieces:
        raise ValueError('File %s was not recognized by binwalk' % filespec)
    if outdir is None:
        outdir = os.path.dirname(filespec)
        warning = True  # may be unexpected, so let user know
    logging.debug('outdir: %s, filespec: %s', outdir, filespec)
    dirname = os.path.join(outdir, os.path.basename(filespec) + '.pieces')
    if warning:
        logging.warning('Output goes to %s', dirname)
    os.mkdir(dirname)  # raises OSError if already exists
    with open(filespec, 'rb') as infile:
        filedata = infile.read()
    pieces.append([str(len(filedata))])
    logging.debug('pieces: %s', pieces)
    for index in range(len(pieces) - 1):
        offset, description = pieces[index]
        size = int(pieces[index + 1][0], 16)
        with open(os.path.join(dirname, offset + '.raw'), 'wb') as outfile:
            outfile.write(filedata[int(offset, 16):size])
        with open(os.path.join(dirname, offset + '.info'), 'w') as outfile:
            print(description, file=outfile)
        if description.startswith(tuple(DECOMPRESSOR)):
            decompressed = decompress(
                description, filedata[int(offset, 16):size])
            with open(os.path.join(dirname, offset + '.dat'), 'wb') as outfile:
                outfile.write(decompressed)
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
    return hexadecimal, info

def decompress(compression, data):
    '''
    Return decompressed data for specified compression method
    '''
    prefix = compression.split(',')[0]
    module = DECOMPRESSOR[prefix]
    return eval(module).decompress(data)

if __name__ == '__main__':
    split(*sys.argv[1:])
