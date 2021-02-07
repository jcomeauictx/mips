#!/usr/bin/python
'''
Tiny replacement for Heffner/Collake FMK
'''
import sys, os, subprocess, logging

logging.basicConfig(level=logging.DEBUG if __debug__ else logging.WARN)

def split(filespec, outdir=None):
    '''
    Run binwalk on the file and extract the various pieces
    '''
    binwalk = subprocess.check_output(['/usr/bin/binwalk', filespec])
    logging.debug('binwalk output: %s', binwalk)
    pieces = [lineinfo(line) for line in binwalk.splitlines()[3:] if len(line)]
    warning = False
    if not pieces:
        raise ValueError('File %s was not recognized by binwalk' % filespec)
    if outdir is None:
        outdir = os.path.dirname(filespec)
        warning = True  # may be unexpected, so let user know
    logging.debug('outdir: %s, filespec: %s', outdir, filespec)
    dirname = os.path.join(outdir, os.path.basename(filespec) + '.pieces')
    if warning:
        logging.warn('Output goes to %s', dirname)
    os.mkdir(dirname)  # raises OSError if already exists
    with open(filespec, 'rb') as infile:
        filedata = infile.read()
    pieces.append([str(len(filedata))])
    logging.debug('pieces: %s', pieces)
    for index in range(len(pieces) - 1):
        offset, description = pieces[index]
        size = int(pieces[index + 1][0])
        with open(os.path.join(dirname, offset + '.dat'), 'wb') as outfile:
            outfile.write(filedata[int(offset):size])
        with open(os.path.join(dirname, offset + '.info'), 'w') as outfile:
            outfile.write(description)

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
    return decimal, info

if __name__ == '__main__':
    split(*sys.argv[1:])
