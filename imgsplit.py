#!/usr/bin/python
'''
Tiny replacement for Heffner/Collake FMK
'''
import sys, os, subprocess

def split(filespec, outdir=None):
    '''
    Run binwalk on the file and extract the various pieces
    '''
    binwalk = subprocess.check_output(['/usr/src/binwalk', filespec])
    pieces = [lineinfo(line) for line in binwalk.splitlines()[2:]]
    if not pieces:
        raise ValueError('File %s was not recognized by binwalk' % filespec)
    dirname = os.path.join(outdir, os.path.filename(filespec) + '.pieces')
    os.mkdir(dirname)  # raises OSError if already exists
    with open(filespec, 'rb') as infile:
        filedata = infile.read()
    pieces.append([str(len(filedata))])
    for index in range(len(pieces) - 1):
        offset, description = lineinfo(pieces[index])
        size = int(pieces[index + 1][0])
        with open(os.path.join(dirname, offset + '.dat'), 'rw') as outfile:
            outfile.write(filedata[int(offset):size])
        with open(os.path.join(filename, offset + '.info'), 'w') as outfile:
            outfile.write(description)

def lineinfo(line):
    '''
    Return offset and info for each line of binwalk
    '''
    decimal, hexadecimal, info = line.split(None, 2)
    if int(decimal) != int(hexadecimal, 16):
        raise ValueError('Bad offset: %s != %s' % (decimal, hexadecimal))
    return decimal, info

if __name__ == '__main__':
    split(*sys.argv[1:])
