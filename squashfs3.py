#!/usr/bin/python3 -OO
'''
squash and unsquash version 3 squashfs filesystems

information from https://dr-emann.github.io/squashfs/
'''
import sys, os, struct, lzma, gzip, zlib, logging

logging.basicConfig(level=logging.DEBUG if __debug__ else logging.WARN)

MAGIC = 'hsqs'
HEADER_SPEC = [
    ['magic', 4, None],
    ['inodes', 4, '<L'],
    ['mtime', 4, '<L'],
]

def unsquash(filespec):
    '''
    uncompress the entire filesystem
    '''
    with open(filespec, 'rb') as infile:
        filedata = infile.read()
    header = {}
    offset = 0
    for name, count, packformat in HEADER_SPEC:
        logging.debug('processing %s in header', [name, count, packformat])
        value = chunk = filedata[offset:offset + count]
        if packformat:
            value = struct.unpack(packformat, chunk)[0]
        header[name] = value
        offset += count
    return header

if __name__ == '__main__':
    COMMAND = sys.argv[1]
    print(eval(COMMAND)(*sys.argv[2:]))
