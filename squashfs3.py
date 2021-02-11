#!/usr/bin/python3
'''
squash and unsquash version 3 squashfs filesystems

information from https://dr-emann.github.io/squashfs/
'''
import sys, os, struct, lzma, gzip, zlib, logging

logging.basicConfig(level=logging.DEBUG if __debug__ else logging.WARN)

def unsquash(filespec):
    '''
    uncompress the entire filesystem
    '''
    with open(filespec, 'rb') as infile:
        filedata = infile.read()
    magic = filedata[:4]
    return magic

if __name__ == '__main__':
    COMMAND = sys.argv[1]
    print(eval(COMMAND)(*sys.argv[2:]))
