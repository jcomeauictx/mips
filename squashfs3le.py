#!/usr/bin/python3 -OO
'''
squash and unsquash version 3 little-endian squashfs filesystems

information from //dr-emann.github.io/squashfs/
and, for 3.0, //github.com/plougher/squashfs-tools/squashfs-tools/squashfs_fs.h,
checkout tag 3.1
'''
import sys, os, struct, lzma, gzip, zlib, logging

logging.basicConfig(level=logging.DEBUG if __debug__ else logging.WARN)

MAGIC = 'hsqs'  # little-endian; big-endian would be seen as 'sqsh'
HEADER_SPEC = [  # called struct squashfs_super_block in squashfs_fs.h
    ['s_magic', 4, None],
    ['inodes', 4, '<L'],
    ['bytes_used_2', 4, '<L'],
    ['uid_start_2', 4, '<L'],
    ['guid_start_2', 4, '<L'],
    ['inode_table_start_2', 4, '<L'],
    ['directory_table_start_2', 4, '<L'],
    ['s.major', 2, '<H'],
    ['s.minor', 2, '<H'],
    ['block_size_1', 2, '<H'],
    ['block_log', 2, '<H'],
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
