#!/usr/bin/python3
'''
Reversible gzip for trx unpacking/repacking

Will be slow compared to standard Python module, but will provide all data
necessary to rebuild a trx identical to the original.

RFCs 1952 (gzip) and 1951 (deflate) are attached for reference.

Network Working Group                                         P. Deutsch
Request for Comments: 1952                           Aladdin Enterprises
Category: Informational                                         May 1996


               GZIP file format specification version 4.3

Status of This Memo

   This memo provides information for the Internet community.  This memo
   does not specify an Internet standard of any kind.  Distribution of
   this memo is unlimited.

IESG Note:

   The IESG takes no position on the validity of any Intellectual
   Property Rights statements contained in this document.

Notices

   Copyright (c) 1996 L. Peter Deutsch

   Permission is granted to copy and distribute this document for any
   purpose and without charge, including translations into other
   languages and incorporation into compilations, provided that the
   copyright notice and this notice are preserved, and that any
   substantive changes or deletions from the original are clearly
   marked.

   A pointer to the latest version of this and related documentation in
   HTML format can be found at the URL
   <ftp://ftp.uu.net/graphics/png/documents/zlib/zdoc-index.html>.

Abstract

   This specification defines a lossless compressed data format that is
   compatible with the widely used GZIP utility.  The format includes a
   cyclic redundancy check value for detecting data corruption.  The
   format presently uses the DEFLATE method of compression but can be
   easily extended to use other compression methods.  The format can be
   implemented readily in a manner not covered by patents.


Deutsch                      Informational                      [Page 1]

RFC 1952             GZIP File Format Specification             May 1996


Table of Contents

   1. Introduction ................................................... 2
      1.1. Purpose ................................................... 2
      1.2. Intended audience ......................................... 3
      1.3. Scope ..................................................... 3
      1.4. Compliance ................................................ 3
      1.5. Definitions of terms and conventions used ................. 3
      1.6. Changes from previous versions ............................ 3
   2. Detailed specification ......................................... 4
      2.1. Overall conventions ....................................... 4
      2.2. File format ............................................... 5
      2.3. Member format ............................................. 5
          2.3.1. Member header and trailer ........................... 6
              2.3.1.1. Extra field ................................... 8
              2.3.1.2. Compliance .................................... 9
      3. References .................................................. 9
      4. Security Considerations .................................... 10
      5. Acknowledgements ........................................... 10
      6. Author's Address ........................................... 10
      7. Appendix: Jean-Loup Gailly's gzip utility .................. 11
      8. Appendix: Sample CRC Code .................................. 11

1. Introduction

   1.1. Purpose

      The purpose of this specification is to define a lossless
      compressed data format that:

          * Is independent of CPU type, operating system, file system,
            and character set, and hence can be used for interchange;
          * Can compress or decompress a data stream (as opposed to a
            randomly accessible file) to produce another data stream,
            using only an a priori bounded amount of intermediate
            storage, and hence can be used in data communications or
            similar structures such as Unix filters;
          * Compresses data with efficiency comparable to the best
            currently available general-purpose compression methods,
            and in particular considerably better than the "compress"
            program;
          * Can be implemented readily in a manner not covered by
            patents, and hence can be practiced freely;
          * Is compatible with the file format produced by the current
            widely used gzip utility, in that conforming decompressors
            will be able to read data produced by the existing gzip
            compressor.

Deutsch                      Informational                      [Page 2]

RFC 1952             GZIP File Format Specification             May 1996


      The data format defined by this specification does not attempt to:

          * Provide random access to compressed data;
          * Compress specialized data (e.g., raster graphics) as well as
            the best currently available specialized algorithms.

   1.2. Intended audience

      This specification is intended for use by implementors of software
      to compress data into gzip format and/or decompress data from gzip
      format.

      The text of the specification assumes a basic background in
      programming at the level of bits and other primitive data
      representations.

   1.3. Scope

      The specification specifies a compression method and a file format
      (the latter assuming only that a file can store a sequence of
      arbitrary bytes).  It does not specify any particular interface to
      a file system or anything about character sets or encodings
      (except for file names and comments, which are optional).

   1.4. Compliance

      Unless otherwise indicated below, a compliant decompressor must be
      able to accept and decompress any file that conforms to all the
      specifications presented here; a compliant compressor must produce
      files that conform to all the specifications presented here.  The
      material in the appendices is not part of the specification per se
      and is not relevant to compliance.

   1.5. Definitions of terms and conventions used

      byte: 8 bits stored or transmitted as a unit (same as an octet).
      (For this specification, a byte is exactly 8 bits, even on
      machines which store a character on a number of bits different
      from 8.)  See below for the numbering of bits within a byte.

   1.6. Changes from previous versions

      There have been no technical changes to the gzip format since
      version 4.1 of this specification.  In version 4.2, some
      terminology was changed, and the sample CRC code was rewritten for
      clarity and to eliminate the requirement for the caller to do pre-
      and post-conditioning.  Version 4.3 is a conversion of the
      specification to RFC style.

Deutsch                      Informational                      [Page 3]

RFC 1952             GZIP File Format Specification             May 1996


2. Detailed specification

   2.1. Overall conventions

      In the diagrams below, a box like this:

         +---+
         |   | <-- the vertical bars might be missing
         +---+

      represents one byte; a box like this:

         +==============+
         |              |
         +==============+

      represents a variable number of bytes.

      Bytes stored within a computer do not have a "bit order", since
      they are always treated as a unit.  However, a byte considered as
      an integer between 0 and 255 does have a most- and least-
      significant bit, and since we write numbers with the most-
      significant digit on the left, we also write bytes with the most-
      significant bit on the left.  In the diagrams below, we number the
      bits of a byte so that bit 0 is the least-significant bit, i.e.,
      the bits are numbered:

         +--------+
         |76543210|
         +--------+

      This document does not address the issue of the order in which
      bits of a byte are transmitted on a bit-sequential medium, since
      the data format described here is byte- rather than bit-oriented.

      Within a computer, a number may occupy multiple bytes.  All
      multi-byte numbers in the format described here are stored with
      the least-significant byte first (at the lower memory address).
      For example, the decimal number 520 is stored as:

             0        1
         +--------+--------+
         |00001000|00000010|
         +--------+--------+
          ^        ^
          |        |
          |        + more significant byte = 2 x 256
          + less significant byte = 8

Deutsch                      Informational                      [Page 4]

RFC 1952             GZIP File Format Specification             May 1996


   2.2. File format

      A gzip file consists of a series of "members" (compressed data
      sets).  The format of each member is specified in the following
      section.  The members simply appear one after another in the file,
      with no additional information before, between, or after them.

   2.3. Member format

      Each member has the following structure:

         +---+---+---+---+---+---+---+---+---+---+
         |ID1|ID2|CM |FLG|     MTIME     |XFL|OS | (more-->)
         +---+---+---+---+---+---+---+---+---+---+

      (if FLG.FEXTRA set)

         +---+---+=================================+
         | XLEN  |...XLEN bytes of "extra field"...| (more-->)
         +---+---+=================================+

      (if FLG.FNAME set)

         +=========================================+
         |...original file name, zero-terminated...| (more-->)
         +=========================================+

      (if FLG.FCOMMENT set)

         +===================================+
         |...file comment, zero-terminated...| (more-->)
         +===================================+

      (if FLG.FHCRC set)

         +---+---+
         | CRC16 |
         +---+---+

         +=======================+
         |...compressed blocks...| (more-->)
         +=======================+

           0   1   2   3   4   5   6   7
         +---+---+---+---+---+---+---+---+
         |     CRC32     |     ISIZE     |
         +---+---+---+---+---+---+---+---+

Deutsch                      Informational                      [Page 5]

RFC 1952             GZIP File Format Specification             May 1996


      2.3.1. Member header and trailer

         ID1 (IDentification 1)
         ID2 (IDentification 2)
            These have the fixed values ID1 = 31 (0x1f, \037), ID2 = 139
            (0x8b, \213), to identify the file as being in gzip format.

         CM (Compression Method)
            This identifies the compression method used in the file.  CM
            = 0-7 are reserved.  CM = 8 denotes the "deflate"
            compression method, which is the one customarily used by
            gzip and which is documented elsewhere.

         FLG (FLaGs)
            This flag byte is divided into individual bits as follows:

               bit 0   FTEXT
               bit 1   FHCRC
               bit 2   FEXTRA
               bit 3   FNAME
               bit 4   FCOMMENT
               bit 5   reserved
               bit 6   reserved
               bit 7   reserved

            If FTEXT is set, the file is probably ASCII text.  This is
            an optional indication, which the compressor may set by
            checking a small amount of the input data to see whether any
            non-ASCII characters are present.  In case of doubt, FTEXT
            is cleared, indicating binary data. For systems which have
            different file formats for ascii text and binary data, the
            decompressor can use FTEXT to choose the appropriate format.
            We deliberately do not specify the algorithm used to set
            this bit, since a compressor always has the option of
            leaving it cleared and a decompressor always has the option
            of ignoring it and letting some other program handle issues
            of data conversion.

            If FHCRC is set, a CRC16 for the gzip header is present,
            immediately before the compressed data. The CRC16 consists
            of the two least significant bytes of the CRC32 for all
            bytes of the gzip header up to and not including the CRC16.
            [The FHCRC bit was never set by versions of gzip up to
            1.2.4, even though it was documented with a different
            meaning in gzip 1.2.4.]

            If FEXTRA is set, optional extra fields are present, as
            described in a following section.

Deutsch                      Informational                      [Page 6]

RFC 1952             GZIP File Format Specification             May 1996


            If FNAME is set, an original file name is present,
            terminated by a zero byte.  The name must consist of ISO
            8859-1 (LATIN-1) characters; on operating systems using
            EBCDIC or any other character set for file names, the name
            must be translated to the ISO LATIN-1 character set.  This
            is the original name of the file being compressed, with any
            directory components removed, and, if the file being
            compressed is on a file system with case insensitive names,
            forced to lower case. There is no original file name if the
            data was compressed from a source other than a named file;
            for example, if the source was stdin on a Unix system, there
            is no file name.

            If FCOMMENT is set, a zero-terminated file comment is
            present.  This comment is not interpreted; it is only
            intended for human consumption.  The comment must consist of
            ISO 8859-1 (LATIN-1) characters.  Line breaks should be
            denoted by a single line feed character (10 decimal).

            Reserved FLG bits must be zero.

         MTIME (Modification TIME)
            This gives the most recent modification time of the original
            file being compressed.  The time is in Unix format, i.e.,
            seconds since 00:00:00 GMT, Jan.  1, 1970.  (Note that this
            may cause problems for MS-DOS and other systems that use
            local rather than Universal time.)  If the compressed data
            did not come from a file, MTIME is set to the time at which
            compression started.  MTIME = 0 means no time stamp is
            available.

         XFL (eXtra FLags)
            These flags are available for use by specific compression
            methods.  The "deflate" method (CM = 8) sets these flags as
            follows:

               XFL = 2 - compressor used maximum compression,
                         slowest algorithm
               XFL = 4 - compressor used fastest algorithm

         OS (Operating System)
            This identifies the type of file system on which compression
            took place.  This may be useful in determining end-of-line
            convention for text files.  The currently defined values are
            as follows:

Deutsch                      Informational                      [Page 7]

RFC 1952             GZIP File Format Specification             May 1996


                 0 - FAT filesystem (MS-DOS, OS/2, NT/Win32)
                 1 - Amiga
                 2 - VMS (or OpenVMS)
                 3 - Unix
                 4 - VM/CMS
                 5 - Atari TOS
                 6 - HPFS filesystem (OS/2, NT)
                 7 - Macintosh
                 8 - Z-System
                 9 - CP/M
                10 - TOPS-20
                11 - NTFS filesystem (NT)
                12 - QDOS
                13 - Acorn RISCOS
               255 - unknown

         XLEN (eXtra LENgth)
            If FLG.FEXTRA is set, this gives the length of the optional
            extra field.  See below for details.

         CRC32 (CRC-32)
            This contains a Cyclic Redundancy Check value of the
            uncompressed data computed according to CRC-32 algorithm
            used in the ISO 3309 standard and in section 8.1.1.6.2 of
            ITU-T recommendation V.42.  (See http://www.iso.ch for
            ordering ISO documents. See gopher://info.itu.ch for an
            online version of ITU-T V.42.)

         ISIZE (Input SIZE)
            This contains the size of the original (uncompressed) input
            data modulo 2^32.

      2.3.1.1. Extra field

         If the FLG.FEXTRA bit is set, an "extra field" is present in
         the header, with total length XLEN bytes.  It consists of a
         series of subfields, each of the form:

            +---+---+---+---+==================================+
            |SI1|SI2|  LEN  |... LEN bytes of subfield data ...|
            +---+---+---+---+==================================+

         SI1 and SI2 provide a subfield ID, typically two ASCII letters
         with some mnemonic value.  Jean-Loup Gailly
         <gzip@prep.ai.mit.edu> is maintaining a registry of subfield
         IDs; please send him any subfield ID you wish to use.  Subfield
         IDs with SI2 = 0 are reserved for future use.  The following
         IDs are currently defined:

Deutsch                      Informational                      [Page 8]

RFC 1952             GZIP File Format Specification             May 1996


            SI1         SI2         Data
            ----------  ----------  ----
            0x41 ('A')  0x70 ('P')  Apollo file type information

         LEN gives the length of the subfield data, excluding the 4
         initial bytes.

      2.3.1.2. Compliance

         A compliant compressor must produce files with correct ID1,
         ID2, CM, CRC32, and ISIZE, but may set all the other fields in
         the fixed-length part of the header to default values (255 for
         OS, 0 for all others).  The compressor must set all reserved
         bits to zero.

         A compliant decompressor must check ID1, ID2, and CM, and
         provide an error indication if any of these have incorrect
         values.  It must examine FEXTRA/XLEN, FNAME, FCOMMENT and FHCRC
         at least so it can skip over the optional fields if they are
         present.  It need not examine any other part of the header or
         trailer; in particular, a decompressor may ignore FTEXT and OS
         and always produce binary output, and still be compliant.  A
         compliant decompressor must give an error indication if any
         reserved bit is non-zero, since such a bit could indicate the
         presence of a new field that would cause subsequent data to be
         interpreted incorrectly.

3. References

   [1] "Information Processing - 8-bit single-byte coded graphic
       character sets - Part 1: Latin alphabet No.1" (ISO 8859-1:1987).
       The ISO 8859-1 (Latin-1) character set is a superset of 7-bit
       ASCII. Files defining this character set are available as
       iso_8859-1.* in ftp://ftp.uu.net/graphics/png/documents/

   [2] ISO 3309

   [3] ITU-T recommendation V.42

   [4] Deutsch, L.P.,"DEFLATE Compressed Data Format Specification",
       available in ftp://ftp.uu.net/pub/archiving/zip/doc/

   [5] Gailly, J.-L., GZIP documentation, available as gzip-*.tar in
       ftp://prep.ai.mit.edu/pub/gnu/

   [6] Sarwate, D.V., "Computation of Cyclic Redundancy Checks via Table
       Look-Up", Communications of the ACM, 31(8), pp.1008-1013.


Deutsch                      Informational                      [Page 9]

RFC 1952             GZIP File Format Specification             May 1996


   [7] Schwaderer, W.D., "CRC Calculation", April 85 PC Tech Journal,
       pp.118-133.

   [8] ftp://ftp.adelaide.edu.au/pub/rocksoft/papers/crc_v3.txt,
       describing the CRC concept.

4. Security Considerations

   Any data compression method involves the reduction of redundancy in
   the data.  Consequently, any corruption of the data is likely to have
   severe effects and be difficult to correct.  Uncompressed text, on
   the other hand, will probably still be readable despite the presence
   of some corrupted bytes.

   It is recommended that systems using this data format provide some
   means of validating the integrity of the compressed data, such as by
   setting and checking the CRC-32 check value.

5. Acknowledgements

   Trademarks cited in this document are the property of their
   respective owners.

   Jean-Loup Gailly designed the gzip format and wrote, with Mark Adler,
   the related software described in this specification.  Glenn
   Randers-Pehrson converted this document to RFC and HTML format.

6. Author's Address

   L. Peter Deutsch
   Aladdin Enterprises
   203 Santa Margarita Ave.
   Menlo Park, CA 94025

   Phone: (415) 322-0103 (AM only)
   FAX:   (415) 322-1734
   EMail: <ghost@aladdin.com>

   Questions about the technical content of this specification can be
   sent by email to:

   Jean-Loup Gailly <gzip@prep.ai.mit.edu> and
   Mark Adler <madler@alumni.caltech.edu>

   Editorial comments on this specification can be sent by email to:

   L. Peter Deutsch <ghost@aladdin.com> and
   Glenn Randers-Pehrson <randeg@alumni.rpi.edu>

Deutsch                      Informational                     [Page 10]

RFC 1952             GZIP File Format Specification             May 1996


7. Appendix: Jean-Loup Gailly's gzip utility

   The most widely used implementation of gzip compression, and the
   original documentation on which this specification is based, were
   created by Jean-Loup Gailly <gzip@prep.ai.mit.edu>.  Since this
   implementation is a de facto standard, we mention some more of its
   features here.  Again, the material in this section is not part of
   the specification per se, and implementations need not follow it to
   be compliant.

   When compressing or decompressing a file, gzip preserves the
   protection, ownership, and modification time attributes on the local
   file system, since there is no provision for representing protection
   attributes in the gzip file format itself.  Since the file format
   includes a modification time, the gzip decompressor provides a
   command line switch that assigns the modification time from the file,
   rather than the local modification time of the compressed input, to
   the decompressed output.

8. Appendix: Sample CRC Code

   The following sample code represents a practical implementation of
   the CRC (Cyclic Redundancy Check). (See also ISO 3309 and ITU-T V.42
   for a formal specification.)

   The sample code is in the ANSI C programming language. Non C users
   may find it easier to read with these hints:

      &      Bitwise AND operator.
      ^      Bitwise exclusive-OR operator.
      >>     Bitwise right shift operator. When applied to an
             unsigned quantity, as here, right shift inserts zero
             bit(s) at the left.
      !      Logical NOT operator.
      ++     "n++" increments the variable n.
      0xNNN  0x introduces a hexadecimal (base 16) constant.
             Suffix L indicates a long value (at least 32 bits).

      /* Table of CRCs of all 8-bit messages. */
      unsigned long crc_table[256];

      /* Flag: has the table been computed? Initially false. */
      int crc_table_computed = 0;

      /* Make the table for a fast CRC. */
      void make_crc_table(void)
      {
        unsigned long c;

Deutsch                      Informational                     [Page 11]

RFC 1952             GZIP File Format Specification             May 1996


        int n, k;
        for (n = 0; n < 256; n++) {
          c = (unsigned long) n;
          for (k = 0; k < 8; k++) {
            if (c & 1) {
              c = 0xedb88320L ^ (c >> 1);
            } else {
              c = c >> 1;
            }
          }
          crc_table[n] = c;
        }
        crc_table_computed = 1;
      }

      /*
         Update a running crc with the bytes buf[0..len-1] and return
       the updated crc. The crc should be initialized to zero. Pre- and
       post-conditioning (one's complement) is performed within this
       function so it shouldn't be done by the caller. Usage example:

         unsigned long crc = 0L;

         while (read_buffer(buffer, length) != EOF) {
           crc = update_crc(crc, buffer, length);
         }
         if (crc != original_crc) error();
      */
      unsigned long update_crc(unsigned long crc,
                      unsigned char *buf, int len)
      {
        unsigned long c = crc ^ 0xffffffffL;
        int n;

        if (!crc_table_computed)
          make_crc_table();
        for (n = 0; n < len; n++) {
          c = crc_table[(c ^ buf[n]) & 0xff] ^ (c >> 8);
        }
        return c ^ 0xffffffffL;
      }

      /* Return the CRC of the bytes buf[0..len-1]. */
      unsigned long crc(unsigned char *buf, int len)
      {
        return update_crc(0L, buf, len);
      }


Deutsch                      Informational                     [Page 12]


Network Working Group                                         P. Deutsch
Request for Comments: 1951                           Aladdin Enterprises
Category: Informational                                         May 1996


        DEFLATE Compressed Data Format Specification version 1.3

Status of This Memo

   This memo provides information for the Internet community.  This memo
   does not specify an Internet standard of any kind.  Distribution of
   this memo is unlimited.

IESG Note:

   The IESG takes no position on the validity of any Intellectual
   Property Rights statements contained in this document.

Notices

   Copyright (c) 1996 L. Peter Deutsch

   Permission is granted to copy and distribute this document for any
   purpose and without charge, including translations into other
   languages and incorporation into compilations, provided that the
   copyright notice and this notice are preserved, and that any
   substantive changes or deletions from the original are clearly
   marked.

   A pointer to the latest version of this and related documentation in
   HTML format can be found at the URL
   <ftp://ftp.uu.net/graphics/png/documents/zlib/zdoc-index.html>.

Abstract

   This specification defines a lossless compressed data format that
   compresses data using a combination of the LZ77 algorithm and Huffman
   coding, with efficiency comparable to the best currently available
   general-purpose compression methods.  The data can be produced or
   consumed, even for an arbitrarily long sequentially presented input
   data stream, using only an a priori bounded amount of intermediate
   storage.  The format can be implemented readily in a manner not
   covered by patents.


Deutsch                      Informational                      [Page 1]

RFC 1951      DEFLATE Compressed Data Format Specification      May 1996


Table of Contents

   1. Introduction ................................................... 2
      1.1. Purpose ................................................... 2
      1.2. Intended audience ......................................... 3
      1.3. Scope ..................................................... 3
      1.4. Compliance ................................................ 3
      1.5.  Definitions of terms and conventions used ................ 3
      1.6. Changes from previous versions ............................ 4
   2. Compressed representation overview ............................. 4
   3. Detailed specification ......................................... 5
      3.1. Overall conventions ....................................... 5
          3.1.1. Packing into bytes .................................. 5
      3.2. Compressed block format ................................... 6
          3.2.1. Synopsis of prefix and Huffman coding ............... 6
          3.2.2. Use of Huffman coding in the "deflate" format ....... 7
          3.2.3. Details of block format ............................. 9
          3.2.4. Non-compressed blocks (BTYPE=00) ................... 11
          3.2.5. Compressed blocks (length and distance codes) ...... 11
          3.2.6. Compression with fixed Huffman codes (BTYPE=01) .... 12
          3.2.7. Compression with dynamic Huffman codes (BTYPE=10) .. 13
      3.3. Compliance ............................................... 14
   4. Compression algorithm details ................................. 14
   5. References .................................................... 16
   6. Security Considerations ....................................... 16
   7. Source code ................................................... 16
   8. Acknowledgements .............................................. 16
   9. Author's Address .............................................. 17

1. Introduction

   1.1. Purpose

      The purpose of this specification is to define a lossless
      compressed data format that:
          * Is independent of CPU type, operating system, file system,
            and character set, and hence can be used for interchange;
          * Can be produced or consumed, even for an arbitrarily long
            sequentially presented input data stream, using only an a
            priori bounded amount of intermediate storage, and hence
            can be used in data communications or similar structures
            such as Unix filters;
          * Compresses data with efficiency comparable to the best
            currently available general-purpose compression methods,
            and in particular considerably better than the "compress"
            program;
          * Can be implemented readily in a manner not covered by
            patents, and hence can be practiced freely;



Deutsch                      Informational                      [Page 2]

RFC 1951      DEFLATE Compressed Data Format Specification      May 1996


          * Is compatible with the file format produced by the current
            widely used gzip utility, in that conforming decompressors
            will be able to read data produced by the existing gzip
            compressor.

      The data format defined by this specification does not attempt to:

          * Allow random access to compressed data;
          * Compress specialized data (e.g., raster graphics) as well
            as the best currently available specialized algorithms.

      A simple counting argument shows that no lossless compression
      algorithm can compress every possible input data set.  For the
      format defined here, the worst case expansion is 5 bytes per 32K-
      byte block, i.e., a size increase of 0.015% for large data sets.
      English text usually compresses by a factor of 2.5 to 3;
      executable files usually compress somewhat less; graphical data
      such as raster images may compress much more.

   1.2. Intended audience

      This specification is intended for use by implementors of software
      to compress data into "deflate" format and/or decompress data from
      "deflate" format.

      The text of the specification assumes a basic background in
      programming at the level of bits and other primitive data
      representations.  Familiarity with the technique of Huffman coding
      is helpful but not required.

   1.3. Scope

      The specification specifies a method for representing a sequence
      of bytes as a (usually shorter) sequence of bits, and a method for
      packing the latter bit sequence into bytes.

   1.4. Compliance

      Unless otherwise indicated below, a compliant decompressor must be
      able to accept and decompress any data set that conforms to all
      the specifications presented here; a compliant compressor must
      produce data sets that conform to all the specifications presented
      here.

   1.5.  Definitions of terms and conventions used

      Byte: 8 bits stored or transmitted as a unit (same as an octet).
      For this specification, a byte is exactly 8 bits, even on machines



Deutsch                      Informational                      [Page 3]

RFC 1951      DEFLATE Compressed Data Format Specification      May 1996


      which store a character on a number of bits different from eight.
      See below, for the numbering of bits within a byte.

      String: a sequence of arbitrary bytes.

   1.6. Changes from previous versions

      There have been no technical changes to the deflate format since
      version 1.1 of this specification.  In version 1.2, some
      terminology was changed.  Version 1.3 is a conversion of the
      specification to RFC style.

2. Compressed representation overview

   A compressed data set consists of a series of blocks, corresponding
   to successive blocks of input data.  The block sizes are arbitrary,
   except that non-compressible blocks are limited to 65,535 bytes.

   Each block is compressed using a combination of the LZ77 algorithm
   and Huffman coding. The Huffman trees for each block are independent
   of those for previous or subsequent blocks; the LZ77 algorithm may
   use a reference to a duplicated string occurring in a previous block,
   up to 32K input bytes before.

   Each block consists of two parts: a pair of Huffman code trees that
   describe the representation of the compressed data part, and a
   compressed data part.  (The Huffman trees themselves are compressed
   using Huffman encoding.)  The compressed data consists of a series of
   elements of two types: literal bytes (of strings that have not been
   detected as duplicated within the previous 32K input bytes), and
   pointers to duplicated strings, where a pointer is represented as a
   pair <length, backward distance>.  The representation used in the
   "deflate" format limits distances to 32K bytes and lengths to 258
   bytes, but does not limit the size of a block, except for
   uncompressible blocks, which are limited as noted above.

   Each type of value (literals, distances, and lengths) in the
   compressed data is represented using a Huffman code, using one code
   tree for literals and lengths and a separate code tree for distances.
   The code trees for each block appear in a compact form just before
   the compressed data for that block.


Deutsch                      Informational                      [Page 4]

RFC 1951      DEFLATE Compressed Data Format Specification      May 1996


3. Detailed specification

   3.1. Overall conventions In the diagrams below, a box like this:

         +---+
         |   | <-- the vertical bars might be missing
         +---+

      represents one byte; a box like this:

         +==============+
         |              |
         +==============+

      represents a variable number of bytes.

      Bytes stored within a computer do not have a "bit order", since
      they are always treated as a unit.  However, a byte considered as
      an integer between 0 and 255 does have a most- and least-
      significant bit, and since we write numbers with the most-
      significant digit on the left, we also write bytes with the most-
      significant bit on the left.  In the diagrams below, we number the
      bits of a byte so that bit 0 is the least-significant bit, i.e.,
      the bits are numbered:

         +--------+
         |76543210|
         +--------+

      Within a computer, a number may occupy multiple bytes.  All
      multi-byte numbers in the format described here are stored with
      the least-significant byte first (at the lower memory address).
      For example, the decimal number 520 is stored as:

             0        1
         +--------+--------+
         |00001000|00000010|
         +--------+--------+
          ^        ^
          |        |
          |        + more significant byte = 2 x 256
          + less significant byte = 8

      3.1.1. Packing into bytes

         This document does not address the issue of the order in which
         bits of a byte are transmitted on a bit-sequential medium,
         since the final data format described here is byte- rather than

Deutsch                      Informational                      [Page 5]

RFC 1951      DEFLATE Compressed Data Format Specification      May 1996


         bit-oriented.  However, we describe the compressed block format
         in below, as a sequence of data elements of various bit
         lengths, not a sequence of bytes.  We must therefore specify
         how to pack these data elements into bytes to form the final
         compressed byte sequence:

             * Data elements are packed into bytes in order of
               increasing bit number within the byte, i.e., starting
               with the least-significant bit of the byte.
             * Data elements other than Huffman codes are packed
               starting with the least-significant bit of the data
               element.
             * Huffman codes are packed starting with the most-
               significant bit of the code.

         In other words, if one were to print out the compressed data as
         a sequence of bytes, starting with the first byte at the
         *right* margin and proceeding to the *left*, with the most-
         significant bit of each byte on the left as usual, one would be
         able to parse the result from right to left, with fixed-width
         elements in the correct MSB-to-LSB order and Huffman codes in
         bit-reversed order (i.e., with the first bit of the code in the
         relative LSB position).

   3.2. Compressed block format

      3.2.1. Synopsis of prefix and Huffman coding

         Prefix coding represents symbols from an a priori known
         alphabet by bit sequences (codes), one code for each symbol, in
         a manner such that different symbols may be represented by bit
         sequences of different lengths, but a parser can always parse
         an encoded string unambiguously symbol-by-symbol.

         We define a prefix code in terms of a binary tree in which the
         two edges descending from each non-leaf node are labeled 0 and
         1 and in which the leaf nodes correspond one-for-one with (are
         labeled with) the symbols of the alphabet; then the code for a
         symbol is the sequence of 0's and 1's on the edges leading from
         the root to the leaf labeled with that symbol.  For example:


Deutsch                      Informational                      [Page 6]

RFC 1951      DEFLATE Compressed Data Format Specification      May 1996


                          /\              Symbol    Code
                         0  1             ------    ----
                        /    \                A      00
                       /\     B               B       1
                      0  1                    C     011
                     /    \                   D     010
                    A     /\
                         0  1
                        /    \
                       D      C

         A parser can decode the next symbol from an encoded input
         stream by walking down the tree from the root, at each step
         choosing the edge corresponding to the next input bit.

         Given an alphabet with known symbol frequencies, the Huffman
         algorithm allows the construction of an optimal prefix code
         (one which represents strings with those symbol frequencies
         using the fewest bits of any possible prefix codes for that
         alphabet).  Such a code is called a Huffman code.  (See
         reference [1] in Chapter 5, references for additional
         information on Huffman codes.)

         Note that in the "deflate" format, the Huffman codes for the
         various alphabets must not exceed certain maximum code lengths.
         This constraint complicates the algorithm for computing code
         lengths from symbol frequencies.  Again, see Chapter 5,
         references for details.

      3.2.2. Use of Huffman coding in the "deflate" format

         The Huffman codes used for each alphabet in the "deflate"
         format have two additional rules:

             * All codes of a given bit length have lexicographically
               consecutive values, in the same order as the symbols
               they represent;

             * Shorter codes lexicographically precede longer codes.


Deutsch                      Informational                      [Page 7]

RFC 1951      DEFLATE Compressed Data Format Specification      May 1996


         We could recode the example above to follow this rule as
         follows, assuming that the order of the alphabet is ABCD:

            Symbol  Code
            ------  ----
            A       10
            B       0
            C       110
            D       111

         I.e., 0 precedes 10 which precedes 11x, and 110 and 111 are
         lexicographically consecutive.

         Given this rule, we can define the Huffman code for an alphabet
         just by giving the bit lengths of the codes for each symbol of
         the alphabet in order; this is sufficient to determine the
         actual codes.  In our example, the code is completely defined
         by the sequence of bit lengths (2, 1, 3, 3).  The following
         algorithm generates the codes as integers, intended to be read
         from most- to least-significant bit.  The code lengths are
         initially in tree[I].Len; the codes are produced in
         tree[I].Code.

         1)  Count the number of codes for each code length.  Let
             bl_count[N] be the number of codes of length N, N >= 1.

         2)  Find the numerical value of the smallest code for each
             code length:

                code = 0;
                bl_count[0] = 0;
                for (bits = 1; bits <= MAX_BITS; bits++) {
                    code = (code + bl_count[bits-1]) << 1;
                    next_code[bits] = code;
                }

         3)  Assign numerical values to all codes, using consecutive
             values for all codes of the same length with the base
             values determined at step 2. Codes that are never used
             (which have a bit length of zero) must not be assigned a
             value.

                for (n = 0;  n <= max_code; n++) {
                    len = tree[n].Len;
                    if (len != 0) {
                        tree[n].Code = next_code[len];
                        next_code[len]++;
                    }


Deutsch                      Informational                      [Page 8]

RFC 1951      DEFLATE Compressed Data Format Specification      May 1996


                }

         Example:

         Consider the alphabet ABCDEFGH, with bit lengths (3, 3, 3, 3,
         3, 2, 4, 4).  After step 1, we have:

            N      bl_count[N]
            -      -----------
            2      1
            3      5
            4      2

         Step 2 computes the following next_code values:

            N      next_code[N]
            -      ------------
            1      0
            2      0
            3      2
            4      14

         Step 3 produces the following code values:

            Symbol Length   Code
            ------ ------   ----
            A       3        010
            B       3        011
            C       3        100
            D       3        101
            E       3        110
            F       2         00
            G       4       1110
            H       4       1111

      3.2.3. Details of block format

         Each block of compressed data begins with 3 header bits
         containing the following data:

            first bit       BFINAL
            next 2 bits     BTYPE

         Note that the header bits do not necessarily begin on a byte
         boundary, since a block does not necessarily occupy an integral
         number of bytes.


Deutsch                      Informational                      [Page 9]

RFC 1951      DEFLATE Compressed Data Format Specification      May 1996


         BFINAL is set if and only if this is the last block of the data
         set.

         BTYPE specifies how the data are compressed, as follows:

            00 - no compression
            01 - compressed with fixed Huffman codes
            10 - compressed with dynamic Huffman codes
            11 - reserved (error)

         The only difference between the two compressed cases is how the
         Huffman codes for the literal/length and distance alphabets are
         defined.

         In all cases, the decoding algorithm for the actual data is as
         follows:

            do
               read block header from input stream.
               if stored with no compression
                  skip any remaining bits in current partially
                     processed byte
                  read LEN and NLEN (see next section)
                  copy LEN bytes of data to output
               otherwise
                  if compressed with dynamic Huffman codes
                     read representation of code trees (see
                        subsection below)
                  loop (until end of block code recognized)
                     decode literal/length value from input stream
                     if value < 256
                        copy value (literal byte) to output stream
                     otherwise
                        if value = end of block (256)
                           break from loop
                        otherwise (value = 257..285)
                           decode distance from input stream

                           move backwards distance bytes in the output
                           stream, and copy length bytes from this
                           position to the output stream.
                  end loop
            while not last block

         Note that a duplicated string reference may refer to a string
         in a previous block; i.e., the backward distance may cross one
         or more block boundaries.  However a distance cannot refer past
         the beginning of the output stream.  (An application using a



Deutsch                      Informational                     [Page 10]

RFC 1951      DEFLATE Compressed Data Format Specification      May 1996


         preset dictionary might discard part of the output stream; a
         distance can refer to that part of the output stream anyway)
         Note also that the referenced string may overlap the current
         position; for example, if the last 2 bytes decoded have values
         X and Y, a string reference with <length = 5, distance = 2>
         adds X,Y,X,Y,X to the output stream.

         We now specify each compression method in turn.

      3.2.4. Non-compressed blocks (BTYPE=00)

         Any bits of input up to the next byte boundary are ignored.
         The rest of the block consists of the following information:

              0   1   2   3   4...
            +---+---+---+---+================================+
            |  LEN  | NLEN  |... LEN bytes of literal data...|
            +---+---+---+---+================================+

         LEN is the number of data bytes in the block.  NLEN is the
         one's complement of LEN.

      3.2.5. Compressed blocks (length and distance codes)

         As noted above, encoded data blocks in the "deflate" format
         consist of sequences of symbols drawn from three conceptually
         distinct alphabets: either literal bytes, from the alphabet of
         byte values (0..255), or <length, backward distance> pairs,
         where the length is drawn from (3..258) and the distance is
         drawn from (1..32,768).  In fact, the literal and length
         alphabets are merged into a single alphabet (0..285), where
         values 0..255 represent literal bytes, the value 256 indicates
         end-of-block, and values 257..285 represent length codes
         (possibly in conjunction with extra bits following the symbol
         code) as follows:

Deutsch                      Informational                     [Page 11]

RFC 1951      DEFLATE Compressed Data Format Specification      May 1996


                 Extra               Extra               Extra
            Code Bits Length(s) Code Bits Lengths   Code Bits Length(s)
            ---- ---- ------     ---- ---- -------   ---- ---- -------
             257   0     3       267   1   15,16     277   4   67-82
             258   0     4       268   1   17,18     278   4   83-98
             259   0     5       269   2   19-22     279   4   99-114
             260   0     6       270   2   23-26     280   4  115-130
             261   0     7       271   2   27-30     281   5  131-162
             262   0     8       272   2   31-34     282   5  163-194
             263   0     9       273   3   35-42     283   5  195-226
             264   0    10       274   3   43-50     284   5  227-257
             265   1  11,12      275   3   51-58     285   0    258
             266   1  13,14      276   3   59-66

         The extra bits should be interpreted as a machine integer
         stored with the most-significant bit first, e.g., bits 1110
         represent the value 14.

                  Extra           Extra               Extra
             Code Bits Dist  Code Bits   Dist     Code Bits Distance
             ---- ---- ----  ---- ----  ------    ---- ---- --------
               0   0    1     10   4     33-48    20    9   1025-1536
               1   0    2     11   4     49-64    21    9   1537-2048
               2   0    3     12   5     65-96    22   10   2049-3072
               3   0    4     13   5     97-128   23   10   3073-4096
               4   1   5,6    14   6    129-192   24   11   4097-6144
               5   1   7,8    15   6    193-256   25   11   6145-8192
               6   2   9-12   16   7    257-384   26   12  8193-12288
               7   2  13-16   17   7    385-512   27   12 12289-16384
               8   3  17-24   18   8    513-768   28   13 16385-24576
               9   3  25-32   19   8   769-1024   29   13 24577-32768

      3.2.6. Compression with fixed Huffman codes (BTYPE=01)

         The Huffman codes for the two alphabets are fixed, and are not
         represented explicitly in the data.  The Huffman code lengths
         for the literal/length alphabet are:

                   Lit Value    Bits        Codes
                   ---------    ----        -----
                     0 - 143     8          00110000 through
                                            10111111
                   144 - 255     9          110010000 through
                                            111111111
                   256 - 279     7          0000000 through
                                            0010111
                   280 - 287     8          11000000 through
                                            11000111

Deutsch                      Informational                     [Page 12]

RFC 1951      DEFLATE Compressed Data Format Specification      May 1996


         The code lengths are sufficient to generate the actual codes,
         as described above; we show the codes in the table for added
         clarity.  Literal/length values 286-287 will never actually
         occur in the compressed data, but participate in the code
         construction.

         Distance codes 0-31 are represented by (fixed-length) 5-bit
         codes, with possible additional bits as shown in the table
         shown in Paragraph 3.2.5, above.  Note that distance codes 30-
         31 will never actually occur in the compressed data.

      3.2.7. Compression with dynamic Huffman codes (BTYPE=10)

         The Huffman codes for the two alphabets appear in the block
         immediately after the header bits and before the actual
         compressed data, first the literal/length code and then the
         distance code.  Each code is defined by a sequence of code
         lengths, as discussed in Paragraph 3.2.2, above.  For even
         greater compactness, the code length sequences themselves are
         compressed using a Huffman code.  The alphabet for code lengths
         is as follows:

               0 - 15: Represent code lengths of 0 - 15
                   16: Copy the previous code length 3 - 6 times.
                       The next 2 bits indicate repeat length
                             (0 = 3, ... , 3 = 6)
                          Example:  Codes 8, 16 (+2 bits 11),
                                    16 (+2 bits 10) will expand to
                                    12 code lengths of 8 (1 + 6 + 5)
                   17: Repeat a code length of 0 for 3 - 10 times.
                       (3 bits of length)
                   18: Repeat a code length of 0 for 11 - 138 times
                       (7 bits of length)

         A code length of 0 indicates that the corresponding symbol in
         the literal/length or distance alphabet will not occur in the
         block, and should not participate in the Huffman code
         construction algorithm given earlier.  If only one distance
         code is used, it is encoded using one bit, not zero bits; in
         this case there is a single code length of one, with one unused
         code.  One distance code of zero bits means that there are no
         distance codes used at all (the data is all literals).

         We can now define the format of the block:

               5 Bits: HLIT, # of Literal/Length codes - 257 (257 - 286)
               5 Bits: HDIST, # of Distance codes - 1        (1 - 32)
               4 Bits: HCLEN, # of Code Length codes - 4     (4 - 19)

Deutsch                      Informational                     [Page 13]

RFC 1951      DEFLATE Compressed Data Format Specification      May 1996


               (HCLEN + 4) x 3 bits: code lengths for the code length
                  alphabet given just above, in the order: 16, 17, 18,
                  0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15

                  These code lengths are interpreted as 3-bit integers
                  (0-7); as above, a code length of 0 means the
                  corresponding symbol (literal/length or distance code
                  length) is not used.

               HLIT + 257 code lengths for the literal/length alphabet,
                  encoded using the code length Huffman code

               HDIST + 1 code lengths for the distance alphabet,
                  encoded using the code length Huffman code

               The actual compressed data of the block,
                  encoded using the literal/length and distance Huffman
                  codes

               The literal/length symbol 256 (end of data),
                  encoded using the literal/length Huffman code

         The code length repeat codes can cross from HLIT + 257 to the
         HDIST + 1 code lengths.  In other words, all code lengths form
         a single sequence of HLIT + HDIST + 258 values.

   3.3. Compliance

      A compressor may limit further the ranges of values specified in
      the previous section and still be compliant; for example, it may
      limit the range of backward pointers to some value smaller than
      32K.  Similarly, a compressor may limit the size of blocks so that
      a compressible block fits in memory.

      A compliant decompressor must accept the full range of possible
      values defined in the previous section, and must accept blocks of
      arbitrary size.

4. Compression algorithm details

   While it is the intent of this document to define the "deflate"
   compressed data format without reference to any particular
   compression algorithm, the format is related to the compressed
   formats produced by LZ77 (Lempel-Ziv 1977, see reference [2] below);
   since many variations of LZ77 are patented, it is strongly
   recommended that the implementor of a compressor follow the general
   algorithm presented here, which is known not to be patented per se.
   The material in this section is not part of the definition of the

Deutsch                      Informational                     [Page 14]

RFC 1951      DEFLATE Compressed Data Format Specification      May 1996


   specification per se, and a compressor need not follow it in order to
   be compliant.

   The compressor terminates a block when it determines that starting a
   new block with fresh trees would be useful, or when the block size
   fills up the compressor's block buffer.

   The compressor uses a chained hash table to find duplicated strings,
   using a hash function that operates on 3-byte sequences.  At any
   given point during compression, let XYZ be the next 3 input bytes to
   be examined (not necessarily all different, of course).  First, the
   compressor examines the hash chain for XYZ.  If the chain is empty,
   the compressor simply writes out X as a literal byte and advances one
   byte in the input.  If the hash chain is not empty, indicating that
   the sequence XYZ (or, if we are unlucky, some other 3 bytes with the
   same hash function value) has occurred recently, the compressor
   compares all strings on the XYZ hash chain with the actual input data
   sequence starting at the current point, and selects the longest
   match.

   The compressor searches the hash chains starting with the most recent
   strings, to favor small distances and thus take advantage of the
   Huffman encoding.  The hash chains are singly linked. There are no
   deletions from the hash chains; the algorithm simply discards matches
   that are too old.  To avoid a worst-case situation, very long hash
   chains are arbitrarily truncated at a certain length, determined by a
   run-time parameter.

   To improve overall compression, the compressor optionally defers the
   selection of matches ("lazy matching"): after a match of length N has
   been found, the compressor searches for a longer match starting at
   the next input byte.  If it finds a longer match, it truncates the
   previous match to a length of one (thus producing a single literal
   byte) and then emits the longer match.  Otherwise, it emits the
   original match, and, as described above, advances N bytes before
   continuing.

   Run-time parameters also control this "lazy match" procedure.  If
   compression ratio is most important, the compressor attempts a
   complete second search regardless of the length of the first match.
   In the normal case, if the current match is "long enough", the
   compressor reduces the search for a longer match, thus speeding up
   the process.  If speed is most important, the compressor inserts new
   strings in the hash table only when no match was found, or when the
   match is not "too long".  This degrades the compression ratio but
   saves time since there are both fewer insertions and fewer searches.


Deutsch                      Informational                     [Page 15]

RFC 1951      DEFLATE Compressed Data Format Specification      May 1996


5. References

   [1] Huffman, D. A., "A Method for the Construction of Minimum
       Redundancy Codes", Proceedings of the Institute of Radio
       Engineers, September 1952, Volume 40, Number 9, pp. 1098-1101.

   [2] Ziv J., Lempel A., "A Universal Algorithm for Sequential Data
       Compression", IEEE Transactions on Information Theory, Vol. 23,
       No. 3, pp. 337-343.

   [3] Gailly, J.-L., and Adler, M., ZLIB documentation and sources,
       available in ftp://ftp.uu.net/pub/archiving/zip/doc/

   [4] Gailly, J.-L., and Adler, M., GZIP documentation and sources,
       available as gzip-*.tar in ftp://prep.ai.mit.edu/pub/gnu/

   [5] Schwartz, E. S., and Kallick, B. "Generating a canonical prefix
       encoding." Comm. ACM, 7,3 (Mar. 1964), pp. 166-169.

   [6] Hirschberg and Lelewer, "Efficient decoding of prefix codes,"
       Comm. ACM, 33,4, April 1990, pp. 449-459.

6. Security Considerations

   Any data compression method involves the reduction of redundancy in
   the data.  Consequently, any corruption of the data is likely to have
   severe effects and be difficult to correct.  Uncompressed text, on
   the other hand, will probably still be readable despite the presence
   of some corrupted bytes.

   It is recommended that systems using this data format provide some
   means of validating the integrity of the compressed data.  See
   reference [3], for example.

7. Source code

   Source code for a C language implementation of a "deflate" compliant
   compressor and decompressor is available within the zlib package at
   ftp://ftp.uu.net/pub/archiving/zip/zlib/.

8. Acknowledgements

   Trademarks cited in this document are the property of their
   respective owners.

   Phil Katz designed the deflate format.  Jean-Loup Gailly and Mark
   Adler wrote the related software described in this specification.
   Glenn Randers-Pehrson converted this document to RFC and HTML format.



Deutsch                      Informational                     [Page 16]

RFC 1951      DEFLATE Compressed Data Format Specification      May 1996


9. Author's Address

   L. Peter Deutsch
   Aladdin Enterprises
   203 Santa Margarita Ave.
   Menlo Park, CA 94025

   Phone: (415) 322-0103 (AM only)
   FAX:   (415) 322-1734
   EMail: <ghost@aladdin.com>

   Questions about the technical content of this specification can be
   sent by email to:

   Jean-Loup Gailly <gzip@prep.ai.mit.edu> and
   Mark Adler <madler@alumni.caltech.edu>

   Editorial comments on this specification can be sent by email to:

   L. Peter Deutsch <ghost@aladdin.com> and
   Glenn Randers-Pehrson <randeg@alumni.rpi.edu>

Deutsch                      Informational                     [Page 17]
'''
import sys, os, struct, logging

logging.basicConfig(level=logging.DEBUG if __debug__ else logging.WARN)

try:
    EXECUTABLE, COMMAND, *ARGS = sys.argv
except ValueError:
    raise ValueError('Must specify command and args for that function')
EXEC = os.path.splitext(os.path.basename(EXECUTABLE))[0]
if EXEC == 'doctest':
    DOCTESTDEBUG = logging.debug
else:
    DOCTESTDEBUG = lambda *args, **kwargs: None

OS = [
    'FAT filesystem (MS-DOS, OS/2, NT/Win32)',
    'Amiga',
    'VMS (or OpenVMS)',
    'Unix',
    'VM/CMS',
    'Atari TOS',
    'HPFS filesystem (OS/2, NT)',
    'Macintosh',
    'Z-System',
    'CP/M',
    'TOPS-20',
    'NTFS filesystem (NT)',
    'QDOS',
    'Acorn RISCOS',
]  #  255 - unknown

FLG = [
    'FTEXT',
    'FHCRC',
    'FEXTRA',
    'FNAME',
    'FCOMMENT',
]  # bits 5-7 reserved

# build hashtable matching FLG values to names
FLAGS = {key: 1 << FLG.index(key) for key in FLG}
FLAGS.update({1 << FLG.index(key): key for key in FLG})

def compress(infilespec=None, outfilespec=None):
    '''
    compress data to gzip specification
    '''
    if infilespec:
        infile = open(infilespec, 'rb')
    else:
        infile = sys.stdin
    if outfilespec:
        outfile = open(outfilespec, 'wb')
    elif infilespec:
        outfile = open(infilespec + '.gz', 'wb')
    else:
        outfile = sys.stdout
    data = infile.read()
    infile.close()
    logging.debug('compressing %r...', data[:16])
    offset = 0

def decompress(infilespec=None, outfilespec=None):
    '''
    decompress data according to gzip specification
    '''
    if infilespec:
        infile = open(infilespec, 'rb')
    else:
        infile = sys.stdin.buffer
    if outfilespec:
        outfile = open(outfilespec, 'wb')
    elif infilespec and infilespec.endswith('.gz'):
        outfile = open(infilespec[:-3], 'wb')
    else:
        outfile = sys.stdout.buffer
    data = infile.read()
    infile.close()
    logging.debug('compressing %r...', data[:16])
    offset = 0
    while offset < len(data):
        id1 = data[offset]
        id2 = data[offset + 1]
        cm = data[offset + 2]
        flg = data[offset + 3]
        mtime = data[offset + 4:offset + 8]
        xfl = data[offset + 8]
        os = data[offset + 9]
        logging.debug('locals: %s', {key: value for key, value in
                                     locals().items()
                                     if not hasattr(value, '__len__') or
                                     0 < len(value) < 16})
        if id1 != 0x1f or id2 != 0x8b:
            raise ValueError('File magic %r is wrong for gzip!' %
                             data[offset:offset + 2])
        try:
            os_string = OS[os]
        except IndexError:
            if os == 255:
                os_string = 'unknown'
            else:
                os_string = 'reserved value %d' % os
        logging.debug('operating system: %s (%d)', os_string, os)
        if cm == 8:
            compression = 'deflate (8)'
            if xfl == 2:
                compression += ', maximum compression (2)'
            elif xfl == 4:
                compression += ', minimum compression (4)'
            elif xfl == 0:
                compression += ', compression level unspecified (0)'
            else:
                compression += ', compression level unknown (%d)' % xfl
        logging.debug('compression method: %s', compression)
        logging.debug('remainder of file: %r', data[10:][:128])
        if flg != 0:
            raise NotImplementedError('Flags not yet implemented')
        offset = 10
        bit = 0
        # start deflation of data
        '''
         Each block of compressed data begins with 3 header bits
         containing the following data:

            first bit       BFINAL
            next 2 bits     BTYPE

         Note that the header bits do not necessarily begin on a byte
         boundary, since a block does not necessarily occupy an integral
         number of bytes.

         BFINAL is set if and only if this is the last block of the data
         set.

         BTYPE specifies how the data are compressed, as follows:

            00 - no compression
            01 - compressed with fixed Huffman codes
            10 - compressed with dynamic Huffman codes
            11 - reserved (error)

         The only difference between the two compressed cases is how the
         Huffman codes for the literal/length and distance alphabets are
         defined.

         In all cases, the decoding algorithm for the actual data is as
         follows:

            do
               read block header from input stream.
               if stored with no compression
                  skip any remaining bits in current partially
                     processed byte
                  read LEN and NLEN (see next section)
                  copy LEN bytes of data to output
               otherwise
                  if compressed with dynamic Huffman codes
                     read representation of code trees (see
                        subsection below)
                  loop (until end of block code recognized)
                     decode literal/length value from input stream
                     if value < 256
                        copy value (literal byte) to output stream
                     otherwise
                        if value = end of block (256)
                           break from loop
                        otherwise (value = 257..285)
                           decode distance from input stream

                           move backwards distance bytes in the output
                           stream, and copy length bytes from this
                           position to the output stream.
                  end loop
            while not last block

         Note that a duplicated string reference may refer to a string
         in a previous block; i.e., the backward distance may cross one
         or more block boundaries.  However a distance cannot refer past
         the beginning of the output stream.  (An application using a
         preset dictionary might discard part of the output stream; a
         distance can refer to that part of the output stream anyway)
         Note also that the referenced string may overlap the current
         position; for example, if the last 2 bytes decoded have values
         X and Y, a string reference with <length = 5, distance = 2>
         adds X,Y,X,Y,X to the output stream.

         We now specify each compression method in turn.
        '''
        while True:
            bfinal, bit, offset = nextbits(1, data, bit, offset)
            btype, bit, offset = nextbits(2, data, bit, offset)
            if btype == 0:
                logging.debug('data in this block is uncompressed')
                bit, offset = 0, offset + 1
                length = struct.unpack('<H', data[offset:offset + 2])[0]
                nlength = struct.unpack('<H', data[offset + 2:offset + 4])[0]
                offset += 4
                if length != ~nlength:
                    raise ValueError('LEN and NLEN fail match:'
                                     ' 0x%04x != 0x%04x' % (length, nlength))
                else:
                    break  # enough for tonight
            elif btype == 0b01:
                logging.debug('block compressed with fixed Huffman codes')
                code, bit, offset = nextcode(data, bit, offset)
                logging.debug('first code: %s', bin(code))
                break  # enough for tonight
            elif btype == 0b10:
                logging.debug('block compressed with dynamic Huffman codes')
                break  # enough for tonight
            else:
                break  # enough for tonight
        # force end to data processing while script is incomplete
        offset = len(data)

def nextbits(count, data, bit, offset, reverse=False):
    r'''
    Fetch next `count` bits from data, and return with updated bit and offset

    Huffman codes should be reversed before returning; the LSBs are actually
    the MSBs. Reverse is either False or True; `count` bits are reversed.

    >>> nextbits(1, b'\x02', 1, 0)
    (1, 2, 0)
    >>> nextbits(8, b'\xff\x00', 7, 0)
    (1, 7, 1)
    >>> nextbits(7, b'\x5a', 0, 0, True)
    (45, 7, 0)
    '''
    if count > 25:
        raise NotImplementedError('Bit counts > 25 not supported')
    if count > 8 - bit:
        # grab a 32-bit chunk
        number = struct.unpack('<L', (data + b'\0\0\0')[offset:offset + 4])[0]
    else:
        number = data[offset]
    mask = (1 << count) - 1
    DOCTESTDEBUG('shift: %d, mask: %s', bit, bin(mask))
    value = (number >> bit) & mask
    adjustment, bit = divmod(count + bit, 8)
    if reverse > 0:
        # slow but foolproof
        DOCTESTDEBUG('reversing value %s', bin(value)[2:].zfill(count))
        value = int(bin(value)[2:].zfill(count)[::-1], 2)
        DOCTESTDEBUG('reversed value is %s', bin(value)[2:].zfill(count))
    return value, bit, offset + adjustment

def nextcode(data, bit, offset):
    '''
    Get next Huffman code from stream
    >>> nextcode(bytes((0b10000,)), 0, 0)
    (260, 7, 0)
    >>> nextcode(bytes((0b10000000, 0b00000001)), 7, 0)
    (280, 7, 1)
    '''
    saved = (bit, offset)
    code, bit, offset = nextbits(7, data, bit, offset, reverse=True)
    if 0b0000000 <= code <= 0b0010111:
        DOCTESTDEBUG('got code between 256 and 279')
        code += 256
    else:
        code, bit, offset = nextbits(8, data, *saved, reverse=True)
        if 0b00110000 <= code <= 0b10111111:
            DOCTESTDEBUG('got code between 0 and 143')
            code -= 0b00110000
        elif 0b11000000 <= code <= 0b11000111:
            DOCTESTDEBUG('got code between 280 and 287')
            code += 88  # 280 - 0b11000000 (192) = 88
        else:
            code, bit, offset = nextbits(9, data, *saved, reverse=True)
            DOCTESTDEBUG('got code between 144 and 255')
            code -= 256
    return code, bit, offset

if __name__ == '__main__':
    eval(COMMAND)(*sys.argv[2:])
