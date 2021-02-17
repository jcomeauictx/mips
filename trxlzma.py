





Internet Engineering Task Force (IETF)                     J. Alakuijala
Request for Comments: 7932                                   Z. Szabadka
Category: Informational                                     Google, Inc.
ISSN: 2070-1721                                                July 2016


                     Brotli Compressed Data Format

Abstract

   This specification defines a lossless compressed data format that
   compresses data using a combination of the LZ77 algorithm and Huffman
   coding, with efficiency comparable to the best currently available
   general-purpose compression methods.

Status of This Memo

   This document is not an Internet Standards Track specification; it is
   published for informational purposes.

   This document is a product of the Internet Engineering Task Force
   (IETF).  It has been approved for publication by the Internet
   Engineering Steering Group (IESG).  Not all documents approved by the
   IESG are a candidate for any level of Internet Standard; see Section
   2 of RFC 7841.

   Information about the current status of this document, any errata,
   and how to provide feedback on it may be obtained at
   http://www.rfc-editor.org/info/rfc7932.

Copyright Notice

   Copyright (c) 2016 IETF Trust and the persons identified as the
   document authors.  All rights reserved.

   This document is subject to BCP 78 and the IETF Trust's Legal
   Provisions Relating to IETF Documents
   (http://trustee.ietf.org/license-info) in effect on the date of
   publication of this document.  Please review these documents
   carefully, as they describe your rights and restrictions with respect
   to this document.  Code Components extracted from this document must
   include Simplified BSD License text as described in Section 4.e of
   the Trust Legal Provisions and are provided without warranty as
   described in the Simplified BSD License.







Alakuijala & Szabadka         Informational                     [Page 1]

RFC 7932                         Brotli                        July 2016


Table of Contents

   1. Introduction ....................................................3
      1.1. Purpose ....................................................3
      1.2. Intended Audience ..........................................3
      1.3. Scope ......................................................4
      1.4. Compliance .................................................4
      1.5. Definitions of Terms and Conventions Used ..................4
           1.5.1. Packing into Bytes ..................................5
   2. Compressed Representation Overview ..............................6
   3. Compressed Representation of Prefix Codes ......................10
      3.1. Introduction to Prefix Coding .............................10
      3.2. Use of Prefix Coding in the Brotli Format .................11
      3.3. Alphabet Sizes ............................................13
      3.4. Simple Prefix Codes .......................................14
      3.5. Complex Prefix Codes ......................................15
   4. Encoding of Distances ..........................................17
   5. Encoding of Literal Insertion Lengths and Copy Lengths .........19
   6. Encoding of Block-Switch Commands ..............................22
   7. Context Modeling ...............................................23
      7.1. Context Modes and Context ID Lookup for Literals ..........23
      7.2. Context ID for Distances ..................................26
      7.3. Encoding of the Context Map ...............................26
   8. Static Dictionary ..............................................28
   9. Compressed Data Format .........................................31
      9.1. Format of the Stream Header ...............................31
      9.2. Format of the Meta-Block Header ...........................32
      9.3. Format of the Meta-Block Data .............................35
   10. Decoding Algorithm ............................................36
   11. Considerations for Compressor Implementations .................38
      11.1. Trivial Compressor .......................................39
      11.2. Aligning Compressed Meta-Blocks to Byte Boundaries .......39
      11.3. Creating Self-Contained Parts within the
            Compressed Data ..........................................40
   12. Security Considerations .......................................41
   13. IANA Considerations ...........................................42
   14. Informative References ........................................43
   Appendix A. Static Dictionary Data ................................44
   Appendix B. List of Word Transformations .........................124
   Appendix C. Computing CRC-32 Check Values ........................127
   Appendix D. Source Code ..........................................127
   Acknowledgments ..................................................127
   Authors' Addresses ...............................................128








Alakuijala & Szabadka         Informational                     [Page 2]

RFC 7932                         Brotli                        July 2016


1.  Introduction

1.1.  Purpose

   The purpose of this specification is to define a lossless compressed
   data format that:

      *  is independent of CPU type, operating system, file system, and
         character set; hence, it can be used for interchange.

      *  can be produced or consumed, even for an arbitrarily long,
         sequentially presented input data stream, using only an a
         priori bounded amount of intermediate storage; hence, it can be
         used in data communications or similar structures, such as Unix
         filters.

      *  compresses data with a compression ratio comparable to the best
         currently available general-purpose compression methods, in
         particular, considerably better than the gzip program.

      *  decompresses much faster than current LZMA implementations.

   The data format defined by this specification does not attempt to:

      *  allow random access to compressed data.

      *  compress specialized data (e.g., raster graphics) as densely as
         the best currently available specialized algorithms.

   This document is the authoritative specification of the brotli
   compressed data format.  It defines the set of valid brotli
   compressed data streams and a decoder algorithm that produces the
   uncompressed data stream from a valid brotli compressed data stream.

1.2.  Intended Audience

   This specification is intended for use by software implementers to
   compress data into and/or decompress data from the brotli format.

   The text of the specification assumes a basic background in
   programming at the level of bits and other primitive data
   representations.  Familiarity with the technique of Huffman coding is
   helpful but not required.








Alakuijala & Szabadka         Informational                     [Page 3]

RFC 7932                         Brotli                        July 2016


   This specification uses (heavily) the notations and terminology
   introduced in the DEFLATE format specification [RFC1951].  For the
   sake of completeness, we always include the whole text of the
   relevant parts of RFC 1951; therefore, familiarity with the DEFLATE
   format is helpful but not required.

   The compressed data format defined in this specification is an
   integral part of the WOFF File Format 2.0 [WOFF2]; therefore, this
   specification is also intended for implementers of WOFF 2.0
   compressors and decompressors.

1.3.  Scope

   This document specifies a method for representing a sequence of bytes
   as a (usually shorter) sequence of bits and a method for packing the
   latter bit sequence into bytes.

1.4.  Compliance

   Unless otherwise indicated below, a compliant decompressor must be
   able to accept and decompress any data set that conforms to all the
   specifications presented here.  A compliant compressor must produce
   data sets that conform to all the specifications presented here.

1.5.  Definitions of Terms and Conventions Used

   Byte: 8 bits stored or transmitted as a unit (same as an octet).  For
   this specification, a byte is exactly 8 bits, even on machines that
   store a character on a number of bits different from eight.  See
   below for the numbering of bits within a byte.

   String: a sequence of arbitrary bytes.

   Bytes stored within a computer do not have a "bit order", since they
   are always treated as a unit.  However, a byte considered as an
   integer between 0 and 255 does have a most and least significant bit
   (lsb), and since we write numbers with the most significant digit on
   the left, we also write bytes with the most significant bit (msb) on
   the left.  In the diagrams below, we number the bits of a byte so
   that bit 0 is the least significant bit, i.e., the bits are numbered:

      +--------+
      |76543210|
      +--------+







Alakuijala & Szabadka         Informational                     [Page 4]

RFC 7932                         Brotli                        July 2016


   Within a computer, a number may occupy multiple bytes.  All multi-
   byte numbers in the format described here are stored with the least
   significant byte first (at the lower memory address).  For example,
   the decimal number 520 is stored as:

      0        1
      +--------+--------+
      |00001000|00000010|
      +--------+--------+
      ^        ^
      |        |
      |        + more significant byte = 2 * 256
      + less significant byte = 8

1.5.1.  Packing into Bytes

   This document does not address the issue of the order in which bits
   of a byte are transmitted on a bit-sequential medium, since the final
   data format described here is byte rather than bit oriented.
   However, we describe the compressed block format below as a sequence
   of data elements of various bit lengths, not a sequence of bytes.
   Therefore, we must specify how to pack these data elements into bytes
   to form the final compressed byte sequence:

      *  Data elements are packed into bytes in order of increasing bit
         number within the byte, i.e., starting with the least
         significant bit of the byte.

      *  Data elements other than prefix codes are packed starting with
         the least significant bit of the data element.  These are
         referred to here as "integer values" and are considered
         unsigned.

      *  Prefix codes are packed starting with the most significant bit
         of the code.

   In other words, if one were to print out the compressed data as a
   sequence of bytes, starting with the first byte at the *right* margin
   and proceeding to the *left*, with the most significant bit of each
   byte on the left as usual, one would be able to parse the result from
   right to left, with fixed-width elements in the correct msb-to-lsb
   order and prefix codes in bit-reversed order (i.e., with the first
   bit of the code in the relative lsb position).

   As an example, consider packing the following data elements into a
   sequence of 3 bytes: 3-bit integer value 6, 4-bit integer value 2,
   prefix code 110, prefix code 10, 12-bit integer value 3628.




Alakuijala & Szabadka         Informational                     [Page 5]

RFC 7932                         Brotli                        July 2016


        byte 2   byte 1   byte 0
      +--------+--------+--------+
      |11100010|11000101|10010110|
      +--------+--------+--------+
       ^            ^ ^   ^   ^
       |            | |   |   |
       |            | |   |   +------ integer value 6
       |            | |   +---------- integer value 2
       |            | +-------------- prefix code 110
       |            +---------------- prefix code 10
       +----------------------------- integer value 3628

2.  Compressed Representation Overview

   A compressed data set consists of a header and a series of meta-
   blocks.  Each meta-block decompresses to a sequence of 0 to
   16,777,216 (16 MiB) uncompressed bytes.  The final uncompressed data
   is the concatenation of the uncompressed sequences from each meta-
   block.

   The header contains the size of the sliding window that was used
   during compression.  The decompressor must retain at least that
   amount of uncompressed data prior to the current position in the
   stream, in order to be able to decompress what follows.  The sliding
   window size is a power of two, minus 16, where the power is in the
   range of 10 to 24.  The possible sliding window sizes range from 1
   KiB - 16 B to 16 MiB - 16 B.

   Each meta-block is compressed using a combination of the LZ77
   algorithm (Lempel-Ziv 1977, [LZ77]) and Huffman coding.  The result
   of Huffman coding is referred to here as a "prefix code".  The prefix
   codes for each meta-block are independent of those for previous or
   subsequent meta-blocks; the LZ77 algorithm may use a reference to a
   duplicated string occurring in a previous meta-block, up to the
   sliding window size of uncompressed bytes before.  In addition, in
   the brotli format, a string reference may instead refer to a static
   dictionary entry.

   Each meta-block consists of two parts: a meta-block header that
   describes the representation of the compressed data part and a
   compressed data part.  The compressed data consists of a series of
   commands.  Each command consists of two parts: a sequence of literal
   bytes (of strings that have not been detected as duplicated within
   the sliding window) and a pointer to a duplicated string, which is
   represented as a pair <length, backward distance>.  There can be zero
   literal bytes in the command.  The minimum length of the string to be





Alakuijala & Szabadka         Informational                     [Page 6]

RFC 7932                         Brotli                        July 2016


   duplicated is two, but the last command in the meta-block is
   permitted to have only literals and no pointer to a string to
   duplicate.

   Each command in the compressed data is represented using three
   categories of prefix codes:

      1) One set of prefix codes are for the literal sequence lengths
         (also referred to as literal insertion lengths) and backward
         copy lengths.  That is, a single code word represents two
         lengths: one of the literal sequence and one of the backward
         copy.

      2) One set of prefix codes are for literals.

      3) One set of prefix codes are for distances.

   The prefix code descriptions for each meta-block appear in a compact
   form just before the compressed data in the meta-block header.  The
   insert-and-copy length and distance prefix codes may be followed by
   extra bits that are added to the base values determined by the codes.
   The number of extra bits is determined by the code.

   One meta-block command then appears as a sequence of prefix codes:

      Insert-and-copy length, literal, literal, ..., literal, distance

   where the insert-and-copy length defines an insertion length and a
   copy length.  The insertion length determines the number of literals
   that immediately follow.  The distance defines how far back to go for
   the copy and the copy length determines the number of bytes to copy.
   The resulting uncompressed data is the sequence of bytes:

      literal, literal, ..., literal, copy, copy, ..., copy

   where the number of literal bytes and copy bytes are determined by
   the insert-and-copy length code.  (The number of bytes copied for a
   static dictionary entry can vary from the copy length.)

   The last command in the meta-block may end with the last literal if
   the total uncompressed length of the meta-block has been satisfied.
   In that case, there is no distance in the last command, and the copy
   length is ignored.

   There can be more than one prefix code for each category, where the
   prefix code to use for the next element of that category is
   determined by the context of the compressed stream that precedes that
   element.  Part of that context is three current block types, one for



Alakuijala & Szabadka         Informational                     [Page 7]

RFC 7932                         Brotli                        July 2016


   each category.  A block type is in the range of 0..255.  For each
   category there is a count of how many elements of that category
   remain to be decoded using the current block type.  Once that count
   is expended, a new block type and block count is read from the stream
   immediately preceding the next element of that category, which will
   use the new block type.

   The insert-and-copy block type directly determines which prefix code
   to use for the next insert-and-copy length.  For the literal and
   distance elements, the respective block type is used in combination
   with other context information to determine which prefix code to use
   for the next element.

   Consider the following example:

      (IaC0, L0, L1, L2, D0)(IaC1, D1)(IaC2, L3, L4, D2)(IaC3, L5, D3)

   The meta-block here has four commands, contained in parentheses for
   clarity, where each of the three categories of symbols within these
   commands can be interpreted using different block types.  Here we
   separate out each category as its own sequence to show an example of
   block types assigned to those elements.  Each square-bracketed group
   is a block that uses the same block type:

      [IaC0, IaC1][IaC2, IaC3]  <-- insert-and-copy: block types 0 and 1

      [L0, L1][L2, L3, L4][L5]  <-- literals: block types 0, 1, and 0

      [D0][D1, D2, D3]          <-- distances: block types 0 and 1

   The subsequent blocks within each block category must have different
   block types, but we see that block types can be reused later in the
   meta-block.  The block types are numbered from 0 to the maximum block
   type number of 255, and the first block of each block category is
   type 0.  The block structure of a meta-block is represented by the
   sequence of block-switch commands for each block category, where a
   block-switch command is a pair <block type, block count>.  The block-
   switch commands are represented in the compressed data before the
   start of each new block using a prefix code for block types and a
   separate prefix code for block counts for each block category.  For
   the above example, the physical layout of the meta-block is then:

      IaC0 L0 L1 LBlockSwitch(1, 3) L2 D0 IaC1 DBlockSwitch(1, 3) D1
      IaCBlockSwitch(1, 2) IaC2 L3 L4 D2 IaC3 LBlockSwitch(0, 1) L5 D3

   where xBlockSwitch(t, n) switches to block type t for a count of n
   elements.  In this example, note that DBlockSwitch(1, 3) immediately
   precedes the next required distance, D1.  It does not follow the last



Alakuijala & Szabadka         Informational                     [Page 8]

RFC 7932                         Brotli                        July 2016


   distance of the previous block, D0.  Whenever an element of a
   category is needed, and the block count for that category has reached
   zero, then a new block type and count are read from the stream just
   before reading that next element.

   The block-switch commands for the first blocks of each category are
   not part of the meta-block compressed data.  Instead, the first block
   type is defined to be 0, and the first block count for each category
   is encoded in the meta-block header.  The prefix codes for the block
   types and counts, a total of six prefix codes over the three
   categories, are defined in a compact form in the meta-block header.

   Each category of value (insert-and-copy lengths, literals, and
   distances) can be encoded with any prefix code from a collection of
   prefix codes belonging to the same category appearing in the meta-
   block header.  The particular prefix code used can depend on two
   factors: the block type of the block the value appears in and the
   context of the value.  In the case of the literals, the context is
   the previous two bytes in the uncompressed data; and in the case of
   distances, the context is the copy length from the same command.  For
   insert-and-copy lengths, no context is used and the prefix code
   depends only on the block type.  In the case of literals and
   distances, the context is mapped to a context ID in the range 0..63
   for literals and 0..3 for distances.  The matrix of the prefix code
   indexes for each block type and context ID, called the context map,
   is encoded in a compact form in the meta-block header.

   For example, the prefix code to use to decode L2 depends on the block
   type (1), and the literal context ID determined by the two
   uncompressed bytes that were decoded from L0 and L1.  Similarly, the
   prefix code to use to decode D0 depends on the block type (0) and the
   distance context ID determined by the copy length decoded from IaC0.
   The prefix code to use to decode IaC3 depends only on the block type
   (1).

   In addition to the parts listed above (prefix code for insert-and-
   copy lengths, literals, distances, block types, block counts, and the
   context map), the meta-block header contains the number of
   uncompressed bytes coded in the meta-block and two additional
   parameters used in the representation of match distances: the number
   of postfix bits and the number of direct distance codes.

   A compressed meta-block may be marked in the header as the last meta-
   block, which terminates the compressed stream.

   A meta-block may, instead, simply store the uncompressed data
   directly as bytes on byte boundaries with no coding or matching
   strings.  In this case, the meta-block header information only



Alakuijala & Szabadka         Informational                     [Page 9]

RFC 7932                         Brotli                        July 2016


   contains the number of uncompressed bytes and the indication that the
   meta-block is uncompressed.  An uncompressed meta-block cannot be the
   last meta-block.

   A meta-block may also be empty, which generates no uncompressed data
   at all.  An empty meta-block may contain metadata information as
   bytes starting on byte boundaries, which are not part of either the
   sliding window or the uncompressed data.  Thus, these metadata bytes
   cannot be used to create matching strings in subsequent meta-blocks
   and are not used as context bytes for literals.

3.  Compressed Representation of Prefix Codes

3.1.  Introduction to Prefix Coding

   Prefix coding represents symbols from an a priori known alphabet by
   bit sequences (codes), one code for each symbol, in a manner such
   that different symbols may be represented by bit sequences of
   different lengths, but a parser can always parse an encoded string
   unambiguously symbol-by-symbol.

   We define a prefix code in terms of a binary tree in which the two
   edges descending from each non-leaf node are labeled 0 and 1, and in
   which the leaf nodes correspond one-for-one with (are labeled with)
   the symbols of the alphabet.  The code for a symbol is the sequence
   of 0's and 1's on the edges leading from the root to the leaf labeled
   with that symbol.  For example:

               /\              Symbol    Code
              0  1             ------    ----
             /    \                A     00
            /\     B               B     1
           0  1                    C     011
          /    \                   D     010
         A     /\
              0  1
             /    \
            D      C

   A parser can decode the next symbol from the compressed stream by
   walking down the tree from the root, at each step choosing the edge
   corresponding to the next compressed data bit.

   Given an alphabet with known symbol frequencies, the Huffman
   algorithm allows the construction of an optimal prefix code (one that
   represents strings with those symbol frequencies using the fewest





Alakuijala & Szabadka         Informational                    [Page 10]

RFC 7932                         Brotli                        July 2016


   bits of any possible prefix codes for that alphabet).  Such a prefix
   code is called a Huffman code.  (See [HUFFMAN] for additional
   information on Huffman codes.)

   In the brotli format, note that the prefix codes for the various
   alphabets must not exceed certain maximum code lengths.  This
   constraint complicates the algorithm for computing code lengths from
   symbol frequencies.  Again, see [HUFFMAN] for details.

3.2.  Use of Prefix Coding in the Brotli Format

   The prefix codes used for each alphabet in the brotli format are
   canonical prefix codes, which have two additional rules:

      *  All codes of a given bit length have lexicographically
         consecutive values, in the same order as the symbols they
         represent;

      *  Shorter codes lexicographically precede longer codes.

   We could recode the example above to follow this rule as follows,
   assuming that the order of the alphabet is ABCD:

      Symbol  Code
      ------  ----
      A       10
      B       0
      C       110
      D       111

   That is, 0 precedes 10, which precedes 11x, and 110 and 111 are
   lexicographically consecutive.

   Given this rule, we can define the canonical prefix code for an
   alphabet just by giving the bit lengths of the codes for each symbol
   of the alphabet in order; this is sufficient to determine the actual
   codes.  In our example, the code is completely defined by the
   sequence of bit lengths (2, 1, 3, 3).  The following algorithm
   generates the codes as integers, intended to be read from most to
   least significant bit.  The code lengths are initially in
   tree[I].Len; the codes are produced in tree[I].Code.

      1) Count the number of codes for each code length.  Let
         bl_count[N] be the number of codes of length N, N >= 1.







Alakuijala & Szabadka         Informational                    [Page 11]

RFC 7932                         Brotli                        July 2016


      2) Find the numerical value of the smallest code for each code
         length:

            code = 0;
            bl_count[0] = 0;
            for (bits = 1; bits <= MAX_BITS; bits++) {
               code = (code + bl_count[bits-1]) << 1;
               next_code[bits] = code;
            }

      3) Assign numerical values to all codes, using consecutive values
         for all codes of the same length with the base values
         determined at step 2.  Codes that are never used (which have a
         bit length of zero) must not be assigned a value.

            for (n = 0; n <= max_code; n++) {
               len = tree[n].Len;
               if (len != 0) {
                  tree[n].Code = next_code[len];
                  next_code[len]++;
               }
            }


   Example:

   Consider the alphabet ABCDEFGH, with bit lengths (3, 3, 3, 3, 3, 2,
   4, 4).  After step 1, we have:

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








Alakuijala & Szabadka         Informational                    [Page 12]

RFC 7932                         Brotli                        July 2016


   Step 3 produces the following code values:

      Symbol Length   Code
      ------ ------   ----
      A       3       010
      B       3       011
      C       3       100
      D       3       101
      E       3       110
      F       2       00
      G       4       1110
      H       4       1111

3.3.  Alphabet Sizes

   Prefix codes are used for different purposes in the brotli format,
   and each purpose has a different alphabet size.  For literal codes,
   the alphabet size is 256.  For insert-and-copy length codes, the
   alphabet size is 704.  For block count codes, the alphabet size is
   26.  For distance codes, block type codes, and the prefix codes used
   in compressing the context map, the alphabet size is dynamic and is
   based on parameters defined in later sections.  The following table
   summarizes the alphabet sizes for the various prefix codes and the
   sections of this document in which they are defined.

      +-----------------+-------------------------+------------+
      | Prefix Code     | Alphabet Size           | Definition |
      +-----------------+-------------------------+------------+
      | literal         | 256                     |            |
      +-----------------+-------------------------+------------+
      | distance        | 16 + NDIRECT +          | Section 4  |
      |                 | (48 << NPOSTFIX)        |            |
      +-----------------+-------------------------+------------+
      | insert-and-copy | 704                     | Section 5  |
      | length          |                         |            |
      +-----------------+-------------------------+------------+
      | block count     | 26                      | Section 6  |
      +-----------------+-------------------------+------------+
      | block type      | NBLTYPESx + 2,          | Section 6  |
      |                 | (where x is I, L, or D) |            |
      +-----------------+-------------------------+------------+
      | context map     | NTREESx + RLEMAXx       | Section 7  |
      |                 | (where x is L or D)     |            |
      +-----------------+-------------------------+------------+







Alakuijala & Szabadka         Informational                    [Page 13]

RFC 7932                         Brotli                        July 2016


3.4.  Simple Prefix Codes

   The first two bits of the compressed representation of each prefix
   code distinguish between simple and complex prefix codes.  If this
   value is 1, then a simple prefix code follows as described in this
   section.  Otherwise, a complex prefix code follows as described in
   Section 3.5.

   A simple prefix code can have up to four symbols with non-zero code
   length.  The format of the simple prefix code is as follows:

      2 bits: value of 1 indicates a simple prefix code
      2 bits: NSYM - 1, where NSYM = number of symbols coded

      NSYM symbols, each encoded using ALPHABET_BITS bits

      1 bit:  tree-select, present only for NSYM = 4

   The value of ALPHABET_BITS depends on the alphabet of the prefix
   code: it is the smallest number of bits that can represent all
   symbols in the alphabet.  For example, for the alphabet of literal
   bytes, ALPHABET_BITS is 8.  The value of each of the NSYM symbols
   above is the value of the ALPHABET_BITS width integer value.  If the
   integer value is greater than or equal to the alphabet size, or the
   value is identical to a previous value, then the stream should be
   rejected as invalid.

   Note that the NSYM symbols may not be presented in sorted order.
   Prefix codes of the same bit length must be assigned to the symbols
   in sorted order.

   The (non-zero) code lengths of the symbols can be reconstructed as
   follows:

      *  if NSYM = 1, the code length for the one symbol is zero -- when
         encoding this symbol in the compressed data stream using this
         prefix code, no actual bits are emitted.  Similarly, when
         decoding a symbol using this prefix code, no bits are read and
         the one symbol is returned.

      *  if NSYM = 2, both symbols have code length 1.

      *  if NSYM = 3, the code lengths for the symbols are 1, 2, 2 in
         the order they appear in the representation of the simple
         prefix code.






Alakuijala & Szabadka         Informational                    [Page 14]

RFC 7932                         Brotli                        July 2016


      *  if NSYM = 4, the code lengths (in order of symbols decoded)
         depend on the tree-select bit: 2, 2, 2, 2 (tree-select bit 0),
         or 1, 2, 3, 3 (tree-select bit 1).

3.5.  Complex Prefix Codes

   A complex prefix code is a canonical prefix code, defined by the
   sequence of code lengths, as discussed in Section 3.2.  For even
   greater compactness, the code length sequences themselves are
   compressed using a prefix code.  The alphabet for code lengths is as
   follows:

       0..15: Represent code lengths of 0..15
          16: Copy the previous non-zero code length 3..6 times.
              The next 2 bits indicate repeat length
                    (0 = 3, ... , 3 = 6)
              If this is the first code length, or all previous
              code lengths are zero, a code length of 8 is
              repeated 3..6 times.
              A repeated code length code of 16 modifies the
              repeat count of the previous one as follows:
                 repeat count = (4 * (repeat count - 2)) +
                                (3..6 on the next 2 bits)
              Example:  Codes 7, 16 (+2 bits 11), 16 (+2 bits 10)
                        will expand to 22 code lengths of 7
                        (1 + 4 * (6 - 2) + 5)
          17: Repeat a code length of 0 for 3..10 times.
              The next 3 bits indicate repeat length
                    (0 = 3, ... , 7 = 10)
              A repeated code length code of 17 modifies the
              repeat count of the previous one as follows:
                 repeat count = (8 * (repeat count - 2)) +
                                (3..10 on the next 3 bits)

   Note that a code of 16 that follows an immediately preceding 16
   modifies the previous repeat count, which becomes the new repeat
   count.  The same is true for a 17 following a 17.  A sequence of
   three or more 16 codes in a row or three of more 17 codes in a row is
   possible, modifying the count each time.  Only the final repeat count
   is used.  The modification only applies if the same code follows.  A
   16 repeat does not modify an immediately preceding 17 count nor vice
   versa.

   A code length of 0 indicates that the corresponding symbol in the
   alphabet will not occur in the compressed data, and it should not
   participate in the prefix code construction algorithm given earlier.
   A complex prefix code must have at least two non-zero code lengths.




Alakuijala & Szabadka         Informational                    [Page 15]

RFC 7932                         Brotli                        July 2016


   The bit lengths of the prefix code over the code length alphabet are
   compressed with the following variable-length code (as it appears in
   the compressed data, where the bits are parsed from right to left):

      Symbol   Code
      ------   ----
      0          00
      1        0111
      2         011
      3          10
      4          01
      5        1111

   We can now define the format of the complex prefix code as follows:

   o  2 bits: HSKIP, the number of skipped code lengths, can have values
      of 0, 2, or 3.  The skipped lengths are taken to be zero.  (An
      HSKIP of 1 indicates a Simple prefix code.)

   o  Code lengths for symbols in the code length alphabet given just
      above, in the order: 1, 2, 3, 4, 0, 5, 17, 6, 16, 7, 8, 9, 10, 11,
      12, 13, 14, 15.  If HSKIP is 2, then the code lengths for symbols
      1 and 2 are zero, and the first code length is for symbol 3.  If
      HSKIP is 3, then the code length for symbol 3 is also zero, and
      the first code length is for symbol 4.

      The code lengths of code length symbols are between 0 and 5, and
      they are represented with 2..4 bits according to the variable-
      length code above.  A code length of 0 means the corresponding
      code length symbol is not used.

      If HSKIP is 2 or 3, a respective number of leading code lengths
      are implicit zeros and are not present in the code length sequence
      above.

      If there are at least two non-zero code lengths, any trailing zero
      code lengths are omitted, i.e., the last code length in the
      sequence must be non-zero.  In this case, the sum of (32 >> code
      length) over all the non-zero code lengths must equal to 32.

      If the lengths have been read for the entire code length alphabet
      and there was only one non-zero code length, then the prefix code
      has one symbol whose code has zero length.  In this case, that
      symbol results in no bits being emitted by the compressor and no
      bits consumed by the decompressor.  That single symbol is
      immediately returned when this code is decoded.  An example of
      where this occurs is if the entire code to be represented has
      symbols of length 8.  For example, a literal code that represents



Alakuijala & Szabadka         Informational                    [Page 16]

RFC 7932                         Brotli                        July 2016


      all literal values with equal probability.  In this case the
      single symbol is 16, which repeats the previous length.  The
      previous length is taken to be 8 before any code length code
      lengths are read.

   o  Sequence of code length symbols, which is at most the size of the
      alphabet, encoded using the code length prefix code.  Any trailing
      0 or 17 must be omitted, i.e., the last encoded code length symbol
      must be between 1 and 16.  The sum of (32768 >> code length) over
      all the non-zero code lengths in the alphabet, including those
      encoded using repeat code(s) of 16, must be equal to 32768.  If
      the number of times to repeat the previous length or repeat a zero
      length would result in more lengths in total than the number of
      symbols in the alphabet, then the stream should be rejected as
      invalid.

4.  Encoding of Distances

   As described in Section 2, one component of a compressed meta-block
   is a sequence of backward distances.  In this section, we provide the
   details to the encoding of distances.

   Each distance in the compressed data part of a meta-block is
   represented with a pair <distance code, extra bits>.  The distance
   code and the extra bits are encoded back-to-back, the distance code
   is encoded using a prefix code over the distance alphabet, while the
   extra bits value is encoded as a fixed-width integer value.  The
   number of extra bits can be 0..24, and it is dependent on the
   distance code.

   To convert a distance code and associated extra bits to a backward
   distance, we need the sequence of past distances and two additional
   parameters: the number of "postfix bits", denoted by NPOSTFIX (0..3),
   and the number of direct distance codes, denoted by NDIRECT (0..120).
   Both of these parameters are encoded in the meta-block header.  We
   will also use the following derived parameter:

      POSTFIX_MASK = (1 << NPOSTFIX) - 1













Alakuijala & Szabadka         Informational                    [Page 17]

RFC 7932                         Brotli                        July 2016


   The first 16 distance symbols are special symbols that reference past
   distances as follows:

      0: last distance
      1: second-to-last distance
      2: third-to-last distance
      3: fourth-to-last distance
      4: last distance - 1
      5: last distance + 1
      6: last distance - 2
      7: last distance + 2
      8: last distance - 3
      9: last distance + 3
     10: second-to-last distance - 1
     11: second-to-last distance + 1
     12: second-to-last distance - 2
     13: second-to-last distance + 2
     14: second-to-last distance - 3
     15: second-to-last distance + 3

   The ring buffer of the four last distances is initialized by the
   values 16, 15, 11, and 4 (i.e., the fourth-to-last is set to 16, the
   third-to-last to 15, the second-to-last to 11, and the last distance
   to 4) at the beginning of the *stream* (as opposed to the beginning
   of the meta-block), and it is not reset at meta-block boundaries.
   When a distance symbol 0 appears, the distance it represents (i.e.,
   the last distance in the sequence of distances) is not pushed to the
   ring buffer of last distances; in other words, the expression
   "second-to-last distance" means the second-to-last distance that was
   not represented by a 0 distance symbol (and similar for "third-to-
   last distance" and "fourth-to-last distance").  Similarly, distances
   that represent static dictionary words (see Section 8) are not pushed
   to the ring buffer of last distances.

   If a special distance symbol resolves to a zero or negative value,
   the stream should be rejected as invalid.

   If NDIRECT is greater than zero, then the next NDIRECT distance
   symbols, from 16 to 15 + NDIRECT, represent distances from 1 to
   NDIRECT.  Neither the special distance symbols nor the NDIRECT direct
   distance symbols are followed by any extra bits.

   Distance symbols 16 + NDIRECT and greater all have extra bits, where
   the number of extra bits for a distance symbol "dcode" is given by
   the following formula:

      ndistbits = 1 + ((dcode - NDIRECT - 16) >> (NPOSTFIX + 1))




Alakuijala & Szabadka         Informational                    [Page 18]

RFC 7932                         Brotli                        July 2016


   The maximum number of extra bits is 24; therefore, the size of the
   distance symbol alphabet is (16 + NDIRECT + (48 << NPOSTFIX)).

   Given a distance symbol "dcode" (>= 16 + NDIRECT), and extra bits
   "dextra", the backward distance is given by the following formula:

      hcode = (dcode - NDIRECT - 16) >> NPOSTFIX
      lcode = (dcode - NDIRECT - 16) & POSTFIX_MASK
      offset = ((2 + (hcode & 1)) << ndistbits) - 4
      distance = ((offset + dextra) << NPOSTFIX) + lcode + NDIRECT + 1

5.  Encoding of Literal Insertion Lengths and Copy Lengths

   As described in Section 2, the literal insertion lengths and backward
   copy lengths are encoded using a single prefix code.  This section
   provides the details to this encoding.

   Each <insertion length, copy length> pair in the compressed data part
   of a meta-block is represented with the following triplet:

      <insert-and-copy length code, insert extra bits, copy extra bits>

   The insert-and-copy length code, the insert extra bits, and the copy
   extra bits are encoded back-to-back, the insert-and-copy length code
   is encoded using a prefix code over the insert-and-copy length code
   alphabet, while the extra bits values are encoded as fixed-width
   integer values.  The number of insert and copy extra bits can be
   0..24, and they are dependent on the insert-and-copy length code.

   Some of the insert-and-copy length codes also express the fact that
   the distance symbol of the distance in the same command is 0, i.e.,
   the distance component of the command is the same as that of the
   previous command.  In this case, the distance code and extra bits for
   the distance are omitted from the compressed data stream.

















Alakuijala & Szabadka         Informational                    [Page 19]

RFC 7932                         Brotli                        July 2016


   We describe the insert-and-copy length code alphabet in terms of the
   (not directly used) insert length code and copy length code
   alphabets.  The symbols of the insert length code alphabet, along
   with the number of insert extra bits, and the range of the insert
   lengths are as follows:

           Extra              Extra               Extra
      Code Bits Lengths  Code Bits Lengths   Code Bits Lengths
      ---- ---- -------  ---- ---- -------   ---- ---- -------
       0    0     0       8    2   10..13    16    6   130..193
       1    0     1       9    2   14..17    17    7   194..321
       2    0     2      10    3   18..25    18    8   322..577
       3    0     3      11    3   26..33    19    9   578..1089
       4    0     4      12    4   34..49    20   10   1090..2113
       5    0     5      13    4   50..65    21   12   2114..6209
       6    1    6,7     14    5   66..97    22   14   6210..22593
       7    1    8,9     15    5   98..129   23   24   22594..16799809

   The symbols of the copy length code alphabet, along with the number
   of copy extra bits, and the range of copy lengths are as follows:

           Extra              Extra               Extra
      Code Bits Lengths  Code Bits Lengths   Code Bits Lengths
      ---- ---- -------  ---- ---- -------   ---- ---- -------
       0    0     2       8    1    10,11    16    5   70..101
       1    0     3       9    1    12,13    17    5   102..133
       2    0     4      10    2    14..17   18    6   134..197
       3    0     5      11    2    18..21   19    7   198..325
       4    0     6      12    3    22..29   20    8   326..581
       5    0     7      13    3    30..37   21    9   582..1093
       6    0     8      14    4    38..53   22   10   1094..2117
       7    0     9      15    4    54..69   23   24   2118..16779333



















Alakuijala & Szabadka         Informational                    [Page 20]

RFC 7932                         Brotli                        July 2016


   To convert an insert-and-copy length code to an insert length code
   and a copy length code, the following table can be used:

          Insert
          length        Copy length code
          code       0..7       8..15     16..23
                 +----------+----------+
                 |          |          |
           0..7  |   0..63  |  64..127 | <--- distance symbol 0
                 |          |          |
                 +----------+----------+----------+
                 |          |          |          |
           0..7  | 128..191 | 192..255 | 384..447 |
                 |          |          |          |
                 +----------+----------+----------+
                 |          |          |          |
           8..15 | 256..319 | 320..383 | 512..575 |
                 |          |          |          |
                 +----------+----------+----------+
                 |          |          |          |
          16..23 | 448..511 | 576..639 | 640..703 |
                 |          |          |          |
                 +----------+----------+----------+

   First, look up the cell with the 64 value range containing the
   insert-and-copy length code; this gives the insert length code and
   the copy length code ranges, both 8 values long.  The copy length
   code within its range is determined by bits 0..2 (counted from the
   lsb) of the insert-and-copy length code.  The insert length code
   within its range is determined by bits 3..5 (counted from the lsb) of
   the insert-and-copy length code.  Given the insert length and copy
   length codes, the actual insert and copy lengths can be obtained by
   reading the number of extra bits given by the tables above.

   If the insert-and-copy length code is between 0 and 127, the distance
   code of the command is set to zero (the last distance reused).















Alakuijala & Szabadka         Informational                    [Page 21]

RFC 7932                         Brotli                        July 2016


6.  Encoding of Block-Switch Commands

   As described in Section 2, a block-switch command is a pair <block
   type, block count>.  These are encoded in the compressed data part of
   the meta-block, right before the start of each new block of a
   particular block category.

   Each block type in the compressed data is represented with a block
   type code, encoded using a prefix code over the block type code
   alphabet.  A block type symbol 0 means that the new block type is the
   same as the type of the previous block from the same block category,
   i.e., the block type that preceded the current type, while a block
   type symbol 1 means that the new block type equals the current block
   type plus one.  If the current block type is the maximal possible,
   then a block type symbol of 1 results in wrapping to a new block type
   of 0.  Block type symbols 2..257 represent block types 0..255,
   respectively.  The previous and current block types are initialized
   to 1 and 0, respectively, at the end of the meta-block header.

   Since the first block type of each block category is 0, the block
   type of the first block-switch command is not encoded in the
   compressed data.  If a block category has only one block type, the
   block count of the first block-switch command is also omitted from
   the compressed data; otherwise, it is encoded in the meta-block
   header.

   Since the end of the meta-block is detected by the number of
   uncompressed bytes produced, the block counts for any of the three
   categories need not count down to exactly zero at the end of the
   meta-block.

   The number of different block types in each block category, denoted
   by NBLTYPESL, NBLTYPESI, and NBLTYPESD for literals, insert-and-copy
   lengths, and distances, respectively, is encoded in the meta-block
   header, and it must equal to the largest block type plus one in that
   block category.  In other words, the set of literal, insert-and-copy
   length, and distance block types must be [0..NBLTYPESL-1],
   [0..NBLTYPESI-1], and [0..NBLTYPESD-1], respectively.  From this it
   follows that the alphabet size of literal, insert-and-copy length,
   and distance block type codes is NBLTYPESL + 2, NBLTYPESI + 2, and
   NBLTYPESD + 2, respectively.

   Each block count in the compressed data is represented with a pair
   <block count code, extra bits>.  The block count code and the extra
   bits are encoded back-to-back, the block count code is encoded using
   a prefix code over the block count code alphabet, while the extra
   bits value is encoded as a fixed-width integer value.  The number of
   extra bits can be 0..24, and it is dependent on the block count code.



Alakuijala & Szabadka         Informational                    [Page 22]

RFC 7932                         Brotli                        July 2016


   The symbols of the block count code alphabet along with the number of
   extra bits and the range of block counts are as follows:

           Extra              Extra               Extra
      Code Bits Lengths  Code Bits Lengths   Code Bits Lengths
      ---- ---- -------  ---- ---- -------   ---- ---- -------
       0    2    1..4     9    4   65..80    18    7   369..496
       1    2    5..8    10    4   81..96    19    8   497..752
       2    2    9..12   11    4   97..112   20    9   753..1264
       3    2   13..16   12    5  113..144   21   10   1265..2288
       4    3   17..24   13    5  145..176   22   11   2289..4336
       5    3   25..32   14    5  177..208   23   12   4337..8432
       6    3   33..40   15    5  209..240   24   13   8433..16624
       7    3   41..48   16    6  241..304   25   24   16625..16793840
       8    4   49..64   17    6  305..368

   The first block-switch command of each block category is special in
   the sense that it is encoded in the meta-block header, and as
   described earlier, the block type code is omitted since it is an
   implicit zero.

7.  Context Modeling

   As described in Section 2, the prefix tree used to encode a literal
   byte or a distance code depends on the block type and the context ID.
   This section specifies how to compute the context ID for a particular
   literal and distance code and how to encode the context map that maps
   a <block type, context ID> pair to the index of a prefix code in the
   array of literal and distance prefix codes.

7.1.  Context Modes and Context ID Lookup for Literals

   The context for encoding the next literal is defined by the last two
   bytes in the stream (p1, p2, where p1 is the most recent byte),
   regardless of whether these bytes are produced by uncompressed meta-
   blocks, backward references, static dictionary references, or by
   literal insertions.  At the start of the stream, p1 and p2 are
   initialized to zero.

   There are four methods, called context modes, to compute the Context
   ID:

      *  LSB6, where the Context ID is the value of six least
         significant bits of p1,

      *  MSB6, where the Context ID is the value of six most significant
         bits of p1,




Alakuijala & Szabadka         Informational                    [Page 23]

RFC 7932                         Brotli                        July 2016


      *  UTF8, where the Context ID is a complex function of p1, p2,
         optimized for text compression, and

      *  Signed, where Context ID is a complex function of p1, p2,
         optimized for compressing sequences of signed integers.

   The Context ID for the UTF8 and Signed context modes is computed
   using the following lookup tables Lut0, Lut1, and Lut2.

      Lut0 :=
         0,  0,  0,  0,  0,  0,  0,  0,  0,  4,  4,  0,  0,  4,  0,  0,
         0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
         8, 12, 16, 12, 12, 20, 12, 16, 24, 28, 12, 12, 32, 12, 36, 12,
        44, 44, 44, 44, 44, 44, 44, 44, 44, 44, 32, 32, 24, 40, 28, 12,
        12, 48, 52, 52, 52, 48, 52, 52, 52, 48, 52, 52, 52, 52, 52, 48,
        52, 52, 52, 52, 52, 48, 52, 52, 52, 52, 52, 24, 12, 28, 12, 12,
        12, 56, 60, 60, 60, 56, 60, 60, 60, 56, 60, 60, 60, 60, 60, 56,
        60, 60, 60, 60, 60, 56, 60, 60, 60, 60, 60, 24, 12, 28, 12,  0,
         0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
         0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
         0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
         0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1,
         2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
         2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
         2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3,
         2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3, 2, 3

      Lut1 :=
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
         2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1,
         1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
         2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1,
         1, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
         3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 1, 1, 1, 1, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
         2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
         2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2







Alakuijala & Szabadka         Informational                    [Page 24]

RFC 7932                         Brotli                        July 2016


      Lut2 :=
         0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
         2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
         2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
         2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
         3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
         3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
         3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
         3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
         4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
         4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
         4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
         4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
         5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
         5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
         5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5,
         6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7

   The lengths and the CRC-32 check values (see Appendix C) of each of
   these tables as a sequence of bytes are as follows:

      Table    Length    CRC-32
      -----    ------    ------
      Lut0     256       0x8e91efb7
      Lut1     256       0xd01a32f4
      Lut2     256       0x0dd7a0d6

   Given p1 is the last uncompressed byte and p2 is the second-to-last
   uncompressed byte, the context IDs can be computed as follows:

      For LSB6:    Context ID = p1 & 0x3f
      For MSB6:    Context ID = p1 >> 2
      For UTF8:    Context ID = Lut0[p1] | Lut1[p2]
      For Signed:  Context ID = (Lut2[p1] << 3) | Lut2[p2]

   From the lookup tables defined above and the operations to compute
   the context IDs, we can see that context IDs for literals are in the
   range of 0..63.

   The context modes LSB6, MSB6, UTF8, and Signed are denoted by
   integers 0, 1, 2, 3.

   A context mode is defined for each literal block type and they are
   stored in a consecutive array of bits in the meta-block header,
   always two bits per block type.






Alakuijala & Szabadka         Informational                    [Page 25]

RFC 7932                         Brotli                        July 2016


7.2.  Context ID for Distances

   The context for encoding a distance code is defined by the copy
   length corresponding to the distance.  The context IDs are 0, 1, 2,
   and 3 for copy lengths 2, 3, 4, and more than 4, respectively.

7.3.  Encoding of the Context Map

   There are two context maps, one for literals and one for distances.
   The size of the context map is 64 * NBLTYPESL for literals, and 4 *
   NBLTYPESD for distances.  Each value in the context map is an integer
   between 0 and 255, indicating the index of the prefix code to be used
   when encoding the next literal or distance.

   The context maps are two-dimensional matrices, encoded as one-
   dimensional arrays:

      CMAPL[0..(64 * NBLTYPESL - 1)]
      CMAPD[0..(4 * NBLTYPESD - 1)]

   The index of the prefix code for encoding a literal or distance code
   with block type, BTYPE_x, and context ID, CIDx, is:

      index of literal prefix code = CMAPL[64 * BTYPE_L + CIDL]
      index of distance prefix code = CMAPD[4 * BTYPE_D + CIDD]

   The values of the context map are encoded with the combination of run
   length encoding for zero values and prefix coding.  Let RLEMAX denote
   the number of run length codes and NTREES denote the maximum value in
   the context map plus one.  NTREES must equal the number of different
   values in the context map; in other words, the different values in
   the context map must be the [0..NTREES-1] interval.  The alphabet of
   the prefix code has the following RLEMAX + NTREES symbols:

      0: value zero
      1: repeat a zero 2 to 3 times, read 1 bit for repeat length
      2: repeat a zero 4 to 7 times, read 2 bits for repeat length
      ...
      RLEMAX: repeat a zero (1 << RLEMAX) to (1 << (RLEMAX+1))-1
              times, read RLEMAX bits for repeat length
      RLEMAX + 1: value 1
      ...
      RLEMAX + NTREES - 1: value NTREES - 1








Alakuijala & Szabadka         Informational                    [Page 26]

RFC 7932                         Brotli                        July 2016


   If RLEMAX = 0, the run length coding is not used and the symbols of
   the alphabet are directly the values in the context map.  We can now
   define the format of the context map (the same format is used for
   literal and distance context maps):

      1..5 bits: RLEMAX, 0 is encoded with one 0 bit, and values 1..16
                 are encoded with bit pattern xxxx1 (so 01001 is 5)

      Prefix code with alphabet size NTREES + RLEMAX

      Context map size values encoded with the above prefix code and run
         length coding for zero values.  If a run length would result in
         more lengths in total than the size of the context map, then
         the stream should be rejected as invalid.

      1 bit:  IMTF bit, if set, we do an inverse move-to-front transform
              on the values in the context map to get the prefix code
              indexes.

   Note that RLEMAX may be larger than the value necessary to represent
   the longest sequence of zero values.  Also, the NTREES value is
   encoded right before the context map as described in Section 9.2.

   We define the inverse move-to-front transform used in this
   specification by the following C language function:

      void InverseMoveToFrontTransform(uint8_t* v, int v_len) {
         uint8_t mtf[256];
         int i;
         for (i = 0; i < 256; ++i) {
            mtf[i] = (uint8_t)i;
         }
         for (i = 0; i < v_len; ++i) {
            uint8_t index = v[i];
            uint8_t value = mtf[index];
            v[i] = value;
            for (; index; --index) {
               mtf[index] = mtf[index - 1];
            }
            mtf[0] = value;
         }
      }

   Note that the inverse move-to-front transform will not produce values
   outside the [0..NTREES-1] interval.






Alakuijala & Szabadka         Informational                    [Page 27]

RFC 7932                         Brotli                        July 2016


8.  Static Dictionary

   At any given point during decoding the compressed data, a reference
   to a duplicated string in the uncompressed data produced so far has a
   maximum backward distance value, which is the minimum of the window
   size and the number of uncompressed bytes produced.  However,
   decoding a distance from the compressed stream, as described in
   Section 4, can produce distances that are greater than this maximum
   allowed value.  In this case, the distance is treated as a reference
   to a word in the static dictionary given in Appendix A.  The copy
   length for a static dictionary reference must be between 4 and 24.
   The static dictionary has three parts:

      * DICT[0..DICTSIZE], an array of bytes
      * DOFFSET[0..24], an array of byte-offset values for each length
      * NDBITS[0..24], an array of bit-depth values for each length

   The number of static dictionary words for a given length is:

      NWORDS[length] = 0                       (if length < 4)
      NWORDS[length] = (1 << NDBITS[length])   (if length >= 4)

   DOFFSET and DICTSIZE are defined by the following recursion:

      DOFFSET[0] = 0
      DOFFSET[length + 1] = DOFFSET[length] + length * NWORDS[length]
      DICTSIZE = DOFFSET[24] + 24 * NWORDS[24]

   The offset of a word within the DICT array for a given length and
   index is:

      offset(length, index) = DOFFSET[length] + index * length

   Each static dictionary word has 121 different forms, given by
   applying a word transformation to a base word in the DICT array.  The
   list of word transformations is given in Appendix B.  The static
   dictionary word for a <length, distance> pair can be reconstructed as
   follows:

      word_id = distance - (max allowed distance + 1)
      index = word_id % NWORDS[length]
      base_word = DICT[offset(length, index)..offset(length, index+1)-1]
      transform_id = word_id >> NDBITS[length]

   The string copied to the uncompressed stream is computed by applying
   the transformation to the base dictionary word.  If transform_id is
   greater than 120, or the length is smaller than 4 or greater than 24,
   then the compressed stream should be rejected as invalid.



Alakuijala & Szabadka         Informational                    [Page 28]

RFC 7932                         Brotli                        July 2016


   Each word transformation has the following form:

      transform_i(word) = prefix_i + T_i(word) + suffix_i

   where the _i subscript denotes the transform_id above.  Each T_i is
   one of the following 21 elementary transforms:

      Identity, FermentFirst, FermentAll,
      OmitFirst1, ..., OmitFirst9, OmitLast1, ..., OmitLast9

   The form of these elementary transforms is as follows:

      Identity(word) = word

      FermentFirst(word) = see below

      FermentAll(word) = see below

      OmitFirstk(word) = the last (length(word) - k) bytes of word, or
                         empty string if length(word) < k

      OmitLastk(word) = the first (length(word) - k) bytes of word, or
                        empty string if length(word) < k




























Alakuijala & Szabadka         Informational                    [Page 29]

RFC 7932                         Brotli                        July 2016


   We define the FermentFirst and FermentAll transforms used in this
   specification by the following C language functions:

      int Ferment(uint8_t* word, int word_len, int pos) {
         if (word[pos] < 192) {
            if (word[pos] >= 97 and word[pos] <= 122) {
               word[pos] = word[pos] ^ 32;
            }
            return 1;
         } else if (word[pos] < 224) {
            if (pos + 1 < word_len) {
               word[pos + 1] = word[pos + 1] ^ 32;
            }
            return 2;
         } else {
            if (pos + 2 < word_len) {
               word[pos + 2] = word[pos + 2] ^ 5;
            }
            return 3;
         }
      }

      void FermentFirst(uint8_t* word, int word_len) {
         if (word_len > 0) {
            Ferment(word, word_len, 0);
         }
      }

      void FermentAll(uint8_t* word, int word_len) {
         int i = 0;
         while (i < word_len) {
            i += Ferment(word, word_len, i);
         }
      }

   Appendix B contains the list of transformations by specifying the
   prefix, elementary transform and suffix components of each of them.
   Note that the OmitFirst8 elementary transform is not used in the list
   of transformations.  The strings in Appendix B are in C-string format
   with respect to escape (backslash) characters.

   The maximum number of additional bytes that a transform may add to a
   base word is 13.  Since the largest base word is 24 bytes long, a
   buffer of 38 bytes is sufficient to store any transformed words
   (counting a terminating zero byte).






Alakuijala & Szabadka         Informational                    [Page 30]

RFC 7932                         Brotli                        July 2016


9.  Compressed Data Format

   In this section, we describe the format of the compressed data set in
   terms of the format of the individual data items described in the
   previous sections.

9.1.  Format of the Stream Header

   The stream header has only the following one field:

      1..7 bits: WBITS, a value in the range 10..24, encoded with the
                 following variable-length code (as it appears in the
                 compressed data, where the bits are parsed from right
                 to left):

                      Value    Bit Pattern
                      -----    -----------
                         10        0100001
                         11        0110001
                         12        1000001
                         13        1010001
                         14        1100001
                         15        1110001
                         16              0
                         17        0000001
                         18           0011
                         19           0101
                         20           0111
                         21           1001
                         22           1011
                         23           1101
                         24           1111

                 Note that bit pattern 0010001 is invalid and must not
                 be used.

   The size of the sliding window, which is the maximum value of any
   non-dictionary reference backward distance, is given by the following
   formula:

      window size = (1 << WBITS) - 16










Alakuijala & Szabadka         Informational                    [Page 31]

RFC 7932                         Brotli                        July 2016


9.2.  Format of the Meta-Block Header

   A compliant compressed data set has at least one meta-block.  Each
   meta-block contains a header with information about the uncompressed
   length of the meta-block, and a bit signaling if the meta-block is
   the last one.  The format of the meta-block header is the following:

      1 bit:  ISLAST, set to 1 if this is the last meta-block

      1 bit:  ISLASTEMPTY, if set to 1, the meta-block is empty; this
              field is only present if ISLAST bit is set -- if it is 1,
              then the meta-block and the brotli stream ends at that
              bit, with any remaining bits in the last byte of the
              compressed stream filled with zeros (if the fill bits are
              not zero, then the stream should be rejected as invalid)

      2 bits: MNIBBLES, number of nibbles to represent the uncompressed
              length, encoded with the following fixed-length code:

                    Value    Bit Pattern
                    -----    -----------
                        0             11
                        4             00
                        5             01
                        6             10

              If MNIBBLES is 0, the meta-block is empty, i.e., it does
              not generate any uncompressed data.  In this case, the
              rest of the meta-block has the following format:

                   1 bit:  reserved, must be zero

                   2 bits: MSKIPBYTES, number of bytes to represent
                           metadata length

                   MSKIPBYTES * 8 bits: MSKIPLEN - 1, where MSKIPLEN is
                           the number of metadata bytes; this field is
                           only present if MSKIPBYTES is positive;
                           otherwise, MSKIPLEN is 0 (if MSKIPBYTES is
                           greater than 1, and the last byte is all
                           zeros, then the stream should be rejected as
                           invalid)

                   0..7 bits: fill bits until the next byte boundary,
                           must be all zeros

                   MSKIPLEN bytes of metadata, not part of the
                           uncompressed data or the sliding window



Alakuijala & Szabadka         Informational                    [Page 32]

RFC 7932                         Brotli                        July 2016


      MNIBBLES * 4 bits: MLEN - 1, where MLEN is the length of the meta-
              block uncompressed data in bytes (if MNIBBLES is greater
              than 4, and the last nibble is all zeros, then the stream
              should be rejected as invalid)

      1 bit:  ISUNCOMPRESSED, if set to 1, any bits of compressed data
              up to the next byte boundary are ignored, and the rest of
              the meta-block contains MLEN bytes of literal data; this
              field is only present if the ISLAST bit is not set (if the
              ignored bits are not all zeros, the stream should be
              rejected as invalid)

      1..11 bits: NBLTYPESL, number of literal block types, encoded with
              the following variable-length code (as it appears in the
              compressed data, where the bits are parsed from right to
              left, so 0110111 has the value 12):

                       Value    Bit Pattern
                       -----    -----------
                         1                0
                         2             0001
                       3..4           x0011
                       5..8          xx0101
                       9..16        xxx0111
                      17..32       xxxx1001
                      33..64      xxxxx1011
                      65..128    xxxxxx1101
                     129..256   xxxxxxx1111

         Prefix code over the block type code alphabet for literal block
            types, appears only if NBLTYPESL >= 2

         Prefix code over the block count code alphabet for literal
            block counts, appears only if NBLTYPESL >= 2

         Block count code + extra bits for first literal block count,
            appears only if NBLTYPESL >= 2

      1..11 bits: NBLTYPESI, number of insert-and-copy block types,
                  encoded with the same variable-length code as above

         Prefix code over the block type code alphabet for insert-and-
            copy block types, appears only if NBLTYPESI >= 2

         Prefix code over the block count code alphabet for insert-and-
            copy block counts, appears only if NBLTYPESI >= 2





Alakuijala & Szabadka         Informational                    [Page 33]

RFC 7932                         Brotli                        July 2016


         Block count code + extra bits for first insert-and-copy block
            count, appears only if NBLTYPESI >= 2

      1..11 bits: NBLTYPESD, number of distance block types, encoded
                  with the same variable-length code as above

         Prefix code over the block type code alphabet for distance
            block types, appears only if NBLTYPESD >= 2

         Prefix code over the block count code alphabet for distance
            block counts, appears only if NBLTYPESD >= 2

         Block count code + extra bits for first distance block count,
            appears only if NBLTYPESD >= 2

      2 bits: NPOSTFIX, parameter used in the distance coding

      4 bits: four most significant bits of NDIRECT, to get the actual
              value of the parameter NDIRECT, left-shift this four-bit
              number by NPOSTFIX bits

      NBLTYPESL * 2 bits: context mode for each literal block type

      1..11 bits: NTREESL, number of literal prefix trees, encoded with
                  the same variable-length code as NBLTYPESL

         Literal context map, encoded as described in Section 7.3,
            appears only if NTREESL >= 2; otherwise, the context map has
            only zero values

      1..11 bits: NTREESD, number of distance prefix trees, encoded with
                  the same variable-length code as NBLTYPESD

         Distance context map, encoded as described in Section 7.3,
            appears only if NTREESD >= 2; otherwise, the context map has
            only zero values

      NTREESL prefix codes for literals

      NBLTYPESI prefix codes for insert-and-copy lengths

      NTREESD prefix codes for distances









Alakuijala & Szabadka         Informational                    [Page 34]

RFC 7932                         Brotli                        July 2016


9.3.  Format of the Meta-Block Data

   The compressed data part of a meta-block consists of a series of
   commands.  Each command has the following format:

      Block type code for next insert-and-copy block type, appears only
         if NBLTYPESI >= 2 and the previous insert-and-copy block count
         is zero

      Block count code + extra bits for next insert-and-copy block
         count, appears only if NBLTYPESI >= 2 and the previous insert-
         and-copy block count is zero

      Insert-and-copy length, encoded as in Section 5, using the insert-
         and-copy length prefix code with the current insert-and-copy
         block type index

      Insert length number of literals, with the following format:

         Block type code for next literal block type, appears only if
            NBLTYPESL >= 2 and the previous literal block count is zero

         Block count code + extra bits for next literal block count,
            appears only if NBLTYPESL >= 2 and the previous literal
            block count is zero

         Next byte of the uncompressed data, encoded with the literal
            prefix code with the index determined by the previous two
            bytes of the uncompressed data, the current literal block
            type, and the context map, as described in Section 7.3

      Block type code for next distance block type, appears only if
         NBLTYPESD >= 2 and the previous distance block count is zero

      Block count code + extra bits for next distance block count,
         appears only if NBLTYPESD >= 2 and the previous distance block
         count is zero

      Distance code, encoded as in Section 4, using the distance prefix
         code with the index determined by the copy length, the current
         distance block type, and the distance context map, as described
         in Section 7.3, appears only if the distance code is not an
         implicit 0, as indicated by the insert-and-copy length code








Alakuijala & Szabadka         Informational                    [Page 35]

RFC 7932                         Brotli                        July 2016


   The number of commands in the meta-block is such that the sum of the
   uncompressed bytes produced (i.e., the number of literals inserted
   plus the number of bytes copied from past data or generated from the
   static dictionary) over all the commands gives the uncompressed
   length, MLEN encoded in the meta-block header.

   If the total number of uncompressed bytes produced after the insert
   part of the last command equals MLEN, then the copy length of the
   last command is ignored and will not produce any uncompressed output.
   In this case, the copy length of the last command can have any value.
   In any other case, if the number of literals to insert, the copy
   length, or the resulting dictionary word length would cause MLEN to
   be exceeded, then the stream should be rejected as invalid.

   If the last command of the last non-empty meta-block does not end on
   a byte boundary, the unused bits in the last byte must be zeros.

10.  Decoding Algorithm

   The decoding algorithm that produces the uncompressed data is as
   follows:

      read window size
      do
         read ISLAST bit
         if ISLAST
            read ISLASTEMPTY bit
            if ISLASTEMPTY
               break from loop
         read MNIBBLES
         if MNIBBLES is zero
            verify reserved bit is zero
            read MSKIPLEN
            skip any bits up to the next byte boundary
            skip MSKIPLEN bytes
            continue to the next meta-block
         else
            read MLEN
         if not ISLAST
            read ISUNCOMPRESSED bit
            if ISUNCOMPRESSED
               skip any bits up to the next byte boundary
               copy MLEN bytes of compressed data as literals
               continue to the next meta-block







Alakuijala & Szabadka         Informational                    [Page 36]

RFC 7932                         Brotli                        July 2016


         loop for each three block categories (i = L, I, D)
            read NBLTYPESi
            if NBLTYPESi >= 2
               read prefix code for block types, HTREE_BTYPE_i
               read prefix code for block counts, HTREE_BLEN_i
               read block count, BLEN_i
               set block type, BTYPE_i to 0
               initialize second-to-last and last block types to 0 and 1
            else
               set block type, BTYPE_i to 0
               set block count, BLEN_i to 16777216
         read NPOSTFIX and NDIRECT
         read array of literal context modes, CMODE[]
         read NTREESL
         if NTREESL >= 2
            read literal context map, CMAPL[]
         else
            fill CMAPL[] with zeros
         read NTREESD
         if NTREESD >= 2
            read distance context map, CMAPD[]
         else
            fill CMAPD[] with zeros
         read array of literal prefix codes, HTREEL[]
         read array of insert-and-copy length prefix codes, HTREEI[]
         read array of distance prefix codes, HTREED[]
         do
            if BLEN_I is zero
               read block type using HTREE_BTYPE_I and set BTYPE_I
                  save previous block type
               read block count using HTREE_BLEN_I and set BLEN_I
            decrement BLEN_I
            read insert-and-copy length symbol using HTREEI[BTYPE_I]
            compute insert length, ILEN, and copy length, CLEN
            loop for ILEN
               if BLEN_L is zero
                  read block type using HTREE_BTYPE_L and set BTYPE_L
                     save previous block type
                  read block count using HTREE_BLEN_L and set BLEN_L
               decrement BLEN_L
               look up context mode CMODE[BTYPE_L]
               compute context ID, CIDL from last two uncompressed bytes
               read literal using HTREEL[CMAPL[64*BTYPE_L + CIDL]]
               write literal to uncompressed stream
            if number of uncompressed bytes produced in the loop for
               this meta-block is MLEN, then break from loop (in this
               case the copy length is ignored and can have any value)




Alakuijala & Szabadka         Informational                    [Page 37]

RFC 7932                         Brotli                        July 2016


            if distance code is implicit zero from insert-and-copy code
               set backward distance to the last distance
            else
               if BLEN_D is zero
                  read block type using HTREE_BTYPE_D and set BTYPE_D
                     save previous block type
                  read block count using HTREE_BLEN_D and set BLEN_D
               decrement BLEN_D
               compute context ID, CIDD from CLEN
               read distance code using HTREED[CMAPD[4*BTYPE_D + CIDD]]
               compute distance by distance short code substitution
               if distance code is not zero,
                  and distance is not a static dictionary reference,
                  push distance to the ring buffer of last distances
            if distance is less than the max allowed distance plus one
               move backwards distance bytes in the uncompressed data,
               and copy CLEN bytes from this position to
               the uncompressed stream
            else
               look up the static dictionary word, transform the word as
               directed, and copy the result to the uncompressed stream
         while number of uncompressed bytes for this meta-block < MLEN
      while not ISLAST

   If the stream ends before the completion of the last meta-block, then
   the stream should be rejected as invalid.

   Note that a duplicated string reference may refer to a string in a
   previous meta-block, i.e., the backward distance may cross one or
   more meta-block boundaries.  However, a backward copy distance will
   not refer past the beginning of the uncompressed stream or the window
   size; any such distance is interpreted as a reference to a static
   dictionary word.  Also, note that the referenced string may overlap
   the current position, for example, if the last 2 bytes decoded have
   values X and Y, a string reference with <length = 5, distance = 2>
   adds X,Y,X,Y,X to the uncompressed stream.

11.  Considerations for Compressor Implementations

   Since the intent of this document is to define the brotli compressed
   data format without reference to any particular compression
   algorithm, the material in this section is not part of the definition
   of the format, and a compressor need not follow it in order to be
   compliant.







Alakuijala & Szabadka         Informational                    [Page 38]

RFC 7932                         Brotli                        July 2016


11.1.  Trivial Compressor

   In this section, we present a very simple algorithm that produces a
   valid brotli stream representing an arbitrary sequence of
   uncompressed bytes in the form of the following C++ language
   function.

      string BrotliCompressTrivial(const string& u) {
         if (u.empty()) {
            return string(1, 6);
         }
         int i;
         string c;
         c.append(1, 12);
         for (i = 0; i + 65535 < u.size(); i += 65536) {
            c.append(1, 248);
            c.append(1, 255);
            c.append(1, 15);
            c.append(&u[i], 65536);
         }
         if (i < u.size()) {
            int r = u.size() - i - 1;
            c.append(1, (r & 31) << 3);
            c.append(1, r >> 5);
            c.append(1, 8 + (r >> 13));
            c.append(&u[i], r + 1);
         }
         c.append(1, 3);
         return c;
      }

   Note that this simple algorithm does not actually compress data, that
   is, the brotli representation will always be bigger than the
   original, but it shows that every sequence of N uncompressed bytes
   can be represented with a valid brotli stream that is not longer than
   N + (3 * (N >> 16) + 5) bytes.

11.2.  Aligning Compressed Meta-Blocks to Byte Boundaries

   As described in Section 9, only those meta-blocks that immediately
   follow an uncompressed meta-block or a metadata meta-block are
   guaranteed to start on a byte boundary.  In some applications, it
   might be required that every non-metadata meta-block starts on a byte
   boundary.  This can be achieved by appending an empty metadata meta-
   block after every non-metadata meta-block that does not end on a byte
   boundary.





Alakuijala & Szabadka         Informational                    [Page 39]

RFC 7932                         Brotli                        July 2016


11.3.  Creating Self-Contained Parts within the Compressed Data

   In some encoder implementations, it might be required to make a
   sequence of bytes within a brotli stream self-contained, that is,
   such that they can be decompressed independently from previous parts
   of the compressed data.  This is a useful feature for three reasons.
   First, if a large compressed file is damaged, it is possible to
   recover some of the file after the damage.  Second, it is useful when
   doing differential transfer of compressed data.  If a sequence of
   uncompressed bytes is unchanged and compressed independently from
   previous data, then the compressed representation may also be
   unchanged and can therefore be transferred very cheaply.  Third, if
   sequences of uncompressed bytes are compressed independently, it
   allows for parallel compression of these byte sequences within the
   same file, in addition to parallel compression of multiple files.

   Given two sequences of uncompressed bytes, U0 and U1, we will now
   describe how to create two sequences of compressed bytes, C0 and C1,
   such that the concatenation of C0 and C1 is a valid brotli stream,
   and that C0 and C1 (together with the first byte of C0 that contains
   the window size) can be decompressed independently from each other to
   U0 and U1.

   When compressing the byte sequence U0 to produce C0, we can use any
   compressor that works on the complete set of uncompressed bytes U0,
   with the following two changes.  First, the ISLAST bit of the last
   meta-block of C0 must not be set.  Second, C0 must end at a byte-
   boundary, which can be ensured by appending an empty metadata meta-
   block to it, as in Section 11.2.

   When compressing the byte sequence U1 to produce C1, we can use any
   compressor that starts a new meta-block at the beginning of U1 within
   the U0+U1 input stream, with the following two changes.  First,
   backward distances in C1 must not refer to static dictionary words or
   uncompressed bytes in U0.  Even if a sequence of bytes in U1 would
   match a static dictionary word, or a sequence of bytes that overlaps
   U0, the compressor must represent this sequence of bytes with a
   combination of literal insertions and backward references to bytes in
   U1 instead.  Second, the ring buffer of last four distances must be
   replenished first with distances in C1 before using it to encode
   other distances in C1.  Note that both compressors producing C0 and
   C1 have to use the same window size, but the stream header is emitted
   only by the compressor that produces C0.

   Note that this method can be easily generalized to more than two
   sequences of uncompressed bytes.





Alakuijala & Szabadka         Informational                    [Page 40]

RFC 7932                         Brotli                        July 2016


12.  Security Considerations

   As with any compressed file formats, decompressor implementations
   should handle all compressed data byte sequences, not only those that
   conform to this specification, where non-conformant compressed data
   sequences should be rejected as invalid.

   A possible attack against a system containing a decompressor
   implementation (e.g., a web browser) is to exploit a buffer overflow
   triggered by invalid compressed data.  Therefore, decompressor
   implementations should perform bounds-checking for each memory access
   that result from values decoded from the compressed stream and
   derivatives thereof.

   Another possible attack against a system containing a decompressor
   implementation is to provide it (either valid or invalid) compressed
   data that can make the decompressor system's resource consumption
   (CPU, memory, or storage) to be disproportionately large compared to
   the size of the compressed data.  In addition to the size of the
   compressed data, the amount of CPU, memory, and storage required to
   decompress a single compressed meta-block within a brotli stream is
   controlled by the following two parameters: the size of the
   uncompressed meta-block, which is encoded at the start of the
   compressed meta-block, and the size of the sliding window, which is
   encoded at the start of the brotli stream.  Decompressor
   implementations in systems where memory or storage is constrained
   should perform a sanity-check on these two parameters.  The
   uncompressed meta-block size that was decoded from the compressed
   stream should be compared against either a hard limit, given by the
   system's constraints or some expectation about the uncompressed data,
   or against a certain multiple of the size of the compressed data.  If
   the uncompressed meta-block size is determined to be too high, the
   compressed data should be rejected.  Likewise, when the complete
   uncompressed stream is kept in the system containing the decompressor
   implementation, the total uncompressed size of the stream should be
   checked before decompressing each additional meta-block.  If the size
   of the sliding window that was decoded from the start of the
   compressed stream is greater than a certain soft limit, then the
   decompressor implementation should, at first, allocate a smaller
   sliding window that fits the first uncompressed meta-block, and
   afterwards, before decompressing each additional meta-block, it
   should increase the size of the sliding window until the sliding
   window size specified in the compressed data is reached.








Alakuijala & Szabadka         Informational                    [Page 41]

RFC 7932                         Brotli                        July 2016


   Correspondingly, possible attacks against a system containing a
   compressor implementation (e.g., a web server) are to exploit a
   buffer overflow or cause disproportionately large resource
   consumption by providing, e.g., uncompressible data.  As described in
   Section 11.1, an output buffer of

            S(N) = N + (3 * (N >> 16) + 5)

   bytes is sufficient to hold a valid compressed brotli stream
   representing an arbitrary sequence of N uncompressed bytes.
   Therefore, compressor implementations should allocate at least S(N)
   bytes of output buffer before compressing N bytes of data with
   unknown compressibility and should perform bounds-checking for each
   write into this output buffer.  If their output buffer is full,
   compressor implementations should revert to the trivial compression
   algorithm described in Section 11.1.  The resource consumption of a
   compressor implementation for a particular input data depends mostly
   on the algorithm used to find backward matches and on the algorithm
   used to construct context maps and prefix codes and only to a lesser
   extent on the input data itself.  If the system containing a
   compressor implementation is overloaded, a possible way to reduce
   resource usage is to switch to more simple algorithms for backward
   reference search and prefix code construction, or to fall back to the
   trivial compression algorithm described in Section 11.1.

   A possible attack against a system that sends compressed data over an
   encrypted channel is the following.  An attacker who can repeatedly
   mix arbitrary (attacker-supplied) data with secret data (passwords,
   cookies) and observe the length of the ciphertext can potentially
   reconstruct the secret data.  To protect against this kind of attack,
   applications should not mix sensitive data with non-sensitive,
   potentially attacker-supplied data in the same compressed stream.

13.  IANA Considerations

   The "HTTP Content Coding Registry" has been updated with the
   registration below:

      +-------+-------------------------------------+------------+
      | Name  | Description                         | Reference  |
      +-------+-------------------------------------+------------+
      | br    | Brotli Compressed Data Format       | RFC 7932   |
      +-------+-------------------------------------+------------+








Alakuijala & Szabadka         Informational                    [Page 42]

RFC 7932                         Brotli                        July 2016


14.  Informative References

   [HUFFMAN]  Huffman, D. A., "A Method for the Construction of Minimum
              Redundancy Codes", Proceedings of the Institute of Radio
              Engineers, September 1952, Vol. 40, No. 9, pp. 1098-1101.

   [LZ77]     Ziv, J. and A. Lempel, "A Universal Algorithm for
              Sequential Data Compression", IEEE Transactions on
              Information Theory, Vol. 23, No. 3, pp. 337-343,
              DOI 10.1109/TIT.1977.1055714, May 1977,
              <https://www.cs.duke.edu/courses/spring03/cps296.5/papers/
              ziv_lempel_1977_universal_algorithm.pdf>.

   [RFC1951]  Deutsch, P., "DEFLATE Compressed Data Format Specification
              version 1.3", RFC 1951, DOI 10.17487/RFC1951, May 1996,
              <http://www.rfc-editor.org/info/rfc1951>.

   [WOFF2]    Levantovsky, V., Ed., and R. Levien, Ed., "WOFF File
              Format 2.0", W3C Candidate Recommendation, March 2016,
              <http://www.w3.org/TR/WOFF2/>.































Alakuijala & Szabadka         Informational                    [Page 43]

RFC 7932                         Brotli                        July 2016


Appendix A.  Static Dictionary Data

   The hexadecimal form of the DICT array is the following, where the
   length is 122,784 bytes and the CRC-32 of the byte sequence is
   0x5136cb04.

      74696d65646f776e6c6966656c6566746261636b636f64656461746173686f77
      6f6e6c7973697465636974796f70656e6a7573746c696b6566726565776f726b
      74657874796561726f766572626f64796c6f7665666f726d626f6f6b706c6179
      6c6976656c696e6568656c70686f6d65736964656d6f7265776f72646c6f6e67
      7468656d7669657766696e64706167656461797366756c6c686561647465726d
      656163686172656166726f6d747275656d61726b61626c6575706f6e68696768
      646174656c616e646e6577736576656e6e65787463617365626f7468706f7374
      757365646d61646568616e6468657265776861746e616d654c696e6b626c6f67
      73697a656261736568656c646d616b656d61696e757365722729202b686f6c64
      656e6473776974684e65777372656164776572657369676e74616b6568617665
      67616d657365656e63616c6c7061746877656c6c706c75736d656e7566696c6d
      706172746a6f696e746869736c697374676f6f646e6565647761797377657374
      6a6f62736d696e64616c736f6c6f676f72696368757365736c6173747465616d
      61726d79666f6f646b696e6777696c6c65617374776172646265737466697265
      506167656b6e6f77617761792e706e676d6f76657468616e6c6f616467697665
      73656c666e6f74656d756368666565646d616e79726f636b69636f6e6f6e6365
      6c6f6f6b6869646564696564486f6d6572756c65686f7374616a6178696e666f
      636c75626c6177736c65737368616c66736f6d65737563687a6f6e6531303025
      6f6e65736361726554696d6572616365626c7565666f75727765656b66616365
      686f706567617665686172646c6f73747768656e7061726b6b65707470617373
      73686970726f6f6d48544d4c706c616e54797065646f6e65736176656b656570
      666c61676c696e6b736f6c6466697665746f6f6b72617465746f776e6a756d70
      746875736461726b6361726466696c6566656172737461796b696c6c74686174
      66616c6c6175746f657665722e636f6d74616c6b73686f70766f746564656570
      6d6f6465726573747475726e626f726e62616e6466656c6c726f736575726c28
      736b696e726f6c65636f6d6561637473616765736d656574676f6c642e6a7067
      6974656d7661727966656c747468656e73656e6464726f7056696577636f7079
      312e30223c2f613e73746f70656c73656c696573746f75727061636b2e676966
      706173746373733f677261796d65616e2667743b7269646573686f746c617465
      73616964726f6164766172206665656c6a6f686e7269636b706f727466617374
      2755412d646561643c2f623e706f6f7262696c6c74797065552e532e776f6f64
      6d7573743270783b496e666f72616e6b7769646577616e7477616c6c6c656164
      5b305d3b7061756c776176657375726524282723776169746d61737361726d73
      676f65736761696e6c616e6770616964212d2d206c6f636b756e6974726f6f74
      77616c6b6669726d77696665786d6c22736f6e6774657374323070786b696e64
      726f7773746f6f6c666f6e746d61696c73616665737461726d617073636f7265
      7261696e666c6f77626162797370616e736179733470783b3670783b61727473
      666f6f747265616c77696b696865617473746570747269706f72672f6c616b65
      7765616b746f6c64466f726d6361737466616e7362616e6b7665727972756e73
      6a756c797461736b3170783b676f616c67726577736c6f776564676569643d22
      736574733570783b2e6a733f3430707869662028736f6f6e736561746e6f6e65
      747562657a65726f73656e747265656466616374696e746f676966746861726d



Alakuijala & Szabadka         Informational                    [Page 44]

RFC 7932                         Brotli                        July 2016


      3138707863616d6568696c6c626f6c647a6f6f6d766f69646561737972696e67
      66696c6c7065616b696e6974636f73743370783b6a61636b7461677362697473
      726f6c6c656469746b6e65776e6561723c212d2d67726f774a534f4e64757479
      4e616d6573616c65796f75206c6f74737061696e6a617a7a636f6c6465796573
      666973687777772e7269736b7461627370726576313070787269736532357078
      426c756564696e673330302c62616c6c666f72646561726e77696c64626f782e
      666169726c61636b76657273706169726a756e6574656368696628217069636b
      6576696c242822237761726d6c6f7264646f657370756c6c2c30303069646561
      647261776875676573706f7466756e646275726e6872656663656c6c6b657973
      7469636b686f75726c6f73736675656c31327078737569746465616c52535322
      6167656467726579474554226561736561696d736769726c616964733870783b
      6e617679677269647469707323393939776172736c61647963617273293b207d
      7068703f68656c6c74616c6c77686f6d7a683ae52a2f0d0a2031303068616c6c
      2e0a0a413770783b70757368636861743070783b637265772a2f3c2f68617368
      37357078666c6174726172652026262074656c6c63616d706f6e746f6c616964
      6d697373736b697074656e7466696e656d616c6567657473706c6f743430302c
      0d0a0d0a636f6f6c666565742e7068703c62723e657269636d6f737467756964
      62656c6c64657363686169726d61746861746f6d2f696d67262338326c75636b
      63656e743030303b74696e79676f6e6568746d6c73656c6c6472756746524545
      6e6f64656e69636b3f69643d6c6f73656e756c6c7661737477696e6452535320
      7765617272656c796265656e73616d6564756b656e6173616361706577697368
      67756c665432333a68697473736c6f74676174656b69636b626c757274686579
      313570782727293b293b223e6d73696577696e7362697264736f727462657461
      7365656b5431383a6f726473747265656d616c6c363070786661726de2809973
      626f79735b305d2e27293b22504f5354626561726b696473293b7d7d6d617279
      74656e6428554b29717561647a683ae62d73697a2d2d2d2d70726f7027293b0d
      6c6966745431393a76696365616e6479646562743e525353706f6f6c6e65636b
      626c6f775431363a646f6f726576616c5431373a6c6574736661696c6f72616c
      706f6c6c6e6f7661636f6c7367656e6520e28094736f6674726f6d6574696c6c
      726f73733c68333e706f75726661646570696e6b3c74723e6d696e69297c2128
      6d696e657a683ae862617273686561723030293b6d696c6b202d2d3e69726f6e
      667265646469736b77656e74736f696c707574732f6a732f686f6c795432323a
      4953424e5432303a6164616d736565733c68323e6a736f6e272c2027636f6e74
      5432313a205253536c6f6f70617369616d6f6f6e3c2f703e736f756c4c494e45
      666f7274636172745431343a3c68313e38307078212d2d3c3970783b5430343a
      6d696b653a34365a6e696365696e6368596f726b726963657a683ae42729293b
      707572656d61676570617261746f6e65626f6e643a33375a5f6f665f275d293b
      3030302c7a683ae774616e6b79617264626f776c627573683a35365a4a617661
      333070780a7c7d0a254333253a33345a6a656666455850496361736876697361
      676f6c66736e6f777a683ae9717565722e6373737369636b6d6561746d696e2e
      62696e6464656c6c686972657069637372656e743a33365a485454502d323031
      666f746f776f6c66454e442078626f783a35345a424f44596469636b3b0a7d0a
      657869743a33355a7661727362656174277d293b646965743939393b616e6e65
      7d7d3c2f5b695d2e4c616e676b6dc2b277697265746f7973616464737365616c
      616c65783b0a097d6563686f6e696e652e6f726730303529746f6e796a657773
      73616e646c656773726f6f66303030292032303077696e6567656172646f6773
      626f6f74676172796375747374796c6574656d7074696f6e2e786d6c636f636b
      67616e672428272e3530707850682e446d697363616c616e6c6f616e6465736b



Alakuijala & Szabadka         Informational                    [Page 45]

RFC 7932                         Brotli                        July 2016


      6d696c657279616e756e697864697363293b7d0a64757374636c6970292e0a0a
      373070782d32303044564473375d3e3c7461706564656d6f692b2b2977616765
      6575726f7068696c6f707473686f6c65464151736173696e2d3236546c616273
      7065747355524c2062756c6b636f6f6b3b7d0d0a484541445b305d2961626272
      6a75616e283139386c6573687477696e3c2f693e736f6e79677579736675636b
      706970657c2d0a21303032296e646f775b315d3b5b5d3b0a4c6f672073616c74
      0d0a090962616e677472696d62617468297b0d0a303070780a7d293b6b6f3aec
      6665657361643e0d733a2f2f205b5d3b746f6c6c706c756728297b0a7b0d0a20
      2e6a7327323030706475616c626f61742e4a5047293b0a7d71756f74293b0a0a
      27293b0a0d0a7d0d323031343230313532303136323031373230313832303139
      3230323032303231323032323230323332303234323032353230323632303237
      3230323832303239323033303230333132303332323033333230333432303335
      3230333632303337323031333230313232303131323031303230303932303038
      3230303732303036323030353230303432303033323030323230303132303030
      3139393931393938313939373139393631393935313939343139393331393932
      3139393131393930313938393139383831393837313938363139383531393834
      3139383331393832313938313139383031393739313937383139373731393736
      3139373531393734313937333139373231393731313937303139363931393638
      3139363731393636313936353139363431393633313936323139363131393630
      3139353931393538313935373139353631393535313935343139353331393532
      31393531313935303130303031303234313339343030303039393939636f6d6f
      6dc3a17365737465657374617065726f746f646f686163656361646161c3b16f
      6269656e64c3ad616173c3ad766964616361736f6f74726f666f726f736f6c6f
      6f7472616375616c64696a6f7369646f6772616e7469706f74656d6164656265
      616c676f7175c3a96573746f6e61646174726573706f636f6361736162616a6f
      746f646173696e6f6167756170756573756e6f73616e7465646963656c756973
      656c6c616d61796f7a6f6e61616d6f727069736f6f627261636c6963656c6c6f
      64696f73686f726163617369d0b7d0b0d0bdd0b0d0bed0bcd180d0b0d180d183
      d182d0b0d0bdd0b5d0bfd0bed0bed182d0b8d0b7d0bdd0bed0b4d0bed182d0be
      d0b6d0b5d0bed0bdd0b8d185d09dd0b0d0b5d0b5d0b1d18bd0bcd18bd092d18b
      d181d0bed0b2d18bd0b2d0bed09dd0bed0bed0b1d09fd0bed0bbd0b8d0bdd0b8
      d0a0d0a4d09dd0b5d09cd18bd182d18bd09ed0bdd0b8d0bcd0b4d0b0d097d0b0
      d094d0b0d09dd183d09ed0b1d182d0b5d098d0b7d0b5d0b9d0bdd183d0bcd0bc
      d0a2d18bd183d0b6d981d98ad8a3d986d985d8a7d985d8b9d983d984d8a3d988
      d8b1d8afd98ad8a7d981d989d987d988d984d985d984d983d8a7d988d984d987
      d8a8d8b3d8a7d984d8a5d986d987d98ad8a3d98ad982d8afd987d984d8abd985
      d8a8d987d984d988d984d98ad8a8d984d8a7d98ad8a8d983d8b4d98ad8a7d985
      d8a3d985d986d8aad8a8d98ad984d986d8add8a8d987d985d985d8b4d988d8b4
      6669727374766964656f6c69676874776f726c646d656469617768697465636c
      6f7365626c61636b7269676874736d616c6c626f6f6b73706c6163656d757369
      636669656c646f72646572706f696e7476616c75656c6576656c7461626c6562
      6f617264686f75736567726f7570776f726b7379656172737374617465746f64
      6179776174657273746172747374796c656465617468706f77657270686f6e65
      6e696768746572726f72696e70757461626f75747465726d737469746c65746f
      6f6c736576656e746c6f63616c74696d65736c61726765776f72647367616d65
      7373686f72747370616365666f637573636c6561726d6f64656c626c6f636b67
      75696465726164696f7368617265776f6d656e616761696e6d6f6e6579696d61
      67656e616d6573796f756e676c696e65736c61746572636f6c6f72677265656e



Alakuijala & Szabadka         Informational                    [Page 46]

RFC 7932                         Brotli                        July 2016


      66726f6e7426616d703b7761746368666f726365707269636572756c65736265
      67696e616674657276697369746973737565617265617362656c6f77696e6465
      78746f74616c686f7572736c6162656c7072696e7470726573736275696c746c
      696e6b73737065656473747564797472616465666f756e6473656e7365756e64
      657273686f776e666f726d7372616e676561646465647374696c6c6d6f766564
      74616b656e61626f7665666c61736866697865646f6674656e6f746865727669
      657773636865636b6c6567616c72697665726974656d73717569636b73686170
      6568756d616e6578697374676f696e676d6f7669657468697264626173696370
      65616365737461676577696474686c6f67696e696465617377726f7465706167
      65737573657273647269766573746f7265627265616b736f757468766f696365
      73697465736d6f6e746877686572656275696c6477686963686561727468666f
      72756d746872656573706f72747061727479436c69636b6c6f7765726c697665
      73636c6173736c61796572656e74727973746f72797573616765736f756e6463
      6f757274796f7572206269727468706f70757074797065736170706c79496d61
      67656265696e6775707065726e6f746573657665727973686f77736d65616e73
      65787472616d61746368747261636b6b6e6f776e6561726c79626567616e7375
      70657270617065726e6f7274686c6561726e676976656e6e616d6564656e6465
      645465726d73706172747347726f75706272616e647573696e67776f6d616e66
      616c73657265616479617564696f74616b65737768696c652e636f6d2f6c6976
      656463617365736461696c796368696c6467726561746a7564676574686f7365
      756e6974736e6576657262726f6164636f617374636f7665726170706c656669
      6c65736379636c657363656e65706c616e73636c69636b777269746571756565
      6e7069656365656d61696c6672616d656f6c64657270686f746f6c696d697463
      61636865636976696c7363616c65656e7465727468656d657468657265746f75
      6368626f756e64726f79616c61736b656477686f6c6573696e636573746f636b
      206e616d6566616974686865617274656d7074796f6666657273636f70656f77
      6e65646d69676874616c62756d7468696e6b626c6f6f6461727261796d616a6f
      72747275737463616e6f6e756e696f6e636f756e7476616c696473746f6e6553
      74796c654c6f67696e68617070796f636375726c6566743a6672657368717569
      746566696c6d7367726164656e65656473757262616e66696768746261736973
      686f7665726175746f3b726f7574652e68746d6c6d6978656466696e616c596f
      757220736c696465746f70696362726f776e616c6f6e65647261776e73706c69
      747265616368526967687464617465736d6172636871756f7465676f6f64734c
      696e6b73646f7562746173796e637468756d62616c6c6f776368696566796f75
      74686e6f76656c313070783b7365727665756e74696c68616e6473436865636b
      537061636571756572796a616d6573657175616c7477696365302c3030305374
      61727470616e656c736f6e6773726f756e6465696768747368696674776f7274
      68706f7374736c656164737765656b7361766f696474686573656d696c657370
      6c616e65736d617274616c706861706c616e746d61726b737261746573706c61
      7973636c61696d73616c65737465787473737461727377726f6e673c2f68333e
      7468696e672e6f72672f6d756c74696865617264506f7765727374616e64746f
      6b656e736f6c696428746869736272696e677368697073737461666674726965
      6463616c6c7366756c6c7966616374736167656e7454686973202f2f2d2d3e61
      646d696e65677970744576656e74313570783b456d61696c747275652263726f
      73737370656e74626c6f6773626f78223e6e6f7465646c656176656368696e61
      73697a657367756573743c2f68343e726f626f746865617679747275652c7365
      76656e6772616e646372696d657369676e73617761726564616e636570686173
      653e3c212d2d656e5f5553262333393b32303070785f6e616d656c6174696e65



Alakuijala & Szabadka         Informational                    [Page 47]

RFC 7932                         Brotli                        July 2016


      6e6a6f79616a61782e6174696f6e736d697468552e532e20686f6c6473706574
      6572696e6469616e6176223e636861696e73636f7265636f6d6573646f696e67
      7072696f7253686172653139393073726f6d616e6c697374736a6170616e6661
      6c6c73747269616c6f776e657261677265653c2f68323e6162757365616c6572
      746f70657261222d2f2f57636172647368696c6c737465616d7350686f746f74
      72757468636c65616e2e7068703f7361696e746d6574616c6c6f7569736d6561
      6e7470726f6f666272696566726f77223e67656e7265747275636b6c6f6f6b73
      56616c75654672616d652e6e65742f2d2d3e0a3c747279207b0a766172206d61
      6b6573636f737473706c61696e6164756c747175657374747261696e6c61626f
      7268656c707363617573656d616769636d6f746f72746865697232353070786c
      656173747374657073436f756e74636f756c64676c617373736964657366756e
      6473686f74656c61776172646d6f7574686d6f76657370617269736769766573
      6475746368746578617366727569746e756c6c2c7c7c5b5d3b746f70223e0a3c
      212d2d504f5354226f6365616e3c62722f3e666c6f6f72737065616b64657074
      682073697a6562616e6b7363617463686368617274323070783b616c69676e64
      65616c73776f756c64353070783b75726c3d227061726b736d6f7573654d6f73
      74202e2e2e3c2f616d6f6e67627261696e626f6479206e6f6e653b6261736564
      636172727964726166747265666572706167655f686f6d652e6d657465726465
      6c6179647265616d70726f76656a6f696e743c2f74723e64727567733c212d2d
      20617072696c696465616c616c6c656e6578616374666f727468636f6465736c
      6f67696356696577207365656d73626c616e6b706f7274732028323030736176
      65645f6c696e6b676f616c736772616e74677265656b686f6d657372696e6773
      7261746564333070783b77686f7365706172736528293b2220426c6f636b6c69
      6e75786a6f6e6573706978656c27293b223e293b6966282d6c65667464617669
      64686f727365466f6375737261697365626f786573547261636b656d656e743c
      2f656d3e626172223e2e7372633d746f776572616c743d226361626c6568656e
      7279323470783b73657475706974616c7973686172706d696e6f727461737465
      77616e7473746869732e7265736574776865656c6769726c732f6373732f3130
      30253b636c75627373747566666269626c65766f74657320313030306b6f7265
      617d293b0d0a62616e647371756575653d207b7d3b383070783b636b696e677b
      0d0a09096168656164636c6f636b69726973686c696b6520726174696f737461
      7473466f726d227961686f6f295b305d3b41626f757466696e64733c2f68313e
      64656275677461736b7355524c203d63656c6c737d2928293b313270783b7072
      696d6574656c6c737475726e7330783630302e6a706722737061696e62656163
      6874617865736d6963726f616e67656c2d2d3e3c2f676966747373746576652d
      6c696e6b626f64792e7d293b0a096d6f756e7420283139394641513c2f726f67
      65726672616e6b436c617373323870783b66656564733c68313e3c73636f7474
      7465737473323270783b6472696e6b29207c7c206c657769737368616c6c2330
      33393b20666f72206c6f7665647761737465303070783b6a613ae38273696d6f
      6e3c666f6e747265706c796d65657473756e7465726368656170746967687442
      72616e642920213d206472657373636c697073726f6f6d736f6e6b65796d6f62
      696c6d61696e2e4e616d6520706c61746566756e6e797472656573636f6d2f22
      312e6a7067776d6f6465706172616d53544152546c65667420696464656e2c20
      323031293b0a7d0a666f726d2e766972757363686169727472616e73776f7273
      7450616765736974696f6e70617463683c212d2d0a6f2d6361636669726d7374
      6f7572732c30303020617369616e692b2b297b61646f626527295b305d69643d
      3130626f74683b6d656e75202e322e6d692e706e67226b6576696e636f616368
      4368696c646272756365322e6a706755524c292b2e6a70677c7375697465736c



Alakuijala & Szabadka         Informational                    [Page 48]

RFC 7932                         Brotli                        July 2016


      69636568617272793132302220737765657474723e0d0a6e616d653d64696567
      6f706167652073776973732d2d3e0a0a236666663b223e4c6f672e636f6d2274
      7265617473686565742920262620313470783b736c6565706e74656e7466696c
      65646a613ae38369643d22634e616d6522776f72736573686f74732d626f782d
      64656c74610a266c743b62656172733a34385a3c646174612d727572616c3c2f
      613e207370656e6462616b657273686f70733d2022223b706870223e6374696f
      6e313370783b627269616e68656c6c6f73697a653d6f3d253246206a6f696e6d
      617962653c696d6720696d67223e2c20666a73696d67222022295b305d4d546f
      704254797065226e65776c7944616e736b637a656368747261696c6b6e6f7773
      3c2f68353e666171223e7a682d636e3130293b0a2d3122293b747970653d626c
      7565737472756c7964617669732e6a73273b3e0d0a3c21737465656c20796f75
      2068323e0d0a666f726d206a6573757331303025206d656e752e0d0a090d0a77
      616c65737269736b73756d656e746464696e67622d6c696b7465616368676966
      2220766567617364616e736b6565737469736871697073756f6d69736f627265
      6465736465656e747265746f646f73707565646561c3b16f73657374c3a17469
      656e6568617374616f74726f737061727465646f6e64656e7565766f68616365
      72666f726d616d69736d6f6d656a6f726d756e646f617175c3ad64c3ad617373
      c3b36c6f61797564616665636861746f64617374616e746f6d656e6f73646174
      6f736f74726173736974696f6d7563686f61686f72616c756761726d61796f72
      6573746f73686f72617374656e6572616e746573666f746f7365737461737061
      c3ad736e7565766173616c7564666f726f736d6564696f717569656e6d657365
      73706f6465726368696c65736572c3a1766563657364656369726a6f73c3a965
      7374617276656e7461677275706f686563686f656c6c6f7374656e676f616d69
      676f636f7361736e6976656c67656e74656d69736d6161697265736a756c696f
      74656d617368616369616661766f726a756e696f6c6962726570756e746f6275
      656e6f6175746f72616272696c6275656e61746578746f6d61727a6f73616265
      726c697374616c7565676f63c3b36d6f656e65726f6a7565676f706572c3ba68
      616265726573746f796e756e63616d756a657276616c6f7266756572616c6962
      726f6775737461696775616c766f746f736361736f736775c3ad61707565646f
      736f6d6f73617669736f7573746564646562656e6e6f63686562757363616661
      6c74616575726f737365726965646963686f637572736f636c61766563617361
      736c65c3b36e706c617a6f6c6172676f6f62726173766973746161706f796f6a
      756e746f7472617461766973746f637265617263616d706f68656d6f7363696e
      636f636172676f7069736f736f7264656e686163656ec3a1726561646973636f
      706564726f63657263617075656461706170656c6d656e6f72c3ba74696c636c
      61726f6a6f72676563616c6c65706f6e657274617264656e616469656d617263
      617369677565656c6c61737369676c6f636f6368656d6f746f736d6164726563
      6c617365726573746f6e69c3b16f7175656461706173617262616e636f68696a
      6f737669616a657061626c6fc3a97374657669656e657265696e6f64656a6172
      666f6e646f63616e616c6e6f7274656c657472616361757361746f6d61726d61
      6e6f736c756e65736175746f7376696c6c6176656e646f70657361727469706f
      7374656e67616d6172636f6c6c6576617061647265756e69646f76616d6f737a
      6f6e6173616d626f7362616e64616d61726961616275736f6d75636861737562
      697272696f6a617669766972677261646f6368696361616c6cc3ad6a6f76656e
      6469636861657374616e74616c657373616c69727375656c6f7065736f736669
      6e65736c6c616d61627573636fc3a97374616c6c6567616e6567726f706c617a
      6168756d6f7270616761726a756e7461646f626c6569736c6173626f6c736162
      61c3b16f6861626c616c75636861c381726561646963656e6a756761726e6f74



Alakuijala & Szabadka         Informational                    [Page 49]

RFC 7932                         Brotli                        July 2016


      617376616c6c65616c6cc3a16361726761646f6c6f726162616a6f657374c3a9
      677573746f6d656e74656d6172696f6669726d61636f73746f6669636861706c
      617461686f67617261727465736c65796573617175656c6d7573656f62617365
      73706f636f736d697461646369656c6f636869636f6d6965646f67616e617273
      616e746f65746170616465626573706c61796172656465737369657465636f72
      7465636f7265616475646173646573656f7669656a6f64657365616167756173
      2671756f743b646f6d61696e636f6d6d6f6e7374617475736576656e74736d61
      7374657273797374656d616374696f6e62616e6e657272656d6f76657363726f
      6c6c757064617465676c6f62616c6d656469756d66696c7465726e756d626572
      6368616e6765726573756c747075626c696373637265656e63686f6f73656e6f
      726d616c74726176656c697373756573736f7572636574617267657473707269
      6e676d6f64756c656d6f62696c6573776974636870686f746f73626f72646572
      726567696f6e697473656c66736f6369616c616374697665636f6c756d6e7265
      636f7264666f6c6c6f777469746c653e6569746865726c656e67746866616d69
      6c79667269656e646c61796f7574617574686f72637265617465726576696577
      73756d6d6572736572766572706c61796564706c61796572657870616e64706f
      6c696379666f726d6174646f75626c65706f696e747373657269657370657273
      6f6e6c6976696e6764657369676e6d6f6e746873666f72636573756e69717565
      77656967687470656f706c65656e657267796e61747572657365617263686669
      67757265686176696e67637573746f6d6f66667365746c657474657277696e64
      6f777375626d697472656e64657267726f75707375706c6f61646865616c7468
      6d6574686f64766964656f737363686f6f6c667574757265736861646f776465
      6261746576616c7565734f626a6563746f74686572737269676874736c656167
      75656368726f6d6573696d706c656e6f74696365736861726564656e64696e67
      736561736f6e7265706f72746f6e6c696e65737175617265627574746f6e696d
      61676573656e61626c656d6f76696e676c617465737477696e7465724672616e
      6365706572696f647374726f6e677265706561744c6f6e646f6e64657461696c
      666f726d656464656d616e64736563757265706173736564746f67676c65706c
      6163657364657669636573746174696363697469657373747265616d79656c6c
      6f7761747461636b737472656574666c6967687468696464656e696e666f223e
      6f70656e656475736566756c76616c6c65796361757365736c65616465727365
      637265747365636f6e6464616d61676573706f72747365786365707472617469
      6e677369676e65647468696e67736566666563746669656c6473737461746573
      6f666669636576697375616c656469746f72766f6c756d655265706f72746d75
      7365756d6d6f76696573706172656e746163636573736d6f73746c796d6f7468
      6572222069643d226d61726b657467726f756e646368616e6365737572766579
      6265666f726573796d626f6c6d6f6d656e747370656563686d6f74696f6e696e
      736964656d617474657243656e7465726f626a6563746578697374736d696464
      6c654575726f706567726f7774686c65676163796d616e6e6572656e6f756768
      636172656572616e737765726f726967696e706f7274616c636c69656e747365
      6c65637472616e646f6d636c6f736564746f70696373636f6d696e6766617468
      65726f7074696f6e73696d706c7972616973656465736361706563686f73656e
      636875726368646566696e65726561736f6e636f726e65726f75747075746d65
      6d6f7279696672616d65706f6c6963656d6f64656c734e756d62657264757269
      6e676f66666572737374796c65736b696c6c65646c697374656463616c6c6564
      73696c7665726d617267696e64656c65746562657474657262726f7773656c69
      6d697473476c6f62616c73696e676c6577696467657463656e74657262756467
      65746e6f77726170637265646974636c61696d73656e67696e65736166657479



Alakuijala & Szabadka         Informational                    [Page 50]

RFC 7932                         Brotli                        July 2016


      63686f6963657370697269742d7374796c657370726561646d616b696e676e65
      65646564727573736961706c65617365657874656e7453637269707462726f6b
      656e616c6c6f7773636861726765646976696465666163746f726d656d626572
      2d62617365647468656f7279636f6e66696761726f756e64776f726b65646865
      6c706564436875726368696d7061637473686f756c64616c776179736c6f676f
      2220626f74746f6d6c697374223e297b766172207072656669786f72616e6765
      4865616465722e7075736828636f75706c6567617264656e6272696467656c61
      756e636852657669657774616b696e67766973696f6e6c6974746c6564617469
      6e67427574746f6e6265617574797468656d6573666f72676f74536561726368
      616e63686f72616c6d6f73746c6f616465644368616e676572657475726e7374
      72696e6772656c6f61644d6f62696c65696e636f6d65737570706c79536f7572
      63656f7264657273766965776564266e6273703b636f7572736541626f757420
      69736c616e643c68746d6c20636f6f6b69656e616d653d22616d617a6f6e6d6f
      6465726e616476696365696e3c2f613e3a20546865206469616c6f67686f7573
      6573424547494e204d657869636f73746172747363656e747265686569676874
      616464696e6749736c616e64617373657473456d706972655363686f6f6c6566
      666f72746469726563746e6561726c796d616e75616c53656c6563742e0a0a4f
      6e656a6f696e65646d656e75223e5068696c697061776172647368616e646c65
      696d706f72744f6666696365726567617264736b696c6c736e6174696f6e5370
      6f7274736465677265657765656b6c792028652e672e626568696e64646f6374
      6f726c6f67676564756e697465643c2f623e3c2f626567696e73706c616e7473
      61737369737461727469737469737375656433303070787c63616e6164616167
      656e6379736368656d6572656d61696e4272617a696c73616d706c656c6f676f
      223e6265796f6e642d7363616c656163636570747365727665646d6172696e65
      466f6f74657263616d6572613c2f68313e0a5f666f726d226c65617665737374
      7265737322202f3e0d0a2e67696622206f6e6c6f61646c6f616465724f78666f
      72647369737465727375727669766c697374656e66656d616c6544657369676e
      73697a653d2261707065616c74657874223e6c6576656c737468616e6b736869
      67686572666f72636564616e696d616c616e796f6e6541667269636161677265
      6564726563656e7450656f706c653c6272202f3e776f6e646572707269636573
      7475726e65647c7c207b7d3b6d61696e223e696e6c696e6573756e6461797772
      6170223e6661696c656463656e7375736d696e757465626561636f6e71756f74
      657331353070787c65737461746572656d6f7465656d61696c226c696e6b6564
      72696768743b7369676e616c666f726d616c312e68746d6c7369676e75707072
      696e6365666c6f61743a2e706e672220666f72756d2e41636365737370617065
      7273736f756e6473657874656e64486569676874736c696465725554462d3822
      26616d703b204265666f72652e205769746873747564696f6f776e6572736d61
      6e61676570726f6669746a5175657279616e6e75616c706172616d73626f7567
      687466616d6f7573676f6f676c656c6f6e676572692b2b29207b69737261656c
      736179696e67646563696465686f6d65223e686561646572656e737572656272
      616e6368706965636573626c6f636b3b737461746564746f70223e3c72616369
      6e67726573697a652d2d2667743b70616369747973657875616c627572656175
      2e6a7067222031302c3030306f627461696e7469746c6573616d6f756e742c20
      496e632e636f6d6564796d656e7522206c7972696373746f6461792e696e6465
      6564636f756e74795f6c6f676f2e46616d696c796c6f6f6b65644d61726b6574
      6c7365206966506c617965727475726b6579293b76617220666f726573746769
      76696e676572726f7273446f6d61696e7d656c73657b696e73657274426c6f67
      3c2f666f6f7465726c6f67696e2e6661737465726167656e74733c626f647920



Alakuijala & Szabadka         Informational                    [Page 51]

RFC 7932                         Brotli                        July 2016


      313070782030707261676d616672696461796a756e696f72646f6c6c6172706c
      61636564636f76657273706c7567696e352c3030302070616765223e626f7374
      6f6e2e74657374286176617461727465737465645f636f756e74666f72756d73
      736368656d61696e6465782c66696c6c6564736861726573726561646572616c
      657274286170706561725375626d69746c696e65223e626f6479223e0a2a2054
      686554686f756768736565696e676a65727365794e6577733c2f766572696679
      657870657274696e6a75727977696474683d436f6f6b69655354415254206163
      726f73735f696d6167657468726561646e6174697665706f636b6574626f7822
      3e0a53797374656d20446176696463616e6365727461626c657370726f766564
      417072696c207265616c6c796472697665726974656d223e6d6f7265223e626f
      61726473636f6c6f727363616d7075736669727374207c7c205b5d3b6d656469
      612e67756974617266696e69736877696474683a73686f7765644f7468657220
      2e7068702220617373756d656c617965727377696c736f6e73746f7265737265
      6c69656673776564656e437573746f6d656173696c7920796f75722053747269
      6e670a0a5768696c7461796c6f72636c6561723a7265736f72746672656e6368
      74686f7567682229202b20223c626f64793e627579696e676272616e64734d65
      6d6265726e616d65223e6f7070696e67736563746f723570783b223e76737061
      6365706f737465726d616a6f7220636f666665656d617274696e6d6174757265
      68617070656e3c2f6e61763e6b616e7361736c696e6b223e496d616765733d66
      616c73657768696c65206873706163653026616d703b200a0a496e2020706f77
      6572506f6c736b692d636f6c6f726a6f7264616e426f74746f6d537461727420
      2d636f756e74322e68746d6c6e657773223e30312e6a70674f6e6c696e652d72
      696768746d696c6c657273656e696f724953424e2030302c3030302067756964
      657376616c756529656374696f6e7265706169722e786d6c2220207269676874
      732e68746d6c2d626c6f636b7265674578703a686f76657277697468696e7669
      7267696e70686f6e65733c2f74723e0d7573696e67200a09766172203e27293b
      0a093c2f74643e0a3c2f74723e0a62616861736162726173696c67616c65676f
      6d6167796172706f6c736b69737270736b69d8b1d8afd988e4b8ade69687e7ae
      80e4bd93e7b981e9ab94e4bfa1e681afe4b8ade59bbde68891e4bbace4b880e4
      b8aae585ace58fb8e7aea1e79086e8aebae59d9be58fafe4bba5e69c8de58aa1
      e697b6e997b4e4b8aae4babae4baa7e59381e887aae5b7b1e4bc81e4b89ae69f
      a5e79c8be5b7a5e4bd9ce88194e7b3bbe6b2a1e69c89e7bd91e7ab99e68980e6
      9c89e8af84e8aebae4b8ade5bf83e69687e7aba0e794a8e688b7e9a696e9a1b5
      e4bd9ce88085e68a80e69cafe997aee9a298e79bb8e585b3e4b88be8bdbde690
      9ce7b4a2e4bdbfe794a8e8bdafe4bbb6e59ca8e7babfe4b8bbe9a298e8b584e6
      9699e8a786e9a291e59b9ee5a48de6b3a8e5868ce7bd91e7bb9ce694b6e8978f
      e58685e5aeb9e68ea8e88d90e5b882e59cbae6b688e681afe7a9bae997b4e58f
      91e5b883e4bb80e4b988e5a5bde58f8be7949fe6b4bbe59bbee78987e58f91e5
      b195e5a682e69e9ce6898be69cbae696b0e997bbe69c80e696b0e696b9e5bc8f
      e58c97e4baace68f90e4be9be585b3e4ba8ee69bb4e5a49ae8bf99e4b8aae7b3
      bbe7bb9fe79fa5e98193e6b8b8e6888fe5b9bfe5918ae585b6e4bb96e58f91e8
      a1a8e5ae89e585a8e7acace4b880e4bc9ae59198e8bf9be8a18ce782b9e587bb
      e78988e69d83e794b5e5ad90e4b896e7958ce8aebee8aea1e5858de8b4b9e695
      99e882b2e58aa0e585a5e6b4bbe58aa8e4bb96e4bbace59586e59381e58d9ae5
      aea2e78eb0e59ca8e4b88ae6b5b7e5a682e4bd95e5b7b2e7bb8fe79599e8a880
      e8afa6e7bb86e7a4bee58cbae799bbe5bd95e69cace7ab99e99c80e8a681e4bb
      b7e6a0bce694afe68c81e59bbde99985e993bee68ea5e59bbde5aeb6e5bbbae8
      aebee69c8be58f8be99885e8afbbe6b395e5be8be4bd8de7bdaee7bb8fe6b58e



Alakuijala & Szabadka         Informational                    [Page 52]

RFC 7932                         Brotli                        July 2016


      e98089e68ba9e8bf99e6a0b7e5bd93e5898de58886e7b1bbe68e92e8a18ce59b
      a0e4b8bae4baa4e69893e69c80e5908ee99fb3e4b990e4b88de883bde9809ae8
      bf87e8a18ce4b89ae7a791e68a80e58fafe883bde8aebee5a487e59088e4bd9c
      e5a4a7e5aeb6e7a4bee4bc9ae7a094e7a9b6e4b893e4b89ae585a8e983a8e9a1
      b9e79baee8bf99e9878ce8bf98e698afe5bc80e5a78be68385e586b5e794b5e8
      8491e69687e4bbb6e59381e7898ce5b8aee58aa9e69687e58c96e8b584e6ba90
      e5a4a7e5ada6e5ada6e4b9a0e59cb0e59d80e6b58fe8a788e68a95e8b584e5b7
      a5e7a88be8a681e6b182e6808ee4b988e697b6e58099e58a9fe883bde4b8bbe8
      a681e79baee5898de8b584e8aeafe59f8ee5b882e696b9e6b395e794b5e5bdb1
      e68b9be88198e5a3b0e6988ee4bbbbe4bd95e581a5e5bab7e695b0e68daee7be
      8ee59bbde6b1bde8bda6e4bb8be7bb8de4bd86e698afe4baa4e6b581e7949fe4
      baa7e68980e4bba5e794b5e8af9de698bee7a4bae4b880e4ba9be58d95e4bd8d
      e4babae59198e58886e69e90e59cb0e59bbee69785e6b8b8e5b7a5e585b7e5ad
      a6e7949fe7b3bbe58897e7bd91e58f8be5b896e5ad90e5af86e7a081e9a291e9
      8193e68ea7e588b6e59cb0e58cbae59fbae69cace585a8e59bbde7bd91e4b88a
      e9878de8a681e7acace4ba8ce5969ce6aca2e8bf9be585a5e58f8be68385e8bf
      99e4ba9be88083e8af95e58f91e78eb0e59fb9e8aeade4bba5e4b88ae694bfe5
      ba9ce68890e4b8bae78eafe5a283e9a699e6b8afe5908ce697b6e5a8b1e4b990
      e58f91e98081e4b880e5ae9ae5bc80e58f91e4bd9ce59381e6a087e58786e6ac
      a2e8bf8ee8a7a3e586b3e59cb0e696b9e4b880e4b88be4bba5e58f8ae8b4a3e4
      bbbbe68896e88085e5aea2e688b7e4bba3e8a1a8e7a7afe58886e5a5b3e4baba
      e695b0e7a081e99480e594aee587bae78eb0e7a6bbe7babfe5ba94e794a8e588
      97e8a1a8e4b88de5908ce7bc96e8be91e7bb9fe8aea1e69fa5e8afa2e4b88de8
      a681e69c89e585b3e69cbae69e84e5be88e5a49ae692ade694bee7bb84e7bb87
      e694bfe7ad96e79bb4e68ea5e883bde58a9be69da5e6ba90e69982e99693e79c
      8be588b0e783ade997a8e585b3e994aee4b893e58cbae99d9ee5b8b8e88bb1e8
      afade799bee5baa6e5b88ce69c9be7be8ee5a5b3e6af94e8be83e79fa5e8af86
      e8a784e5ae9ae5bbbae8aeaee983a8e997a8e6848fe8a781e7b2bee5bda9e697
      a5e69cace68f90e9ab98e58f91e8a880e696b9e99da2e59fbae98791e5a484e7
      9086e69d83e99990e5bdb1e78987e993b6e8a18ce8bf98e69c89e58886e4baab
      e789a9e59381e7bb8fe890a5e6b7bbe58aa0e4b893e5aeb6e8bf99e7a78de8af
      9de9a298e8b5b7e69da5e4b89ae58aa1e585ace5918ae8aeb0e5bd95e7ae80e4
      bb8be8b4a8e9878fe794b7e4babae5bdb1e5938de5bc95e794a8e68aa5e5918a
      e983a8e58886e5bfabe9809fe592a8e8afa2e697b6e5b09ae6b3a8e6848fe794
      b3e8afb7e5ada6e6a0a1e5ba94e8afa5e58e86e58fb2e58faae698afe8bf94e5
      9b9ee8b4ade4b9b0e5908de7a7b0e4b8bae4ba86e68890e58a9fe8afb4e6988e
      e4be9be5ba94e5ada9e5ad90e4b893e9a298e7a88be5ba8fe4b880e888ace69c
      83e593a1e58faae69c89e585b6e5ae83e4bf9de68aa4e8808ce4b894e4bb8ae5
      a4a9e7aa97e58fa3e58aa8e68081e78ab6e68081e789b9e588abe8aea4e4b8ba
      e5bf85e9a1bbe69bb4e696b0e5b08fe8afb4e68891e58091e4bd9ce4b8bae5aa
      92e4bd93e58c85e68bace982a3e4b988e4b880e6a0b7e59bbde58685e698afe5
      90a6e6a0b9e68daee794b5e8a786e5ada6e999a2e585b7e69c89e8bf87e7a88b
      e794b1e4ba8ee4babae6898de587bae69da5e4b88de8bf87e6ada3e59ca8e698
      8ee6989fe69585e4ba8be585b3e7b3bbe6a087e9a298e59586e58aa1e8be93e5
      85a5e4b880e79bb4e59fbae7a180e69599e5ada6e4ba86e8a7a3e5bbbae7ad91
      e7bb93e69e9ce585a8e79083e9809ae79fa5e8aea1e58892e5afb9e4ba8ee889
      bae69cafe79bb8e5868ce58f91e7949fe79c9fe79a84e5bbbae7ab8be7ad89e7
      baa7e7b1bbe59e8be7bb8fe9aa8ce5ae9ee78eb0e588b6e4bd9ce69da5e887aa



Alakuijala & Szabadka         Informational                    [Page 53]

RFC 7932                         Brotli                        July 2016


      e6a087e7adbee4bba5e4b88be58e9fe5889be697a0e6b395e585b6e4b8ade580
      8be4babae4b880e58887e68c87e58d97e585b3e997ade99b86e59ba2e7acace4
      b889e585b3e6b3a8e59ba0e6ada4e785a7e78987e6b7b1e59cb3e59586e4b89a
      e5b9bfe5b79ee697a5e69c9fe9ab98e7baa7e69c80e8bf91e7bbbce59088e8a1
      a8e7a4bae4b893e8be91e8a18ce4b8bae4baa4e9809ae8af84e4bbb7e8a789e5
      be97e7b2bee58d8ee5aeb6e5baade5ae8ce68890e6849fe8a789e5ae89e8a385
      e5be97e588b0e982aee4bbb6e588b6e5baa6e9a39fe59381e899bde784b6e8bd
      ace8bdbde68aa5e4bbb7e8aeb0e88085e696b9e6a188e8a18ce694bfe4babae6
      b091e794a8e59381e4b89ce8a5bfe68f90e587bae98592e5ba97e784b6e5908e
      e4bb98e6acbee783ade782b9e4bba5e5898de5ae8ce585a8e58f91e5b896e8ae
      bee7bdaee9a286e5afbce5b7a5e4b89ae58cbbe999a2e79c8be79c8be7bb8fe5
      85b8e58e9fe59ba0e5b9b3e58fb0e59084e7a78de5a29ee58aa0e69d90e69699
      e696b0e5a29ee4b98be5908ee8818ce4b89ae69588e69e9ce4bb8ae5b9b4e8ae
      bae69687e68891e59bbde5918ae8af89e78988e4b8bbe4bfaee694b9e58f82e4
      b88ee68993e58db0e5bfabe4b990e69cbae6a2b0e8a782e782b9e5ad98e59ca8
      e7b2bee7a59ee88eb7e5be97e588a9e794a8e7bba7e7bbade4bda0e4bbace8bf
      99e4b988e6a8a1e5bc8fe8afade8a880e883bde5a49fe99b85e8998ee6938de4
      bd9ce9a38ee6a0bce4b880e8b5b7e7a791e5ada6e4bd93e882b2e79fade4bfa1
      e69da1e4bbb6e6b2bbe79697e8bf90e58aa8e4baa7e4b89ae4bc9ae8aeaee5af
      bce888aae58588e7949fe88194e79b9fe58fafe698afe5958fe9a18ce7bb93e6
      9e84e4bd9ce794a8e8b083e69fa5e8b387e69699e887aae58aa8e8b49fe8b4a3
      e5869ce4b89ae8aebfe997aee5ae9ee696bde68ea5e58f97e8aea8e8aebae982
      a3e4b8aae58f8de9a688e58aa0e5bcbae5a5b3e680a7e88c83e59bb4e69c8de5
      8b99e4bc91e997b2e4bb8ae697a5e5aea2e69c8de8a780e79c8be58f82e58aa0
      e79a84e8af9de4b880e782b9e4bf9de8af81e59bbee4b9a6e69c89e69588e6b5
      8be8af95e7a7bbe58aa8e6898de883bde586b3e5ae9ae882a1e7a5a8e4b88de6
      96ade99c80e6b182e4b88de5be97e58a9ee6b395e4b98be997b4e98787e794a8
      e890a5e99480e68a95e8af89e79baee6a087e788b1e68385e69184e5bdb1e69c
      89e4ba9be8a487e8a3bde69687e5ada6e69cbae4bc9ae695b0e5ad97e8a385e4
      bfaee8b4ade789a9e5869ce69d91e585a8e99da2e7b2bee59381e585b6e5ae9e
      e4ba8be68385e6b0b4e5b9b3e68f90e7a4bae4b88ae5b882e8b0a2e8b0a2e699
      aee9809ae69599e5b888e4b88ae4bca0e7b1bbe588abe6ad8ce69bb2e68ba5e6
      9c89e5889be696b0e9858de4bbb6e58faae8a681e697b6e4bba3e8b387e8a88a
      e8bebee588b0e4babae7949fe8aea2e99885e88081e5b888e5b195e7a4bae5bf
      83e79086e8b4b4e5ad90e7b6b2e7ab99e4b8bbe9a18ce887aae784b6e7baa7e5
      88abe7ae80e58d95e694b9e99da9e982a3e4ba9be69da5e8afb4e68993e5bc80
      e4bba3e7a081e588a0e999a4e8af81e588b8e88a82e79baee9878de782b9e6ac
      a1e695b8e5a49ae5b091e8a784e58892e8b584e98791e689bee588b0e4bba5e5
      908ee5a4a7e585a8e4b8bbe9a1b5e69c80e4bdb3e59b9ee7ad94e5a4a9e4b88b
      e4bf9de99a9ce78eb0e4bba3e6a380e69fa5e68a95e7a5a8e5b08fe697b6e6b2
      92e69c89e6ada3e5b8b8e7949ae887b3e4bba3e79086e79baee5bd95e585ace5
      bc80e5a48de588b6e98791e89e8de5b9b8e7a68fe78988e69cace5bda2e68890
      e58786e5a487e8a18ce68385e59b9ee588b0e6809de683b3e6808ee6a0b7e58d
      8fe8aeaee8aea4e8af81e69c80e5a5bde4baa7e7949fe68c89e785a7e69c8de8
      a385e5b9bfe4b89ce58aa8e6bcabe98787e8b4ade696b0e6898be7bb84e59bbe
      e99da2e69dbfe58f82e88083e694bfe6b2bbe5aeb9e69893e5a4a9e59cb0e58a
      aae58a9be4babae4bbace58d87e7baa7e9809fe5baa6e4babae789a9e8b083e6
      95b4e6b581e8a18ce980a0e68890e69687e5ad97e99fa9e59bbde8b4b8e69893



Alakuijala & Szabadka         Informational                    [Page 54]

RFC 7932                         Brotli                        July 2016


      e5bc80e5b195e79bb8e9979ce8a1a8e78eb0e5bdb1e8a786e5a682e6ada4e7be
      8ee5aeb9e5a4a7e5b08fe68aa5e98193e69da1e6acbee5bf83e68385e8aeb8e5
      a49ae6b395e8a784e5aeb6e5b185e4b9a6e5ba97e8bf9ee68ea5e7ab8be58db3
      e4b8bee68aa5e68a80e5b7a7e5a5a5e8bf90e799bbe585a5e4bba5e69da5e790
      86e8aebae4ba8be4bbb6e887aae794b1e4b8ade58d8ee58a9ee585ace5a688e5
      a688e79c9fe6ada3e4b88de99499e585a8e69687e59088e5908ce4bbb7e580bc
      e588abe4babae79b91e79da3e585b7e4bd93e4b896e7baaae59ba2e9989fe588
      9be4b89ae689bfe68b85e5a29ee995bfe69c89e4babae4bf9de68c81e59586e5
      aeb6e7bbb4e4bfaee58fb0e6b9bee5b7a6e58fb3e882a1e4bbbde7ad94e6a188
      e5ae9ee99985e794b5e4bfa1e7bb8fe79086e7949fe591bde5aea3e4bca0e4bb
      bbe58aa1e6ada3e5bc8fe789b9e889b2e4b88be69da5e58d8fe4bc9ae58faae8
      83bde5bd93e784b6e9878de696b0e585a7e5aeb9e68c87e5afbce8bf90e8a18c
      e697a5e5bf97e8b3a3e5aeb6e8b685e8bf87e59c9fe59cb0e6b599e6b19fe694
      afe4bb98e68ea8e587bae7ab99e995bfe69dade5b79ee689a7e8a18ce588b6e9
      80a0e4b98be4b880e68ea8e5b9bfe78eb0e59cbae68f8fe8bfb0e58f98e58c96
      e4bca0e7bb9fe6ad8ce6898be4bf9de999a9e8afbee7a88be58cbbe79697e7bb
      8fe8bf87e8bf87e58ebbe4b98be5898de694b6e585a5e5b9b4e5baa6e69d82e5
      bf97e7be8ee4b8bde69c80e9ab98e799bbe99986e69caae69da5e58aa0e5b7a5
      e5858de8b4a3e69599e7a88be78988e59d97e8baabe4bd93e9878de5ba86e587
      bae594aee68890e69cace5bda2e5bc8fe59c9fe8b186e587bae583b9e4b89ce6
      96b9e982aee7aeb1e58d97e4baace6b182e8818ce58f96e5be97e8818ce4bd8d
      e79bb8e4bfa1e9a1b5e99da2e58886e9929fe7bd91e9a1b5e7a1aee5ae9ae59b
      bee4be8be7bd91e59d80e7a7afe69e81e99499e8afafe79baee79a84e5ae9de8
      b49de69cbae585b3e9a38ee999a9e68e88e69d83e79785e6af92e5aea0e789a9
      e999a4e4ba86e8a995e8ab96e796bee79785e58f8ae697b6e6b182e8b4ade7ab
      99e782b9e584bfe7aba5e6af8fe5a4a9e4b8ade5a4aee8aea4e8af86e6af8fe4
      b8aae5a4a9e6b4a5e5ad97e4bd93e58fb0e781a3e7bbb4e68aa4e69cace9a1b5
      e4b8aae680a7e5ae98e696b9e5b8b8e8a781e79bb8e69cbae68898e795a5e5ba
      94e5bd93e5be8be5b888e696b9e4bebfe6a0a1e59bade882a1e5b882e688bfe5
      b18be6a08fe79baee59198e5b7a5e5afbce887b4e7aa81e784b6e98193e585b7
      e69cace7bd91e7bb93e59088e6a1a3e6a188e58ab3e58aa8e58fa6e5a496e7be
      8ee58583e5bc95e8b5b7e694b9e58f98e7acace59b9be4bc9ae8aea1e8aaaae6
      988ee99a90e7a781e5ae9de5ae9de8a784e88c83e6b688e8b4b9e585b1e5908c
      e5bf98e8aeb0e4bd93e7b3bbe5b8a6e69da5e5908de5ad97e799bce8a1a8e5bc
      80e694bee58aa0e79b9fe58f97e588b0e4ba8ce6898be5a4a7e9878fe68890e4
      babae695b0e9878fe585b1e4baabe58cbae59f9fe5a5b3e5ada9e58e9fe58899
      e68980e59ca8e7bb93e69d9fe9809ae4bfa1e8b685e7baa7e9858de7bdaee5bd
      93e697b6e4bc98e7a780e680a7e6849fe688bfe4baa7e9818ae688b2e587bae5
      8fa3e68f90e4baa4e5b0b1e4b89ae4bf9de581a5e7a88be5baa6e58f82e695b0
      e4ba8be4b89ae695b4e4b8aae5b1b1e4b89ce68385e6849fe789b9e6ae8ae588
      86e9a19ee6909ce5b08be5b19ee4ba8ee997a8e688b7e8b4a2e58aa1e5a3b0e9
      9fb3e58f8ae585b6e8b4a2e7bb8fe59d9ae68c81e5b9b2e983a8e68890e7ab8b
      e588a9e79b8ae88083e89991e68890e983bde58c85e8a385e794a8e688b6e6af
      94e8b59be69687e6988ee68b9be59586e5ae8ce695b4e79c9fe698afe79cbce7
      9d9be4bc99e4bcb4e5a881e69c9be9a286e59f9fe58dabe7949fe4bc98e683a0
      e8ab96e5a387e585ace585b1e889afe5a5bde58585e58886e7aca6e59088e999
      84e4bbb6e789b9e782b9e4b88de58fafe88bb1e69687e8b584e4baa7e6a0b9e6
      9cace6988ee698bee5af86e7a2bce585ace4bc97e6b091e6978fe69bb4e58aa0



Alakuijala & Szabadka         Informational                    [Page 55]

RFC 7932                         Brotli                        July 2016


      e4baabe58f97e5908ce5ada6e590afe58aa8e98082e59088e58e9fe69da5e997
      aee7ad94e69cace69687e7be8ee9a39fe7bbbfe889b2e7a8b3e5ae9ae7bb88e4
      ba8ee7949fe789a9e4be9be6b182e6909ce78b90e58a9be9878fe4b8a5e9878d
      e6b0b8e8bf9ce58699e79c9fe69c89e99990e7ab9ee4ba89e5afb9e8b1a1e8b4
      b9e794a8e4b88de5a5bde7bb9de5afb9e58d81e58886e4bf83e8bf9be782b9e8
      af84e5bdb1e99fb3e4bc98e58abfe4b88de5b091e6aca3e8b58fe5b9b6e4b894
      e69c89e782b9e696b9e59091e585a8e696b0e4bfa1e794a8e8aebee696bde5bd
      a2e8b1a1e8b584e6a0bce7aa81e7a0b4e99a8fe79d80e9878de5a4a7e4ba8ee6
      98afe6af95e4b89ae699bae883bde58c96e5b7a5e5ae8ce7be8ee59586e59f8e
      e7bb9fe4b880e587bae78988e68993e980a0e794a2e59381e6a682e586b5e794
      a8e4ba8ee4bf9de79599e59ba0e7b4a0e4b8ade59c8be5ad98e582a8e8b4b4e5
      9bbee69c80e6849be995bfe69c9fe58fa3e4bbb7e79086e8b4a2e59fbae59cb0
      e5ae89e68e92e6ada6e6b189e9878ce99da2e5889be5bbbae5a4a9e7a9bae9a6
      96e58588e5ae8ce59684e9a9b1e58aa8e4b88be99da2e4b88de5868de8af9ae4
      bfa1e6848fe4b989e998b3e58589e88bb1e59bbde6bc82e4baaee5869be4ba8b
      e78ea9e5aeb6e7bea4e4bc97e5869ce6b091e58db3e58fafe5908de7a8b1e5ae
      b6e585b7e58aa8e794bbe683b3e588b0e6b3a8e6988ee5b08fe5ada6e680a7e8
      83bde88083e7a094e7a1ace4bbb6e8a782e79c8be6b885e6a59ae6909ee7ac91
      e9a696e9a081e9bb84e98791e98082e794a8e6b19fe88b8fe79c9fe5ae9ee4b8
      bbe7aea1e998b6e6aeb5e8a8bbe5868ae7bfbbe8af91e69d83e588a9e5819ae5
      a5bde4bcbce4b98ee9809ae8aeafe696bde5b7a5e78b80e6858be4b99fe8aeb8
      e78eafe4bf9de59fb9e585bbe6a682e5bfb5e5a4a7e59e8be69cbae7a5a8e790
      86e8a7a3e58cbfe5908d6375616e646f656e766961726d616472696462757363
      6172696e6963696f7469656d706f706f727175656375656e746165737461646f
      70756564656e6a7565676f73636f6e747261657374c3a16e6e6f6d6272657469
      656e656e70657266696c6d616e657261616d69676f7363697564616463656e74
      726f61756e71756570756564657364656e74726f7072696d657270726563696f
      736567c3ba6e6275656e6f73766f6c76657270756e746f7373656d616e616861
      62c3ad6161676f73746f6e7565766f73756e69646f736361726c6f7365717569
      706f6e69c3b16f736d7563686f73616c67756e61636f7272656f696d6167656e
      7061727469726172726962616d6172c3ad61686f6d627265656d706c656f7665
      7264616463616d62696f6d7563686173667565726f6e70617361646f6cc3ad6e
      65617061726563656e7565766173637572736f7365737461626171756965726f
      6c6962726f736375616e746f61636365736f6d696775656c766172696f736375
      6174726f7469656e6573677275706f73736572c3a16e6575726f70616d656469
      6f736672656e746561636572636164656dc3a1736f6665727461636f63686573
      6d6f64656c6f6974616c69616c6574726173616c67c3ba6e636f6d7072616375
      616c657365786973746563756572706f7369656e646f7072656e73616c6c6567
      61727669616a657364696e65726f6d7572636961706f6472c3a170756573746f
      64696172696f707565626c6f7175696572656d616e75656c70726f70696f6372
      6973697363696572746f73656775726f6d75657274656675656e746563657272
      61726772616e646565666563746f7061727465736d656469646170726f706961
      6f6672656365746965727261652d6d61696c766172696173666f726d61736675
      7475726f6f626a65746f73656775697272696573676f6e6f726d61736d69736d
      6f73c3ba6e69636f63616d696e6f736974696f7372617ac3b36e64656269646f
      707275656261746f6c65646f74656ec3ad616a6573c3ba7365737065726f636f
      63696e616f726967656e7469656e64616369656e746f63c3a164697a6861626c
      6172736572c3ad616c6174696e61667565727a61657374696c6f677565727261



Alakuijala & Szabadka         Informational                    [Page 56]

RFC 7932                         Brotli                        July 2016


      656e74726172c3a97869746f6cc3b370657a6167656e646176c3ad64656f6576
      69746172706167696e616d6574726f736a617669657270616472657366c3a163
      696c636162657a61c3a17265617373616c696461656e76c3ad6f6a6170c3b36e
      616275736f736269656e6573746578746f736c6c6576617270756564616e6675
      65727465636f6dc3ba6e636c6173657368756d616e6f74656e69646f62696c62
      616f756e69646164657374c3a17365646974617263726561646fd0b4d0bbd18f
      d187d182d0bed0bad0b0d0bad0b8d0bbd0b8d18dd182d0bed0b2d181d0b5d0b5
      d0b3d0bed0bfd180d0b8d182d0b0d0bad0b5d189d0b5d183d0b6d0b5d09ad0b0
      d0bad0b1d0b5d0b7d0b1d18bd0bbd0bed0bdd0b8d092d181d0b5d0bfd0bed0b4
      d0add182d0bed182d0bed0bcd187d0b5d0bcd0bdd0b5d182d0bbd0b5d182d180
      d0b0d0b7d0bed0bdd0b0d0b3d0b4d0b5d0bcd0bdd0b5d094d0bbd18fd09fd180
      d0b8d0bdd0b0d181d0bdd0b8d185d182d0b5d0bcd0bad182d0bed0b3d0bed0b4
      d0b2d0bed182d182d0b0d0bcd0a1d0a8d090d0bcd0b0d18fd0a7d182d0bed0b2
      d0b0d181d0b2d0b0d0bcd0b5d0bcd183d0a2d0b0d0bad0b4d0b2d0b0d0bdd0b0
      d0bcd18dd182d0b8d18dd182d183d092d0b0d0bcd182d0b5d185d0bfd180d0be
      d182d183d182d0bdd0b0d0b4d0b4d0bdd18fd092d0bed182d182d180d0b8d0bd
      d0b5d0b9d092d0b0d181d0bdd0b8d0bcd181d0b0d0bcd182d0bed182d180d183
      d0b1d09ed0bdd0b8d0bcd0b8d180d0bdd0b5d0b5d09ed09ed09ed0bbd0b8d186
      d18dd182d0b0d09ed0bdd0b0d0bdd0b5d0bcd0b4d0bed0bcd0bcd0bed0b9d0b4
      d0b2d0b5d0bed0bdd0bed181d183d0b4e0a495e0a587e0a4b9e0a588e0a495e0
      a580e0a4b8e0a587e0a495e0a4bee0a495e0a58be0a494e0a4b0e0a4aae0a4b0
      e0a4a8e0a587e0a48fe0a495e0a495e0a4bfe0a4ade0a580e0a487e0a4b8e0a4
      95e0a4b0e0a4a4e0a58be0a4b9e0a58be0a486e0a4aae0a4b9e0a580e0a4afe0
      a4b9e0a4afe0a4bee0a4a4e0a495e0a4a5e0a4be6a616772616ee0a486e0a49c
      e0a49ce0a58be0a485e0a4ace0a4a6e0a58be0a497e0a488e0a49ce0a4bee0a4
      97e0a48fe0a4b9e0a4aee0a487e0a4a8e0a4b5e0a4b9e0a4afe0a587e0a4a5e0
      a587e0a4a5e0a580e0a498e0a4b0e0a49ce0a4ace0a4a6e0a580e0a495e0a488
      e0a49ce0a580e0a4b5e0a587e0a4a8e0a488e0a4a8e0a48fe0a4b9e0a4b0e0a4
      89e0a4b8e0a4aee0a587e0a495e0a4aee0a4b5e0a58be0a4b2e0a587e0a4b8e0
      a4ace0a4aee0a488e0a4a6e0a587e0a493e0a4b0e0a486e0a4aee0a4ace0a4b8
      e0a4ade0a4b0e0a4ace0a4a8e0a49ae0a4b2e0a4aee0a4a8e0a486e0a497e0a4
      b8e0a580e0a4b2e0a580d8b9d984d989d8a5d984d989d987d8b0d8a7d8a2d8ae
      d8b1d8b9d8afd8afd8a7d984d989d987d8b0d987d8b5d988d8b1d8bad98ad8b1
      d983d8a7d986d988d984d8a7d8a8d98ad986d8b9d8b1d8b6d8b0d984d983d987
      d986d8a7d98ad988d985d982d8a7d984d8b9d984d98ad8a7d986d8a7d984d983
      d986d8add8aad989d982d8a8d984d988d8add8a9d8a7d8aed8b1d981d982d8b7
      d8b9d8a8d8afd8b1d983d986d8a5d8b0d8a7d983d985d8a7d8a7d8add8afd8a5
      d984d8a7d981d98ad987d8a8d8b9d8b6d983d98ad981d8a8d8add8abd988d985
      d986d988d987d988d8a3d986d8a7d8acd8afd8a7d984d987d8a7d8b3d984d985
      d8b9d986d8afd984d98ad8b3d8b9d8a8d8b1d8b5d984d989d985d986d8b0d8a8
      d987d8a7d8a3d986d987d985d8abd984d983d986d8aad8a7d984d8a7d8add98a
      d8abd985d8b5d8b1d8b4d8b1d8add8add988d984d988d981d98ad8a7d8b0d8a7
      d984d983d984d985d8b1d8a9d8a7d986d8aad8a7d984d981d8a3d8a8d988d8ae
      d8a7d8b5d8a3d986d8aad8a7d986d987d8a7d984d98ad8b9d8b6d988d988d982
      d8afd8a7d8a8d986d8aed98ad8b1d8a8d986d8aad984d983d985d8b4d8a7d8a1
      d988d987d98ad8a7d8a8d988d982d8b5d8b5d988d985d8a7d8b1d982d985d8a3
      d8add8afd986d8add986d8b9d8afd985d8b1d8a3d98ad8a7d8add8a9d983d8aa
      d8a8d8afd988d986d98ad8acd8a8d985d986d987d8aad8add8aad8acd987d8a9



Alakuijala & Szabadka         Informational                    [Page 57]

RFC 7932                         Brotli                        July 2016


      d8b3d986d8a9d98ad8aad985d983d8b1d8a9d8bad8b2d8a9d986d981d8b3d8a8
      d98ad8aad984d984d987d984d986d8a7d8aad984d983d982d984d8a8d984d985
      d8a7d8b9d986d987d8a3d988d984d8b4d98ad8a1d986d988d8b1d8a3d985d8a7
      d981d98ad983d8a8d983d984d8b0d8a7d8aad8b1d8aad8a8d8a8d8a3d986d987
      d985d8b3d8a7d986d983d8a8d98ad8b9d981d982d8afd8add8b3d986d984d987
      d985d8b4d8b9d8b1d8a3d987d984d8b4d987d8b1d982d8b7d8b1d8b7d984d8a8
      70726f66696c657365727669636564656661756c7468696d73656c6664657461
      696c73636f6e74656e74737570706f7274737461727465646d65737361676573
      75636365737366617368696f6e3c7469746c653e636f756e7472796163636f75
      6e746372656174656473746f72696573726573756c747372756e6e696e677072
      6f6365737377726974696e676f626a6563747376697369626c6577656c636f6d
      6561727469636c65756e6b6e6f776e6e6574776f726b636f6d70616e7964796e
      616d696362726f777365727072697661637970726f626c656d53657276696365
      72657370656374646973706c6179726571756573747265736572766577656273
      697465686973746f7279667269656e64736f7074696f6e73776f726b696e6776
      657273696f6e6d696c6c696f6e6368616e6e656c77696e646f772e6164647265
      73737669736974656477656174686572636f727265637470726f647563746564
      6972656374666f7277617264796f752063616e72656d6f7665647375626a6563
      74636f6e74726f6c6172636869766563757272656e7472656164696e676c6962
      726172796c696d697465646d616e616765726675727468657273756d6d617279
      6d616368696e656d696e7574657370726976617465636f6e7465787470726f67
      72616d736f63696574796e756d626572737772697474656e656e61626c656474
      726967676572736f75726365736c6f6164696e67656c656d656e74706172746e
      657266696e616c6c79706572666563746d65616e696e6773797374656d736b65
      6570696e6763756c747572652671756f743b2c6a6f75726e616c70726f6a6563
      7473757266616365732671756f743b657870697265737265766965777362616c
      616e6365456e676c697368436f6e74656e747468726f756768506c6561736520
      6f70696e696f6e636f6e74616374617665726167657072696d61727976696c6c
      6167655370616e69736867616c6c6572796465636c696e656d656574696e676d
      697373696f6e706f70756c61727175616c6974796d65617375726567656e6572
      616c7370656369657373657373696f6e73656374696f6e77726974657273636f
      756e746572696e697469616c7265706f727473666967757265736d656d626572
      73686f6c64696e67646973707574656561726c69657265787072657373646967
      6974616c70696374757265416e6f746865726d61727269656474726166666963
      6c656164696e676368616e67656463656e7472616c766963746f7279696d6167
      65732f726561736f6e7373747564696573666561747572656c697374696e676d
      7573742062657363686f6f6c7356657273696f6e757375616c6c79657069736f
      6465706c6179696e6767726f77696e676f6276696f75736f7665726c61797072
      6573656e74616374696f6e733c2f756c3e0d0a77726170706572616c72656164
      796365727461696e7265616c69747973746f72616765616e6f74686572646573
      6b746f706f6666657265647061747465726e756e757375616c4469676974616c
      6361706974616c576562736974656661696c757265636f6e6e65637472656475
      636564416e64726f696464656361646573726567756c61722026616d703b2061
      6e696d616c7372656c656173654175746f6d617467657474696e676d6574686f
      64736e6f7468696e67506f70756c617263617074696f6e6c6574746572736361
      7074757265736369656e63656c6963656e73656368616e676573456e676c616e
      643d3126616d703b486973746f7279203d206e65772043656e7472616c757064
      617465645370656369616c4e6574776f726b72657175697265636f6d6d656e74



Alakuijala & Szabadka         Informational                    [Page 58]

RFC 7932                         Brotli                        July 2016


      7761726e696e67436f6c6c656765746f6f6c62617272656d61696e7362656361
      757365656c65637465644465757473636866696e616e6365776f726b65727371
      7569636b6c796265747765656e65786163746c7973657474696e676469736561
      7365536f6369657479776561706f6e7365786869626974266c743b212d2d436f
      6e74726f6c636c6173736573636f76657265646f75746c696e6561747461636b
      73646576696365732877696e646f77707572706f73657469746c653d224d6f62
      696c65206b696c6c696e6773686f77696e674974616c69616e64726f70706564
      68656176696c79656666656374732d31275d293b0a636f6e6669726d43757272
      656e74616476616e636573686172696e676f70656e696e6764726177696e6762
      696c6c696f6e6f7264657265644765726d616e7972656c617465643c2f666f72
      6d3e696e636c75646577686574686572646566696e6564536369656e63656361
      74616c6f6741727469636c65627574746f6e736c617267657374756e69666f72
      6d6a6f75726e6579736964656261724368696361676f686f6c6964617947656e
      6572616c706173736167652c2671756f743b616e696d6174656665656c696e67
      6172726976656470617373696e676e61747572616c726f7567686c792e0a0a54
      686520627574206e6f7464656e736974794272697461696e4368696e6573656c
      61636b206f66747269627574654972656c616e642220646174612d666163746f
      727372656365697665746861742069734c69627261727968757362616e64696e
      206661637461666661697273436861726c65737261646963616c62726f756768
      7466696e64696e676c616e64696e673a6c616e673d2272657475726e206c6561
      64657273706c616e6e65647072656d69756d7061636b616765416d6572696361
      45646974696f6e5d2671756f743b4d6573736167656e65656420746f76616c75
      653d22636f6d706c65786c6f6f6b696e6773746174696f6e62656c6965766573
      6d616c6c65722d6d6f62696c657265636f72647377616e7420746f6b696e6420
      6f6646697265666f78796f752061726573696d696c6172737475646965646d61
      78696d756d68656164696e6772617069646c79636c696d6174656b696e67646f
      6d656d6572676564616d6f756e7473666f756e64656470696f6e656572666f72
      6d756c6164796e61737479686f7720746f20537570706f7274726576656e7565
      65636f6e6f6d79526573756c747362726f74686572736f6c646965726c617267
      656c7963616c6c696e672e2671756f743b4163636f756e744564776172642073
      65676d656e74526f62657274206566666f727473506163696669636c6561726e
      6564757020776974686865696768743a77652068617665416e67656c65736e61
      74696f6e735f7365617263686170706c696564616371756972656d6173736976
      656772616e7465643a2066616c7365747265617465646269676765737462656e
      6566697464726976696e67537475646965736d696e696d756d70657268617073
      6d6f726e696e6773656c6c696e67697320757365647265766572736576617269
      616e7420726f6c653d226d697373696e676163686965766570726f6d6f746573
      747564656e74736f6d656f6e6565787472656d65726573746f7265626f74746f
      6d3a65766f6c766564616c6c20746865736974656d6170656e676c6973687761
      7920746f202041756775737473796d626f6c73436f6d70616e796d6174746572
      736d75736963616c616761696e737473657276696e677d2928293b0d0a706179
      6d656e7474726f75626c65636f6e63657074636f6d70617265706172656e7473
      706c6179657273726567696f6e736d6f6e69746f722027275468652077696e6e
      696e676578706c6f72656164617074656447616c6c65727970726f6475636561
      62696c697479656e68616e636563617265657273292e2054686520636f6c6c65
      637453656172636820616e6369656e7465786973746564666f6f746572206861
      6e646c65727072696e746564636f6e736f6c654561737465726e6578706f7274
      7377696e646f77734368616e6e656c696c6c6567616c6e65757472616c737567



Alakuijala & Szabadka         Informational                    [Page 59]

RFC 7932                         Brotli                        July 2016


      676573745f6865616465727369676e696e672e68746d6c223e736574746c6564
      7765737465726e63617573696e672d7765626b6974636c61696d65644a757374
      6963656368617074657276696374696d7354686f6d6173206d6f7a696c6c6170
      726f6d6973657061727469657365646974696f6e6f7574736964653a66616c73
      652c68756e647265644f6c796d7069635f627574746f6e617574686f72737265
      61636865646368726f6e696364656d616e64737365636f6e647370726f746563
      7461646f70746564707265706172656e65697468657267726561746c79677265
      617465726f766572616c6c696d70726f7665636f6d6d616e647370656369616c
      7365617263682e776f727368697066756e64696e6774686f7567687468696768
      657374696e73746561647574696c6974797175617274657243756c7475726574
      657374696e67636c6561726c796578706f73656442726f777365726c69626572
      616c7d20636174636850726f6a6563746578616d706c656869646528293b466c
      6f72696461616e7377657273616c6c6f776564456d7065726f72646566656e73
      65736572696f757366726565646f6d5365766572616c2d627574746f6e467572
      746865726f7574206f6620213d206e756c6c747261696e656444656e6d61726b
      766f69642830292f616c6c2e6a7370726576656e745265717565737453746570
      68656e0a0a5768656e206f6273657276653c2f68323e0d0a4d6f6465726e2070
      726f766964652220616c743d22626f72646572732e0a0a466f72200a0a4d616e
      792061727469737473706f7765726564706572666f726d66696374696f6e7479
      7065206f666d65646963616c7469636b6574736f70706f736564436f756e6369
      6c7769746e6573736a75737469636547656f7267652042656c6769756d2e2e2e
      3c2f613e747769747465726e6f7461626c7977616974696e6777617266617265
      204f746865722072616e6b696e67706872617365736d656e74696f6e73757276
      6976657363686f6c61723c2f703e0d0a20436f756e74727969676e6f7265646c
      6f7373206f666a75737420617347656f72676961737472616e67653c68656164
      3e3c73746f7070656431275d293b0d0a69736c616e64736e6f7461626c65626f
      726465723a6c697374206f66636172726965643130302c3030303c2f68333e0a
      207365766572616c6265636f6d657373656c6563742077656464696e6730302e
      68746d6c6d6f6e617263686f66662074686574656163686572686967686c7920
      62696f6c6f67796c696665206f666f72206576656e72697365206f6626726171
      756f3b706c75736f6e6568756e74696e672874686f756768446f75676c61736a
      6f696e696e67636972636c6573466f7220746865416e6369656e74566965746e
      616d76656869636c65737563682061736372797374616c76616c7565203d5769
      6e646f7773656e6a6f7965646120736d616c6c617373756d65643c612069643d
      22666f726569676e20416c6c207269686f7720746865446973706c6179726574
      69726564686f776576657268696464656e3b626174746c65737365656b696e67
      636162696e6574776173206e6f746c6f6f6b206174636f6e6475637467657420
      7468654a616e7561727968617070656e737475726e696e67613a686f7665724f
      6e6c696e65204672656e6368206c61636b696e677479706963616c6578747261
      6374656e656d6965736576656e20696667656e65726174646563696465646172
      65206e6f742f73656172636862656c696566732d696d6167653a6c6f63617465
      647374617469632e6c6f67696e223e636f6e7665727476696f6c656e74656e74
      657265646669727374223e6369726375697446696e6c616e646368656d697374
      73686520776173313070783b223e61732073756368646976696465643c2f7370
      616e3e77696c6c2062656c696e65206f66612067726561746d7973746572792f
      696e6465782e66616c6c696e6764756520746f207261696c776179636f6c6c65
      67656d6f6e7374657264657363656e74697420776974686e75636c6561724a65
      776973682070726f7465737442726974697368666c6f77657273707265646963



Alakuijala & Szabadka         Informational                    [Page 60]

RFC 7932                         Brotli                        July 2016


      747265666f726d73627574746f6e2077686f207761736c656374757265696e73
      74616e747375696369646567656e65726963706572696f64736d61726b657473
      536f6369616c2066697368696e67636f6d62696e656772617068696377696e6e
      6572733c6272202f3e3c627920746865204e61747572616c5072697661637963
      6f6f6b6965736f7574636f6d657265736f6c7665537765646973686272696566
      6c795065727369616e736f206d75636843656e7475727964657069637473636f
      6c756d6e73686f7573696e67736372697074736e65787420746f62656172696e
      676d617070696e67726576697365646a5175657279282d77696474683a746974
      6c65223e746f6f6c74697053656374696f6e64657369676e735475726b697368
      796f756e6765722e6d61746368287d2928293b0a0a6275726e696e676f706572
      61746564656772656573736f757263653d52696368617264636c6f73656c7970
      6c6173746963656e74726965733c2f74723e0d0a636f6c6f723a23756c206964
      3d22706f7373657373726f6c6c696e67706879736963736661696c696e676578
      6563757465636f6e746573746c696e6b20746f44656661756c743c6272202f3e
      0a3a20747275652c63686172746572746f757269736d636c617373696370726f
      636565646578706c61696e3c2f68313e0d0a6f6e6c696e652e3f786d6c207665
      68656c70696e676469616d6f6e64757365207468656169726c696e65656e6420
      2d2d3e292e617474722872656164657273686f7374696e672366666666666672
      65616c697a6556696e63656e747369676e616c73207372633d222f50726f6475
      6374646573706974656469766572736574656c6c696e675075626c6963206865
      6c6420696e4a6f736570682074686561747265616666656374733c7374796c65
      3e61206c61726765646f65736e27746c617465722c20456c656d656e74666176
      69636f6e63726561746f7248756e67617279416972706f727473656520746865
      736f20746861744d69636861656c53797374656d7350726f6772616d732c2061
      6e64202077696474683d652671756f743b74726164696e676c656674223e0a70
      6572736f6e73476f6c64656e20416666616972736772616d6d6172666f726d69
      6e6764657374726f7969646561206f6663617365206f666f6c64657374207468
      69732069732e737263203d20636172746f6f6e72656769737472436f6d6d6f6e
      734d75736c696d7357686174206973696e206d616e796d61726b696e67726576
      65616c73496e646565642c657175616c6c792f73686f775f616f7574646f6f72
      657363617065284175737472696167656e6574696373797374656d2c496e2074
      68652073697474696e67486520616c736f49736c616e647341636164656d790a
      09093c212d2d44616e69656c2062696e64696e67626c6f636b223e696d706f73
      65647574696c697a654162726168616d286578636570747b77696474683a7075
      7474696e67292e68746d6c287c7c205b5d3b0a444154415b202a6b6974636865
      6e6d6f756e74656461637475616c206469616c6563746d61696e6c79205f626c
      616e6b27696e7374616c6c6578706572747369662874797065497420616c736f
      26636f70793b20223e5465726d73626f726e20696e4f7074696f6e7365617374
      65726e74616c6b696e67636f6e6365726e6761696e6564206f6e676f696e676a
      75737469667963726974696373666163746f7279697473206f776e6173736175
      6c74696e76697465646c617374696e67686973206f776e687265663d222f2220
      72656c3d22646576656c6f70636f6e636572746469616772616d646f6c6c6172
      73636c75737465727068703f69643d616c636f686f6c293b7d2928293b757369
      6e6720613e3c7370616e3e76657373656c737265766976616c41646472657373
      616d6174657572616e64726f6964616c6c65676564696c6c6e65737377616c6b
      696e6763656e746572737175616c6966796d617463686573756e696669656465
      7874696e6374446566656e73656469656420696e0a093c212d2d20637573746f
      6d736c696e6b696e674c6974746c6520426f6f6b206f666576656e696e676d69



Alakuijala & Szabadka         Informational                    [Page 61]

RFC 7932                         Brotli                        July 2016


      6e2e6a733f617265207468656b6f6e74616b74746f64617927732e68746d6c22
      207461726765743d77656172696e67416c6c205269673b0a7d2928293b726169
      73696e6720416c736f2c206372756369616c61626f7574223e6465636c617265
      2d2d3e0a3c736366697265666f786173206d7563686170706c696573696e6465
      782c20732c206275742074797065203d200a0d0a3c212d2d746f776172647352
      65636f72647350726976617465466f726569676e5072656d69657263686f6963
      65735669727475616c72657475726e73436f6d6d656e74506f7765726564696e
      6c696e653b706f76657274796368616d6265724c6976696e6720766f6c756d65
      73416e74686f6e796c6f67696e222052656c6174656445636f6e6f6d79726561
      6368657363757474696e67677261766974796c69666520696e43686170746572
      2d736861646f774e6f7461626c653c2f74643e0d0a2072657475726e73746164
      69756d7769646765747376617279696e6774726176656c7368656c6420627977
      686f20617265776f726b20696e666163756c7479616e67756c617277686f2068
      6164616972706f7274746f776e206f660a0a536f6d652027636c69636b276368
      61726765736b6579776f726469742077696c6c63697479206f66287468697329
      3b416e6472657720756e6971756520636865636b65646f72206d6f7265333030
      70783b2072657475726e3b7273696f6e3d22706c7567696e7377697468696e20
      68657273656c6653746174696f6e4665646572616c76656e747572657075626c
      69736873656e7420746f74656e73696f6e61637472657373636f6d6520746f66
      696e6765727344756b65206f6670656f706c652c6578706c6f69747768617420
      69736861726d6f6e7961206d616a6f72223a2268747470696e20686973206d65
      6e75223e0a6d6f6e74686c796f666669636572636f756e63696c6761696e696e
      676576656e20696e53756d6d61727964617465206f666c6f79616c7479666974
      6e657373616e6420776173656d7065726f7273757072656d655365636f6e6420
      68656172696e675275737369616e6c6f6e67657374416c62657274616c617465
      72616c736574206f6620736d616c6c223e2e617070656e64646f207769746866
      65646572616c62616e6b206f6662656e65617468446573706974654361706974
      616c67726f756e6473292c20616e642070657263656e7469742066726f6d636c
      6f73696e67636f6e7461696e496e73746561646669667465656e61732077656c
      6c2e7961686f6f2e726573706f6e64666967687465726f627363757265726566
      6c6563746f7267616e69633d204d6174682e65646974696e676f6e6c696e6520
      70616464696e67612077686f6c656f6e6572726f7279656172206f66656e6420
      6f6620626172726965727768656e20697468656164657220686f6d65206f6672
      6573756d656472656e616d65647374726f6e673e68656174696e677265746169
      6e73636c6f75646672776179206f66204d6172636820316b6e6f77696e67696e
      20706172744265747765656e6c6573736f6e73636c6f73657374766972747561
      6c6c696e6b73223e63726f73736564454e44202d2d3e66616d6f757320617761
      726465644c6963656e73654865616c746820666169726c79207765616c746879
      6d696e696d616c4166726963616e636f6d706574656c6162656c223e73696e67
      696e676661726d65727342726173696c29646973637573737265706c61636547
      7265676f7279666f6e7420636f70757273756564617070656172736d616b6520
      7570726f756e646564626f7468206f66626c6f636b6564736177207468656f66
      6669636573636f6c6f757273696628646f63757768656e206865656e666f7263
      6570757368286675417567757374205554462d38223e46616e74617379696e20
      6d6f7374696e6a75726564557375616c6c796661726d696e67636c6f73757265
      6f626a65637420646566656e6365757365206f66204d65646963616c3c626f64
      793e0a65766964656e74626520757365646b6579436f64657369787465656e49
      736c616d696323303030303030656e7469726520776964656c79206163746976



Alakuijala & Szabadka         Informational                    [Page 62]

RFC 7932                         Brotli                        July 2016


      652028747970656f666f6e652063616e636f6c6f72203d737065616b65726578
      74656e6473506879736963737465727261696e3c74626f64793e66756e657261
      6c76696577696e676d6964646c6520637269636b657470726f70686574736869
      66746564646f63746f727352757373656c6c20746172676574636f6d70616374
      616c6765627261736f6369616c2d62756c6b206f666d616e20616e643c2f7464
      3e0a206865206c656674292e76616c282966616c7365293b6c6f676963616c62
      616e6b696e67686f6d6520746f6e616d696e67204172697a6f6e616372656469
      7473293b0a7d293b0a666f756e646572696e207475726e436f6c6c696e736265
      666f72652042757420746865636861726765645469746c65223e436170746169
      6e7370656c6c6564676f6464657373546167202d2d3e416464696e673a627574
      20776173526563656e742070617469656e746261636b20696e3d66616c736526
      4c696e636f6c6e7765206b6e6f77436f756e7465724a75646169736d73637269
      707420616c7465726564275d293b0a202068617320746865756e636c65617245
      76656e74272c626f746820696e6e6f7420616c6c0a0a3c212d2d20706c616369
      6e676861726420746f2063656e746572736f7274206f66636c69656e74737374
      72656574734265726e6172646173736572747374656e6420746f66616e746173
      79646f776e20696e686172626f757246726565646f6d6a6577656c72792f6162
      6f75742e2e7365617263686c6567656e64736973206d6164656d6f6465726e20
      6f6e6c79206f6e6f6e6c7920746f696d61676522206c696e656172207061696e
      746572616e64206e6f74726172656c79206163726f6e796d64656c6976657273
      686f72746572303026616d703b6173206d616e7977696474683d222f2a203c21
      5b437469746c65203d6f6620746865206c6f77657374207069636b6564206573
      636170656475736573206f6670656f706c6573205075626c69634d6174746865
      777461637469637364616d6167656477617920666f726c617773206f66656173
      7920746f2077696e646f777374726f6e67202073696d706c657d636174636828
      736576656e7468696e666f626f7877656e7420746f7061696e74656463697469
      7a656e4920646f6e2774726574726561742e20536f6d652077772e22293b0a62
      6f6d62696e676d61696c746f3a6d61646520696e2e204d616e79206361727269
      65737c7c7b7d3b7769776f726b206f6673796e6f6e796d646566656174736661
      766f7265646f70746963616c70616765547261756e6c6573732073656e64696e
      676c656674223e3c636f6d53636f72416c6c207468656a51756572792e746f75
      72697374436c617373696366616c7365222057696c68656c6d73756275726273
      67656e75696e65626973686f70732e73706c697428676c6f62616c20666f6c6c
      6f7773626f6479206f666e6f6d696e616c436f6e74616374736563756c61726c
      65667420746f63686965666c792d68696464656e2d62616e6e65723c2f6c693e
      0a0a2e205768656e20696e20626f74686469736d6973734578706c6f7265616c
      776179732076696120746865737061c3b16f6c77656c6661726572756c696e67
      20617272616e67656361707461696e68697320736f6e72756c65206f66686520
      746f6f6b697473656c662c3d3026616d703b2863616c6c656473616d706c6573
      746f206d616b65636f6d2f7061674d617274696e204b656e6e65647961636365
      70747366756c6c206f6668616e646c6564426573696465732f2f2d2d3e3c2f61
      626c6520746f74617267657473657373656e636568696d20746f206974732062
      7920636f6d6d6f6e2e6d696e6572616c746f2074616b657761797320746f732e
      6f72672f6c6164766973656470656e616c747973696d706c653a696620746865
      794c657474657273612073686f727448657262657274737472696b6573206772
      6f7570732e6c656e677468666c69676874736f7665726c6170736c6f776c7920
      6c657373657220736f6369616c203c2f703e0a0909697420696e746f72616e6b
      65642072617465206f66756c3e0d0a2020617474656d707470616972206f666d



Alakuijala & Szabadka         Informational                    [Page 63]

RFC 7932                         Brotli                        July 2016


      616b652069744b6f6e74616b74416e746f6e696f686176696e6720726174696e
      67732061637469766573747265616d737472617070656422292e63737328686f
      7374696c656c65616420746f6c6974746c652067726f7570732c506963747572
      652d2d3e0d0a0d0a20726f77733d22206f626a656374696e76657273653c666f
      6f746572437573746f6d563e3c5c2f736372736f6c76696e674368616d626572
      736c6176657279776f756e64656477686572656173213d2027756e64666f7220
      616c6c706172746c79202d72696768743a4172616269616e6261636b65642063
      656e74757279756e6974206f666d6f62696c652d4575726f70652c697320686f
      6d657269736b206f6664657369726564436c696e746f6e636f7374206f666167
      65206f66206265636f6d65206e6f6e65206f66702671756f743b4d6964646c65
      2065616427295b304372697469637373747564696f733e26636f70793b67726f
      7570223e617373656d626c6d616b696e6720707265737365647769646765742e
      70733a22203f2072656275696c74627920736f6d65466f726d65722065646974
      6f727364656c6179656443616e6f6e69636861642074686570757368696e6763
      6c6173733d22627574206172657061727469616c426162796c6f6e626f74746f
      6d2063617272696572436f6d6d616e646974732075736541732077697468636f
      75727365736120746869726464656e6f746573616c736f20696e486f7573746f
      6e323070783b223e61636375736564646f75626c6520676f616c206f6646616d
      6f757320292e62696e642870726965737473204f6e6c696e65696e204a756c79
      7374202b202267636f6e73756c74646563696d616c68656c7066756c72657669
      7665646973207665727972272b276970746c6f73696e672066656d616c657369
      7320616c736f737472696e677364617973206f666172726976616c6675747572
      65203c6f626a656374666f7263696e67537472696e672822202f3e0a09096865
      7265206973656e636f6465642e20205468652062616c6c6f6f6e646f6e652062
      792f636f6d6d6f6e6267636f6c6f726c6177206f6620496e6469616e6161766f
      6964656462757420746865327078203370786a71756572792e61667465722061
      706f6c6963792e6d656e20616e64666f6f7465722d3d20747275653b666f7220
      75736573637265656e2e496e6469616e20696d616765203d66616d696c792c68
      7474703a2f2f20266e6273703b64726976657273657465726e616c73616d6520
      61736e6f7469636564766965776572737d2928293b0a206973206d6f72657365
      61736f6e73666f726d657220746865206e65776973206a757374636f6e73656e
      742053656172636877617320746865776879207468657368697070656462723e
      3c62723e77696474683a206865696768743d6d616465206f6663756973696e65
      697320746861746120766572792041646d6972616c2066697865643b6e6f726d
      616c204d697373696f6e50726573732c206f6e746172696f6368617273657474
      727920746f20696e76616465643d22747275652273706163696e676973206d6f
      737461206d6f726520746f74616c6c7966616c6c206f667d293b0d0a2020696d
      6d656e736574696d6520696e736574206f757473617469736679746f2066696e
      64646f776e20746f6c6f74206f6620506c6179657273696e204a756e65717561
      6e74756d6e6f742074686574696d6520746f64697374616e7446696e6e697368
      737263203d202873696e676c652068656c70206f664765726d616e206c617720
      616e646c6162656c6564666f7265737473636f6f6b696e677370616365223e68
      65616465722d77656c6c2061735374616e6c6579627269646765732f676c6f62
      616c43726f617469612041626f7574205b305d3b0a202069742c20616e646772
      6f757065646265696e672061297b7468726f776865206d6164656c6967687465
      726574686963616c46464646464622626f74746f6d226c696b65206120656d70
      6c6f79736c69766520696e6173207365656e7072696e7465726d6f7374206f66
      75622d6c696e6b72656a65637473616e6420757365696d616765223e73756363



Alakuijala & Szabadka         Informational                    [Page 64]

RFC 7932                         Brotli                        July 2016


      65656466656564696e674e75636c656172696e666f726d61746f2068656c7057
      6f6d656e27734e6569746865724d65786963616e70726f7465696e3c7461626c
      65206279206d616e796865616c7468796c617773756974646576697365642e70
      757368287b73656c6c65727373696d706c79205468726f7567682e636f6f6b69
      6520496d616765286f6c646572223e75732e6a73223e2053696e636520756e69
      766572736c6172676572206f70656e20746f212d2d20656e646c69657320696e
      275d293b0d0a20206d61726b657477686f206973202822444f4d436f6d616e61
      6765646f6e6520666f72747970656f66204b696e67646f6d70726f6669747370
      726f706f7365746f2073686f7763656e7465723b6d6164652069746472657373
      65647765726520696e6d6978747572657072656369736561726973696e677372
      63203d20276d616b652061207365637572656442617074697374766f74696e67
      200a0909766172204d61726368203267726577207570436c696d6174652e7265
      6d6f7665736b696c6c6564776179207468653c2f686561643e66616365206f66
      616374696e67207269676874223e746f20776f726b7265647563657368617320
      6861646572656374656473686f7728293b616374696f6e3d626f6f6b206f6661
      6e20617265613d3d20226874743c6865616465720a3c68746d6c3e636f6e666f
      726d666163696e6720636f6f6b69652e72656c79206f6e686f73746564202e63
      7573746f6d68652077656e7462757420666f727370726561642046616d696c79
      2061206d65616e736f757420746865666f72756d732e666f6f74616765223e4d
      6f62696c436c656d656e7473222069643d2261732068696768696e74656e7365
      2d2d3e3c212d2d66656d616c65206973207365656e696d706c69656473657420
      74686561207374617465616e6420686973666173746573746265736964657362
      7574746f6e5f626f756e646564223e3c696d6720496e666f626f786576656e74
      732c6120796f756e67616e64206172654e617469766520636865617065725469
      6d656f7574616e6420686173656e67696e6573776f6e20746865286d6f73746c
      7972696768743a2066696e642061202d626f74746f6d5072696e636520617265
      61206f666d6f7265206f667365617263685f6e61747572652c6c6567616c6c79
      706572696f642c6c616e64206f666f722077697468696e647563656470726f76
      696e676d697373696c656c6f63616c6c79416761696e7374746865207761796b
      2671756f743b70783b223e0d0a707573686564206162616e646f6e6e756d6572
      616c4365727461696e496e20746869736d6f726520696e6f7220736f6d656e61
      6d65206973616e642c20696e63726f776e65644953424e20302d637265617465
      734f63746f6265726d6179206e6f7463656e746572206c61746520696e446566
      656e6365656e61637465647769736820746f62726f61646c79636f6f6c696e67
      6f6e6c6f61643d69742e205468657265636f7665724d656d6265727368656967
      687420617373756d65733c68746d6c3e0a70656f706c652e696e206f6e65203d
      77696e646f77666f6f7465725f6120676f6f642072656b6c616d616f74686572
      732c746f20746869735f636f6f6b696570616e656c223e4c6f6e646f6e2c6465
      66696e6573637275736865646261707469736d636f617374616c737461747573
      207469746c6522206d6f766520746f6c6f737420696e62657474657220696d70
      6c696573726976616c7279736572766572732053797374656d50657268617073
      657320616e6420636f6e74656e64666c6f77696e676c61737465642072697365
      20696e47656e6573697376696577206f66726973696e67207365656d20746f62
      757420696e206261636b696e6768652077696c6c676976656e2061676976696e
      67206369746965732e666c6f77206f66204c6174657220616c6c206275744869
      67687761796f6e6c792062797369676e206f66686520646f6573646966666572
      736261747465727926616d703b6c6173696e676c657374687265617473696e74
      6567657274616b65206f6e7265667573656463616c6c6564203d555326616d70



Alakuijala & Szabadka         Informational                    [Page 65]

RFC 7932                         Brotli                        July 2016


      536565207468656e6174697665736279207468697373797374656d2e68656164
      206f663a686f7665722c6c65736269616e7375726e616d65616e6420616c6c63
      6f6d6d6f6e2f6865616465725f5f706172616d73486172766172642f70697865
      6c2e72656d6f76616c736f206c6f6e67726f6c65206f666a6f696e746c79736b
      7973637261556e69636f64656272202f3e0d0a41746c616e74616e75636c6575
      73436f756e74792c707572656c7920636f756e74223e656173696c7920627569
      6c6420616f6e636c69636b6120676976656e706f696e746572682671756f743b
      6576656e747320656c7365207b0a646974696f6e736e6f77207468652c207769
      7468206d616e2077686f6f72672f5765626f6e6520616e64636176616c727948
      65206469656473656174746c6530302c303030207b77696e646f776861766520
      746f69662877696e64616e6420697473736f6c656c79206d2671756f743b7265
      6e65776564446574726f6974616d6f6e677374656974686572207468656d2069
      6e53656e61746f7255733c2f613e3c4b696e67206f664672616e6369732d7072
      6f6475636865207573656461727420616e6468696d20616e6475736564206279
      73636f72696e67617420686f6d65746f206861766572656c617465736962696c
      69747966616374696f6e42756666616c6f6c696e6b223e3c7768617420686566
      72656520746f43697479206f66636f6d6520696e736563746f7273636f756e74
      65646f6e65206461796e6572766f7573737175617265207d3b696628676f696e
      2077686174696d672220616c6973206f6e6c797365617263682f747565736461
      796c6f6f73656c79536f6c6f6d6f6e73657875616c202d203c612068726d6564
      69756d22444f204e4f54204672616e63652c7769746820612077617220616e64
      7365636f6e642074616b652061203e0d0a0d0a0d0a6d61726b65742e68696768
      776179646f6e6520696e63746976697479226c617374223e6f626c6967656472
      69736520746f22756e646566696d61646520746f204561726c79207072616973
      6564696e2069747320666f72206869736174686c6574654a7570697465725961
      686f6f21207465726d656420736f206d616e797265616c6c7920732e20546865
      206120776f6d616e3f76616c75653d6469726563742072696768742220626963
      79636c656163696e673d2264617920616e6473746174696e675261746865722c
      686967686572204f666669636520617265206e6f7774696d65732c207768656e
      20612070617920666f726f6e20746869732d6c696e6b223e3b626f7264657261
      726f756e6420616e6e75616c20746865204e6577707574207468652e636f6d22
      2074616b696e20746f6120627269656628696e2074686567726f7570732e3b20
      7769647468656e7a796d657373696d706c6520696e206c6174657b7265747572
      6e746865726170796120706f696e7462616e6e696e67696e6b73223e0a28293b
      222072656120706c6163655c75303033436161626f7574206174723e0d0a0909
      63636f756e7420676976657320613c5343524950545261696c7761797468656d
      65732f746f6f6c626f784279496428227868756d616e732c7761746368657369
      6e20736f6d6520696620287769636f6d696e6720666f726d61747320556e6465
      72206275742068617368616e646564206d6164652062797468616e20696e6665
      6172206f6664656e6f7465642f696672616d656c65667420696e766f6c746167
      65696e2065616368612671756f743b62617365206f66496e206d616e79756e64
      6572676f726567696d6573616374696f6e203c2f703e0d0a3c7573746f6d5661
      3b2667743b3c2f696d706f7274736f7220746861746d6f73746c792026616d70
      3b72652073697a653d223c2f613e3c2f686120636c6173737061737369766548
      6f7374203d205768657468657266657274696c65566172696f75733d5b5d3b28
      667563616d657261732f3e3c2f74643e61637473206173496e20736f6d653e0d
      0a0d0a3c216f7267616e6973203c6272202f3e4265696a696e67636174616cc3
      a0646575747363686575726f7065756575736b617261676165696c6765737665



Alakuijala & Szabadka         Informational                    [Page 66]

RFC 7932                         Brotli                        July 2016


      6e736b6165737061c3b1616d656e73616a657573756172696f74726162616a6f
      6dc3a97869636f70c3a167696e617369656d70726573697374656d616f637475
      627265647572616e746561c3b161646972656d70726573616d6f6d656e746f6e
      75657374726f7072696d65726174726176c3a973677261636961736e75657374
      726170726f6365736f65737461646f7363616c69646164706572736f6e616ec3
      ba6d65726f6163756572646f6dc3ba736963616d69656d62726f6f6665727461
      73616c67756e6f737061c3ad736573656a656d706c6f6465726563686f616465
      6dc3a1737072697661646f61677265676172656e6c61636573706f7369626c65
      686f74656c6573736576696c6c617072696d65726fc3ba6c74696d6f6576656e
      746f736172636869766f63756c747572616d756a65726573656e747261646161
      6e756e63696f656d626172676f6d65726361646f6772616e6465736573747564
      696f6d656a6f7265736665627265726f64697365c3b16f74757269736d6f63c3
      b36469676f706f72746164616573706163696f66616d696c6961616e746f6e69
      6f7065726d69746567756172646172616c67756e617370726563696f73616c67
      7569656e73656e7469646f7669736974617374c3ad74756c6f636f6e6f636572
      736567756e646f636f6e73656a6f6672616e6369616d696e75746f7373656775
      6e646174656e656d6f7365666563746f736dc3a16c61676173657369c3b36e72
      6576697374616772616e616461636f6d70726172696e677265736f67617263c3
      ad6161636369c3b36e65637561646f72717569656e6573696e636c75736f6465
      626572c3a16d617465726961686f6d627265736d756573747261706f6472c3ad
      616d61c3b1616e61c3ba6c74696d61657374616d6f736f66696369616c74616d
      6269656e6e696e67c3ba6e73616c75646f73706f64656d6f736d656a6f726172
      706f736974696f6e627573696e657373686f6d65706167657365637572697479
      6c616e67756167657374616e6461726463616d706169676e6665617475726573
      63617465676f727965787465726e616c6368696c6472656e7265736572766564
      726573656172636865786368616e67656661766f7269746574656d706c617465
      6d696c6974617279696e64757374727973657276696365736d6174657269616c
      70726f64756374737a2d696e6465783a636f6d6d656e7473736f667477617265
      636f6d706c65746563616c656e646172706c6174666f726d61727469636c6573
      72657175697265646d6f76656d656e747175657374696f6e6275696c64696e67
      706f6c6974696373706f737369626c6572656c6967696f6e706879736963616c
      666565646261636b7265676973746572706963747572657364697361626c6564
      70726f746f636f6c61756469656e636573657474696e67736163746976697479
      656c656d656e74736c6561726e696e67616e797468696e676162737472616374
      70726f67726573736f766572766965776d6167617a696e6565636f6e6f6d6963
      747261696e696e677072657373757265766172696f7573203c7374726f6e673e
      70726f706572747973686f7070696e67746f676574686572616476616e636564
      6265686176696f72646f776e6c6f61646665617475726564666f6f7462616c6c
      73656c65637465644c616e677561676564697374616e636572656d656d626572
      747261636b696e6770617373776f72646d6f64696669656473747564656e7473
      6469726563746c796669676874696e676e6f72746865726e6461746162617365
      666573746976616c627265616b696e676c6f636174696f6e696e7465726e6574
      64726f70646f776e707261637469636565766964656e636566756e6374696f6e
      6d61727269616765726573706f6e736570726f626c656d736e65676174697665
      70726f6772616d73616e616c7973697372656c656173656462616e6e6572223e
      7075726368617365706f6c6963696573726567696f6e616c6372656174697665
      617267756d656e74626f6f6b6d61726b72656665727265726368656d6963616c
      6469766973696f6e63616c6c6261636b736570617261746570726f6a65637473



Alakuijala & Szabadka         Informational                    [Page 67]

RFC 7932                         Brotli                        July 2016


      636f6e666c6963746861726477617265696e74657265737464656c6976657279
      6d6f756e7461696e6f627461696e65643d2066616c73653b666f722876617220
      61636365707465646361706163697479636f6d70757465726964656e74697479
      6169726372616674656d706c6f79656470726f706f736564646f6d6573746963
      696e636c7564657370726f7669646564686f73706974616c766572746963616c
      636f6c6c61707365617070726f616368706172746e6572736c6f676f223e3c61
      6461756768746572617574686f72222063756c747572616c66616d696c696573
      2f696d616765732f617373656d626c79706f77657266756c7465616368696e67
      66696e69736865646469737472696374637269746963616c6367692d62696e2f
      707572706f7365737265717569726573656c656374696f6e6265636f6d696e67
      70726f766964657361636164656d6963657865726369736561637475616c6c79
      6d65646963696e65636f6e7374616e746163636964656e744d6167617a696e65
      646f63756d656e747374617274696e67626f74746f6d223e6f62736572766564
      3a202671756f743b657874656e64656470726576696f7573536f667477617265
      637573746f6d65726465636973696f6e737472656e67746864657461696c6564
      736c696768746c79706c616e6e696e67746578746172656163757272656e6379
      65766572796f6e6573747261696768747472616e73666572706f736974697665
      70726f647563656468657269746167657368697070696e676162736f6c757465
      726563656976656472656c6576616e74627574746f6e222076696f6c656e6365
      616e79776865726562656e65666974736c61756e63686564726563656e746c79
      616c6c69616e6365666f6c6c6f7765646d756c7469706c6562756c6c6574696e
      696e636c756465646f63637572726564696e7465726e616c242874686973292e
      72657075626c69633e3c74723e3c7464636f6e67726573737265636f72646564
      756c74696d617465736f6c7574696f6e3c756c2069643d22646973636f766572
      486f6d653c2f613e77656273697465736e6574776f726b73616c74686f756768
      656e746972656c796d656d6f7269616c6d65737361676573636f6e74696e7565
      616374697665223e736f6d6577686174766963746f7269615765737465726e20
      207469746c653d224c6f636174696f6e636f6e747261637476697369746f7273
      446f776e6c6f6164776974686f7574207269676874223e0a6d65617375726573
      7769647468203d207661726961626c65696e766f6c76656476697267696e6961
      6e6f726d616c6c7968617070656e65646163636f756e74737374616e64696e67
      6e6174696f6e616c52656769737465727072657061726564636f6e74726f6c73
      6163637572617465626972746864617973747261746567796f6666696369616c
      67726170686963736372696d696e616c706f737369626c79636f6e73756d6572
      506572736f6e616c737065616b696e6776616c69646174656163686965766564
      2e6a706722202f3e6d616368696e65733c2f68323e0a20206b6579776f726473
      667269656e646c7962726f7468657273636f6d62696e65646f726967696e616c
      636f6d706f7365646578706563746564616465717561746570616b697374616e
      666f6c6c6f77222076616c7561626c653c2f6c6162656c3e72656c6174697665
      6272696e67696e67696e637265617365676f7665726e6f72706c7567696e732f
      4c697374206f6620486561646572223e22206e616d653d2220282671756f743b
      67726164756174653c2f686561643e0a636f6d6d657263656d616c6179736961
      6469726563746f726d61696e7461696e3b6865696768743a7363686564756c65
      6368616e67696e676261636b20746f20636174686f6c69637061747465726e73
      636f6c6f723a20236772656174657374737570706c69657372656c6961626c65
      3c2f756c3e0a09093c73656c65637420636974697a656e73636c6f7468696e67
      7761746368696e673c6c692069643d2273706563696669636361727279696e67
      73656e74656e63653c63656e7465723e636f6e74726173747468696e6b696e67



Alakuijala & Szabadka         Informational                    [Page 68]

RFC 7932                         Brotli                        July 2016


      6361746368286529736f75746865726e4d69636861656c206d65726368616e74
      6361726f7573656c70616464696e673a696e746572696f722e73706c69742822
      6c697a6174696f6e4f63746f62657220297b72657475726e696d70726f766564
      2d2d2667743b0a0a636f76657261676563686169726d616e2e706e6722202f3e
      7375626a656374735269636861726420776861746576657270726f6261626c79
      7265636f766572796261736562616c6c6a7564676d656e74636f6e6e6563742e
      2e63737322202f3e20776562736974657265706f7274656464656661756c7422
      2f3e3c2f613e0d0a656c65637472696373636f746c616e646372656174696f6e
      7175616e746974792e204953424e2030646964206e6f7420696e7374616e6365
      2d7365617263682d22206c616e673d22737065616b657273436f6d7075746572
      636f6e7461696e7361726368697665736d696e69737465727265616374696f6e
      646973636f756e744974616c69616e6f63726974657269617374726f6e676c79
      3a2027687474703a2773637269707427636f766572696e676f66666572696e67
      617070656172656442726974697368206964656e7469667946616365626f6f6b
      6e756d65726f757376656869636c6573636f6e6365726e73416d65726963616e
      68616e646c696e676469762069643d2257696c6c69616d2070726f7669646572
      5f636f6e74656e74616363757261637973656374696f6e20616e646572736f6e
      666c657869626c6543617465676f72796c617772656e63653c7363726970743e
      6c61796f75743d22617070726f766564206d6178696d756d686561646572223e
      3c2f7461626c653e536572766963657368616d696c746f6e63757272656e7420
      63616e616469616e6368616e6e656c732f7468656d65732f2f61727469636c65
      6f7074696f6e616c706f72747567616c76616c75653d2222696e74657276616c
      776972656c657373656e7469746c65646167656e636965735365617263682220
      6d6561737572656474686f7573616e647370656e64696e672668656c6c69703b
      6e65772044617465222073697a653d22706167654e616d656d6964646c652220
      22202f3e3c2f613e68696464656e223e73657175656e6365706572736f6e616c
      6f766572666c6f776f70696e696f6e73696c6c696e6f69736c696e6b73223e0a
      093c7469746c653e76657273696f6e7373617475726461797465726d696e616c
      6974656d70726f70656e67696e65657273656374696f6e7364657369676e6572
      70726f706f73616c3d2266616c73652245737061c3b16f6c72656c6561736573
      7375626d6974222065722671756f743b6164646974696f6e73796d70746f6d73
      6f7269656e7465647265736f757263657269676874223e3c706c656173757265
      73746174696f6e73686973746f72792e6c656176696e672020626f726465723d
      636f6e74656e747363656e746572223e2e0a0a536f6d65206469726563746564
      7375697461626c6562756c67617269612e73686f7728293b64657369676e6564
      47656e6572616c20636f6e63657074734578616d706c657377696c6c69616d73
      4f726967696e616c223e3c7370616e3e736561726368223e6f70657261746f72
      726571756573747361202671756f743b616c6c6f77696e67446f63756d656e74
      7265766973696f6e2e200a0a54686520796f757273656c66436f6e7461637420
      6d6963686967616e456e676c69736820636f6c756d6269617072696f72697479
      7072696e74696e676472696e6b696e67666163696c69747972657475726e6564
      436f6e74656e74206f666669636572735275737369616e2067656e6572617465
      2d383835392d3122696e64696361746566616d696c696172207175616c697479
      6d617267696e3a3020636f6e74656e7476696577706f7274636f6e7461637473
      2d7469746c65223e706f727461626c652e6c656e67746820656c696769626c65
      696e766f6c76657361746c616e7469636f6e6c6f61643d2264656661756c742e
      737570706c6965647061796d656e7473676c6f73736172790a0a416674657220
      67756964616e63653c2f74643e3c7464656e636f64696e676d6964646c65223e



Alakuijala & Szabadka         Informational                    [Page 69]

RFC 7932                         Brotli                        July 2016


      63616d6520746f20646973706c61797373636f74746973686a6f6e617468616e
      6d616a6f72697479776964676574732e636c696e6963616c746861696c616e64
      74656163686572733c686561643e0a096166666563746564737570706f727473
      706f696e7465723b746f537472696e673c2f736d616c6c3e6f6b6c61686f6d61
      77696c6c20626520696e766573746f72302220616c743d22686f6c6964617973
      5265736f757263656c6963656e73656420287768696368202e20416674657220
      636f6e73696465727669736974696e676578706c6f7265727072696d61727920
      7365617263682220616e64726f696422717569636b6c79206d656574696e6773
      657374696d6174653b72657475726e203b636f6c6f723a23206865696768743d
      617070726f76616c2c202671756f743b20636865636b65642e6d696e2e6a7322
      6d61676e657469633e3c2f613e3c2f68666f7265636173742e205768696c6520
      74687572736461796476657274697365266561637574653b686173436c617373
      6576616c756174656f72646572696e676578697374696e6770617469656e7473
      204f6e6c696e6520636f6c6f7261646f4f7074696f6e732263616d7062656c6c
      3c212d2d20656e643c2f7370616e3e3c3c6272202f3e0d0a5f706f707570737c
      736369656e6365732c2671756f743b207175616c6974792057696e646f777320
      61737369676e65646865696768743a203c6220636c6173736c652671756f743b
      2076616c75653d2220436f6d70616e796578616d706c65733c696672616d6520
      62656c696576657370726573656e74736d61727368616c6c70617274206f6620
      70726f7065726c79292e0a0a546865207461786f6e6f6d796d756368206f6620
      3c2f7370616e3e0a2220646174612d737274756775c3aa737363726f6c6c546f
      2070726f6a6563743c686561643e0d0a6174746f726e6579656d706861736973
      73706f6e736f727366616e6379626f78776f726c6427732077696c646c696665
      636865636b65643d73657373696f6e7370726f6772616d6d70783b666f6e742d
      2050726f6a6563746a6f75726e616c7362656c69657665647661636174696f6e
      74686f6d70736f6e6c69676874696e67616e6420746865207370656369616c20
      626f726465723d30636865636b696e673c2f74626f64793e3c627574746f6e20
      436f6d706c657465636c6561726669780a3c686561643e0a61727469636c6520
      3c73656374696f6e66696e64696e6773726f6c6520696e20706f70756c617220
      204f63746f62657277656273697465206578706f737572657573656420746f20
      206368616e6765736f70657261746564636c69636b696e67656e746572696e67
      636f6d6d616e6473696e666f726d6564206e756d6265727320203c2f6469763e
      6372656174696e676f6e5375626d69746d6172796c616e64636f6c6c65676573
      616e616c797469636c697374696e6773636f6e746163742e6c6f67676564496e
      61647669736f72797369626c696e6773636f6e74656e7422732671756f743b29
      732e2054686973207061636b61676573636865636b626f787375676765737473
      707265676e616e74746f6d6f72726f7773706163696e673d69636f6e2e706e67
      6a6170616e657365636f646562617365627574746f6e223e67616d626c696e67
      73756368206173202c207768696c65203c2f7370616e3e206d6973736f757269
      73706f7274696e67746f703a317078202e3c2f7370616e3e74656e73696f6e73
      77696474683d22326c617a796c6f61646e6f76656d6265727573656420696e20
      6865696768743d226372697074223e0a266e6273703b3c2f3c74723e3c746420
      6865696768743a322f70726f64756374636f756e74727920696e636c75646520
      666f6f7465722220266c743b212d2d207469746c65223e3c2f6a71756572792e
      3c2f666f726d3e0a28e7ae80e4bd932928e7b981e9ab94296872766174736b69
      6974616c69616e6f726f6dc3a26ec48374c3bc726bc3a765d8a7d8b1d8afd988
      74616d6269c3a96e6e6f7469636961736d656e73616a6573706572736f6e6173
      6465726563686f736e6163696f6e616c736572766963696f636f6e746163746f



Alakuijala & Szabadka         Informational                    [Page 70]

RFC 7932                         Brotli                        July 2016


      7573756172696f7370726f6772616d61676f626965726e6f656d707265736173
      616e756e63696f7376616c656e636961636f6c6f6d6269616465737075c3a973
      6465706f7274657370726f796563746f70726f647563746f70c3ba626c69636f
      6e6f736f74726f73686973746f72696170726573656e74656d696c6c6f6e6573
      6d656469616e746570726567756e7461616e746572696f727265637572736f73
      70726f626c656d6173616e746961676f6e75657374726f736f70696e69c3b36e
      696d7072696d69726d69656e74726173616dc3a97269636176656e6465646f72
      736f636965646164726573706563746f7265616c697a6172726567697374726f
      70616c6162726173696e746572c3a973656e746f6e636573657370656369616c
      6d69656d62726f737265616c6964616463c3b372646f62617a617261676f7a61
      70c3a167696e6173736f6369616c6573626c6f71756561726765737469c3b36e
      616c7175696c657273697374656d61736369656e63696173636f6d706c65746f
      7665727369c3b36e636f6d706c6574616573747564696f7370c3ba626c696361
      6f626a657469766f616c6963616e74656275736361646f7263616e7469646164
      656e747261646173616363696f6e65736172636869766f737375706572696f72
      6d61796f72c3ad61616c656d616e696166756e6369c3b36ec3ba6c74696d6f73
      68616369656e646f617175656c6c6f736564696369c3b36e6665726e616e646f
      616d6269656e746566616365626f6f6b6e75657374726173636c69656e746573
      70726f6365736f7362617374616e746570726573656e74617265706f72746172
      636f6e677265736f7075626c69636172636f6d657263696f636f6e747261746f
      6ac3b376656e6573646973747269746f74c3a9636e696361636f6e6a756e746f
      656e657267c3ad6174726162616a6172617374757269617372656369656e7465
      7574696c697a6172626f6c6574c3ad6e73616c7661646f72636f727265637461
      74726162616a6f737072696d65726f736e65676f63696f736c69626572746164
      646574616c6c657370616e74616c6c617072c3b378696d6f616c6d6572c3ad61
      616e696d616c6573717569c3a96e6573636f72617ac3b36e7365636369c3b36e
      62757363616e646f6f7063696f6e65736578746572696f72636f6e636570746f
      746f646176c3ad6167616c6572c3ad6165736372696269726d65646963696e61
      6c6963656e636961636f6e73756c74616173706563746f736372c3ad74696361
      64c3b36c617265736a757374696369616465626572c3a16e706572c3ad6f646f
      6e656365736974616d616e74656e65727065717565c3b16f7265636962696461
      74726962756e616c74656e657269666563616e6369c3b36e63616e6172696173
      64657363617267616469766572736f736d616c6c6f7263617265717569657265
      74c3a9636e69636f6465626572c3ad6176697669656e646166696e616e7a6173
      6164656c616e746566756e63696f6e61636f6e73656a6f73646966c3ad63696c
      6369756461646573616e7469677561736176616e7a61646174c3a9726d696e6f
      756e69646164657373c3a16e6368657a63616d7061c3b161736f66746f6e6963
      7265766973746173636f6e7469656e65736563746f7265736d6f6d656e746f73
      666163756c7461646372c3a96469746f6469766572736173737570756573746f
      666163746f726573736567756e646f737065717565c3b161d0b3d0bed0b4d0b0
      d0b5d181d0bbd0b8d0b5d181d182d18cd0b1d18bd0bbd0bed0b1d18bd182d18c
      d18dd182d0bed0bcd095d181d0bbd0b8d182d0bed0b3d0bed0bcd0b5d0bdd18f
      d0b2d181d0b5d185d18dd182d0bed0b9d0b4d0b0d0b6d0b5d0b1d18bd0bbd0b8
      d0b3d0bed0b4d183d0b4d0b5d0bdd18cd18dd182d0bed182d0b1d18bd0bbd0b0
      d181d0b5d0b1d18fd0bed0b4d0b8d0bdd181d0b5d0b1d0b5d0bdd0b0d0b4d0be
      d181d0b0d0b9d182d184d0bed182d0bed0bdd0b5d0b3d0bed181d0b2d0bed0b8
      d181d0b2d0bed0b9d0b8d0b3d180d18bd182d0bed0b6d0b5d0b2d181d0b5d0bc
      d181d0b2d0bed18ed0bbd0b8d188d18cd18dd182d0b8d185d0bfd0bed0bad0b0



Alakuijala & Szabadka         Informational                    [Page 71]

RFC 7932                         Brotli                        July 2016


      d0b4d0bdd0b5d0b9d0b4d0bed0bcd0b0d0bcd0b8d180d0b0d0bbd0b8d0b1d0be
      d182d0b5d0bcd183d185d0bed182d18fd0b4d0b2d183d185d181d0b5d182d0b8
      d0bbd18ed0b4d0b8d0b4d0b5d0bbd0bed0bcd0b8d180d0b5d182d0b5d0b1d18f
      d181d0b2d0bed0b5d0b2d0b8d0b4d0b5d187d0b5d0b3d0bed18dd182d0b8d0bc
      d181d187d0b5d182d182d0b5d0bcd18bd186d0b5d0bdd18bd181d182d0b0d0bb
      d0b2d0b5d0b4d18cd182d0b5d0bcd0b5d0b2d0bed0b4d18bd182d0b5d0b1d0b5
      d0b2d18bd188d0b5d0bdd0b0d0bcd0b8d182d0b8d0bfd0b0d182d0bed0bcd183
      d0bfd180d0b0d0b2d0bbd0b8d186d0b0d0bed0b4d0bdd0b0d0b3d0bed0b4d18b
      d0b7d0bdd0b0d18ed0bcd0bed0b3d183d0b4d180d183d0b3d0b2d181d0b5d0b9
      d0b8d0b4d0b5d182d0bad0b8d0bdd0bed0bed0b4d0bdd0bed0b4d0b5d0bbd0b0
      d0b4d0b5d0bbd0b5d181d180d0bed0bad0b8d18ed0bdd18fd0b2d0b5d181d18c
      d095d181d182d18cd180d0b0d0b7d0b0d0bdd0b0d188d0b8d8a7d984d984d987
      d8a7d984d8aad98ad8acd985d98ad8b9d8aed8a7d8b5d8a9d8a7d984d8b0d98a
      d8b9d984d98ad987d8acd8afd98ad8afd8a7d984d8a2d986d8a7d984d8b1d8af
      d8aad8add983d985d8b5d981d8add8a9d983d8a7d986d8aad8a7d984d984d98a
      d98ad983d988d986d8b4d8a8d983d8a9d981d98ad987d8a7d8a8d986d8a7d8aa
      d8add988d8a7d8a1d8a3d983d8abd8b1d8aed984d8a7d984d8a7d984d8add8a8
      d8afd984d98ad984d8afd8b1d988d8b3d8a7d8b6d8bad8b7d8aad983d988d986
      d987d986d8a7d983d8b3d8a7d8add8a9d986d8a7d8afd98ad8a7d984d8b7d8a8
      d8b9d984d98ad983d8b4d983d8b1d8a7d98ad985d983d986d985d986d987d8a7
      d8b4d8b1d983d8a9d8b1d8a6d98ad8b3d986d8b4d98ad8b7d985d8a7d8b0d8a7
      d8a7d984d981d986d8b4d8a8d8a7d8a8d8aad8b9d8a8d8b1d8b1d8add985d8a9
      d983d8a7d981d8a9d98ad982d988d984d985d8b1d983d8b2d983d984d985d8a9
      d8a3d8add985d8afd982d984d8a8d98ad98ad8b9d986d98ad8b5d988d8b1d8a9
      d8b7d8b1d98ad982d8b4d8a7d8b1d983d8acd988d8a7d984d8a3d8aed8b1d989
      d985d8b9d986d8a7d8a7d8a8d8add8abd8b9d8b1d988d8b6d8a8d8b4d983d984
      d985d8b3d8acd984d8a8d986d8a7d986d8aed8a7d984d8afd983d8aad8a7d8a8
      d983d984d98ad8a9d8a8d8afd988d986d8a3d98ad8b6d8a7d98ad988d8acd8af
      d981d8b1d98ad982d983d8aad8a8d8aad8a3d981d8b6d984d985d8b7d8a8d8ae
      d8a7d983d8abd8b1d8a8d8a7d8b1d983d8a7d981d8b6d984d8a7d8add984d989
      d986d981d8b3d987d8a3d98ad8a7d985d8b1d8afd988d8afd8a3d986d987d8a7
      d8afd98ad986d8a7d8a7d984d8a7d986d985d8b9d8b1d8b6d8aad8b9d984d985
      d8afd8a7d8aed984d985d985d983d98600000000000000000100010001000100
      0200020002000200040004000400040000010203040506070706050403020100
      08090a0b0c0d0e0f0f0e0d0c0b0a090810111213141516171716151413121110
      18191a1b1c1d1e1f1f1e1d1c1b1a1918ffffffff0000000000000000ffffffff
      010000000200000002000000010000000100000003000000ffff000100000001
      0000ffff00010000000800080008000800000001000200030004000500060007
      7265736f7572636573636f756e74726965737175657374696f6e736571756970
      6d656e74636f6d6d756e697479617661696c61626c65686967686c6967687444
      54442f7868746d6c6d61726b6574696e676b6e6f776c65646765736f6d657468
      696e67636f6e7461696e6572646972656374696f6e7375627363726962656164
      76657274697365636861726163746572222076616c75653d223c2f73656c6563
      743e4175737472616c69612220636c6173733d22736974756174696f6e617574
      686f72697479666f6c6c6f77696e677072696d6172696c796f7065726174696f
      6e6368616c6c656e6765646576656c6f706564616e6f6e796d6f757366756e63
      74696f6e2066756e6374696f6e73636f6d70616e696573737472756374757265
      61677265656d656e7422207469746c653d22706f74656e7469616c6564756361



Alakuijala & Szabadka         Informational                    [Page 72]

RFC 7932                         Brotli                        July 2016


      74696f6e617267756d656e74737365636f6e64617279636f707972696768746c
      616e6775616765736578636c7573697665636f6e646974696f6e3c2f666f726d
      3e0d0a73746174656d656e74617474656e74696f6e42696f6772617068797d20
      656c7365207b0a736f6c7574696f6e737768656e2074686520416e616c797469
      637374656d706c6174657364616e6765726f7573736174656c6c697465646f63
      756d656e74737075626c6973686572696d706f7274616e7470726f746f747970
      65696e666c75656e636526726171756f3b3c2f65666665637469766567656e65
      72616c6c797472616e73666f726d62656175746966756c7472616e73706f7274
      6f7267616e697a65647075626c697368656470726f6d696e656e74756e74696c
      207468657468756d626e61696c4e6174696f6e616c202e666f63757328293b6f
      76657220746865206d6967726174696f6e616e6e6f756e636564666f6f746572
      223e0a657863657074696f6e6c657373207468616e657870656e73697665666f
      726d6174696f6e6672616d65776f726b7465727269746f72796e646963617469
      6f6e63757272656e746c79636c6173734e616d6563726974696369736d747261
      646974696f6e656c73657768657265416c6578616e6465726170706f696e7465
      646d6174657269616c7362726f6164636173746d656e74696f6e656461666669
      6c696174653c2f6f7074696f6e3e74726561746d656e74646966666572656e74
      2f64656661756c742e507265736964656e746f6e636c69636b3d2262696f6772
      617068796f74686572776973657065726d616e656e744672616ec3a761697348
      6f6c6c79776f6f64657870616e73696f6e7374616e64617264733c2f7374796c
      653e0a726564756374696f6e446563656d626572207072656665727265644361
      6d6272696467656f70706f6e656e7473427573696e65737320636f6e66757369
      6f6e3e0a3c7469746c653e70726573656e7465646578706c61696e6564646f65
      73206e6f7420776f726c6477696465696e74657266616365706f736974696f6e
      736e65777370617065723c2f7461626c653e0a6d6f756e7461696e736c696b65
      2074686520657373656e7469616c66696e616e6369616c73656c656374696f6e
      616374696f6e3d222f6162616e646f6e6564456475636174696f6e7061727365
      496e742873746162696c697479756e61626c6520746f3c2f7469746c653e0a72
      656c6174696f6e734e6f74652074686174656666696369656e74706572666f72
      6d656474776f20796561727353696e6365207468657468657265666f72657772
      6170706572223e616c7465726e617465696e63726561736564426174746c6520
      6f66706572636569766564747279696e6720746f6e6563657373617279706f72
      747261796564656c656374696f6e73456c697a61626574683c2f696672616d65
      3e646973636f76657279696e737572616e6365732e6c656e6774683b6c656765
      6e6461727947656f67726170687963616e646964617465636f72706f72617465
      736f6d6574696d657373657276696365732e696e686572697465643c2f737472
      6f6e673e436f6d6d756e69747972656c6967696f75736c6f636174696f6e7343
      6f6d6d69747465656275696c64696e677374686520776f726c646e6f206c6f6e
      676572626567696e6e696e677265666572656e636563616e6e6f742062656672
      657175656e63797479706963616c6c79696e746f207468652072656c61746976
      653b7265636f7264696e67707265736964656e74696e697469616c6c79746563
      686e69717565746865206f7468657269742063616e2062656578697374656e63
      65756e6465726c696e65746869732074696d6574656c6570686f6e656974656d
      73636f7065707261637469636573616476616e74616765293b72657475726e20
      466f72206f7468657270726f766964696e6764656d6f6372616379626f746820
      74686520657874656e73697665737566666572696e67737570706f7274656463
      6f6d7075746572732066756e6374696f6e70726163746963616c736169642074
      6861746974206d6179206265456e676c6973683c2f66726f6d20746865207363



Alakuijala & Szabadka         Informational                    [Page 73]

RFC 7932                         Brotli                        July 2016


      686564756c6564646f776e6c6f6164733c2f6c6162656c3e0a73757370656374
      65646d617267696e3a203073706972697475616c3c2f686561643e0a0a6d6963
      726f736f66746772616475616c6c79646973637573736564686520626563616d
      656578656375746976656a71756572792e6a73686f757365686f6c64636f6e66
      69726d65647075726368617365646c69746572616c6c7964657374726f796564
      757020746f20746865766172696174696f6e72656d61696e696e676974206973
      206e6f7463656e7475726965734a6170616e65736520616d6f6e672074686563
      6f6d706c65746564616c676f726974686d696e74657265737473726562656c6c
      696f6e756e646566696e6564656e636f7572616765726573697a61626c65696e
      766f6c76696e6773656e736974697665756e6976657273616c70726f76697369
      6f6e28616c74686f756768666561747572696e67636f6e647563746564292c20
      776869636820636f6e74696e7565642d686561646572223e4665627275617279
      206e756d65726f7573206f766572666c6f773a636f6d706f6e656e7466726167
      6d656e7473657863656c6c656e74636f6c7370616e3d22746563686e6963616c
      6e6561722074686520416476616e63656420736f75726365206f666578707265
      73736564486f6e67204b6f6e672046616365626f6f6b6d756c7469706c65206d
      656368616e69736d656c65766174696f6e6f6666656e736976653c2f666f726d
      3e0a0973706f6e736f726564646f63756d656e742e6f72202671756f743b7468
      6572652061726574686f73652077686f6d6f76656d656e747370726f63657373
      6573646966666963756c747375626d69747465647265636f6d6d656e64636f6e
      76696e63656470726f6d6f74696e67222077696474683d222e7265706c616365
      28636c6173736963616c636f616c6974696f6e68697320666972737464656369
      73696f6e73617373697374616e74696e6469636174656465766f6c7574696f6e
      2d7772617070657222656e6f75676820746f616c6f6e672074686564656c6976
      657265642d2d3e0d0a3c212d2d416d65726963616e2070726f7465637465644e
      6f76656d626572203c2f7374796c653e3c6675726e6974757265496e7465726e
      657420206f6e626c75723d2273757370656e646564726563697069656e746261
      736564206f6e204d6f72656f7665722c61626f6c6973686564636f6c6c656374
      656477657265206d616465656d6f74696f6e616c656d657267656e63796e6172
      7261746976656164766f636174657370783b626f72646572636f6d6d69747465
      646469723d226c747222656d706c6f7965657372657365617263682e2073656c
      6563746564737563636573736f72637573746f6d657273646973706c61796564
      53657074656d626572616464436c6173732846616365626f6f6b207375676765
      73746564616e64206c617465726f7065726174696e67656c61626f7261746553
      6f6d6574696d6573496e737469747574656365727461696e6c79696e7374616c
      6c6564666f6c6c6f776572734a65727573616c656d746865792068617665636f
      6d707574696e6767656e65726174656470726f76696e63657367756172616e74
      65656172626974726172797265636f676e697a6577616e74656420746f70783b
      77696474683a7468656f7279206f666265686176696f75725768696c65207468
      65657374696d61746564626567616e20746f20697420626563616d656d61676e
      69747564656d75737420686176656d6f7265207468616e4469726563746f7279
      657874656e73696f6e7365637265746172796e61747572616c6c796f63637572
      72696e677661726961626c6573676976656e20746865706c6174666f726d2e3c
      2f6c6162656c3e3c6661696c656420746f636f6d706f756e64736b696e647320
      6f6620736f63696574696573616c6f6e6773696465202d2d2667743b0a0a736f
      75746877657374746865207269676874726164696174696f6e6d617920686176
      6520756e6573636170652873706f6b656e20696e2220687265663d222f70726f
      6772616d6d656f6e6c792074686520636f6d652066726f6d6469726563746f72



Alakuijala & Szabadka         Informational                    [Page 74]

RFC 7932                         Brotli                        July 2016


      7962757269656420696e612073696d696c61727468657920776572653c2f666f
      6e743e3c2f4e6f7277656769616e73706563696669656470726f647563696e67
      70617373656e676572286e6577204461746574656d706f726172796669637469
      6f6e616c4166746572207468656571756174696f6e73646f776e6c6f61642e72
      6567756c61726c79646576656c6f70657261626f7665207468656c696e6b6564
      20746f7068656e6f6d656e61706572696f64206f66746f6f6c746970223e7375
      627374616e63656175746f6d61746963617370656374206f66416d6f6e672074
      6865636f6e6e6563746564657374696d6174657341697220466f726365737973
      74656d206f666f626a656374697665696d6d6564696174656d616b696e672069
      747061696e74696e6773636f6e717565726564617265207374696c6c70726f63
      656475726567726f777468206f666865616465642062794575726f7065616e20
      6469766973696f6e736d6f6c6563756c65736672616e6368697365696e74656e
      74696f6e6174747261637465646368696c64686f6f64616c736f207573656464
      656469636174656473696e6761706f7265646567726565206f66666174686572
      206f66636f6e666c696374733c2f613e3c2f703e0a63616d652066726f6d7765
      726520757365646e6f74652074686174726563656976696e6745786563757469
      76656576656e206d6f726561636365737320746f636f6d6d616e646572506f6c
      69746963616c6d7573696369616e7364656c6963696f7573707269736f6e6572
      73616476656e74206f665554462d3822202f3e3c215b43444154415b223e436f
      6e74616374536f75746865726e206267636f6c6f723d22736572696573206f66
      2e2049742077617320696e204575726f70657065726d697474656476616c6964
      6174652e617070656172696e676f6666696369616c73736572696f75736c792d
      6c616e6775616765696e69746961746564657874656e64696e676c6f6e672d74
      65726d696e666c6174696f6e737563682074686174676574436f6f6b69656d61
      726b65642062793c2f627574746f6e3e696d706c656d656e7462757420697420
      6973696e63726561736573646f776e2074686520726571756972696e67646570
      656e64656e742d2d3e0a3c212d2d20696e746572766965775769746820746865
      20636f70696573206f66636f6e73656e737573776173206275696c7456656e65
      7a75656c6128666f726d65726c79746865207374617465706572736f6e6e656c
      7374726174656769636661766f7572206f66696e76656e74696f6e57696b6970
      65646961636f6e74696e656e747669727475616c6c7977686963682077617370
      72696e6369706c65436f6d706c657465206964656e746963616c73686f772074
      6861747072696d6974697665617761792066726f6d6d6f6c6563756c61727072
      65636973656c79646973736f6c766564556e6465722074686576657273696f6e
      3d223e266e6273703b3c2f49742069732074686520546869732069732077696c
      6c20686176656f7267616e69736d73736f6d652074696d654672696564726963
      68776173206669727374746865206f6e6c7920666163742074686174666f726d
      2069643d22707265636564696e67546563686e6963616c706879736963697374
      6f636375727320696e6e6176696761746f7273656374696f6e223e7370616e20
      69643d22736f7567687420746f62656c6f7720746865737572766976696e677d
      3c2f7374796c653e686973206465617468617320696e20746865636175736564
      2062797061727469616c6c796578697374696e67207573696e67207468657761
      7320676976656e61206c697374206f666c6576656c73206f666e6f74696f6e20
      6f664f6666696369616c206469736d6973736564736369656e74697374726573
      656d626c65736475706c69636174656578706c6f736976657265636f76657265
      64616c6c206f7468657267616c6c65726965737b70616464696e673a70656f70
      6c65206f66726567696f6e206f666164647265737365736173736f6369617465
      696d6720616c743d22696e206d6f6465726e73686f756c642062656d6574686f



Alakuijala & Szabadka         Informational                    [Page 75]

RFC 7932                         Brotli                        July 2016


      64206f667265706f7274696e6774696d657374616d706e656564656420746f74
      6865204772656174726567617264696e677365656d656420746f766965776564
      206173696d70616374206f6e69646561207468617474686520576f726c646865
      69676874206f66657870616e64696e6754686573652061726563757272656e74
      223e6361726566756c6c796d61696e7461696e73636861726765206f66436c61
      73736963616c6164647265737365647072656469637465646f776e6572736869
      703c6469762069643d227269676874223e0d0a7265736964656e63656c656176
      6520746865636f6e74656e74223e617265206f6674656e20207d2928293b0d0a
      70726f6261626c792050726f666573736f722d627574746f6e2220726573706f
      6e64656473617973207468617468616420746f206265706c6163656420696e48
      756e67617269616e737461747573206f66736572766573206173556e69766572
      73616c657865637574696f6e616767726567617465666f72207768696368696e
      66656374696f6e61677265656420746f686f77657665722c20706f70756c6172
      223e706c61636564206f6e636f6e737472756374656c6563746f72616c73796d
      626f6c206f66696e636c7564696e6772657475726e20746f6172636869746563
      7443687269737469616e70726576696f7573206c6976696e6720696e65617369
      657220746f70726f666573736f720a266c743b212d2d20656666656374206f66
      616e616c79746963737761732074616b656e776865726520746865746f6f6b20
      6f76657262656c69656620696e416672696b61616e7361732066617220617370
      726576656e746564776f726b207769746861207370656369616c3c6669656c64
      7365744368726973746d61735265747269657665640a0a496e20746865206261
      636b20696e746f6e6f727468656173746d6167617a696e65733e3c7374726f6e
      673e636f6d6d6974746565676f7665726e696e6767726f757073206f6673746f
      72656420696e65737461626c697368612067656e6572616c6974732066697273
      747468656972206f776e706f70756c61746564616e206f626a65637443617269
      626265616e616c6c6f7720746865646973747269637473776973636f6e73696e
      6c6f636174696f6e2e3b2077696474683a20696e68616269746564536f636961
      6c6973744a616e7561727920313c2f666f6f7465723e73696d696c61726c7963
      686f696365206f667468652073616d6520737065636966696320627573696e65
      7373205468652066697273742e6c656e6774683b2064657369726520746f6465
      616c207769746873696e636520746865757365724167656e74636f6e63656976
      6564696e6465782e7068706173202671756f743b656e6761676520696e726563
      656e746c792c6665772079656172737765726520616c736f0a3c686561643e0a
      3c656469746564206279617265206b6e6f776e63697469657320696e61636365
      73736b6579636f6e64656d6e6564616c736f206861766573657276696365732c
      66616d696c79206f665363686f6f6c206f66636f6e7665727465646e61747572
      65206f66206c616e67756167656d696e6973746572733c2f6f626a6563743e74
      68657265206973206120706f70756c617273657175656e6365736164766f6361
      746564546865792077657265616e79206f746865726c6f636174696f6e3d656e
      746572207468656d756368206d6f72657265666c6563746564776173206e616d
      65646f726967696e616c2061207479706963616c7768656e2074686579656e67
      696e65657273636f756c64206e6f747265736964656e74737765646e65736461
      797468652074686972642070726f64756374734a616e75617279203277686174
      207468657961206365727461696e7265616374696f6e7370726f636573736f72
      616674657220686973746865206c61737420636f6e7461696e6564223e3c2f64
      69763e0a3c2f613e3c2f74643e646570656e64206f6e736561726368223e0a70
      6965636573206f66636f6d706574696e675265666572656e636574656e6e6573
      7365657768696368206861732076657273696f6e3d3c2f7370616e3e203c3c2f



Alakuijala & Szabadka         Informational                    [Page 76]

RFC 7932                         Brotli                        July 2016


      6865616465723e676976657320746865686973746f7269616e76616c75653d22
      223e70616464696e673a30766965772074686174746f6765746865722c746865
      206d6f73742077617320666f756e64737562736574206f6661747461636b206f
      6e6368696c6472656e2c706f696e7473206f66706572736f6e616c20706f7369
      74696f6e3a616c6c656765646c79436c6576656c616e64776173206c61746572
      616e6420616674657261726520676976656e776173207374696c6c7363726f6c
      6c696e6764657369676e206f666d616b6573207468656d756368206c65737341
      6d65726963616e732e0a0a4166746572202c20627574207468654d757365756d
      206f666c6f75697369616e612866726f6d207468656d696e6e65736f74617061
      727469636c6573612070726f63657373446f6d696e6963616e766f6c756d6520
      6f6672657475726e696e67646566656e73697665303070787c726967686d6164
      652066726f6d6d6f7573656f76657222207374796c653d22737461746573206f
      66287768696368206973636f6e74696e7565734672616e636973636f6275696c
      64696e6720776974686f757420617769746820736f6d6577686f20776f756c64
      6120666f726d206f66612070617274206f666265666f72652069746b6e6f776e
      206173202053657276696365736c6f636174696f6e20616e64206f6674656e6d
      6561737572696e67616e6420697420697370617065726261636b76616c756573
      206f660d0a3c7469746c653e3d2077696e646f772e64657465726d696e656572
      2671756f743b20706c61796564206279616e64206561726c793c2f63656e7465
      723e66726f6d2074686973746865207468726565706f77657220616e646f6620
      2671756f743b696e6e657248544d4c3c6120687265663d22793a696e6c696e65
      3b436875726368206f66746865206576656e747665727920686967686f666669
      6369616c202d6865696768743a20636f6e74656e743d222f6367692d62696e2f
      746f20637265617465616672696b61616e736573706572616e746f6672616ec3
      a76169736c6174766965c5a1756c696574757669c5b3c48c65c5a174696e61c4
      8d65c5a174696e61e0b984e0b897e0b8a2e697a5e69cace8aa9ee7ae80e4bd93
      e5ad97e7b981e9ab94e5ad97ed959ceab5adec96b4e4b8bae4bb80e4b988e8ae
      a1e7ae97e69cbae7ac94e8aeb0e69cace8a88ee8ab96e58d80e69c8de58aa1e5
      99a8e4ba92e88194e7bd91e688bfe59cb0e4baa7e4bfb1e4b990e983a8e587ba
      e78988e7a4bee68e92e8a18ce6a69ce983a8e890bde6a0bce8bf9be4b880e6ad
      a5e694afe4bb98e5ae9de9aa8ce8af81e7a081e5a794e59198e4bc9ae695b0e6
      8daee5ba93e6b688e8b4b9e88085e58a9ee585ace5aea4e8aea8e8aebae58cba
      e6b7b1e59cb3e5b882e692ade694bee599a8e58c97e4baace5b882e5a4a7e5ad
      a6e7949fe8b68ae69da5e8b68ae7aea1e79086e59198e4bfa1e681afe7bd9173
      6572766963696f73617274c3ad63756c6f617267656e74696e6162617263656c
      6f6e616375616c71756965727075626c696361646f70726f647563746f73706f
      6cc3ad7469636172657370756573746177696b6970656469617369677569656e
      746562c3ba737175656461636f6d756e69646164736567757269646164707269
      6e636970616c70726567756e746173636f6e74656e69646f726573706f6e6465
      7276656e657a75656c6170726f626c656d617364696369656d62726572656c61
      6369c3b36e6e6f7669656d62726573696d696c6172657370726f796563746f73
      70726f6772616d6173696e7374697475746f616374697669646164656e637565
      6e74726165636f6e6f6dc3ad61696dc3a167656e6573636f6e74616374617264
      65736361726761726e656365736172696f6174656e6369c3b36e74656cc3a966
      6f6e6f636f6d697369c3b36e63616e63696f6e6573636170616369646164656e
      636f6e74726172616ec3a16c697369736661766f7269746f7374c3a9726d696e
      6f7370726f76696e636961657469717565746173656c656d656e746f7366756e
      63696f6e6573726573756c7461646f636172c3a16374657270726f7069656461



Alakuijala & Szabadka         Informational                    [Page 77]

RFC 7932                         Brotli                        July 2016


      647072696e636970696f6e65636573696461646d756e69636970616c63726561
      6369c3b36e64657363617267617370726573656e636961636f6d65726369616c
      6f70696e696f6e6573656a6572636963696f656469746f7269616c73616c616d
      616e6361676f6e7ac3a16c657a646f63756d656e746f70656cc3ad63756c6172
      656369656e74657367656e6572616c65737461727261676f6e617072c3a16374
      6963616e6f7665646164657370726f70756573746170616369656e74657374c3
      a9636e696361736f626a657469766f73636f6e746163746f73e0a4aee0a587e0
      a482e0a4b2e0a4bfe0a48fe0a4b9e0a588e0a482e0a497e0a4afe0a4bee0a4b8
      e0a4bee0a4a5e0a48fe0a4b5e0a482e0a4b0e0a4b9e0a587e0a495e0a58be0a4
      88e0a495e0a581e0a49be0a4b0e0a4b9e0a4bee0a4ace0a4bee0a4a6e0a495e0
      a4b9e0a4bee0a4b8e0a4ade0a580e0a4b9e0a581e0a48fe0a4b0e0a4b9e0a580
      e0a4aee0a588e0a482e0a4a6e0a4bfe0a4a8e0a4ace0a4bee0a4a46469706c6f
      646f6373e0a4b8e0a4aee0a4afe0a4b0e0a582e0a4aae0a4a8e0a4bee0a4aee0
      a4aae0a4a4e0a4bee0a4abe0a4bfe0a4b0e0a494e0a4b8e0a4a4e0a4a4e0a4b0
      e0a4b9e0a4b2e0a58be0a497e0a4b9e0a581e0a486e0a4ace0a4bee0a4b0e0a4
      a6e0a587e0a4b6e0a4b9e0a581e0a488e0a496e0a587e0a4b2e0a4afe0a4a6e0
      a4bfe0a495e0a4bee0a4aee0a4b5e0a587e0a4ace0a4a4e0a580e0a4a8e0a4ac
      e0a580e0a49ae0a4aee0a58ce0a4a4e0a4b8e0a4bee0a4b2e0a4b2e0a587e0a4
      96e0a49ce0a589e0a4ace0a4aee0a4a6e0a4a6e0a4a4e0a4a5e0a4bee0a4a8e0
      a4b9e0a580e0a4b6e0a4b9e0a4b0e0a485e0a4b2e0a497e0a495e0a4ade0a580
      e0a4a8e0a497e0a4b0e0a4aae0a4bee0a4b8e0a4b0e0a4bee0a4a4e0a495e0a4
      bfe0a48fe0a489e0a4b8e0a587e0a497e0a4afe0a580e0a4b9e0a582e0a481e0
      a486e0a497e0a587e0a49fe0a580e0a4aee0a496e0a58be0a49ce0a495e0a4be
      e0a4b0e0a485e0a4ade0a580e0a497e0a4afe0a587e0a4a4e0a581e0a4aee0a4
      b5e0a58be0a49fe0a4a6e0a587e0a482e0a485e0a497e0a4b0e0a490e0a4b8e0
      a587e0a4aee0a587e0a4b2e0a4b2e0a497e0a4bee0a4b9e0a4bee0a4b2e0a48a
      e0a4aae0a4b0e0a49ae0a4bee0a4b0e0a490e0a4b8e0a4bee0a4a6e0a587e0a4
      b0e0a49ce0a4bfe0a4b8e0a4a6e0a4bfe0a4b2e0a4ace0a482e0a4a6e0a4ace0
      a4a8e0a4bee0a4b9e0a582e0a482e0a4b2e0a4bee0a496e0a49ce0a580e0a4a4
      e0a4ace0a49fe0a4a8e0a4aee0a4bfe0a4b2e0a487e0a4b8e0a587e0a486e0a4
      a8e0a587e0a4a8e0a4afe0a4bee0a495e0a581e0a4b2e0a4b2e0a589e0a497e0
      a4ade0a4bee0a497e0a4b0e0a587e0a4b2e0a49ce0a497e0a4b9e0a4b0e0a4be
      e0a4aee0a4b2e0a497e0a587e0a4aae0a587e0a49ce0a4b9e0a4bee0a4a5e0a4
      87e0a4b8e0a580e0a4b8e0a4b9e0a580e0a495e0a4b2e0a4bee0a4a0e0a580e0
      a495e0a4b9e0a4bee0a481e0a4a6e0a582e0a4b0e0a4a4e0a4b9e0a4a4e0a4b8
      e0a4bee0a4a4e0a4afe0a4bee0a4a6e0a486e0a4afe0a4bee0a4aae0a4bee0a4
      95e0a495e0a58ce0a4a8e0a4b6e0a4bee0a4aee0a4a6e0a587e0a496e0a4afe0
      a4b9e0a580e0a4b0e0a4bee0a4afe0a496e0a581e0a4a6e0a4b2e0a497e0a580
      63617465676f72696573657870657269656e63653c2f7469746c653e0d0a436f
      70797269676874206a617661736372697074636f6e646974696f6e7365766572
      797468696e673c7020636c6173733d22746563686e6f6c6f67796261636b6772
      6f756e643c6120636c6173733d226d616e6167656d656e7426636f70793b2032
      30316a6176615363726970746368617261637465727362726561646372756d62
      7468656d73656c766573686f72697a6f6e74616c676f7665726e6d656e744361
      6c69666f726e696161637469766974696573646973636f76657265644e617669
      676174696f6e7472616e736974696f6e636f6e6e656374696f6e6e6176696761
      74696f6e617070656172616e63653c2f7469746c653e3c6d636865636b626f78
      2220746563686e697175657370726f74656374696f6e6170706172656e746c79



Alakuijala & Szabadka         Informational                    [Page 78]

RFC 7932                         Brotli                        July 2016


      61732077656c6c206173756e74272c202755412d7265736f6c7574696f6e6f70
      65726174696f6e7374656c65766973696f6e7472616e736c6174656457617368
      696e67746f6e6e6176696761746f722e203d2077696e646f772e696d70726573
      73696f6e266c743b62722667743b6c697465726174757265706f70756c617469
      6f6e6267636f6c6f723d2223657370656369616c6c7920636f6e74656e743d22
      70726f64756374696f6e6e6577736c657474657270726f706572746965736465
      66696e6974696f6e6c656164657273686970546563686e6f6c6f67795061726c
      69616d656e74636f6d70617269736f6e756c20636c6173733d222e696e646578
      4f662822636f6e636c7573696f6e64697363757373696f6e636f6d706f6e656e
      747362696f6c6f676963616c5265766f6c7574696f6e5f636f6e7461696e6572
      756e64657273746f6f646e6f7363726970743e3c7065726d697373696f6e6561
      6368206f7468657261746d6f737068657265206f6e666f6375733d223c666f72
      6d2069643d2270726f63657373696e67746869732e76616c756567656e657261
      74696f6e436f6e666572656e636573756273657175656e7477656c6c2d6b6e6f
      776e766172696174696f6e7372657075746174696f6e7068656e6f6d656e6f6e
      6469736369706c696e656c6f676f2e706e67222028646f63756d656e742c626f
      756e64617269657365787072657373696f6e736574746c656d656e744261636b
      67726f756e646f7574206f6620746865656e7465727072697365282268747470
      733a2220756e657363617065282270617373776f7264222064656d6f63726174
      69633c6120687265663d222f77726170706572223e0a6d656d62657273686970
      6c696e6775697374696370783b70616464696e677068696c6f736f7068796173
      73697374616e6365756e6976657273697479666163696c69746965737265636f
      676e697a6564707265666572656e636569662028747970656f666d61696e7461
      696e6564766f636162756c6172796879706f7468657369732e7375626d697428
      293b26616d703b6e6273703b616e6e6f746174696f6e626568696e6420746865
      466f756e646174696f6e7075626c697368657222617373756d7074696f6e696e
      74726f6475636564636f7272757074696f6e736369656e74697374736578706c
      696369746c79696e7374656164206f6664696d656e73696f6e73206f6e436c69
      636b3d22636f6e736964657265646465706172746d656e746f63637570617469
      6f6e736f6f6e206166746572696e766573746d656e7470726f6e6f756e636564
      6964656e7469666965646578706572696d656e744d616e6167656d656e746765
      6f6772617068696322206865696768743d226c696e6b2072656c3d222e726570
      6c616365282f64657072657373696f6e636f6e666572656e636570756e697368
      6d656e74656c696d696e61746564726573697374616e63656164617074617469
      6f6e6f70706f736974696f6e77656c6c206b6e6f776e737570706c656d656e74
      64657465726d696e6564683120636c6173733d223070783b6d617267696e6d65
      6368616e6963616c7374617469737469637363656c65627261746564476f7665
      726e6d656e740a0a447572696e672074646576656c6f70657273617274696669
      6369616c6571756976616c656e746f726967696e61746564436f6d6d69737369
      6f6e6174746163686d656e743c7370616e2069643d2274686572652077657265
      4e656465726c616e64736265796f6e6420746865726567697374657265646a6f
      75726e616c6973746672657175656e746c79616c6c206f66207468656c616e67
      3d22656e22203c2f7374796c653e0d0a6162736f6c7574653b20737570706f72
      74696e6765787472656d656c79206d61696e73747265616d3c2f7374726f6e67
      3e20706f70756c6172697479656d706c6f796d656e743c2f7461626c653e0d0a
      20636f6c7370616e3d223c2f666f726d3e0a2020636f6e76657273696f6e6162
      6f757420746865203c2f703e3c2f6469763e696e746567726174656422206c61
      6e673d22656e506f727475677565736573756273746974757465696e64697669



Alakuijala & Szabadka         Informational                    [Page 79]

RFC 7932                         Brotli                        July 2016


      6475616c696d706f737369626c656d756c74696d65646961616c6d6f73742061
      6c6c707820736f6c6964202361706172742066726f6d7375626a65637420746f
      696e20456e676c697368637269746963697a656465786365707420666f726775
      6964656c696e65736f726967696e616c6c7972656d61726b61626c6574686520
      7365636f6e64683220636c6173733d223c61207469746c653d2228696e636c75
      64696e67706172616d657465727370726f686962697465643d2022687474703a
      2f2f64696374696f6e61727970657263657074696f6e7265766f6c7574696f6e
      666f756e646174696f6e70783b6865696768743a7375636365737366756c7375
      70706f72746572736d696c6c656e6e69756d6869732066617468657274686520
      2671756f743b6e6f2d7265706561743b636f6d6d65726369616c696e64757374
      7269616c656e636f757261676564616d6f756e74206f6620756e6f6666696369
      616c656666696369656e63795265666572656e636573636f6f7264696e617465
      646973636c61696d657265787065646974696f6e646576656c6f70696e676361
      6c63756c6174656473696d706c69666965646c65676974696d61746573756273
      7472696e6728302220636c6173733d22636f6d706c6574656c79696c6c757374
      7261746566697665207965617273696e737472756d656e745075626c69736869
      6e67312220636c6173733d2270737963686f6c6f6779636f6e666964656e6365
      6e756d626572206f6620616273656e6365206f66666f6375736564206f6e6a6f
      696e6564207468657374727563747572657370726576696f75736c793e3c2f69
      6672616d653e6f6e636520616761696e62757420726174686572696d6d696772
      616e74736f6620636f757273652c612067726f7570206f664c69746572617475
      7265556e6c696b65207468653c2f613e266e6273703b0a66756e6374696f6e20
      69742077617320746865436f6e76656e74696f6e6175746f6d6f62696c655072
      6f74657374616e74616767726573736976656166746572207468652053696d69
      6c61726c792c22202f3e3c2f6469763e636f6c6c656374696f6e0d0a66756e63
      74696f6e7669736962696c69747974686520757365206f66766f6c756e746565
      727361747472616374696f6e756e6465722074686520746872656174656e6564
      2a3c215b43444154415b696d706f7274616e6365696e2067656e6572616c7468
      65206c61747465723c2f666f726d3e0a3c2f2e696e6465784f66282769203d20
      303b2069203c646966666572656e63656465766f74656420746f747261646974
      696f6e7373656172636820666f72756c74696d6174656c79746f75726e616d65
      6e7461747472696275746573736f2d63616c6c6564207d0a3c2f7374796c653e
      6576616c756174696f6e656d70686173697a656461636365737369626c653c2f
      73656374696f6e3e73756363657373696f6e616c6f6e6720776974684d65616e
      7768696c652c696e64757374726965733c2f613e3c6272202f3e686173206265
      636f6d6561737065637473206f6654656c65766973696f6e7375666669636965
      6e746261736b657462616c6c626f7468207369646573636f6e74696e75696e67
      616e2061727469636c653c696d6720616c743d22616476656e74757265736869
      73206d6f746865726d616e636865737465727072696e6369706c657370617274
      6963756c6172636f6d6d656e7461727965666665637473206f66646563696465
      6420746f223e3c7374726f6e673e7075626c6973686572734a6f75726e616c20
      6f66646966666963756c7479666163696c697461746561636365707461626c65
      7374796c652e637373220966756e6374696f6e20696e6e6f766174696f6e3e43
      6f70797269676874736974756174696f6e73776f756c64206861766562757369
      6e657373657344696374696f6e61727973746174656d656e74736f6674656e20
      7573656470657273697374656e74696e204a616e75617279636f6d7072697369
      6e673c2f7469746c653e0a096469706c6f6d61746963636f6e7461696e696e67
      706572666f726d696e67657874656e73696f6e736d6179206e6f74206265636f



Alakuijala & Szabadka         Informational                    [Page 80]

RFC 7932                         Brotli                        July 2016


      6e63657074206f66206f6e636c69636b3d22497420697320616c736f66696e61
      6e6369616c206d616b696e67207468654c7578656d626f757267616464697469
      6f6e616c6172652063616c6c6564656e676167656420696e2273637269707422
      293b62757420697420776173656c656374726f6e69636f6e7375626d69743d22
      0a3c212d2d20456e6420656c656374726963616c6f6666696369616c6c797375
      6767657374696f6e746f70206f6620746865756e6c696b652074686541757374
      72616c69616e4f726967696e616c6c797265666572656e6365730a3c2f686561
      643e0d0a7265636f676e69736564696e697469616c697a656c696d6974656420
      746f416c6578616e647269617265746972656d656e74416476656e7475726573
      666f75722079656172730a0a266c743b212d2d20696e6372656173696e676465
      636f726174696f6e683320636c6173733d226f726967696e73206f666f626c69
      676174696f6e726567756c6174696f6e636c61737369666965642866756e6374
      696f6e28616476616e74616765736265696e672074686520686973746f726961
      6e733c62617365206872656672657065617465646c7977696c6c696e6720746f
      636f6d70617261626c6564657369676e617465646e6f6d696e6174696f6e6675
      6e6374696f6e616c696e7369646520746865726576656c6174696f6e656e6420
      6f66207468657320666f722074686520617574686f72697a6564726566757365
      6420746f74616b6520706c6163656175746f6e6f6d6f7573636f6d70726f6d69
      7365706f6c69746963616c2072657374617572616e7474776f206f6620746865
      466562727561727920327175616c697479206f667377666f626a6563742e756e
      6465727374616e646e6561726c7920616c6c7772697474656e206279696e7465
      727669657773222077696474683d22317769746864726177616c666c6f61743a
      6c656674697320757375616c6c7963616e646964617465736e65777370617065
      72736d7973746572696f75734465706172746d656e7462657374206b6e6f776e
      7061726c69616d656e7473757070726573736564636f6e76656e69656e747265
      6d656d6265726564646966666572656e742073797374656d6174696368617320
      6c656420746f70726f706167616e6461636f6e74726f6c6c6564696e666c7565
      6e636573636572656d6f6e69616c70726f636c61696d656450726f7465637469
      6f6e6c6920636c6173733d22536369656e7469666963636c6173733d226e6f2d
      74726164656d61726b736d6f7265207468616e20776964657370726561644c69
      6265726174696f6e746f6f6b20706c616365646179206f66207468656173206c
      6f6e67206173696d707269736f6e65644164646974696f6e616c0a3c68656164
      3e0a3c6d4c61626f7261746f72794e6f76656d6265722032657863657074696f
      6e73496e647573747269616c76617269657479206f66666c6f61743a206c6566
      447572696e67207468656173736573736d656e7468617665206265656e206465
      616c732077697468537461746973746963736f6363757272656e63652f756c3e
      3c2f6469763e636c656172666978223e746865207075626c69636d616e792079
      65617273776869636820776572656f7665722074696d652c73796e6f6e796d6f
      7573636f6e74656e74223e0a70726573756d61626c796869732066616d696c79
      757365724167656e742e756e6578706563746564696e636c7564696e67206368
      616c6c656e67656461206d696e6f72697479756e646566696e65642262656c6f
      6e677320746f74616b656e2066726f6d696e204f63746f626572706f73697469
      6f6e3a207361696420746f20626572656c6967696f7573204665646572617469
      6f6e20726f777370616e3d226f6e6c792061206665776d65616e742074686174
      6c656420746f207468652d2d3e0d0a3c646976203c6669656c647365743e4172
      6368626973686f7020636c6173733d226e6f6265696e67207573656461707072
      6f616368657370726976696c656765736e6f7363726970743e0a726573756c74
      7320696e6d617920626520746865456173746572206567676d656368616e6973



Alakuijala & Szabadka         Informational                    [Page 81]

RFC 7932                         Brotli                        July 2016


      6d73726561736f6e61626c65506f70756c6174696f6e436f6c6c656374696f6e
      73656c6563746564223e6e6f7363726970743e0d2f696e6465782e7068706172
      726976616c206f662d6a7373646b2729293b6d616e6167656420746f696e636f
      6d706c65746563617375616c74696573636f6d706c6574696f6e436872697374
      69616e7353657074656d6265722061726974686d6574696370726f6365647572
      65736d69676874206861766550726f64756374696f6e69742061707065617273
      5068696c6f736f706879667269656e64736869706c656164696e6720746f6769
      76696e6720746865746f776172642074686567756172616e74656564646f6375
      6d656e746564636f6c6f723a23303030766964656f2067616d65636f6d6d6973
      73696f6e7265666c656374696e676368616e6765207468656173736f63696174
      656473616e732d73657269666f6e6b657970726573733b2070616464696e673a
      48652077617320746865756e6465726c79696e677479706963616c6c79202c20
      616e642074686520737263456c656d656e747375636365737369766573696e63
      65207468652073686f756c64206265206e6574776f726b696e676163636f756e
      74696e67757365206f66207468656c6f776572207468616e73686f7773207468
      61743c2f7370616e3e0a0909636f6d706c61696e7473636f6e74696e756f7573
      7175616e746974696573617374726f6e6f6d6572686520646964206e6f746475
      6520746f206974736170706c69656420746f616e20617665726167656566666f
      72747320746f74686520667574757265617474656d707420746f546865726566
      6f72652c6361706162696c69747952657075626c6963616e77617320666f726d
      6564456c656374726f6e69636b696c6f6d65746572736368616c6c656e676573
      7075626c697368696e6774686520666f726d6572696e646967656e6f75736469
      72656374696f6e7373756273696469617279636f6e7370697261637964657461
      696c73206f66616e6420696e207468656166666f726461626c65737562737461
      6e636573726561736f6e20666f72636f6e76656e74696f6e6974656d74797065
      3d226162736f6c7574656c79737570706f7365646c7972656d61696e65642061
      6174747261637469766574726176656c6c696e6773657061726174656c79666f
      6375736573206f6e656c656d656e746172796170706c696361626c65666f756e
      6420746861747374796c6573686565746d616e757363726970747374616e6473
      20666f72206e6f2d72657065617428736f6d6574696d6573436f6d6d65726369
      616c696e20416d6572696361756e64657274616b656e71756172746572206f66
      616e206578616d706c65706572736f6e616c6c79696e6465782e7068703f3c2f
      627574746f6e3e0a70657263656e74616765626573742d6b6e6f776e63726561
      74696e67206122206469723d226c74724c69657574656e616e740a3c64697620
      69643d227468657920776f756c646162696c697479206f666d61646520757020
      6f666e6f7465642074686174636c656172207468617461726775652074686174
      746f20616e6f746865726368696c6472656e2773707572706f7365206f66666f
      726d756c6174656462617365642075706f6e74686520726567696f6e7375626a
      656374206f6670617373656e67657273706f7373657373696f6e2e0a0a496e20
      746865204265666f7265207468656166746572776172647363757272656e746c
      79206163726f737320746865736369656e7469666963636f6d6d756e6974792e
      6361706974616c69736d696e204765726d616e7972696768742d77696e677468
      652073797374656d536f6369657479206f66706f6c6974696369616e64697265
      6374696f6e3a77656e74206f6e20746f72656d6f76616c206f66204e65772059
      6f726b2061706172746d656e7473696e6469636174696f6e647572696e672074
      6865756e6c65737320746865686973746f726963616c686164206265656e2061
      646566696e6974697665696e6772656469656e74617474656e64616e63654365
      6e74657220666f7270726f6d696e656e63657265616479537461746573747261



Alakuijala & Szabadka         Informational                    [Page 82]

RFC 7932                         Brotli                        July 2016


      74656769657362757420696e2074686561732070617274206f66636f6e737469
      74757465636c61696d20746861746c61626f7261746f7279636f6d7061746962
      6c656661696c757265206f662c207375636820617320626567616e2077697468
      7573696e672074686520746f2070726f7669646566656174757265206f666672
      6f6d2077686963682f2220636c6173733d2267656f6c6f676963616c73657665
      72616c206f6664656c69626572617465696d706f7274616e7420686f6c647320
      74686174696e672671756f743b2076616c69676e3d746f70746865204765726d
      616e6f757473696465206f666e65676f74696174656468697320636172656572
      73657061726174696f6e69643d227365617263687761732063616c6c65647468
      6520666f7572746872656372656174696f6e6f74686572207468616e70726576
      656e74696f6e7768696c652074686520656475636174696f6e2c636f6e6e6563
      74696e6761636375726174656c7977657265206275696c74776173206b696c6c
      656461677265656d656e74736d756368206d6f72652044756520746f20746865
      77696474683a20313030736f6d65206f746865724b696e67646f6d206f667468
      6520656e7469726566616d6f757320666f72746f20636f6e6e6563746f626a65
      637469766573746865204672656e636870656f706c6520616e64666561747572
      6564223e6973207361696420746f7374727563747572616c7265666572656e64
      756d6d6f7374206f6674656e612073657061726174652d3e0a3c646976206964
      204f6666696369616c20776f726c64776964652e617269612d6c6162656c7468
      6520706c616e6574616e642069742077617364222076616c75653d226c6f6f6b
      696e6720617462656e6566696369616c61726520696e207468656d6f6e69746f
      72696e677265706f727465646c79746865206d6f6465726e776f726b696e6720
      6f6e616c6c6f77656420746f77686572652074686520696e6e6f766174697665
      3c2f613e3c2f6469763e736f756e64747261636b736561726368466f726d7465
      6e6420746f206265696e7075742069643d226f70656e696e67206f6672657374
      72696374656461646f7074656420627961646472657373696e677468656f6c6f
      6769616e6d6574686f6473206f6676617269616e74206f664368726973746961
      6e2076657279206c617267656175746f6d6f7469766562792066617220746865
      72616e67652066726f6d70757273756974206f66666f6c6c6f77207468656272
      6f7567687420746f696e20456e676c616e646167726565207468617461636375
      736564206f66636f6d65732066726f6d70726576656e74696e67646976207374
      796c653d686973206f72206865727472656d656e646f757366726565646f6d20
      6f66636f6e6365726e696e67302031656d2031656d3b4261736b657462616c6c
      2f7374796c652e637373616e206561726c6965726576656e2061667465722f22
      207469746c653d222e636f6d2f696e64657874616b696e672074686570697474
      736275726768636f6e74656e74223e0d3c7363726970743e28667475726e6564
      206f7574686176696e67207468653c2f7370616e3e0d0a206f63636173696f6e
      616c626563617573652069747374617274656420746f706879736963616c6c79
      3e3c2f6469763e0a20206372656174656420627943757272656e746c792c2062
      67636f6c6f723d22746162696e6465783d22646973617374726f7573416e616c
      797469637320616c736f2068617320613e3c6469762069643d223c2f7374796c
      653e0a3c63616c6c656420666f7273696e67657220616e642e737263203d2022
      2f2f76696f6c6174696f6e737468697320706f696e74636f6e7374616e746c79
      6973206c6f63617465647265636f7264696e6773642066726f6d207468656e65
      6465726c616e6473706f7274756775c3aa73d7a2d791d7a8d799d7aad981d8a7
      d8b1d8b3db8c6465736172726f6c6c6f636f6d656e746172696f656475636163
      69c3b36e7365707469656d6272657265676973747261646f64697265636369c3
      b36e75626963616369c3b36e7075626c69636964616472657370756573746173



Alakuijala & Szabadka         Informational                    [Page 83]

RFC 7932                         Brotli                        July 2016


      726573756c7461646f73696d706f7274616e746572657365727661646f736172
      74c3ad63756c6f736469666572656e7465737369677569656e746573726570c3
      ba626c69636173697475616369c3b36e6d696e6973746572696f707269766163
      696461646469726563746f72696f666f726d616369c3b36e706f626c616369c3
      b36e707265736964656e7465636f6e74656e69646f7361636365736f72696f73
      746563686e6f72617469706572736f6e616c657363617465676f72c3ad616573
      70656369616c6573646973706f6e69626c6561637475616c6964616472656665
      72656e63696176616c6c61646f6c69646269626c696f7465636172656c616369
      6f6e657363616c656e646172696f706f6cc3ad7469636173616e746572696f72
      6573646f63756d656e746f736e61747572616c657a616d6174657269616c6573
      6469666572656e63696165636f6ec3b36d6963617472616e73706f727465726f
      6472c3ad6775657a70617274696369706172656e6375656e7472616e64697363
      757369c3b36e6573747275637475726166756e64616369c3b36e667265637565
      6e7465737065726d616e656e7465746f74616c6d656e7465d0bcd0bed0b6d0bd
      d0bed0b1d183d0b4d0b5d182d0bcd0bed0b6d0b5d182d0b2d180d0b5d0bcd18f
      d182d0b0d0bad0b6d0b5d187d182d0bed0b1d18bd0b1d0bed0bbd0b5d0b5d0be
      d187d0b5d0bdd18cd18dd182d0bed0b3d0bed0bad0bed0b3d0b4d0b0d0bfd0be
      d181d0bbd0b5d0b2d181d0b5d0b3d0bed181d0b0d0b9d182d0b5d187d0b5d180
      d0b5d0b7d0bcd0bed0b3d183d182d181d0b0d0b9d182d0b0d0b6d0b8d0b7d0bd
      d0b8d0bcd0b5d0b6d0b4d183d0b1d183d0b4d183d182d09fd0bed0b8d181d0ba
      d0b7d0b4d0b5d181d18cd0b2d0b8d0b4d0b5d0bed181d0b2d18fd0b7d0b8d0bd
      d183d0b6d0bdd0bed181d0b2d0bed0b5d0b9d0bbd18ed0b4d0b5d0b9d0bfd0be
      d180d0bdd0bed0bcd0bdd0bed0b3d0bed0b4d0b5d182d0b5d0b9d181d0b2d0be
      d0b8d185d0bfd180d0b0d0b2d0b0d182d0b0d0bad0bed0b9d0bcd0b5d181d182
      d0bed0b8d0bcd0b5d0b5d182d0b6d0b8d0b7d0bdd18cd0bed0b4d0bdd0bed0b9
      d0bbd183d187d188d0b5d0bfd0b5d180d0b5d0b4d187d0b0d181d182d0b8d187
      d0b0d181d182d18cd180d0b0d0b1d0bed182d0bdd0bed0b2d18bd185d0bfd180
      d0b0d0b2d0bed181d0bed0b1d0bed0b9d0bfd0bed182d0bed0bcd0bcd0b5d0bd
      d0b5d0b5d187d0b8d181d0bbd0b5d0bdd0bed0b2d18bd0b5d183d181d0bbd183
      d0b3d0bed0bad0bed0bbd0bed0bdd0b0d0b7d0b0d0b4d182d0b0d0bad0bed0b5
      d182d0bed0b3d0b4d0b0d0bfd0bed187d182d0b8d09fd0bed181d0bbd0b5d182
      d0b0d0bad0b8d0b5d0bdd0bed0b2d18bd0b9d181d182d0bed0b8d182d182d0b0
      d0bad0b8d185d181d180d0b0d0b7d183d0a1d0b0d0bdd0bad182d184d0bed180
      d183d0bcd09ad0bed0b3d0b4d0b0d0bad0bdd0b8d0b3d0b8d181d0bbd0bed0b2
      d0b0d0bdd0b0d188d0b5d0b9d0bdd0b0d0b9d182d0b8d181d0b2d0bed0b8d0bc
      d181d0b2d18fd0b7d18cd0bbd18ed0b1d0bed0b9d187d0b0d181d182d0bed181
      d180d0b5d0b4d0b8d09ad180d0bed0bcd0b5d0a4d0bed180d183d0bcd180d18b
      d0bdd0bad0b5d181d182d0b0d0bbd0b8d0bfd0bed0b8d181d0bad182d18bd181
      d18fd187d0bcd0b5d181d18fd186d186d0b5d0bdd182d180d182d180d183d0b4
      d0b0d181d0b0d0bcd18bd185d180d18bd0bdd0bad0b0d09dd0bed0b2d18bd0b9
      d187d0b0d181d0bed0b2d0bcd0b5d181d182d0b0d184d0b8d0bbd18cd0bcd0bc
      d0b0d180d182d0b0d181d182d180d0b0d0bdd0bcd0b5d181d182d0b5d182d0b5
      d0bad181d182d0bdd0b0d188d0b8d185d0bcd0b8d0bdd183d182d0b8d0bcd0b5
      d0bdd0b8d0b8d0bcd0b5d18ed182d0bdd0bed0bcd0b5d180d0b3d0bed180d0be
      d0b4d181d0b0d0bcd0bed0bcd18dd182d0bed0bcd183d0bad0bed0bdd186d0b5
      d181d0b2d0bed0b5d0bcd0bad0b0d0bad0bed0b9d090d180d185d0b8d0b2d985
      d986d8aad8afd989d8a5d8b1d8b3d8a7d984d8b1d8b3d8a7d984d8a9d8a7d984
      d8b9d8a7d985d983d8aad8a8d987d8a7d8a8d8b1d8a7d985d8acd8a7d984d98a



Alakuijala & Szabadka         Informational                    [Page 84]

RFC 7932                         Brotli                        July 2016


      d988d985d8a7d984d8b5d988d8b1d8acd8afd98ad8afd8a9d8a7d984d8b9d8b6
      d988d8a5d8b6d8a7d981d8a9d8a7d984d982d8b3d985d8a7d984d8b9d8a7d8a8
      d8aad8add985d98ad984d985d984d981d8a7d8aad985d984d8aad982d989d8aa
      d8b9d8afd98ad984d8a7d984d8b4d8b9d8b1d8a3d8aed8a8d8a7d8b1d8aad8b7
      d988d98ad8b1d8b9d984d98ad983d985d8a5d8b1d981d8a7d982d8b7d984d8a8
      d8a7d8aad8a7d984d984d8bad8a9d8aad8b1d8aad98ad8a8d8a7d984d986d8a7
      d8b3d8a7d984d8b4d98ad8aed985d986d8aad8afd98ad8a7d984d8b9d8b1d8a8
      d8a7d984d982d8b5d8b5d8a7d981d984d8a7d985d8b9d984d98ad987d8a7d8aa
      d8add8afd98ad8abd8a7d984d984d987d985d8a7d984d8b9d985d984d985d983
      d8aad8a8d8a9d98ad985d983d986d983d8a7d984d8b7d981d984d981d98ad8af
      d98ad988d8a5d8afd8a7d8b1d8a9d8aad8a7d8b1d98ad8aed8a7d984d8b5d8ad
      d8a9d8aad8b3d8acd98ad984d8a7d984d988d982d8aad8b9d986d8afd985d8a7
      d985d8afd98ad986d8a9d8aad8b5d985d98ad985d8a3d8b1d8b4d98ad981d8a7
      d984d8b0d98ad986d8b9d8b1d8a8d98ad8a9d8a8d988d8a7d8a8d8a9d8a3d984
      d8b9d8a7d8a8d8a7d984d8b3d981d8b1d985d8b4d8a7d983d984d8aad8b9d8a7
      d984d989d8a7d984d8a3d988d984d8a7d984d8b3d986d8a9d8acd8a7d985d8b9
      d8a9d8a7d984d8b5d8add981d8a7d984d8afd98ad986d983d984d985d8a7d8aa
      d8a7d984d8aed8a7d8b5d8a7d984d985d984d981d8a3d8b9d8b6d8a7d8a1d983
      d8aad8a7d8a8d8a9d8a7d984d8aed98ad8b1d8b1d8b3d8a7d8a6d984d8a7d984
      d982d984d8a8d8a7d984d8a3d8afd8a8d985d982d8a7d8b7d8b9d985d8b1d8a7
      d8b3d984d985d986d8b7d982d8a9d8a7d984d983d8aad8a8d8a7d984d8b1d8ac
      d984d8a7d8b4d8aad8b1d983d8a7d984d982d8afd985d98ad8b9d8b7d98ad983
      7342795461674e616d65282e6a70672220616c743d2231707820736f6c696420
      232e6769662220616c743d227472616e73706172656e74696e666f726d617469
      6f6e6170706c69636174696f6e22206f6e636c69636b3d2265737461626c6973
      6865646164766572746973696e672e706e672220616c743d22656e7669726f6e
      6d656e74706572666f726d616e6365617070726f70726961746526616d703b6d
      646173683b696d6d6564696174656c793c2f7374726f6e673e3c2f7261746865
      72207468616e74656d7065726174757265646576656c6f706d656e74636f6d70
      65746974696f6e706c616365686f6c6465727669736962696c6974793a636f70
      797269676874223e3022206865696768743d226576656e2074686f7567687265
      706c6163656d656e7464657374696e6174696f6e436f72706f726174696f6e3c
      756c20636c6173733d224173736f63696174696f6e696e646976696475616c73
      706572737065637469766573657454696d656f75742875726c28687474703a2f
      2f6d617468656d61746963736d617267696e2d746f703a6576656e7475616c6c
      79206465736372697074696f6e29206e6f2d726570656174636f6c6c65637469
      6f6e732e4a50477c7468756d627c70617274696369706174652f686561643e3c
      626f6479666c6f61743a6c6566743b3c6c6920636c6173733d2268756e647265
      6473206f660a0a486f77657665722c20636f6d706f736974696f6e636c656172
      3a626f74683b636f6f7065726174696f6e77697468696e20746865206c616265
      6c20666f723d22626f726465722d746f703a4e6577205a65616c616e64726563
      6f6d6d656e64656470686f746f677261706879696e746572657374696e67266c
      743b7375702667743b636f6e74726f76657273794e65746865726c616e647361
      6c7465726e61746976656d61786c656e6774683d22737769747a65726c616e64
      446576656c6f706d656e74657373656e7469616c6c790a0a416c74686f756768
      203c2f74657874617265613e7468756e64657262697264726570726573656e74
      656426616d703b6e646173683b73706563756c6174696f6e636f6d6d756e6974
      6965736c656769736c6174696f6e656c656374726f6e6963730a093c64697620



Alakuijala & Szabadka         Informational                    [Page 85]

RFC 7932                         Brotli                        July 2016


      69643d22696c6c7573747261746564656e67696e656572696e67746572726974
      6f72696573617574686f72697469657364697374726962757465643622206865
      696768743d2273616e732d73657269663b63617061626c65206f662064697361
      70706561726564696e7465726163746976656c6f6f6b696e6720666f72697420
      776f756c6420626541666768616e697374616e77617320637265617465644d61
      74682e666c6f6f7228737572726f756e64696e6763616e20616c736f2062656f
      62736572766174696f6e6d61696e74656e616e6365656e636f756e7465726564
      3c683220636c6173733d226d6f726520726563656e7469742068617320626565
      6e696e766173696f6e206f66292e67657454696d65282966756e64616d656e74
      616c4465737069746520746865223e3c6469762069643d22696e737069726174
      696f6e6578616d696e6174696f6e7072657061726174696f6e6578706c616e61
      74696f6e3c696e7075742069643d223c2f613e3c2f7370616e3e76657273696f
      6e73206f66696e737472756d656e74736265666f72652074686520203d202768
      7474703a2f2f4465736372697074696f6e72656c61746976656c79202e737562
      737472696e672865616368206f66207468656578706572696d656e7473696e66
      6c75656e7469616c696e746567726174696f6e6d616e792070656f706c656475
      6520746f2074686520636f6d62696e6174696f6e646f206e6f7420686176654d
      6964646c6520456173743c6e6f7363726970743e3c636f707972696768742220
      7065726861707320746865696e737469747574696f6e696e20446563656d6265
      72617272616e67656d656e746d6f73742066616d6f7573706572736f6e616c69
      74796372656174696f6e206f666c696d69746174696f6e736578636c75736976
      656c79736f7665726569676e74792d636f6e74656e74223e0a3c746420636c61
      73733d22756e64657267726f756e64706172616c6c656c20746f646f63747269
      6e65206f666f636375706965642062797465726d696e6f6c6f677952656e6169
      7373616e636561206e756d626572206f66737570706f727420666f726578706c
      6f726174696f6e7265636f676e6974696f6e7072656465636573736f723c696d
      67207372633d222f3c683120636c6173733d227075626c69636174696f6e6d61
      7920616c736f2062657370656369616c697a65643c2f6669656c647365743e70
      726f67726573736976656d696c6c696f6e73206f667374617465732074686174
      656e666f7263656d656e7461726f756e6420746865206f6e6520616e6f746865
      722e706172656e744e6f64656167726963756c74757265416c7465726e617469
      76657265736561726368657273746f7761726473207468654d6f7374206f6620
      7468656d616e79206f746865722028657370656369616c6c793c746420776964
      74683d223b77696474683a31303025696e646570656e64656e743c683320636c
      6173733d22206f6e6368616e67653d22292e616464436c61737328696e746572
      616374696f6e4f6e65206f6620746865206461756768746572206f6661636365
      73736f726965736272616e63686573206f660d0a3c6469762069643d22746865
      206c6172676573746465636c61726174696f6e726567756c6174696f6e73496e
      666f726d6174696f6e7472616e736c6174696f6e646f63756d656e7461727969
      6e206f7264657220746f223e0a3c686561643e0a3c22206865696768743d2231
      6163726f737320746865206f7269656e746174696f6e293b3c2f736372697074
      3e696d706c656d656e74656463616e206265207365656e746865726520776173
      206164656d6f6e737472617465636f6e7461696e6572223e636f6e6e65637469
      6f6e737468652042726974697368776173207772697474656e21696d706f7274
      616e743b70783b206d617267696e2d666f6c6c6f7765642062796162696c6974
      7920746f20636f6d706c696361746564647572696e672074686520696d6d6967
      726174696f6e616c736f2063616c6c65643c683420636c6173733d2264697374
      696e6374696f6e7265706c61636564206279676f7665726e6d656e74736c6f63



Alakuijala & Szabadka         Informational                    [Page 86]

RFC 7932                         Brotli                        July 2016


      6174696f6e206f66696e204e6f76656d62657277686574686572207468653c2f
      703e0a3c2f6469763e6163717569736974696f6e63616c6c6564207468652070
      65727365637574696f6e64657369676e6174696f6e7b666f6e742d73697a653a
      617070656172656420696e696e766573746967617465657870657269656e6365
      646d6f7374206c696b656c79776964656c79207573656464697363757373696f
      6e7370726573656e6365206f662028646f63756d656e742e657874656e736976
      656c79497420686173206265656e697420646f6573206e6f74636f6e74726172
      7920746f696e6861626974616e7473696d70726f76656d656e747363686f6c61
      7273686970636f6e73756d7074696f6e696e737472756374696f6e666f722065
      78616d706c656f6e65206f72206d6f726570783b2070616464696e6774686520
      63757272656e746120736572696573206f6661726520757375616c6c79726f6c
      6520696e2074686570726576696f75736c792064657269766174697665736576
      6964656e6365206f66657870657269656e636573636f6c6f72736368656d6573
      7461746564207468617463657274696669636174653c2f613e3c2f6469763e0a
      2073656c65637465643d2268696768207363686f6f6c726573706f6e73652074
      6f636f6d666f727461626c6561646f7074696f6e206f66746872656520796561
      727374686520636f756e747279696e204665627275617279736f207468617420
      74686570656f706c652077686f2070726f76696465642062793c706172616d20
      6e616d656166666563746564206279696e207465726d73206f666170706f696e
      746d656e7449534f2d383835392d312277617320626f726e20696e686973746f
      726963616c2072656761726465642061736d6561737572656d656e7469732062
      61736564206f6e20616e64206f74686572203a2066756e6374696f6e28736967
      6e69666963616e7463656c6562726174696f6e7472616e736d69747465642f6a
      732f6a71756572792e6973206b6e6f776e2061737468656f7265746963616c20
      746162696e6465783d22697420636f756c642062653c6e6f7363726970743e0a
      686176696e67206265656e0d0a3c686561643e0d0a3c202671756f743b546865
      20636f6d70696c6174696f6e686520686164206265656e70726f647563656420
      62797068696c6f736f70686572636f6e7374727563746564696e74656e646564
      20746f616d6f6e67206f74686572636f6d706172656420746f746f2073617920
      74686174456e67696e656572696e676120646966666572656e74726566657272
      656420746f646966666572656e63657362656c696566207468617470686f746f
      6772617068736964656e74696679696e67486973746f7279206f662052657075
      626c6963206f666e65636573736172696c7970726f626162696c697479746563
      686e6963616c6c796c656176696e672074686573706563746163756c61726672
      616374696f6e206f66656c65637472696369747968656164206f662074686572
      657374617572616e7473706172746e657273686970656d706861736973206f6e
      6d6f737420726563656e747368617265207769746820736179696e6720746861
      7466696c6c6564207769746864657369676e656420746f6974206973206f6674
      656e223e3c2f696672616d653e617320666f6c6c6f77733a6d65726765642077
      6974687468726f75676820746865636f6d6d65726369616c20706f696e746564
      206f75746f70706f7274756e69747976696577206f6620746865726571756972
      656d656e746469766973696f6e206f6670726f6772616d6d696e676865207265
      636569766564736574496e74657276616c223e3c2f7370616e3e3c2f696e204e
      657720596f726b6164646974696f6e616c20636f6d7072657373696f6e0a0a3c
      6469762069643d22696e636f72706f726174653b3c2f7363726970743e3c6174
      746163684576656e74626563616d65207468652022207461726765743d225f63
      617272696564206f7574536f6d65206f6620746865736369656e636520616e64
      7468652074696d65206f66436f6e7461696e6572223e6d61696e7461696e696e



Alakuijala & Szabadka         Informational                    [Page 87]

RFC 7932                         Brotli                        July 2016


      674368726973746f706865724d756368206f662074686577726974696e677320
      6f6622206865696768743d223273697a65206f662074686576657273696f6e20
      6f66206d697874757265206f66206265747765656e207468654578616d706c65
      73206f66656475636174696f6e616c636f6d7065746974697665206f6e737562
      6d69743d226469726563746f72206f6664697374696e63746976652f44544420
      5848544d4c2072656c6174696e6720746f74656e64656e637920746f70726f76
      696e6365206f66776869636820776f756c646465737069746520746865736369
      656e7469666963206c656769736c61747572652e696e6e657248544d4c20616c
      6c65676174696f6e734167726963756c74757265776173207573656420696e61
      7070726f61636820746f696e74656c6c6967656e747965617273206c61746572
      2c73616e732d736572696664657465726d696e696e67506572666f726d616e63
      65617070656172616e6365732c20776869636820697320666f756e646174696f
      6e736162627265766961746564686967686572207468616e732066726f6d2074
      686520696e646976696475616c20636f6d706f736564206f66737570706f7365
      6420746f636c61696d7320746861746174747269627574696f6e666f6e742d73
      697a653a31656c656d656e7473206f66486973746f726963616c206869732062
      726f746865726174207468652074696d65616e6e6976657273617279676f7665
      726e656420627972656c6174656420746f20756c74696d6174656c7920696e6e
      6f766174696f6e736974206973207374696c6c63616e206f6e6c792062656465
      66696e6974696f6e73746f474d54537472696e6741206e756d626572206f6669
      6d6720636c6173733d224576656e7475616c6c792c776173206368616e676564
      6f6363757272656420696e6e65696768626f72696e6764697374696e67756973
      687768656e20686520776173696e74726f647563696e67746572726573747269
      616c4d616e79206f66207468656172677565732074686174616e20416d657269
      63616e636f6e7175657374206f66776964657370726561642077657265206b69
      6c6c656473637265656e20616e6420496e206f7264657220746f657870656374
      656420746f64657363656e64616e7473617265206c6f63617465646c65676973
      6c617469766567656e65726174696f6e73206261636b67726f756e646d6f7374
      2070656f706c6579656172732061667465727468657265206973206e6f746865
      20686967686573746672657175656e746c79207468657920646f206e6f746172
      67756564207468617473686f7765642074686174707265646f6d696e616e7474
      68656f6c6f676963616c6279207468652074696d65636f6e7369646572696e67
      73686f72742d6c697665643c2f7370616e3e3c2f613e63616e20626520757365
      6476657279206c6974746c656f6e65206f66207468652068616420616c726561
      6479696e746572707265746564636f6d6d756e69636174656665617475726573
      206f66676f7665726e6d656e742c3c2f6e6f7363726970743e656e7465726564
      2074686522206865696768743d2233496e646570656e64656e74706f70756c61
      74696f6e736c617267652d7363616c652e20416c74686f756768207573656420
      696e207468656465737472756374696f6e706f73736962696c69747973746172
      74696e6720696e74776f206f72206d6f726565787072657373696f6e73737562
      6f7264696e6174656c6172676572207468616e686973746f727920616e643c2f
      6f7074696f6e3e0d0a436f6e74696e656e74616c656c696d696e6174696e6777
      696c6c206e6f742062657072616374696365206f66696e2066726f6e74206f66
      73697465206f6620746865656e737572652074686174746f2063726561746520
      616d69737369737369707069706f74656e7469616c6c796f75747374616e6469
      6e67626574746572207468616e77686174206973206e6f777369747561746564
      20696e6d657461206e616d653d22547261646974696f6e616c73756767657374
      696f6e735472616e736c6174696f6e74686520666f726d206f6661746d6f7370



Alakuijala & Szabadka         Informational                    [Page 88]

RFC 7932                         Brotli                        July 2016


      68657269636964656f6c6f676963616c656e74657270726973657363616c6375
      6c6174696e6765617374206f662074686572656d6e616e7473206f66706c7567
      696e73706167652f696e6465782e7068703f72656d61696e656420696e747261
      6e73666f726d656448652077617320616c736f77617320616c72656164797374
      61746973746963616c696e206661766f72206f664d696e6973747279206f666d
      6f76656d656e74206f66666f726d756c6174696f6e6973207265717569726564
      3c6c696e6b2072656c3d225468697320697320746865203c6120687265663d22
      2f706f70756c6172697a6564696e766f6c76656420696e617265207573656420
      746f616e64207365766572616c6d616465206279207468657365656d7320746f
      2062656c696b656c79207468617450616c657374696e69616e6e616d65642061
      66746572697420686164206265656e6d6f737420636f6d6d6f6e746f20726566
      657220746f6275742074686973206973636f6e736563757469766574656d706f
      726172696c79496e2067656e6572616c2c636f6e76656e74696f6e7374616b65
      7320706c6163657375626469766973696f6e7465727269746f7269616c6f7065
      726174696f6e616c7065726d616e656e746c79776173206c617267656c796f75
      74627265616b206f66696e207468652070617374666f6c6c6f77696e67206120
      786d6c6e733a6f673d223e3c6120636c6173733d22636c6173733d2274657874
      436f6e76657273696f6e206d617920626520757365646d616e75666163747572
      656166746572206265696e67636c656172666978223e0a7175657374696f6e20
      6f6677617320656c6563746564746f206265636f6d6520616265636175736520
      6f6620736f6d652070656f706c65696e73706972656420627973756363657373
      66756c20612074696d65207768656e6d6f726520636f6d6d6f6e616d6f6e6773
      7420746865616e206f6666696369616c77696474683a313030253b746563686e
      6f6c6f67792c7761732061646f70746564746f206b6565702074686573657474
      6c656d656e74736c69766520626972746873696e6465782e68746d6c22436f6e
      6e6563746963757461737369676e656420746f26616d703b74696d65733b6163
      636f756e7420666f72616c69676e3d726967687474686520636f6d70616e7961
      6c77617973206265656e72657475726e656420746f696e766f6c76656d656e74
      42656361757365207468657468697320706572696f6422206e616d653d227122
      20636f6e66696e656420746f6120726573756c74206f6676616c75653d222220
      2f3e69732061637475616c6c79456e7669726f6e6d656e740d0a3c2f68656164
      3e0d0a436f6e76657273656c792c3e0a3c6469762069643d2230222077696474
      683d223169732070726f6261626c7968617665206265636f6d65636f6e74726f
      6c6c696e677468652070726f626c656d636974697a656e73206f66706f6c6974
      696369616e7372656163686564207468656173206561726c792061733a6e6f6e
      653b206f7665723c7461626c652063656c6c76616c6964697479206f66646972
      6563746c7920746f6f6e6d6f757365646f776e77686572652069742069737768
      656e206974207761736d656d62657273206f662072656c6174696f6e20746f61
      63636f6d6d6f64617465616c6f6e67207769746820496e20746865206c617465
      74686520456e676c69736864656c6963696f7573223e74686973206973206e6f
      747468652070726573656e746966207468657920617265616e642066696e616c
      6c7961206d6174746572206f660d0a093c2f6469763e0d0a0d0a3c2f73637269
      70743e666173746572207468616e6d616a6f72697479206f6661667465722077
      68696368636f6d7061726174697665746f206d61696e7461696e696d70726f76
      6520746865617761726465642074686565722220636c6173733d226672616d65
      626f72646572726573746f726174696f6e696e207468652073616d65616e616c
      79736973206f667468656972206669727374447572696e672074686520636f6e
      74696e656e74616c73657175656e6365206f6666756e6374696f6e28297b666f



Alakuijala & Szabadka         Informational                    [Page 89]

RFC 7932                         Brotli                        July 2016


      6e742d73697a653a20776f726b206f6e207468653c2f7363726970743e0a3c62
      6567696e7320776974686a6176617363726970743a636f6e7374697475656e74
      77617320666f756e646564657175696c69627269756d617373756d6520746861
      74697320676976656e2062796e6565647320746f206265636f6f7264696e6174
      657374686520766172696f75736172652070617274206f666f6e6c7920696e20
      74686573656374696f6e73206f666973206120636f6d6d6f6e7468656f726965
      73206f66646973636f7665726965736173736f63696174696f6e65646765206f
      6620746865737472656e677468206f66706f736974696f6e20696e7072657365
      6e742d646179756e6976657273616c6c79746f20666f726d2074686562757420
      696e7374656164636f72706f726174696f6e617474616368656420746f697320
      636f6d6d6f6e6c79726561736f6e7320666f72202671756f743b746865206361
      6e206265206d6164657761732061626c6520746f7768696368206d65616e7362
      757420646964206e6f746f6e4d6f7573654f766572617320706f737369626c65
      6f70657261746564206279636f6d696e672066726f6d746865207072696d6172
      796164646974696f6e206f66666f72207365766572616c7472616e7366657272
      65646120706572696f64206f666172652061626c6520746f686f77657665722c
      20697473686f756c6420686176656d756368206c61726765720a093c2f736372
      6970743e61646f707465642074686570726f7065727479206f66646972656374
      65642062796566666563746976656c797761732062726f756768746368696c64
      72656e206f6650726f6772616d6d696e676c6f6e676572207468616e6d616e75
      7363726970747377617220616761696e73746279206d65616e73206f66616e64
      206d6f7374206f6673696d696c617220746f2070726f70726965746172796f72
      6967696e6174696e6770726573746967696f75736772616d6d61746963616c65
      7870657269656e63652e746f206d616b652074686549742077617320616c736f
      697320666f756e6420696e636f6d70657469746f7273696e2074686520552e53
      2e7265706c6163652074686562726f756768742074686563616c63756c617469
      6f6e66616c6c206f66207468657468652067656e6572616c7072616374696361
      6c6c79696e20686f6e6f72206f6672656c656173656420696e7265736964656e
      7469616c616e6420736f6d65206f666b696e67206f6620746865726561637469
      6f6e20746f317374204561726c206f6663756c7475726520616e647072696e63
      6970616c6c793c2f7469746c653e0a2020746865792063616e2062656261636b
      20746f20746865736f6d65206f66206869736578706f7375726520746f617265
      2073696d696c6172666f726d206f66207468656164644661766f726974656369
      74697a656e736869707061727420696e2074686570656f706c65207769746869
      6e207072616374696365746f20636f6e74696e756526616d703b6d696e75733b
      617070726f7665642062792074686520666972737420616c6c6f776564207468
      65616e6420666f722074686566756e6374696f6e696e67706c6179696e672074
      6865736f6c7574696f6e20746f6865696768743d22302220696e206869732062
      6f6f6b6d6f7265207468616e2061666f6c6c6f77732074686563726561746564
      2074686570726573656e636520696e266e6273703b3c2f74643e6e6174696f6e
      616c6973747468652069646561206f6661206368617261637465727765726520
      666f7263656420636c6173733d2262746e64617973206f662074686566656174
      7572656420696e73686f77696e6720746865696e74657265737420696e696e20
      706c616365206f667475726e206f66207468657468652068656164206f664c6f
      7264206f6620746865706f6c69746963616c6c7968617320697473206f776e45
      6475636174696f6e616c617070726f76616c206f66736f6d65206f6620746865
      65616368206f746865722c6265686176696f72206f66616e6420626563617573
      65616e6420616e6f746865726170706561726564206f6e7265636f7264656420



Alakuijala & Szabadka         Informational                    [Page 90]

RFC 7932                         Brotli                        July 2016


      696e626c61636b2671756f743b6d617920696e636c75646574686520776f726c
      64277363616e206c65616420746f72656665727320746f2061626f726465723d
      22302220676f7665726e6d656e742077696e6e696e6720746865726573756c74
      656420696e207768696c65207468652057617368696e67746f6e2c7468652073
      75626a6563746369747920696e207468653e3c2f6469763e0d0a09097265666c
      65637420746865746f20636f6d706c657465626563616d65206d6f7265726164
      696f61637469766572656a6563746564206279776974686f757420616e796869
      73206661746865722c776869636820636f756c64636f7079206f662074686574
      6f20696e6469636174656120706f6c69746963616c6163636f756e7473206f66
      636f6e7374697475746573776f726b6564207769746865723c2f613e3c2f6c69
      3e6f6620686973206c6966656163636f6d70616e696564636c69656e74576964
      746870726576656e74207468654c656769736c6174697665646966666572656e
      746c79746f67657468657220696e686173207365766572616c666f7220616e6f
      7468657274657874206f6620746865666f756e64656420746865652077697468
      20746865206973207573656420666f726368616e67656420746865757375616c
      6c7920746865706c61636520776865726577686572656173207468653e203c61
      20687265663d22223e3c6120687265663d227468656d73656c7665732c616c74
      686f756768206865746861742063616e206265747261646974696f6e616c726f
      6c65206f66207468656173206120726573756c7472656d6f76654368696c6464
      657369676e656420627977657374206f6620746865536f6d652070656f706c65
      70726f64756374696f6e2c73696465206f66207468656e6577736c6574746572
      737573656420627920746865646f776e20746f20746865616363657074656420
      62796c69766520696e20746865617474656d70747320746f6f75747369646520
      7468656672657175656e63696573486f77657665722c20696e70726f6772616d
      6d6572736174206c6561737420696e617070726f78696d617465616c74686f75
      67682069747761732070617274206f66616e6420766172696f7573476f766572
      6e6f72206f667468652061727469636c657475726e656420696e746f3e3c6120
      687265663d222f7468652065636f6e6f6d79697320746865206d6f73746d6f73
      7420776964656c79776f756c64206c61746572616e6420706572686170737269
      736520746f207468656f6363757273207768656e756e64657220776869636863
      6f6e646974696f6e732e746865207765737465726e7468656f72792074686174
      69732070726f64756365647468652063697479206f66696e2077686963682068
      657365656e20696e207468657468652063656e7472616c6275696c64696e6720
      6f666d616e79206f662068697361726561206f6620746865697320746865206f
      6e6c796d6f7374206f66207468656d616e79206f662074686574686520576573
      7465726e5468657265206973206e6f657874656e64656420746f537461746973
      746963616c636f6c7370616e3d32207c73686f72742073746f7279706f737369
      626c6520746f746f706f6c6f676963616c637269746963616c206f667265706f
      7274656420746f612043687269737469616e6465636973696f6e20746f697320
      657175616c20746f70726f626c656d73206f66546869732063616e2062656d65
      726368616e64697365666f72206d6f7374206f666e6f2065766964656e636565
      646974696f6e73206f66656c656d656e747320696e2671756f743b2e20546865
      636f6d2f696d616765732f7768696368206d616b65737468652070726f636573
      7372656d61696e73207468656c6974657261747572652c69732061206d656d62
      657274686520706f70756c617274686520616e6369656e7470726f626c656d73
      20696e74696d65206f66207468656465666561746564206279626f6479206f66
      2074686561206665772079656172736d756368206f662074686574686520776f
      726b206f6643616c69666f726e69612c7365727665642061732061676f766572



Alakuijala & Szabadka         Informational                    [Page 91]

RFC 7932                         Brotli                        July 2016


      6e6d656e742e636f6e6365707473206f666d6f76656d656e7420696e09093c64
      69762069643d226974222076616c75653d226c616e6775616765206f66617320
      746865792061726570726f647563656420696e69732074686174207468656578
      706c61696e207468656469763e3c2f6469763e0a486f7765766572207468656c
      65616420746f20746865093c6120687265663d222f776173206772616e746564
      70656f706c652068617665636f6e74696e75616c6c79776173207365656e2061
      73616e642072656c6174656474686520726f6c65206f6670726f706f73656420
      62796f6620746865206265737465616368206f746865722e436f6e7374616e74
      696e6570656f706c652066726f6d6469616c65637473206f66746f2072657669
      73696f6e7761732072656e616d65646120736f75726365206f6674686520696e
      697469616c6c61756e6368656420696e70726f7669646520746865746f207468
      6520776573747768657265207468657265616e642073696d696c617262657477
      65656e2074776f697320616c736f20746865456e676c69736820616e64636f6e
      646974696f6e732c7468617420697420776173656e7469746c656420746f7468
      656d73656c7665732e7175616e74697479206f6672616e73706172656e637974
      68652073616d65206173746f206a6f696e20746865636f756e74727920616e64
      746869732069732074686554686973206c656420746f612073746174656d656e
      74636f6e747261737420746f6c617374496e6465784f667468726f7567682068
      697369732064657369676e6564746865207465726d20697369732070726f7669
      64656470726f74656374207468656e673c2f613e3c2f6c693e54686520637572
      72656e747468652073697465206f667375627374616e7469616c657870657269
      656e63652c696e207468652057657374746865792073686f756c64736c6f7665
      6ec48d696e61636f6d656e746172696f73756e697665727369646164636f6e64
      6963696f6e65736163746976696461646573657870657269656e636961746563
      6e6f6c6f67c3ad6170726f6475636369c3b36e70756e7475616369c3b36e6170
      6c6963616369c3b36e636f6e7472617365c3b16163617465676f72c3ad617372
      6567697374726172736570726f666573696f6e616c74726174616d69656e746f
      726567c3ad7374726174657365637265746172c3ad617072696e636970616c65
      7370726f7465636369c3b36e696d706f7274616e746573696d706f7274616e63
      6961706f736962696c69646164696e7465726573616e746563726563696d6965
      6e746f6e65636573696461646573737573637269626972736561736f63696163
      69c3b36e646973706f6e69626c65736576616c75616369c3b36e657374756469
      616e746573726573706f6e7361626c657265736f6c756369c3b36e6775616461
      6c616a6172617265676973747261646f736f706f7274756e69646164636f6d65
      726369616c6573666f746f67726166c3ad616175746f72696461646573696e67
      656e696572c3ad6174656c6576697369c3b36e636f6d706574656e6369616f70
      65726163696f6e657365737461626c656369646f73696d706c656d656e746561
      637475616c6d656e74656e61766567616369c3b36e636f6e666f726d69646164
      6c696e652d6865696768743a666f6e742d66616d696c793a22203a2022687474
      703a2f2f6170706c69636174696f6e736c696e6b2220687265663d2273706563
      69666963616c6c792f2f3c215b43444154415b0a4f7267616e697a6174696f6e
      646973747269627574696f6e3070783b206865696768743a72656c6174696f6e
      736869706465766963652d77696474683c64697620636c6173733d223c6c6162
      656c20666f723d22726567697374726174696f6e3c2f6e6f7363726970743e0a
      2f696e6465782e68746d6c2277696e646f772e6f70656e282021696d706f7274
      616e743b6170706c69636174696f6e2f696e646570656e64656e63652f2f7777
      772e676f6f676c656f7267616e697a6174696f6e6175746f636f6d706c657465
      726571756972656d656e7473636f6e7365727661746976653c666f726d206e61



Alakuijala & Szabadka         Informational                    [Page 92]

RFC 7932                         Brotli                        July 2016


      6d653d22696e74656c6c65637475616c6d617267696e2d6c6566743a31387468
      2063656e74757279616e20696d706f7274616e74696e737469747574696f6e73
      616262726576696174696f6e3c696d6720636c6173733d226f7267616e697361
      74696f6e636976696c697a6174696f6e313974682063656e7475727961726368
      6974656374757265696e636f72706f7261746564323074682063656e74757279
      2d636f6e7461696e6572223e6d6f7374206e6f7461626c792f3e3c2f613e3c2f
      6469763e6e6f74696669636174696f6e27756e646566696e6564272946757274
      6865726d6f72652c62656c696576652074686174696e6e657248544d4c203d20
      7072696f7220746f207468656472616d61746963616c6c79726566657272696e
      6720746f6e65676f74696174696f6e73686561647175617274657273536f7574
      6820416672696361756e7375636365737366756c50656e6e73796c76616e6961
      4173206120726573756c742c3c68746d6c206c616e673d22266c743b2f737570
      2667743b6465616c696e6720776974687068696c6164656c7068696168697374
      6f726963616c6c79293b3c2f7363726970743e0a70616464696e672d746f703a
      6578706572696d656e74616c676574417474726962757465696e737472756374
      696f6e73746563686e6f6c6f6769657370617274206f6620746865203d66756e
      6374696f6e28297b737562736372697074696f6e6c2e647464223e0d0a3c6874
      67656f67726170686963616c436f6e737469747574696f6e272c2066756e6374
      696f6e28737570706f727465642062796167726963756c747572616c636f6e73
      7472756374696f6e7075626c69636174696f6e73666f6e742d73697a653a2031
      612076617269657479206f663c646976207374796c653d22456e6379636c6f70
      65646961696672616d65207372633d2264656d6f6e737472617465646163636f
      6d706c6973686564756e6976657273697469657344656d6f6772617068696373
      293b3c2f7363726970743e3c64656469636174656420746f6b6e6f776c656467
      65206f66736174697366616374696f6e706172746963756c61726c793c2f6469
      763e3c2f6469763e456e676c6973682028555329617070656e644368696c6428
      7472616e736d697373696f6e732e20486f77657665722c20696e74656c6c6967
      656e63652220746162696e6465783d22666c6f61743a72696768743b436f6d6d
      6f6e7765616c746872616e67696e672066726f6d696e20776869636820746865
      6174206c65617374206f6e65726570726f64756374696f6e656e6379636c6f70
      656469613b666f6e742d73697a653a316a7572697364696374696f6e61742074
      6861742074696d65223e3c6120636c6173733d22496e206164646974696f6e2c
      6465736372697074696f6e2b636f6e766572736174696f6e636f6e7461637420
      7769746869732067656e6572616c6c79722220636f6e74656e743d2272657072
      6573656e74696e67266c743b6d6174682667743b70726573656e746174696f6e
      6f63636173696f6e616c6c793c696d672077696474683d226e61766967617469
      6f6e223e636f6d70656e736174696f6e6368616d70696f6e736869706d656469
      613d22616c6c222076696f6c6174696f6e206f667265666572656e636520746f
      72657475726e20747275653b5374726963742f2f454e22207472616e73616374
      696f6e73696e74657276656e74696f6e766572696669636174696f6e496e666f
      726d6174696f6e20646966666963756c746965734368616d70696f6e73686970
      6361706162696c69746965733c215b656e6469665d2d2d3e7d0a3c2f73637269
      70743e0a43687269737469616e697479666f72206578616d706c652c50726f66
      657373696f6e616c7265737472696374696f6e73737567676573742074686174
      7761732072656c656173656428737563682061732074686572656d6f7665436c
      61737328756e656d706c6f796d656e7474686520416d65726963616e73747275
      6374757265206f662f696e6465782e68746d6c207075626c697368656420696e
      7370616e20636c6173733d22223e3c6120687265663d222f696e74726f647563



Alakuijala & Szabadka         Informational                    [Page 93]

RFC 7932                         Brotli                        July 2016


      74696f6e62656c6f6e67696e6720746f636c61696d65642074686174636f6e73
      657175656e6365733c6d657461206e616d653d22477569646520746f20746865
      6f7665727768656c6d696e67616761696e73742074686520636f6e63656e7472
      617465642c0a2e6e6f6e746f756368206f62736572766174696f6e733c2f613e
      0a3c2f6469763e0a662028646f63756d656e742e626f726465723a2031707820
      7b666f6e742d73697a653a3174726561746d656e74206f663022206865696768
      743d22316d6f64696669636174696f6e496e646570656e64656e636564697669
      64656420696e746f67726561746572207468616e616368696576656d656e7473
      65737461626c697368696e674a61766153637269707422206e65766572746865
      6c6573737369676e69666963616e636542726f616463617374696e673e266e62
      73703b3c2f74643e636f6e7461696e6572223e0a737563682061732074686520
      696e666c75656e6365206f666120706172746963756c61727372633d27687474
      703a2f2f6e617669676174696f6e222068616c66206f66207468652073756273
      74616e7469616c20266e6273703b3c2f6469763e616476616e74616765206f66
      646973636f76657279206f6666756e64616d656e74616c206d6574726f706f6c
      6974616e746865206f70706f736974652220786d6c3a6c616e673d2264656c69
      6265726174656c79616c69676e3d63656e74657265766f6c7574696f6e206f66
      707265736572766174696f6e696d70726f76656d656e7473626567696e6e696e
      6720696e4a65737573204368726973745075626c69636174696f6e7364697361
      677265656d656e74746578742d616c69676e3a722c2066756e6374696f6e2829
      73696d696c61726974696573626f64793e3c2f68746d6c3e6973206375727265
      6e746c79616c7068616265746963616c697320736f6d6574696d657374797065
      3d22696d6167652f6d616e79206f662074686520666c6f773a68696464656e3b
      617661696c61626c6520696e6465736372696265207468656578697374656e63
      65206f66616c6c206f7665722074686574686520496e7465726e6574093c756c
      20636c6173733d22696e7374616c6c6174696f6e6e65696768626f72686f6f64
      61726d656420666f726365737265647563696e6720746865636f6e74696e7565
      7320746f4e6f6e657468656c6573732c74656d7065726174757265730a09093c
      6120687265663d22636c6f736520746f207468656578616d706c6573206f6620
      69732061626f757420746865287365652062656c6f77292e222069643d227365
      6172636870726f66657373696f6e616c697320617661696c61626c6574686520
      6f6666696369616c09093c2f7363726970743e0a0a09093c6469762069643d22
      616363656c65726174696f6e7468726f756768207468652048616c6c206f6620
      46616d656465736372697074696f6e737472616e736c6174696f6e73696e7465
      72666572656e636520747970653d27746578742f726563656e74207965617273
      696e2074686520776f726c647665727920706f70756c61727b6261636b67726f
      756e643a747261646974696f6e616c20736f6d65206f662074686520636f6e6e
      656374656420746f6578706c6f69746174696f6e656d657267656e6365206f66
      636f6e737469747574696f6e4120486973746f7279206f667369676e69666963
      616e74206d616e7566616374757265646578706563746174696f6e733e3c6e6f
      7363726970743e3c63616e20626520666f756e64626563617573652074686520
      686173206e6f74206265656e6e65696768626f7572696e67776974686f757420
      74686520616464656420746f20746865093c6c6920636c6173733d22696e7374
      72756d656e74616c536f7669657420556e696f6e61636b6e6f776c6564676564
      77686963682063616e2062656e616d6520666f7220746865617474656e74696f
      6e20746f617474656d70747320746f20646576656c6f706d656e7473496e2066
      6163742c207468653c6c6920636c6173733d2261696d706c69636174696f6e73
      7375697461626c6520666f726d756368206f662074686520636f6c6f6e697a61



Alakuijala & Szabadka         Informational                    [Page 94]

RFC 7932                         Brotli                        July 2016


      74696f6e707265736964656e7469616c63616e63656c427562626c6520496e66
      6f726d6174696f6e6d6f7374206f662074686520697320646573637269626564
      72657374206f6620746865206d6f7265206f72206c657373696e205365707465
      6d626572496e74656c6c6967656e63657372633d22687474703a2f2f70783b20
      6865696768743a20617661696c61626c6520746f6d616e756661637475726572
      68756d616e207269676874736c696e6b20687265663d222f617661696c616269
      6c69747970726f706f7274696f6e616c6f757473696465207468652061737472
      6f6e6f6d6963616c68756d616e206265696e67736e616d65206f662074686520
      61726520666f756e6420696e617265206261736564206f6e736d616c6c657220
      7468616e6120706572736f6e2077686f657870616e73696f6e206f6661726775
      696e6720746861746e6f77206b6e6f776e206173496e20746865206561726c79
      696e7465726d656469617465646572697665642066726f6d5363616e64696e61
      7669616e3c2f613e3c2f6469763e0d0a636f6e736964657220746865616e2065
      7374696d61746564746865204e6174696f6e616c3c6469762069643d22706167
      726573756c74696e6720696e636f6d6d697373696f6e6564616e616c6f676f75
      7320746f6172652072657175697265642f756c3e0a3c2f6469763e0a77617320
      6261736564206f6e616e6420626563616d652061266e6273703b266e6273703b
      74222076616c75653d2222207761732063617074757265646e6f206d6f726520
      7468616e726573706563746976656c79636f6e74696e756520746f203e0d0a3c
      686561643e0d0a3c7765726520637265617465646d6f72652067656e6572616c
      696e666f726d6174696f6e207573656420666f7220746865696e646570656e64
      656e742074686520496d70657269616c636f6d706f6e656e74206f66746f2074
      6865206e6f727468696e636c7564652074686520436f6e737472756374696f6e
      73696465206f662074686520776f756c64206e6f74206265666f7220696e7374
      616e6365696e76656e74696f6e206f666d6f726520636f6d706c6578636f6c6c
      6563746976656c796261636b67726f756e643a20746578742d616c69676e3a20
      697473206f726967696e616c696e746f206163636f756e74746869732070726f
      63657373616e20657874656e73697665686f77657665722c2074686574686579
      20617265206e6f7472656a65637465642074686563726974696369736d206f66
      647572696e6720776869636870726f6261626c79207468657468697320617274
      69636c652866756e6374696f6e28297b49742073686f756c64206265616e2061
      677265656d656e746163636964656e74616c6c79646966666572732066726f6d
      417263686974656374757265626574746572206b6e6f776e617272616e67656d
      656e7473696e666c75656e6365206f6e617474656e646564207468656964656e
      746963616c20746f736f757468206f662074686570617373207468726f756768
      786d6c22207469746c653d227765696768743a626f6c643b6372656174696e67
      20746865646973706c61793a6e6f6e657265706c61636564207468653c696d67
      207372633d222f6968747470733a2f2f7777772e576f726c6420576172204949
      74657374696d6f6e69616c73666f756e6420696e207468657265717569726564
      20746f20616e642074686174207468656265747765656e207468652077617320
      64657369676e6564636f6e7369737473206f6620636f6e736964657261626c79
      7075626c6973686564206279746865206c616e6775616765436f6e7365727661
      74696f6e636f6e736973746564206f66726566657220746f207468656261636b
      20746f207468652063737322206d656469613d2250656f706c652066726f6d20
      617661696c61626c65206f6e70726f76656420746f2062657375676765737469
      6f6e7322776173206b6e6f776e206173766172696574696573206f666c696b65
      6c7920746f206265636f6d707269736564206f66737570706f72742074686520
      68616e6473206f6620746865636f75706c65642077697468636f6e6e65637420



Alakuijala & Szabadka         Informational                    [Page 95]

RFC 7932                         Brotli                        July 2016


      616e6420626f726465723a6e6f6e653b706572666f726d616e6365736265666f
      7265206265696e676c6174657220626563616d6563616c63756c6174696f6e73
      6f6674656e2063616c6c65647265736964656e7473206f666d65616e696e6720
      746861743e3c6c6920636c6173733d2265766964656e636520666f726578706c
      616e6174696f6e73656e7669726f6e6d656e7473223e3c2f613e3c2f6469763e
      776869636820616c6c6f7773496e74726f64756374696f6e646576656c6f7065
      642062796120776964652072616e67656f6e20626568616c66206f6676616c69
      676e3d22746f70227072696e6369706c65206f666174207468652074696d652c
      3c2f6e6f7363726970743e0d7361696420746f2068617665696e207468652066
      697273747768696c65206f74686572736879706f746865746963616c7068696c
      6f736f7068657273706f776572206f6620746865636f6e7461696e656420696e
      706572666f726d6564206279696e6162696c69747920746f7765726520777269
      7474656e7370616e207374796c653d22696e707574206e616d653d2274686520
      7175657374696f6e696e74656e64656420666f7272656a656374696f6e206f66
      696d706c6965732074686174696e76656e74656420746865746865207374616e
      646172647761732070726f6261626c796c696e6b206265747765656e70726f66
      6573736f72206f66696e746572616374696f6e736368616e67696e6720746865
      496e6469616e204f6365616e20636c6173733d226c617374776f726b696e6720
      7769746827687474703a2f2f7777772e7965617273206265666f726554686973
      207761732074686572656372656174696f6e616c656e746572696e6720746865
      6d6561737572656d656e7473616e2065787472656d656c7976616c7565206f66
      207468657374617274206f66207468650a3c2f7363726970743e0a0a616e2065
      66666f727420746f696e63726561736520746865746f2074686520736f757468
      73706163696e673d2230223e73756666696369656e746c79746865204575726f
      7065616e636f6e76657274656420746f636c65617254696d656f757464696420
      6e6f742068617665636f6e73657175656e746c79666f7220746865206e657874
      657874656e73696f6e206f6665636f6e6f6d696320616e64616c74686f756768
      207468656172652070726f6475636564616e64207769746820746865696e7375
      6666696369656e74676976656e2062792074686573746174696e672074686174
      657870656e646974757265733c2f7370616e3e3c2f613e0a74686f7567687420
      746861746f6e2074686520626173697363656c6c70616464696e673d696d6167
      65206f662074686572657475726e696e6720746f696e666f726d6174696f6e2c
      736570617261746564206279617373617373696e61746564732220636f6e7465
      6e743d22617574686f72697479206f666e6f7274687765737465726e3c2f6469
      763e0a3c64697620223e3c2f6469763e0d0a2020636f6e73756c746174696f6e
      636f6d6d756e697479206f66746865206e6174696f6e616c69742073686f756c
      642062657061727469636970616e747320616c69676e3d226c65667474686520
      677265617465737473656c656374696f6e206f6673757065726e61747572616c
      646570656e64656e74206f6e6973206d656e74696f6e6564616c6c6f77696e67
      2074686577617320696e76656e7465646163636f6d70616e79696e6768697320
      706572736f6e616c617661696c61626c652061747374756479206f6620746865
      6f6e20746865206f74686572657865637574696f6e206f6648756d616e205269
      676874737465726d73206f66207468656173736f63696174696f6e7372657365
      6172636820616e64737563636565646564206279646566656174656420746865
      616e642066726f6d20746865627574207468657920617265636f6d6d616e6465
      72206f667374617465206f66207468657965617273206f662061676574686520
      7374756479206f663c756c20636c6173733d2273706c61636520696e20746865
      7768657265206865207761733c6c6920636c6173733d22667468657265206172



Alakuijala & Szabadka         Informational                    [Page 96]

RFC 7932                         Brotli                        July 2016


      65206e6f776869636820626563616d656865207075626c697368656465787072
      657373656420696e746f20776869636820746865636f6d6d697373696f6e6572
      666f6e742d7765696768743a7465727269746f7279206f66657874656e73696f
      6e73223e526f6d616e20456d70697265657175616c20746f20746865496e2063
      6f6e74726173742c686f77657665722c20616e646973207479706963616c6c79
      616e6420686973207769666528616c736f2063616c6c65643e3c756c20636c61
      73733d226566666563746976656c792065766f6c76656420696e746f7365656d
      20746f2068617665776869636820697320746865746865726520776173206e6f
      616e20657863656c6c656e74616c6c206f662074686573656465736372696265
      64206279496e2070726163746963652c62726f616463617374696e6763686172
      67656420776974687265666c656374656420696e7375626a656374656420746f
      6d696c697461727920616e64746f2074686520706f696e7465636f6e6f6d6963
      616c6c79736574546172676574696e676172652061637475616c6c7976696374
      6f7279206f76657228293b3c2f7363726970743e636f6e74696e756f75736c79
      726571756972656420666f7265766f6c7574696f6e617279616e206566666563
      746976656e6f727468206f66207468652c207768696368207761732066726f6e
      74206f66207468656f72206f7468657277697365736f6d6520666f726d206f66
      686164206e6f74206265656e67656e657261746564206279696e666f726d6174
      696f6e2e7065726d697474656420746f696e636c756465732074686564657665
      6c6f706d656e742c656e746572656420696e746f7468652070726576696f7573
      636f6e73697374656e746c79617265206b6e6f776e206173746865206669656c
      64206f66746869732074797065206f66676976656e20746f2074686574686520
      7469746c65206f66636f6e7461696e7320746865696e7374616e636573206f66
      696e20746865206e6f72746864756520746f2074686569726172652064657369
      676e6564636f72706f726174696f6e737761732074686174207468656f6e6520
      6f662074686573656d6f726520706f70756c617273756363656564656420696e
      737570706f72742066726f6d696e20646966666572656e74646f6d696e617465
      6420627964657369676e656420666f726f776e657273686970206f66616e6420
      706f737369626c797374616e64617264697a6564726573706f6e736554657874
      77617320696e74656e646564726563656976656420746865617373756d656420
      746861746172656173206f66207468657072696d6172696c7920696e74686520
      6261736973206f66696e207468652073656e73656163636f756e747320666f72
      64657374726f7965642062796174206c656173742074776f776173206465636c
      61726564636f756c64206e6f74206265536563726574617279206f6661707065
      617220746f2062656d617267696e2d746f703a312f5e5c732b7c5c732b242f67
      65297b7468726f7720657d3b746865207374617274206f6674776f2073657061
      726174656c616e677561676520616e6477686f20686164206265656e6f706572
      6174696f6e206f666465617468206f66207468657265616c206e756d62657273
      093c6c696e6b2072656c3d2270726f7669646564207468657468652073746f72
      79206f66636f6d7065746974696f6e73656e676c6973682028554b29656e676c
      6973682028555329d09cd0bed0bdd0b3d0bed0bbd0a1d180d0bfd181d0bad0b8
      d181d180d0bfd181d0bad0b8d181d180d0bfd181d0bad0bed984d8b9d8b1d8a8
      d98ad8a9e6ada3e9ab94e4b8ade69687e7ae80e4bd93e4b8ade69687e7b981e4
      bd93e4b8ade69687e69c89e99990e585ace58fb8e4babae6b091e694bfe5ba9c
      e998bfe9878ce5b7b4e5b7b4e7a4bee4bc9ae4b8bbe4b989e6938de4bd9ce7b3
      bbe7bb9fe694bfe7ad96e6b395e8a784696e666f726d616369c3b36e68657272
      616d69656e746173656c65637472c3b36e69636f646573637269706369c3b36e
      636c61736966696361646f73636f6e6f63696d69656e746f7075626c69636163



Alakuijala & Szabadka         Informational                    [Page 97]

RFC 7932                         Brotli                        July 2016


      69c3b36e72656c6163696f6e61646173696e666f726dc3a17469636172656c61
      63696f6e61646f73646570617274616d656e746f74726162616a61646f726573
      646972656374616d656e74656179756e74616d69656e746f6d65726361646f4c
      69627265636f6e74c3a16374656e6f7368616269746163696f6e657363756d70
      6c696d69656e746f72657374617572616e746573646973706f73696369c3b36e
      636f6e73656375656e636961656c65637472c3b36e69636161706c6963616369
      6f6e6573646573636f6e65637461646f696e7374616c616369c3b36e7265616c
      697a616369c3b36e7574696c697a616369c3b36e656e6369636c6f7065646961
      656e6665726d656461646573696e737472756d656e746f73657870657269656e
      63696173696e73746974756369c3b36e706172746963756c6172657373756263
      617465676f726961d182d0bed0bbd18cd0bad0bed0a0d0bed181d181d0b8d0b8
      d180d0b0d0b1d0bed182d18bd0b1d0bed0bbd18cd188d0b5d0bfd180d0bed181
      d182d0bed0bcd0bed0b6d0b5d182d0b5d0b4d180d183d0b3d0b8d185d181d0bb
      d183d187d0b0d0b5d181d0b5d0b9d187d0b0d181d0b2d181d0b5d0b3d0b4d0b0
      d0a0d0bed181d181d0b8d18fd09cd0bed181d0bad0b2d0b5d0b4d180d183d0b3
      d0b8d0b5d0b3d0bed180d0bed0b4d0b0d0b2d0bed0bfd180d0bed181d0b4d0b0
      d0bdd0bdd18bd185d0b4d0bed0bbd0b6d0bdd18bd0b8d0bcd0b5d0bdd0bdd0be
      d09cd0bed181d0bad0b2d18bd180d183d0b1d0bbd0b5d0b9d09cd0bed181d0ba
      d0b2d0b0d181d182d180d0b0d0bdd18bd0bdd0b8d187d0b5d0b3d0bed180d0b0
      d0b1d0bed182d0b5d0b4d0bed0bbd0b6d0b5d0bdd183d181d0bbd183d0b3d0b8
      d182d0b5d0bfd0b5d180d18cd09ed0b4d0bdd0b0d0bad0bed0bfd0bed182d0be
      d0bcd183d180d0b0d0b1d0bed182d183d0b0d0bfd180d0b5d0bbd18fd0b2d0be
      d0bed0b1d189d0b5d0bed0b4d0bdd0bed0b3d0bed181d0b2d0bed0b5d0b3d0be
      d181d182d0b0d182d18cd0b8d0b4d180d183d0b3d0bed0b9d184d0bed180d183
      d0bcd0b5d185d0bed180d0bed188d0bed0bfd180d0bed182d0b8d0b2d181d181
      d18bd0bbd0bad0b0d0bad0b0d0b6d0b4d18bd0b9d0b2d0bbd0b0d181d182d0b8
      d0b3d180d183d0bfd0bfd18bd0b2d0bcd0b5d181d182d0b5d180d0b0d0b1d0be
      d182d0b0d181d0bad0b0d0b7d0b0d0bbd0bfd0b5d180d0b2d18bd0b9d0b4d0b5
      d0bbd0b0d182d18cd0b4d0b5d0bdd18cd0b3d0b8d0bfd0b5d180d0b8d0bed0b4
      d0b1d0b8d0b7d0bdd0b5d181d0bed181d0bdd0bed0b2d0b5d0bcd0bed0bcd0b5
      d0bdd182d0bad183d0bfd0b8d182d18cd0b4d0bed0bbd0b6d0bdd0b0d180d0b0
      d0bcd0bad0b0d185d0bdd0b0d187d0b0d0bbd0bed0a0d0b0d0b1d0bed182d0b0
      d0a2d0bed0bbd18cd0bad0bed181d0bed0b2d181d0b5d0bcd0b2d182d0bed180
      d0bed0b9d0bdd0b0d187d0b0d0bbd0b0d181d0bfd0b8d181d0bed0bad181d0bb
      d183d0b6d0b1d18bd181d0b8d181d182d0b5d0bcd0bfd0b5d187d0b0d182d0b8
      d0bdd0bed0b2d0bed0b3d0bed0bfd0bed0bcd0bed189d0b8d181d0b0d0b9d182
      d0bed0b2d0bfd0bed187d0b5d0bcd183d0bfd0bed0bcd0bed189d18cd0b4d0be
      d0bbd0b6d0bdd0bed181d181d18bd0bbd0bad0b8d0b1d18bd181d182d180d0be
      d0b4d0b0d0bdd0bdd18bd0b5d0bcd0bdd0bed0b3d0b8d0b5d0bfd180d0bed0b5
      d0bad182d0a1d0b5d0b9d187d0b0d181d0bcd0bed0b4d0b5d0bbd0b8d182d0b0
      d0bad0bed0b3d0bed0bed0bdd0bbd0b0d0b9d0bdd0b3d0bed180d0bed0b4d0b5
      d0b2d0b5d180d181d0b8d18fd181d182d180d0b0d0bdd0b5d184d0b8d0bbd18c
      d0bcd18bd183d180d0bed0b2d0bdd18fd180d0b0d0b7d0bdd18bd185d0b8d181
      d0bad0b0d182d18cd0bdd0b5d0b4d0b5d0bbd18ed18fd0bdd0b2d0b0d180d18f
      d0bcd0b5d0bdd18cd188d0b5d0bcd0bdd0bed0b3d0b8d185d0b4d0b0d0bdd0bd
      d0bed0b9d0b7d0bdd0b0d187d0b8d182d0bdd0b5d0bbd18cd0b7d18fd184d0be
      d180d183d0bcd0b0d0a2d0b5d0bfd0b5d180d18cd0bcd0b5d181d18fd186d0b0
      d0b7d0b0d189d0b8d182d18bd09bd183d187d188d0b8d0b5e0a4a8e0a4b9e0a5



Alakuijala & Szabadka         Informational                    [Page 98]

RFC 7932                         Brotli                        July 2016


      80e0a482e0a495e0a4b0e0a4a8e0a587e0a485e0a4aae0a4a8e0a587e0a495e0
      a4bfe0a4afe0a4bee0a495e0a4b0e0a587e0a482e0a485e0a4a8e0a58de0a4af
      e0a495e0a58de0a4afe0a4bee0a497e0a4bee0a487e0a4a1e0a4ace0a4bee0a4
      b0e0a587e0a495e0a4bfe0a4b8e0a580e0a4a6e0a4bfe0a4afe0a4bee0a4aae0
      a4b9e0a4b2e0a587e0a4b8e0a4bfe0a482e0a4b9e0a4ade0a4bee0a4b0e0a4a4
      e0a485e0a4aae0a4a8e0a580e0a4b5e0a4bee0a4b2e0a587e0a4b8e0a587e0a4
      b5e0a4bee0a495e0a4b0e0a4a4e0a587e0a4aee0a587e0a4b0e0a587e0a4b9e0
      a58be0a4a8e0a587e0a4b8e0a495e0a4a4e0a587e0a4ace0a4b9e0a581e0a4a4
      e0a4b8e0a4bee0a487e0a49fe0a4b9e0a58be0a497e0a4bee0a49ce0a4bee0a4
      a8e0a587e0a4aee0a4bfe0a4a8e0a49fe0a495e0a4b0e0a4a4e0a4bee0a495e0
      a4b0e0a4a8e0a4bee0a489e0a4a8e0a495e0a587e0a4afe0a4b9e0a4bee0a481
      e0a4b8e0a4ace0a4b8e0a587e0a4ade0a4bee0a4b7e0a4bee0a486e0a4aae0a4
      95e0a587e0a4b2e0a4bfe0a4afe0a587e0a4b6e0a581e0a4b0e0a582e0a487e0
      a4b8e0a495e0a587e0a498e0a482e0a49fe0a587e0a4aee0a587e0a4b0e0a580
      e0a4b8e0a495e0a4a4e0a4bee0a4aee0a587e0a4b0e0a4bee0a4b2e0a587e0a4
      95e0a4b0e0a485e0a4a7e0a4bfe0a495e0a485e0a4aae0a4a8e0a4bee0a4b8e0
      a4aee0a4bee0a49ce0a4aee0a581e0a49de0a587e0a495e0a4bee0a4b0e0a4a3
      e0a4b9e0a58be0a4a4e0a4bee0a495e0a4a1e0a4bce0a580e0a4afe0a4b9e0a4
      bee0a482e0a4b9e0a58be0a49fe0a4b2e0a4b6e0a4ace0a58de0a4a6e0a4b2e0
      a4bfe0a4afe0a4bee0a49ce0a580e0a4b5e0a4a8e0a49ce0a4bee0a4a4e0a4be
      e0a495e0a588e0a4b8e0a587e0a486e0a4aae0a495e0a4bee0a4b5e0a4bee0a4
      b2e0a580e0a4a6e0a587e0a4a8e0a587e0a4aae0a582e0a4b0e0a580e0a4aae0
      a4bee0a4a8e0a580e0a489e0a4b8e0a495e0a587e0a4b9e0a58be0a497e0a580
      e0a4ace0a588e0a4a0e0a495e0a486e0a4aae0a495e0a580e0a4b5e0a4b0e0a5
      8de0a4b7e0a497e0a4bee0a482e0a4b5e0a486e0a4aae0a495e0a58be0a49ce0
      a4bfe0a4b2e0a4bee0a49ce0a4bee0a4a8e0a4bee0a4b8e0a4b9e0a4aee0a4a4
      e0a4b9e0a4aee0a587e0a482e0a489e0a4a8e0a495e0a580e0a4afe0a4bee0a4
      b9e0a582e0a4a6e0a4b0e0a58de0a49ce0a4b8e0a582e0a49ae0a580e0a4aae0
      a4b8e0a482e0a4a6e0a4b8e0a4b5e0a4bee0a4b2e0a4b9e0a58be0a4a8e0a4be
      e0a4b9e0a58be0a4a4e0a580e0a49ce0a588e0a4b8e0a587e0a4b5e0a4bee0a4
      aae0a4b8e0a49ce0a4a8e0a4a4e0a4bee0a4a8e0a587e0a4a4e0a4bee0a49ce0
      a4bee0a4b0e0a580e0a498e0a4bee0a4afe0a4b2e0a49ce0a4bfe0a4b2e0a587
      e0a4a8e0a580e0a49ae0a587e0a49ce0a4bee0a482e0a49ae0a4aae0a4a4e0a5
      8de0a4b0e0a497e0a582e0a497e0a4b2e0a49ce0a4bee0a4a4e0a587e0a4ace0
      a4bee0a4b9e0a4b0e0a486e0a4aae0a4a8e0a587e0a4b5e0a4bee0a4b9e0a4a8
      e0a487e0a4b8e0a495e0a4bee0a4b8e0a581e0a4ace0a4b9e0a4b0e0a4b9e0a4
      a8e0a587e0a487e0a4b8e0a4b8e0a587e0a4b8e0a4b9e0a4bfe0a4a4e0a4ace0
      a4a1e0a4bce0a587e0a498e0a49fe0a4a8e0a4bee0a4a4e0a4b2e0a4bee0a4b6
      e0a4aae0a4bee0a482e0a49ae0a4b6e0a58de0a4b0e0a580e0a4ace0a4a1e0a4
      bce0a580e0a4b9e0a58be0a4a4e0a587e0a4b8e0a4bee0a488e0a49fe0a4b6e0
      a4bee0a4afe0a4a6e0a4b8e0a495e0a4a4e0a580e0a49ce0a4bee0a4a4e0a580
      e0a4b5e0a4bee0a4b2e0a4bee0a4b9e0a49ce0a4bee0a4b0e0a4aae0a49fe0a4
      a8e0a4bee0a4b0e0a496e0a4a8e0a587e0a4b8e0a4a1e0a4bce0a495e0a4aee0
      a4bfe0a4b2e0a4bee0a489e0a4b8e0a495e0a580e0a495e0a587e0a4b5e0a4b2
      e0a4b2e0a497e0a4a4e0a4bee0a496e0a4bee0a4a8e0a4bee0a485e0a4b0e0a5
      8de0a4a5e0a49ce0a4b9e0a4bee0a482e0a4a6e0a587e0a496e0a4bee0a4aae0
      a4b9e0a4b2e0a580e0a4a8e0a4bfe0a4afe0a4aee0a4ace0a4bfe0a4a8e0a4be
      e0a4ace0a588e0a482e0a495e0a495e0a4b9e0a580e0a482e0a495e0a4b9e0a4



Alakuijala & Szabadka         Informational                    [Page 99]

RFC 7932                         Brotli                        July 2016


      a8e0a4bee0a4a6e0a587e0a4a4e0a4bee0a4b9e0a4aee0a4b2e0a587e0a495e0
      a4bee0a4abe0a580e0a49ce0a4ace0a495e0a4bfe0a4a4e0a581e0a4b0e0a4a4
      e0a4aee0a4bee0a482e0a497e0a4b5e0a4b9e0a580e0a482e0a4b0e0a58be0a4
      9ce0a4bce0a4aee0a4bfe0a4b2e0a580e0a486e0a4b0e0a58be0a4aae0a4b8e0
      a587e0a4a8e0a4bee0a4afe0a4bee0a4a6e0a4b5e0a4b2e0a587e0a4a8e0a587
      e0a496e0a4bee0a4a4e0a4bee0a495e0a4b0e0a580e0a4ace0a489e0a4a8e0a4
      95e0a4bee0a49ce0a4b5e0a4bee0a4ace0a4aae0a582e0a4b0e0a4bee0a4ace0
      a4a1e0a4bce0a4bee0a4b8e0a58ce0a4a6e0a4bee0a4b6e0a587e0a4afe0a4b0
      e0a495e0a4bfe0a4afe0a587e0a495e0a4b9e0a4bee0a482e0a485e0a495e0a4
      b8e0a4b0e0a4ace0a4a8e0a4bee0a48fe0a4b5e0a4b9e0a4bee0a482e0a4b8e0
      a58de0a4a5e0a4b2e0a4aee0a4bfe0a4b2e0a587e0a4b2e0a587e0a496e0a495
      e0a4b5e0a4bfe0a4b7e0a4afe0a495e0a58de0a4b0e0a482e0a4b8e0a4aee0a5
      82e0a4b9e0a4a5e0a4bee0a4a8e0a4bed8aad8b3d8aad8b7d98ad8b9d985d8b4
      d8a7d8b1d983d8a9d8a8d988d8a7d8b3d8b7d8a9d8a7d984d8b5d981d8add8a9
      d985d988d8a7d8b6d98ad8b9d8a7d984d8aed8a7d8b5d8a9d8a7d984d985d8b2
      d98ad8afd8a7d984d8b9d8a7d985d8a9d8a7d984d983d8a7d8aad8a8d8a7d984
      d8b1d8afd988d8afd8a8d8b1d986d8a7d985d8acd8a7d984d8afd988d984d8a9
      d8a7d984d8b9d8a7d984d985d8a7d984d985d988d982d8b9d8a7d984d8b9d8b1
      d8a8d98ad8a7d984d8b3d8b1d98ad8b9d8a7d984d8acd988d8a7d984d8a7d984
      d8b0d987d8a7d8a8d8a7d984d8add98ad8a7d8a9d8a7d984d8add982d988d982
      d8a7d984d983d8b1d98ad985d8a7d984d8b9d8b1d8a7d982d985d8add981d988
      d8b8d8a9d8a7d984d8abd8a7d986d98ad985d8b4d8a7d987d8afd8a9d8a7d984
      d985d8b1d8a3d8a9d8a7d984d982d8b1d8a2d986d8a7d984d8b4d8a8d8a7d8a8
      d8a7d984d8add988d8a7d8b1d8a7d984d8acd8afd98ad8afd8a7d984d8a3d8b3
      d8b1d8a9d8a7d984d8b9d984d988d985d985d8acd985d988d8b9d8a9d8a7d984
      d8b1d8add985d986d8a7d984d986d982d8a7d8b7d981d984d8b3d8b7d98ad986
      d8a7d984d983d988d98ad8aad8a7d984d8afd986d98ad8a7d8a8d8b1d983d8a7
      d8aad987d8a7d984d8b1d98ad8a7d8b6d8aad8add98ad8a7d8aad98ad8a8d8aa
      d988d982d98ad8aad8a7d984d8a3d988d984d989d8a7d984d8a8d8b1d98ad8af
      d8a7d984d983d984d8a7d985d8a7d984d8b1d8a7d8a8d8b7d8a7d984d8b4d8ae
      d8b5d98ad8b3d98ad8a7d8b1d8a7d8aad8a7d984d8abd8a7d984d8abd8a7d984
      d8b5d984d8a7d8a9d8a7d984d8add8afd98ad8abd8a7d984d8b2d988d8a7d8b1
      d8a7d984d8aed984d98ad8acd8a7d984d8acd985d98ad8b9d8a7d984d8b9d8a7
      d985d987d8a7d984d8acd985d8a7d984d8a7d984d8b3d8a7d8b9d8a9d985d8b4
      d8a7d987d8afd987d8a7d984d8b1d8a6d98ad8b3d8a7d984d8afd8aed988d984
      d8a7d984d981d986d98ad8a9d8a7d984d983d8aad8a7d8a8d8a7d984d8afd988
      d8b1d98ad8a7d984d8afd8b1d988d8b3d8a7d8b3d8aad8bad8b1d982d8aad8b5
      d8a7d985d98ad985d8a7d984d8a8d986d8a7d8aad8a7d984d8b9d8b8d98ad985
      656e7465727461696e6d656e74756e6465727374616e64696e67203d2066756e
      6374696f6e28292e6a7067222077696474683d22636f6e66696775726174696f
      6e2e706e67222077696474683d223c626f647920636c6173733d224d6174682e
      72616e646f6d2829636f6e74656d706f7261727920556e697465642053746174
      657363697263756d7374616e6365732e617070656e644368696c64286f726761
      6e697a6174696f6e733c7370616e20636c6173733d22223e3c696d6720737263
      3d222f64697374696e6775697368656474686f7573616e6473206f6620636f6d
      6d756e69636174696f6e636c656172223e3c2f6469763e696e76657374696761
      74696f6e66617669636f6e2e69636f22206d617267696e2d72696768743a6261
      736564206f6e20746865204d6173736163687573657474737461626c6520626f



Alakuijala & Szabadka         Informational                   [Page 100]

RFC 7932                         Brotli                        July 2016


      726465723d696e7465726e6174696f6e616c616c736f206b6e6f776e20617370
      726f6e756e63696174696f6e6261636b67726f756e643a236670616464696e67
      2d6c6566743a466f72206578616d706c652c206d697363656c6c616e656f7573
      266c743b2f6d6174682667743b70737963686f6c6f676963616c696e20706172
      746963756c617265617263682220747970653d22666f726d206d6574686f643d
      226173206f70706f73656420746f53757072656d6520436f7572746f63636173
      696f6e616c6c79204164646974696f6e616c6c792c4e6f72746820416d657269
      636170783b6261636b67726f756e646f70706f7274756e6974696573456e7465
      727461696e6d656e742e746f4c6f77657243617365286d616e75666163747572
      696e6770726f66657373696f6e616c20636f6d62696e65642077697468466f72
      20696e7374616e63652c636f6e73697374696e67206f6622206d61786c656e67
      74683d2272657475726e2066616c73653b636f6e7363696f75736e6573734d65
      646974657272616e65616e65787472616f7264696e617279617373617373696e
      6174696f6e73756273657175656e746c7920627574746f6e20747970653d2274
      6865206e756d626572206f66746865206f726967696e616c20636f6d70726568
      656e7369766572656665727320746f207468653c2f756c3e0a3c2f6469763e0a
      7068696c6f736f70686963616c6c6f636174696f6e2e68726566776173207075
      626c697368656453616e204672616e636973636f2866756e6374696f6e28297b
      0a3c6469762069643d226d61696e736f70686973746963617465646d61746865
      6d61746963616c202f686561643e0d0a3c626f64797375676765737473207468
      6174646f63756d656e746174696f6e636f6e63656e74726174696f6e72656c61
      74696f6e73686970736d61792068617665206265656e28666f72206578616d70
      6c652c546869732061727469636c6520696e20736f6d65206361736573706172
      7473206f662074686520646566696e6974696f6e206f66477265617420427269
      7461696e2063656c6c70616464696e673d6571756976616c656e7420746f706c
      616365686f6c6465723d223b20666f6e742d73697a653a206a75737469666963
      6174696f6e62656c6965766564207468617473756666657265642066726f6d61
      7474656d7074656420746f206c6561646572206f662074686563726970742220
      7372633d222f2866756e6374696f6e2829207b61726520617661696c61626c65
      0a093c6c696e6b2072656c3d22207372633d27687474703a2f2f696e74657265
      7374656420696e636f6e76656e74696f6e616c202220616c743d2222202f3e3c
      2f6172652067656e6572616c6c7968617320616c736f206265656e6d6f737420
      706f70756c617220636f72726573706f6e64696e676372656469746564207769
      746874796c653d22626f726465723a3c2f613e3c2f7370616e3e3c2f2e676966
      222077696474683d223c696672616d65207372633d227461626c6520636c6173
      733d22696e6c696e652d626c6f636b3b6163636f7264696e6720746f20746f67
      65746865722077697468617070726f78696d6174656c797061726c69616d656e
      746172796d6f726520616e64206d6f7265646973706c61793a6e6f6e653b7472
      61646974696f6e616c6c79707265646f6d696e616e746c79266e6273703b7c26
      6e6273703b266e6273703b3c2f7370616e3e2063656c6c73706163696e673d3c
      696e707574206e616d653d226f722220636f6e74656e743d22636f6e74726f76
      65727369616c70726f70657274793d226f673a2f782d73686f636b776176652d
      64656d6f6e7374726174696f6e737572726f756e6465642062794e6576657274
      68656c6573732c77617320746865206669727374636f6e736964657261626c65
      20416c74686f7567682074686520636f6c6c61626f726174696f6e73686f756c
      64206e6f7420626570726f706f7274696f6e206f663c7370616e207374796c65
      3d226b6e6f776e206173207468652073686f72746c79206166746572666f7220
      696e7374616e63652c646573637269626564206173202f686561643e0a3c626f



Alakuijala & Szabadka         Informational                   [Page 101]

RFC 7932                         Brotli                        July 2016


      6479207374617274696e672077697468696e6372656173696e676c7920746865
      2066616374207468617464697363757373696f6e206f666d6964646c65206f66
      20746865616e20696e646976696475616c646966666963756c7420746f20706f
      696e74206f662076696577686f6d6f73657875616c697479616363657074616e
      6365206f663c2f7370616e3e3c2f6469763e6d616e756661637475726572736f
      726967696e206f6620746865636f6d6d6f6e6c792075736564696d706f727461
      6e6365206f6664656e6f6d696e6174696f6e736261636b67726f756e643a2023
      6c656e677468206f662074686564657465726d696e6174696f6e61207369676e
      69666963616e742220626f726465723d2230223e7265766f6c7574696f6e6172
      797072696e6369706c6573206f66697320636f6e736964657265647761732064
      6576656c6f706564496e646f2d4575726f7065616e76756c6e657261626c6520
      746f70726f706f6e656e7473206f6661726520736f6d6574696d6573636c6f73
      657220746f207468654e657720596f726b2043697479206e616d653d22736561
      7263686174747269627574656420746f636f75727365206f66207468656d6174
      68656d6174696369616e62792074686520656e64206f6661742074686520656e
      64206f662220626f726465723d22302220746563686e6f6c6f676963616c2e72
      656d6f7665436c617373286272616e6368206f662074686565766964656e6365
      2074686174215b656e6469665d2d2d3e0d0a496e73746974757465206f662069
      6e746f20612073696e676c65726573706563746976656c792e616e6420746865
      7265666f726570726f70657274696573206f666973206c6f636174656420696e
      736f6d65206f66207768696368546865726520697320616c736f636f6e74696e
      75656420746f20617070656172616e6365206f662026616d703b6e646173683b
      2064657363726962657320746865636f6e73696465726174696f6e617574686f
      72206f6620746865696e646570656e64656e746c796571756970706564207769
      7468646f6573206e6f7420686176653c2f613e3c6120687265663d22636f6e66
      7573656420776974683c6c696e6b20687265663d222f61742074686520616765
      206f6661707065617220696e20746865546865736520696e636c756465726567
      6172646c657373206f66636f756c642062652075736564207374796c653d2671
      756f743b7365766572616c2074696d6573726570726573656e7420746865626f
      64793e0a3c2f68746d6c3e74686f7567687420746f206265706f70756c617469
      6f6e206f66706f73736962696c697469657370657263656e74616765206f6661
      636365737320746f20746865616e20617474656d707420746f70726f64756374
      696f6e206f666a71756572792f6a717565727974776f20646966666572656e74
      62656c6f6e6720746f2074686565737461626c6973686d656e747265706c6163
      696e67207468656465736372697074696f6e222064657465726d696e65207468
      65617661696c61626c6520666f724163636f7264696e6720746f207769646520
      72616e6765206f66093c64697620636c6173733d226d6f726520636f6d6d6f6e
      6c796f7267616e69736174696f6e7366756e6374696f6e616c69747977617320
      636f6d706c657465642026616d703b6d646173683b2070617274696369706174
      696f6e74686520636861726163746572616e206164646974696f6e616c617070
      6561727320746f20626566616374207468617420746865616e206578616d706c
      65206f667369676e69666963616e746c796f6e6d6f7573656f7665723d226265
      63617573652074686579206173796e63203d20747275653b70726f626c656d73
      20776974687365656d7320746f206861766574686520726573756c74206f6620
      7372633d22687474703a2f2f66616d696c6961722077697468706f7373657373
      696f6e206f6666756e6374696f6e202829207b746f6f6b20706c61636520696e
      616e6420736f6d6574696d65737375627374616e7469616c6c793c7370616e3e
      3c2f7370616e3e6973206f6674656e2075736564696e20616e20617474656d70



Alakuijala & Szabadka         Informational                   [Page 102]

RFC 7932                         Brotli                        July 2016


      746772656174206465616c206f66456e7669726f6e6d656e74616c7375636365
      737366756c6c79207669727475616c6c7920616c6c323074682063656e747572
      792c70726f66657373696f6e616c736e656365737361727920746f2064657465
      726d696e6564206279636f6d7061746962696c69747962656361757365206974
      20697344696374696f6e617279206f666d6f64696669636174696f6e73546865
      20666f6c6c6f77696e676d617920726566657220746f3a436f6e73657175656e
      746c792c496e7465726e6174696f6e616c616c74686f75676820736f6d657468
      617420776f756c64206265776f726c642773206669727374636c617373696669
      6564206173626f74746f6d206f662074686528706172746963756c61726c7961
      6c69676e3d226c65667422206d6f737420636f6d6d6f6e6c7962617369732066
      6f7220746865666f756e646174696f6e206f66636f6e747269627574696f6e73
      706f70756c6172697479206f6663656e746572206f6620746865746f20726564
      756365207468656a7572697364696374696f6e73617070726f78696d6174696f
      6e206f6e6d6f7573656f75743d224e65772054657374616d656e74636f6c6c65
      6374696f6e206f663c2f7370616e3e3c2f613e3c2f696e2074686520556e6974
      656466696c6d206469726563746f722d7374726963742e647464223e68617320
      6265656e207573656472657475726e20746f20746865616c74686f7567682074
      6869736368616e676520696e207468657365766572616c206f74686572627574
      20746865726520617265756e707265636564656e74656469732073696d696c61
      7220746f657370656369616c6c7920696e7765696768743a20626f6c643b6973
      2063616c6c656420746865636f6d7075746174696f6e616c696e646963617465
      20746861747265737472696374656420746f093c6d657461206e616d653d2261
      7265207479706963616c6c79636f6e666c6963742077697468486f7765766572
      2c2074686520416e206578616d706c65206f66636f6d70617265642077697468
      7175616e746974696573206f66726174686572207468616e2061636f6e737465
      6c6c6174696f6e6e656365737361727920666f727265706f7274656420746861
      7473706563696669636174696f6e706f6c69746963616c20616e64266e627370
      3b266e6273703b3c7265666572656e63657320746f7468652073616d65207965
      6172476f7665726e6d656e74206f6667656e65726174696f6e206f6668617665
      206e6f74206265656e7365766572616c207965617273636f6d6d69746d656e74
      20746f09093c756c20636c6173733d2276697375616c697a6174696f6e313974
      682063656e747572792c70726163746974696f6e657273746861742068652077
      6f756c64616e6420636f6e74696e7565646f636375706174696f6e206f666973
      20646566696e656420617363656e747265206f662074686574686520616d6f75
      6e74206f663e3c646976207374796c653d226571756976616c656e74206f6664
      6966666572656e746961746562726f756768742061626f75746d617267696e2d
      6c6566743a206175746f6d61746963616c6c7974686f75676874206f66206173
      536f6d65206f662074686573650a3c64697620636c6173733d22696e70757420
      636c6173733d227265706c6163656420776974686973206f6e65206f66207468
      65656475636174696f6e20616e64696e666c75656e6365642062797265707574
      6174696f6e2061730a3c6d657461206e616d653d226163636f6d6d6f64617469
      6f6e3c2f6469763e0a3c2f6469763e6c617267652070617274206f66496e7374
      697475746520666f7274686520736f2d63616c6c656420616761696e73742074
      686520496e207468697320636173652c776173206170706f696e746564636c61
      696d656420746f206265486f77657665722c20746869734465706172746d656e
      74206f667468652072656d61696e696e67656666656374206f6e207468657061
      72746963756c61726c79206465616c2077697468207468650a3c646976207374
      796c653d22616c6d6f737420616c776179736172652063757272656e746c7965



Alakuijala & Szabadka         Informational                   [Page 103]

RFC 7932                         Brotli                        July 2016


      787072657373696f6e206f667068696c6f736f706879206f66666f72206d6f72
      65207468616e636976696c697a6174696f6e736f6e207468652069736c616e64
      73656c6563746564496e64657863616e20726573756c7420696e222076616c75
      653d2222202f3e74686520737472756374757265202f3e3c2f613e3c2f646976
      3e4d616e79206f66207468657365636175736564206279207468656f66207468
      6520556e697465647370616e20636c6173733d226d63616e2062652074726163
      656469732072656c6174656420746f626563616d65206f6e65206f6669732066
      72657175656e746c796c6976696e6720696e207468657468656f726574696361
      6c6c79466f6c6c6f77696e67207468655265766f6c7574696f6e617279676f76
      65726e6d656e7420696e69732064657465726d696e656474686520706f6c6974
      6963616c696e74726f647563656420696e73756666696369656e7420746f6465
      736372697074696f6e223e73686f72742073746f726965737365706172617469
      6f6e206f66617320746f20776865746865726b6e6f776e20666f722069747377
      617320696e697469616c6c79646973706c61793a626c6f636b697320616e2065
      78616d706c65746865207072696e636970616c636f6e7369737473206f662061
      7265636f676e697a65642061732f626f64793e3c2f68746d6c3e612073756273
      74616e7469616c7265636f6e737472756374656468656164206f662073746174
      65726573697374616e636520746f756e64657267726164756174655468657265
      206172652074776f6772617669746174696f6e616c6172652064657363726962
      6564696e74656e74696f6e616c6c7973657276656420617320746865636c6173
      733d226865616465726f70706f736974696f6e20746f66756e64616d656e7461
      6c6c79646f6d696e6174656420746865616e6420746865206f74686572616c6c
      69616e6365207769746877617320666f7263656420746f726573706563746976
      656c792c616e6420706f6c69746963616c696e20737570706f7274206f667065
      6f706c6520696e20746865323074682063656e747572792e616e64207075626c
      69736865646c6f6164436861727462656174746f20756e6465727374616e646d
      656d62657220737461746573656e7669726f6e6d656e74616c66697273742068
      616c66206f66636f756e747269657320616e646172636869746563747572616c
      626520636f6e73696465726564636861726163746572697a6564636c65617249
      6e74657276616c617574686f726974617469766546656465726174696f6e206f
      6677617320737563636565646564616e64207468657265206172656120636f6e
      73657175656e636574686520507265736964656e74616c736f20696e636c7564
      65646672656520736f66747761726573756363657373696f6e206f6664657665
      6c6f706564207468657761732064657374726f796564617761792066726f6d20
      7468653b0a3c2f7363726970743e0a3c616c74686f7567682074686579666f6c
      6c6f77656420627920616d6f726520706f77657266756c726573756c74656420
      696e2061556e6976657273697479206f66486f77657665722c206d616e797468
      6520707265736964656e74486f77657665722c20736f6d6569732074686f7567
      687420746f756e74696c2074686520656e6477617320616e6e6f756e63656461
      726520696d706f7274616e74616c736f20696e636c756465733e3c696e707574
      20747970653d7468652063656e746572206f6620444f204e4f5420414c544552
      7573656420746f2072656665727468656d65732f3f736f72743d746861742068
      6164206265656e74686520626173697320666f7268617320646576656c6f7065
      64696e207468652073756d6d6572636f6d70617261746976656c796465736372
      6962656420746865737563682061732074686f736574686520726573756c7469
      6e67697320696d706f737369626c65766172696f7573206f74686572536f7574
      68204166726963616e68617665207468652073616d656566666563746976656e
      657373696e20776869636820636173653b20746578742d616c69676e3a737472



Alakuijala & Szabadka         Informational                   [Page 104]

RFC 7932                         Brotli                        July 2016


      75637475726520616e643b206261636b67726f756e643a726567617264696e67
      20746865737570706f7274656420746865697320616c736f206b6e6f776e7374
      796c653d226d617267696e696e636c7564696e6720746865626168617361204d
      656c6179756e6f72736b20626f6b6dc3a56c6e6f72736b206e796e6f72736b73
      6c6f76656ec5a1c48d696e61696e7465726e6163696f6e616c63616c69666963
      616369c3b36e636f6d756e6963616369c3b36e636f6e73747275636369c3b36e
      223e3c64697620636c6173733d22646973616d626967756174696f6e446f6d61
      696e4e616d65272c202761646d696e697374726174696f6e73696d756c74616e
      656f75736c797472616e73706f72746174696f6e496e7465726e6174696f6e61
      6c206d617267696e2d626f74746f6d3a726573706f6e736962696c6974793c21
      5b656e6469665d2d2d3e0a3c2f3e3c6d657461206e616d653d22696d706c656d
      656e746174696f6e696e667261737472756374757265726570726573656e7461
      74696f6e626f726465722d626f74746f6d3a3c2f686561643e0a3c626f64793e
      3d687474702533412532462532463c666f726d206d6574686f643d226d657468
      6f643d22706f737422202f66617669636f6e2e69636f22207d293b0a3c2f7363
      726970743e0a2e7365744174747269627574652841646d696e69737472617469
      6f6e3d206e657720417272617928293b3c215b656e6469665d2d2d3e0d0a6469
      73706c61793a626c6f636b3b556e666f7274756e6174656c792c223e266e6273
      703b3c2f6469763e2f66617669636f6e2e69636f223e3d277374796c65736865
      657427206964656e74696669636174696f6e2c20666f72206578616d706c652c
      3c6c693e3c6120687265663d222f616e20616c7465726e617469766561732061
      20726573756c74206f667074223e3c2f7363726970743e0a747970653d227375
      626d697422200a2866756e6374696f6e2829207b7265636f6d6d656e64617469
      6f6e666f726d20616374696f6e3d222f7472616e73666f726d6174696f6e7265
      636f6e737472756374696f6e2e7374796c652e646973706c6179204163636f72
      64696e6720746f2068696464656e22206e616d653d22616c6f6e672077697468
      20746865646f63756d656e742e626f64792e617070726f78696d6174656c7920
      436f6d6d756e69636174696f6e73706f73742220616374696f6e3d226d65616e
      696e67202671756f743b2d2d3c215b656e6469665d2d2d3e5072696d65204d69
      6e697374657263686172616374657269737469633c2f613e203c6120636c6173
      733d74686520686973746f7279206f66206f6e6d6f7573656f7665723d227468
      6520676f7665726e6d656e74687265663d2268747470733a2f2f776173206f72
      6967696e616c6c7977617320696e74726f6475636564636c6173736966696361
      74696f6e726570726573656e74617469766561726520636f6e73696465726564
      3c215b656e6469665d2d2d3e0a0a646570656e6473206f6e20746865556e6976
      657273697479206f6620696e20636f6e747261737420746f20706c616365686f
      6c6465723d22696e207468652063617365206f66696e7465726e6174696f6e61
      6c20636f6e737469747574696f6e616c7374796c653d22626f726465722d3a20
      66756e6374696f6e2829207b42656361757365206f66207468652d7374726963
      742e647464223e0a3c7461626c6520636c6173733d226163636f6d70616e6965
      642062796163636f756e74206f66207468653c736372697074207372633d222f
      6e6174757265206f6620746865207468652070656f706c6520696e20696e2061
      64646974696f6e20746f73293b206a732e6964203d206964222077696474683d
      223130302522726567617264696e672074686520526f6d616e20436174686f6c
      6963616e20696e646570656e64656e74666f6c6c6f77696e6720746865202e67
      6966222077696474683d223174686520666f6c6c6f77696e6720646973637269
      6d696e6174696f6e6172636861656f6c6f676963616c7072696d65206d696e69
      737465722e6a73223e3c2f7363726970743e636f6d62696e6174696f6e206f66



Alakuijala & Szabadka         Informational                   [Page 105]

RFC 7932                         Brotli                        July 2016


      206d617267696e77696474683d22637265617465456c656d656e7428772e6174
      746163684576656e74283c2f613e3c2f74643e3c2f74723e7372633d22687474
      70733a2f2f61496e20706172746963756c61722c20616c69676e3d226c656674
      2220437a6563682052657075626c6963556e69746564204b696e67646f6d636f
      72726573706f6e64656e6365636f6e636c7564656420746861742e68746d6c22
      207469746c653d222866756e6374696f6e202829207b636f6d65732066726f6d
      207468656170706c69636174696f6e206f663c7370616e20636c6173733d2273
      62656c696576656420746f206265656d656e742827736372697074273c2f613e
      0a3c2f6c693e0a3c6c697665727920646966666572656e743e3c7370616e2063
      6c6173733d226f7074696f6e2076616c75653d2228616c736f206b6e6f776e20
      6173093c6c693e3c6120687265663d223e3c696e707574206e616d653d227365
      706172617465642066726f6d726566657272656420746f2061732076616c6967
      6e3d22746f70223e666f756e646572206f6620746865617474656d7074696e67
      20746f20636172626f6e2064696f786964650a0a3c64697620636c6173733d22
      636c6173733d227365617263682d2f626f64793e0a3c2f68746d6c3e6f70706f
      7274756e69747920746f636f6d6d756e69636174696f6e733c2f686561643e0d
      0a3c626f6479207374796c653d2277696474683a5469e1babf6e67205669e1bb
      87746368616e67657320696e20746865626f726465722d636f6c6f723a233022
      20626f726465723d223022203c2f7370616e3e3c2f6469763e3c776173206469
      73636f76657265642220747970653d22746578742220293b0a3c2f7363726970
      743e0a0a4465706172746d656e74206f66206563636c6573696173746963616c
      746865726520686173206265656e726573756c74696e672066726f6d3c2f626f
      64793e3c2f68746d6c3e686173206e65766572206265656e7468652066697273
      742074696d65696e20726573706f6e736520746f6175746f6d61746963616c6c
      79203c2f6469763e0a0a3c646976206977617320636f6e736964657265647065
      7263656e74206f662074686522202f3e3c2f613e3c2f6469763e636f6c6c6563
      74696f6e206f662064657363656e6465642066726f6d73656374696f6e206f66
      207468656163636570742d63686172736574746f20626520636f6e6675736564
      6d656d626572206f66207468652070616464696e672d72696768743a7472616e
      736c6174696f6e206f66696e746572707265746174696f6e20687265663d2768
      7474703a2f2f77686574686572206f72206e6f7454686572652061726520616c
      736f746865726520617265206d616e796120736d616c6c206e756d6265726f74
      686572207061727473206f66696d706f737369626c6520746f2020636c617373
      3d22627574746f6e6c6f636174656420696e207468652e20486f77657665722c
      20746865616e64206576656e7475616c6c7941742074686520656e64206f6620
      62656361757365206f6620697473726570726573656e7473207468653c666f72
      6d20616374696f6e3d22206d6574686f643d22706f737422697420697320706f
      737369626c656d6f7265206c696b656c7920746f616e20696e63726561736520
      696e6861766520616c736f206265656e636f72726573706f6e647320746f616e
      6e6f756e6365642074686174616c69676e3d227269676874223e6d616e792063
      6f756e7472696573666f72206d616e792079656172736561726c69657374206b
      6e6f776e62656361757365206974207761737074223e3c2f7363726970743e0d
      2076616c69676e3d22746f702220696e6861626974616e7473206f66666f6c6c
      6f77696e6720796561720d0a3c64697620636c6173733d226d696c6c696f6e20
      70656f706c65636f6e74726f7665727369616c20636f6e6365726e696e672074
      68656172677565207468617420746865676f7665726e6d656e7420616e646120
      7265666572656e636520746f7472616e7366657272656420746f646573637269
      62696e6720746865207374796c653d22636f6c6f723a616c74686f7567682074



Alakuijala & Szabadka         Informational                   [Page 106]

RFC 7932                         Brotli                        July 2016


      6865726562657374206b6e6f776e20666f727375626d697422206e616d653d22
      6d756c7469706c69636174696f6e6d6f7265207468616e206f6e65207265636f
      676e6974696f6e206f66436f756e63696c206f662074686565646974696f6e20
      6f662074686520203c6d657461206e616d653d22456e7465727461696e6d656e
      7420617761792066726f6d20746865203b6d617267696e2d72696768743a6174
      207468652074696d65206f66696e7665737469676174696f6e73636f6e6e6563
      7465642077697468616e64206d616e79206f74686572616c74686f7567682069
      74206973626567696e6e696e672077697468203c7370616e20636c6173733d22
      64657363656e64616e7473206f663c7370616e20636c6173733d226920616c69
      676e3d227269676874223c2f686561643e0a3c626f6479206173706563747320
      6f66207468656861732073696e6365206265656e4575726f7065616e20556e69
      6f6e72656d696e697363656e74206f666d6f726520646966666963756c745669
      636520507265736964656e74636f6d706f736974696f6e206f66706173736564
      207468726f7567686d6f726520696d706f7274616e74666f6e742d73697a653a
      313170786578706c616e6174696f6e206f6674686520636f6e63657074206f66
      7772697474656e20696e20746865093c7370616e20636c6173733d226973206f
      6e65206f662074686520726573656d626c616e636520746f6f6e207468652067
      726f756e6473776869636820636f6e7461696e73696e636c7564696e67207468
      6520646566696e6564206279207468657075626c69636174696f6e206f666d65
      616e732074686174207468656f757473696465206f6620746865737570706f72
      74206f66207468653c696e70757420636c6173733d223c7370616e20636c6173
      733d2274284d6174682e72616e646f6d28296d6f73742070726f6d696e656e74
      6465736372697074696f6e206f66436f6e7374616e74696e6f706c6577657265
      207075626c69736865643c64697620636c6173733d2273656170706561727320
      696e207468653122206865696768743d223122206d6f737420696d706f727461
      6e74776869636820696e636c75646573776869636820686164206265656e6465
      737472756374696f6e206f6674686520706f70756c6174696f6e0a093c646976
      20636c6173733d22706f73736962696c697479206f66736f6d6574696d657320
      7573656461707065617220746f206861766573756363657373206f6620746865
      696e74656e64656420746f20626570726573656e7420696e207468657374796c
      653d22636c6561723a620d0a3c2f7363726970743e0d0a3c77617320666f756e
      64656420696e696e7465727669657720776974685f69642220636f6e74656e74
      3d226361706974616c206f66207468650d0a3c6c696e6b2072656c3d22737265
      6c65617365206f6620746865706f696e74206f75742074686174784d4c487474
      7052657175657374616e642073756273657175656e747365636f6e64206c6172
      676573747665727920696d706f7274616e7473706563696669636174696f6e73
      73757266616365206f66207468656170706c69656420746f20746865666f7265
      69676e20706f6c6963795f736574446f6d61696e4e616d6565737461626c6973
      68656420696e69732062656c696576656420746f496e206164646974696f6e20
      746f6d65616e696e67206f66207468656973206e616d6564206166746572746f
      2070726f7465637420746865697320726570726573656e7465644465636c6172
      6174696f6e206f666d6f726520656666696369656e74436c6173736966696361
      74696f6e6f7468657220666f726d73206f6668652072657475726e656420746f
      3c7370616e20636c6173733d2263706572666f726d616e6365206f662866756e
      6374696f6e2829207b0d696620616e64206f6e6c79206966726567696f6e7320
      6f66207468656c656164696e6720746f2074686572656c6174696f6e73207769
      7468556e69746564204e6174696f6e737374796c653d226865696768743a6f74
      686572207468616e207468657970652220636f6e74656e743d224173736f6369



Alakuijala & Szabadka         Informational                   [Page 107]

RFC 7932                         Brotli                        July 2016


      6174696f6e206f660a3c2f686561643e0a3c626f64796c6f6361746564206f6e
      20746865697320726566657272656420746f28696e636c7564696e6720746865
      636f6e63656e74726174696f6e7374686520696e646976696475616c616d6f6e
      6720746865206d6f73747468616e20616e79206f746865722f3e0a3c6c696e6b
      2072656c3d222072657475726e2066616c73653b74686520707572706f736520
      6f66746865206162696c69747920746f3b636f6c6f723a236666667d0a2e0a3c
      7370616e20636c6173733d22746865207375626a656374206f66646566696e69
      74696f6e73206f663e0d0a3c6c696e6b2072656c3d22636c61696d2074686174
      207468656861766520646576656c6f7065643c7461626c652077696474683d22
      63656c6562726174696f6e206f66466f6c6c6f77696e672074686520746f2064
      697374696e67756973683c7370616e20636c6173733d226274616b657320706c
      61636520696e756e64657220746865206e616d656e6f74656420746861742074
      68653e3c215b656e6469665d2d2d3e0a7374796c653d226d617267696e2d696e
      7374656164206f6620746865696e74726f647563656420746865746865207072
      6f63657373206f66696e6372656173696e6720746865646966666572656e6365
      7320696e657374696d617465642074686174657370656369616c6c7920746865
      2f6469763e3c6469762069643d22776173206576656e7475616c6c797468726f
      7567686f75742068697374686520646966666572656e6365736f6d657468696e
      6720746861747370616e3e3c2f7370616e3e3c2f7369676e69666963616e746c
      79203e3c2f7363726970743e0d0a0d0a656e7669726f6e6d656e74616c20746f
      2070726576656e742074686568617665206265656e2075736564657370656369
      616c6c7920666f72756e6465727374616e6420746865697320657373656e7469
      616c6c797765726520746865206669727374697320746865206c617267657374
      68617665206265656e206d61646522207372633d22687474703a2f2f696e7465
      727072657465642061737365636f6e642068616c66206f6663726f6c6c696e67
      3d226e6f2220697320636f6d706f736564206f6649492c20486f6c7920526f6d
      616e697320657870656374656420746f68617665207468656972206f776e6465
      66696e656420617320746865747261646974696f6e616c6c7920686176652064
      6966666572656e74617265206f6674656e2075736564746f20656e7375726520
      7468617461677265656d656e742077697468636f6e7461696e696e6720746865
      617265206672657175656e746c79696e666f726d6174696f6e206f6e6578616d
      706c6520697320746865726573756c74696e6720696e20613c2f613e3c2f6c69
      3e3c2f756c3e20636c6173733d22666f6f746572616e6420657370656369616c
      6c79747970653d22627574746f6e22203c2f7370616e3e3c2f7370616e3e7768
      69636820696e636c756465643e0a3c6d657461206e616d653d22636f6e736964
      657265642074686563617272696564206f7574206279486f77657665722c2069
      74206973626563616d652070617274206f66696e2072656c6174696f6e20746f
      706f70756c617220696e20746865746865206361706974616c206f6677617320
      6f6666696369616c6c79776869636820686173206265656e7468652048697374
      6f7279206f66616c7465726e617469766520746f646966666572656e74206672
      6f6d746f20737570706f7274207468657375676765737465642074686174696e
      207468652070726f6365737320203c64697620636c6173733d2274686520666f
      756e646174696f6e62656361757365206f6620686973636f6e6365726e656420
      7769746874686520756e69766572736974796f70706f73656420746f20746865
      74686520636f6e74657874206f663c7370616e20636c6173733d227074657874
      22206e616d653d22712209093c64697620636c6173733d227468652073636965
      6e7469666963726570726573656e7465642062796d617468656d617469636961
      6e73656c656374656420627920746865746861742068617665206265656e3e3c



Alakuijala & Szabadka         Informational                   [Page 108]

RFC 7932                         Brotli                        July 2016


      64697620636c6173733d22636469762069643d22686561646572696e20706172
      746963756c61722c636f6e76657274656420696e746f293b0a3c2f7363726970
      743e0a3c7068696c6f736f70686963616c20737270736b6f6872766174736b69
      7469e1babf6e67205669e1bb8774d0a0d183d181d181d0bad0b8d0b9d180d183
      d181d181d0bad0b8d0b9696e766573746967616369c3b36e7061727469636970
      616369c3b36ed0bad0bed182d0bed180d18bd0b5d0bed0b1d0bbd0b0d181d182
      d0b8d0bad0bed182d0bed180d18bd0b9d187d0b5d0bbd0bed0b2d0b5d0bad181
      d0b8d181d182d0b5d0bcd18bd09dd0bed0b2d0bed181d182d0b8d0bad0bed182
      d0bed180d18bd185d0bed0b1d0bbd0b0d181d182d18cd0b2d180d0b5d0bcd0b5
      d0bdd0b8d0bad0bed182d0bed180d0b0d18fd181d0b5d0b3d0bed0b4d0bdd18f
      d181d0bad0b0d187d0b0d182d18cd0bdd0bed0b2d0bed181d182d0b8d0a3d0ba
      d180d0b0d0b8d0bdd18bd0b2d0bed0bfd180d0bed181d18bd0bad0bed182d0be
      d180d0bed0b9d181d0b4d0b5d0bbd0b0d182d18cd0bfd0bed0bcd0bed189d18c
      d18ed181d180d0b5d0b4d181d182d0b2d0bed0b1d180d0b0d0b7d0bed0bcd181
      d182d0bed180d0bed0bdd18bd183d187d0b0d181d182d0b8d0b5d182d0b5d187
      d0b5d0bdd0b8d0b5d093d0bbd0b0d0b2d0bdd0b0d18fd0b8d181d182d0bed180
      d0b8d0b8d181d0b8d181d182d0b5d0bcd0b0d180d0b5d188d0b5d0bdd0b8d18f
      d0a1d0bad0b0d187d0b0d182d18cd0bfd0bed18dd182d0bed0bcd183d181d0bb
      d0b5d0b4d183d0b5d182d181d0bad0b0d0b7d0b0d182d18cd182d0bed0b2d0b0
      d180d0bed0b2d0bad0bed0bdd0b5d187d0bdd0bed180d0b5d188d0b5d0bdd0b8
      d0b5d0bad0bed182d0bed180d0bed0b5d0bed180d0b3d0b0d0bdd0bed0b2d0ba
      d0bed182d0bed180d0bed0bcd0a0d0b5d0bad0bbd0b0d0bcd0b0d8a7d984d985
      d986d8aad8afd989d985d986d8aad8afd98ad8a7d8aad8a7d984d985d988d8b6
      d988d8b9d8a7d984d8a8d8b1d8a7d985d8acd8a7d984d985d988d8a7d982d8b9
      d8a7d984d8b1d8b3d8a7d8a6d984d985d8b4d8a7d8b1d983d8a7d8aad8a7d984
      d8a3d8b9d8b6d8a7d8a1d8a7d984d8b1d98ad8a7d8b6d8a9d8a7d984d8aad8b5
      d985d98ad985d8a7d984d8a7d8b9d8b6d8a7d8a1d8a7d984d986d8aad8a7d8a6
      d8acd8a7d984d8a3d984d8b9d8a7d8a8d8a7d984d8aad8b3d8acd98ad984d8a7
      d984d8a3d982d8b3d8a7d985d8a7d984d8b6d8bad8b7d8a7d8aad8a7d984d981
      d98ad8afd98ad988d8a7d984d8aad8b1d8add98ad8a8d8a7d984d8acd8afd98a
      d8afd8a9d8a7d984d8aad8b9d984d98ad985d8a7d984d8a3d8aed8a8d8a7d8b1
      d8a7d984d8a7d981d984d8a7d985d8a7d984d8a3d981d984d8a7d985d8a7d984
      d8aad8a7d8b1d98ad8aed8a7d984d8aad982d986d98ad8a9d8a7d984d8a7d984
      d8b9d8a7d8a8d8a7d984d8aed988d8a7d8b7d8b1d8a7d984d985d8acd8aad985
      d8b9d8a7d984d8afd98ad983d988d8b1d8a7d984d8b3d98ad8a7d8add8a9d8b9
      d8a8d8afd8a7d984d984d987d8a7d984d8aad8b1d8a8d98ad8a9d8a7d984d8b1
      d988d8a7d8a8d8b7d8a7d984d8a3d8afd8a8d98ad8a9d8a7d984d8a7d8aed8a8
      d8a7d8b1d8a7d984d985d8aad8add8afd8a9d8a7d984d8a7d8bad8a7d986d98a
      637572736f723a706f696e7465723b3c2f7469746c653e0a3c6d657461202220
      687265663d22687474703a2f2f223e3c7370616e20636c6173733d226d656d62
      657273206f66207468652077696e646f772e6c6f636174696f6e766572746963
      616c2d616c69676e3a2f613e207c203c6120687265663d223c21646f63747970
      652068746d6c3e6d656469613d2273637265656e22203c6f7074696f6e207661
      6c75653d2266617669636f6e2e69636f22202f3e0a09093c64697620636c6173
      733d2263686172616374657269737469637322206d6574686f643d2267657422
      202f626f64793e0a3c2f68746d6c3e0a73686f72746375742069636f6e222064
      6f63756d656e742e77726974652870616464696e672d626f74746f6d3a726570
      726573656e746174697665737375626d6974222076616c75653d22616c69676e



Alakuijala & Szabadka         Informational                   [Page 109]

RFC 7932                         Brotli                        July 2016


      3d2263656e74657222207468726f7567686f75742074686520736369656e6365
      2066696374696f6e0a20203c64697620636c6173733d227375626d6974222063
      6c6173733d226f6e65206f6620746865206d6f73742076616c69676e3d22746f
      70223e3c7761732065737461626c6973686564293b0d0a3c2f7363726970743e
      0d0a72657475726e2066616c73653b223e292e7374796c652e646973706c6179
      62656361757365206f662074686520646f63756d656e742e636f6f6b69653c66
      6f726d20616374696f6e3d222f7d626f64797b6d617267696e3a303b456e6379
      636c6f7065646961206f6676657273696f6e206f6620746865202e6372656174
      65456c656d656e74286e616d652220636f6e74656e743d223c2f6469763e0a3c
      2f6469763e0a0a61646d696e697374726174697665203c2f626f64793e0a3c2f
      68746d6c3e686973746f7279206f662074686520223e3c696e70757420747970
      653d22706f7274696f6e206f66207468652061732070617274206f6620746865
      20266e6273703b3c6120687265663d226f7468657220636f756e747269657322
      3e0a3c64697620636c6173733d223c2f7370616e3e3c2f7370616e3e3c496e20
      6f7468657220776f7264732c646973706c61793a20626c6f636b3b636f6e7472
      6f6c206f662074686520696e74726f64756374696f6e206f662f3e0a3c6d6574
      61206e616d653d2261732077656c6c2061732074686520696e20726563656e74
      2079656172730d0a093c64697620636c6173733d223c2f6469763e0a093c2f64
      69763e0a696e7370697265642062792074686574686520656e64206f66207468
      6520636f6d70617469626c652077697468626563616d65206b6e6f776e206173
      207374796c653d226d617267696e3a2e6a73223e3c2f7363726970743e3c2049
      6e7465726e6174696f6e616c2074686572652068617665206265656e4765726d
      616e206c616e6775616765207374796c653d22636f6c6f723a23436f6d6d756e
      697374205061727479636f6e73697374656e742077697468626f726465723d22
      30222063656c6c206d617267696e6865696768743d22746865206d616a6f7269
      7479206f662220616c69676e3d2263656e74657272656c6174656420746f2074
      6865206d616e7920646966666572656e74204f7274686f646f78204368757263
      6873696d696c617220746f20746865202f3e0a3c6c696e6b2072656c3d227377
      6173206f6e65206f662074686520756e74696c206869732064656174687d2928
      293b0a3c2f7363726970743e6f74686572206c616e677561676573636f6d7061
      72656420746f20746865706f7274696f6e73206f6620746865746865204e6574
      6865726c616e6473746865206d6f737420636f6d6d6f6e6261636b67726f756e
      643a75726c286172677565642074686174207468657363726f6c6c696e673d22
      6e6f2220696e636c7564656420696e207468654e6f72746820416d6572696361
      6e20746865206e616d65206f6620746865696e746572707265746174696f6e73
      74686520747261646974696f6e616c646576656c6f706d656e74206f66206672
      657175656e746c7920757365646120636f6c6c656374696f6e206f6676657279
      2073696d696c617220746f737572726f756e64696e67207468656578616d706c
      65206f662074686973616c69676e3d2263656e746572223e776f756c64206861
      7665206265656e696d6167655f63617074696f6e203d61747461636865642074
      6f2074686573756767657374696e672074686174696e2074686520666f726d20
      6f6620696e766f6c76656420696e20746865697320646572697665642066726f
      6d6e616d656420616674657220746865496e74726f64756374696f6e20746f72
      65737472696374696f6e73206f6e207374796c653d2277696474683a2063616e
      206265207573656420746f20746865206372656174696f6e206f666d6f737420
      696d706f7274616e7420696e666f726d6174696f6e20616e64726573756c7465
      6420696e20746865636f6c6c61707365206f662074686554686973206d65616e
      732074686174656c656d656e7473206f6620746865776173207265706c616365



Alakuijala & Szabadka         Informational                   [Page 110]

RFC 7932                         Brotli                        July 2016


      64206279616e616c79736973206f6620746865696e737069726174696f6e2066
      6f727265676172646564206173207468656d6f7374207375636365737366756c
      6b6e6f776e206173202671756f743b6120636f6d70726568656e736976654869
      73746f7279206f6620746865207765726520636f6e7369646572656472657475
      726e656420746f2074686561726520726566657272656420746f556e736f7572
      63656420696d6167653e0a093c64697620636c6173733d22636f6e7369737473
      206f662074686573746f7050726f7061676174696f6e696e7465726573742069
      6e20746865617661696c6162696c697479206f666170706561727320746f2068
      617665656c656374726f6d61676e65746963656e61626c655365727669636573
      2866756e6374696f6e206f6620746865497420697320696d706f7274616e743c
      2f7363726970743e3c2f6469763e66756e6374696f6e28297b7661722072656c
      617469766520746f207468656173206120726573756c74206f66207468652070
      6f736974696f6e206f66466f72206578616d706c652c20696e206d6574686f64
      3d22706f7374222077617320666f6c6c6f77656420627926616d703b6d646173
      683b20746865746865206170706c69636174696f6e6a73223e3c2f7363726970
      743e0d0a756c3e3c2f6469763e3c2f6469763e61667465722074686520646561
      746877697468207265737065637420746f7374796c653d2270616464696e673a
      697320706172746963756c61726c79646973706c61793a696e6c696e653b2074
      7970653d227375626d697422206973206469766964656420696e746fe4b8ade6
      96872028e7ae80e4bd9329726573706f6e736162696c6964616461646d696e69
      737472616369c3b36e696e7465726e6163696f6e616c6573636f72726573706f
      6e6469656e7465e0a489e0a4aae0a4afe0a58be0a497e0a4aae0a582e0a4b0e0
      a58de0a4b5e0a4b9e0a4aee0a4bee0a4b0e0a587e0a4b2e0a58be0a497e0a58b
      e0a482e0a49ae0a581e0a4a8e0a4bee0a4b5e0a4b2e0a587e0a495e0a4bfe0a4
      a8e0a4b8e0a4b0e0a495e0a4bee0a4b0e0a4aae0a581e0a4b2e0a4bfe0a4b8e0
      a496e0a58be0a49ce0a587e0a482e0a49ae0a4bee0a4b9e0a4bfe0a48fe0a4ad
      e0a587e0a49ce0a587e0a482e0a4b6e0a4bee0a4aee0a4bfe0a4b2e0a4b9e0a4
      aee0a4bee0a4b0e0a580e0a49ce0a4bee0a497e0a4b0e0a4a3e0a4ace0a4a8e0
      a4bee0a4a8e0a587e0a495e0a581e0a4aee0a4bee0a4b0e0a4ace0a58de0a4b2
      e0a589e0a497e0a4aee0a4bee0a4b2e0a4bfe0a495e0a4aee0a4b9e0a4bfe0a4
      b2e0a4bee0a4aae0a583e0a4b7e0a58de0a4a0e0a4ace0a4a2e0a4bce0a4a4e0
      a587e0a4ade0a4bee0a49ce0a4aae0a4bee0a495e0a58de0a4b2e0a4bfe0a495
      e0a49fe0a58de0a4b0e0a587e0a4a8e0a496e0a4bfe0a4b2e0a4bee0a4abe0a4
      a6e0a58ce0a4b0e0a4bee0a4a8e0a4aee0a4bee0a4aee0a4b2e0a587e0a4aee0
      a4a4e0a4a6e0a4bee0a4a8e0a4ace0a4bee0a49ce0a4bee0a4b0e0a4b5e0a4bf
      e0a495e0a4bee0a4b8e0a495e0a58de0a4afe0a58be0a482e0a49ae0a4bee0a4
      b9e0a4a4e0a587e0a4aae0a4b9e0a581e0a481e0a49ae0a4ace0a4a4e0a4bee0
      a4afe0a4bee0a4b8e0a482e0a4b5e0a4bee0a4a6e0a4a6e0a587e0a496e0a4a8
      e0a587e0a4aae0a4bfe0a49be0a4b2e0a587e0a4b5e0a4bfe0a4b6e0a587e0a4
      b7e0a4b0e0a4bee0a49ce0a58de0a4afe0a489e0a4a4e0a58de0a4a4e0a4b0e0
      a4aee0a581e0a482e0a4ace0a488e0a4a6e0a58be0a4a8e0a58be0a482e0a489
      e0a4aae0a495e0a4b0e0a4a3e0a4aae0a4a2e0a4bce0a587e0a482e0a4b8e0a5
      8de0a4a5e0a4bfe0a4a4e0a4abe0a4bfe0a4b2e0a58de0a4aee0a4aee0a581e0
      a496e0a58de0a4afe0a485e0a49ae0a58de0a49be0a4bee0a49be0a582e0a49f
      e0a4a4e0a580e0a4b8e0a482e0a497e0a580e0a4a4e0a49ce0a4bee0a48fe0a4
      97e0a4bee0a4b5e0a4bfe0a4ade0a4bee0a497e0a498e0a4a3e0a58de0a49fe0
      a587e0a4a6e0a582e0a4b8e0a4b0e0a587e0a4a6e0a4bfe0a4a8e0a58be0a482
      e0a4b9e0a4a4e0a58de0a4afe0a4bee0a4b8e0a587e0a495e0a58de0a4b8e0a4



Alakuijala & Szabadka         Informational                   [Page 111]

RFC 7932                         Brotli                        July 2016


      97e0a4bee0a482e0a4a7e0a580e0a4b5e0a4bfe0a4b6e0a58de0a4b5e0a4b0e0
      a4bee0a4a4e0a587e0a482e0a4a6e0a588e0a49fe0a58de0a4b8e0a4a8e0a495
      e0a58de0a4b6e0a4bee0a4b8e0a4bee0a4aee0a4a8e0a587e0a485e0a4a6e0a4
      bee0a4b2e0a4a4e0a4ace0a4bfe0a49ce0a4b2e0a580e0a4aae0a581e0a4b0e0
      a582e0a4b7e0a4b9e0a4bfe0a482e0a4a6e0a580e0a4aee0a4bfe0a4a4e0a58d
      e0a4b0e0a495e0a4b5e0a4bfe0a4a4e0a4bee0a4b0e0a581e0a4aae0a4afe0a5
      87e0a4b8e0a58de0a4a5e0a4bee0a4a8e0a495e0a4b0e0a58be0a4a1e0a4bce0
      a4aee0a581e0a495e0a58de0a4a4e0a4afe0a58be0a49ce0a4a8e0a4bee0a495
      e0a583e0a4aae0a4afe0a4bee0a4aae0a58be0a4b8e0a58de0a49fe0a498e0a4
      b0e0a587e0a4b2e0a582e0a495e0a4bee0a4b0e0a58de0a4afe0a4b5e0a4bfe0
      a49ae0a4bee0a4b0e0a4b8e0a582e0a49ae0a4a8e0a4bee0a4aee0a582e0a4b2
      e0a58de0a4afe0a4a6e0a587e0a496e0a587e0a482e0a4b9e0a4aee0a587e0a4
      b6e0a4bee0a4b8e0a58de0a495e0a582e0a4b2e0a4aee0a588e0a482e0a4a8e0
      a587e0a4a4e0a588e0a4afe0a4bee0a4b0e0a49ce0a4bfe0a4b8e0a495e0a587
      7273732b786d6c22207469746c653d222d747970652220636f6e74656e743d22
      7469746c652220636f6e74656e743d226174207468652073616d652074696d65
      2e6a73223e3c2f7363726970743e0a3c22206d6574686f643d22706f73742220
      3c2f7370616e3e3c2f613e3c2f6c693e766572746963616c2d616c69676e3a74
      2f6a71756572792e6d696e2e6a73223e2e636c69636b2866756e6374696f6e28
      207374796c653d2270616464696e672d7d2928293b0a3c2f7363726970743e0a
      3c2f7370616e3e3c6120687265663d223c6120687265663d22687474703a2f2f
      293b2072657475726e2066616c73653b746578742d6465636f726174696f6e3a
      207363726f6c6c696e673d226e6f2220626f726465722d636f6c6c617073653a
      6173736f63696174656420776974682042616861736120496e646f6e65736961
      456e676c697368206c616e67756167653c7465787420786d6c3a73706163653d
      2e6769662220626f726465723d2230223c2f626f64793e0a3c2f68746d6c3e0a
      6f766572666c6f773a68696464656e3b696d67207372633d22687474703a2f2f
      6164644576656e744c697374656e6572726573706f6e7369626c6520666f7220
      732e6a73223e3c2f7363726970743e0a2f66617669636f6e2e69636f22202f3e
      6f7065726174696e672073797374656d22207374796c653d2277696474683a31
      7461726765743d225f626c616e6b223e537461746520556e6976657273697479
      746578742d616c69676e3a6c6566743b0a646f63756d656e742e777269746528
      2c20696e636c7564696e67207468652061726f756e642074686520776f726c64
      293b0d0a3c2f7363726970743e0d0a3c22207374796c653d226865696768743a
      3b6f766572666c6f773a68696464656e6d6f726520696e666f726d6174696f6e
      616e20696e7465726e6174696f6e616c61206d656d626572206f662074686520
      6f6e65206f662074686520666972737463616e20626520666f756e6420696e20
      3c2f6469763e0a09093c2f6469763e0a646973706c61793a206e6f6e653b223e
      22202f3e0a3c6c696e6b2072656c3d220a20202866756e6374696f6e2829207b
      74686520313574682063656e747572792e70726576656e7444656661756c7428
      6c61726765206e756d626572206f662042797a616e74696e6520456d70697265
      2e6a70677c7468756d627c6c6566747c76617374206d616a6f72697479206f66
      6d616a6f72697479206f66207468652020616c69676e3d2263656e746572223e
      556e6976657273697479205072657373646f6d696e6174656420627920746865
      5365636f6e6420576f726c6420576172646973747269627574696f6e206f6620
      7374796c653d22706f736974696f6e3a7468652072657374206f662074686520
      636861726163746572697a65642062792072656c3d226e6f666f6c6c6f77223e
      646572697665732066726f6d20746865726174686572207468616e2074686520



Alakuijala & Szabadka         Informational                   [Page 112]

RFC 7932                         Brotli                        July 2016


      6120636f6d62696e6174696f6e206f667374796c653d2277696474683a313030
      456e676c6973682d737065616b696e67636f6d707574657220736369656e6365
      626f726465723d22302220616c743d22746865206578697374656e6365206f66
      44656d6f63726174696320506172747922207374796c653d226d617267696e2d
      466f72207468697320726561736f6e2c2e6a73223e3c2f7363726970743e0a09
      7342795461674e616d652873295b305d6a73223e3c2f7363726970743e0d0a3c
      2e6a73223e3c2f7363726970743e0d0a6c696e6b2072656c3d2269636f6e2220
      2720616c743d272720636c6173733d27666f726d6174696f6e206f6620746865
      76657273696f6e73206f6620746865203c2f613e3c2f6469763e3c2f6469763e
      2f706167653e0a20203c706167653e0a3c64697620636c6173733d22636f6e74
      626563616d652074686520666972737462616861736120496e646f6e65736961
      656e676c697368202873696d706c6529ce95cebbcebbceb7cebdceb9cebaceac
      d185d180d0b2d0b0d182d181d0bad0b8d0bad0bed0bcd0bfd0b0d0bdd0b8d0b8
      d18fd0b2d0bbd18fd0b5d182d181d18fd094d0bed0b1d0b0d0b2d0b8d182d18c
      d187d0b5d0bbd0bed0b2d0b5d0bad0b0d180d0b0d0b7d0b2d0b8d182d0b8d18f
      d098d0bdd182d0b5d180d0bdd0b5d182d09ed182d0b2d0b5d182d0b8d182d18c
      d0bdd0b0d0bfd180d0b8d0bcd0b5d180d0b8d0bdd182d0b5d180d0bdd0b5d182
      d0bad0bed182d0bed180d0bed0b3d0bed181d182d180d0b0d0bdd0b8d186d18b
      d0bad0b0d187d0b5d181d182d0b2d0b5d183d181d0bbd0bed0b2d0b8d18fd185
      d0bfd180d0bed0b1d0bbd0b5d0bcd18bd0bfd0bed0bbd183d187d0b8d182d18c
      d18fd0b2d0bbd18fd18ed182d181d18fd0bdd0b0d0b8d0b1d0bed0bbd0b5d0b5
      d0bad0bed0bcd0bfd0b0d0bdd0b8d18fd0b2d0bdd0b8d0bcd0b0d0bdd0b8d0b5
      d181d180d0b5d0b4d181d182d0b2d0b0d8a7d984d985d988d8a7d8b6d98ad8b9
      d8a7d984d8b1d8a6d98ad8b3d98ad8a9d8a7d984d8a7d986d8aad982d8a7d984
      d985d8b4d8a7d8b1d983d8a7d8aad983d8a7d984d8b3d98ad8a7d8b1d8a7d8aa
      d8a7d984d985d983d8aad988d8a8d8a9d8a7d984d8b3d8b9d988d8afd98ad8a9
      d8a7d8add8b5d8a7d8a6d98ad8a7d8aad8a7d984d8b9d8a7d984d985d98ad8a9
      d8a7d984d8b5d988d8aad98ad8a7d8aad8a7d984d8a7d986d8aad8b1d986d8aa
      d8a7d984d8aad8b5d8a7d985d98ad985d8a7d984d8a5d8b3d984d8a7d985d98a
      d8a7d984d985d8b4d8a7d8b1d983d8a9d8a7d984d985d8b1d8a6d98ad8a7d8aa
      726f626f74732220636f6e74656e743d223c6469762069643d22666f6f746572
      223e74686520556e69746564205374617465733c696d67207372633d22687474
      703a2f2f2e6a70677c72696768747c7468756d627c2e6a73223e3c2f73637269
      70743e0d0a3c6c6f636174696f6e2e70726f746f636f6c6672616d65626f7264
      65723d223022207322202f3e0a3c6d657461206e616d653d223c2f613e3c2f64
      69763e3c2f6469763e3c666f6e742d7765696768743a626f6c643b2671756f74
      3b20616e64202671756f743b646570656e64696e67206f6e20746865206d6172
      67696e3a303b70616464696e673a222072656c3d226e6f666f6c6c6f77222050
      7265736964656e74206f6620746865207477656e74696574682063656e747572
      7965766973696f6e3e0a20203c2f70616765496e7465726e6574204578706c6f
      726572612e6173796e63203d20747275653b0d0a696e666f726d6174696f6e20
      61626f75743c6469762069643d22686561646572223e2220616374696f6e3d22
      687474703a2f2f3c6120687265663d2268747470733a2f2f3c6469762069643d
      22636f6e74656e74223c2f6469763e0d0a3c2f6469763e0d0a3c646572697665
      642066726f6d20746865203c696d67207372633d27687474703a2f2f6163636f
      7264696e6720746f20746865200a3c2f626f64793e0a3c2f68746d6c3e0a7374
      796c653d22666f6e742d73697a653a736372697074206c616e67756167653d22
      417269616c2c2048656c7665746963612c3c2f613e3c7370616e20636c617373



Alakuijala & Szabadka         Informational                   [Page 113]

RFC 7932                         Brotli                        July 2016


      3d223c2f7363726970743e3c73637269707420706f6c69746963616c20706172
      7469657374643e3c2f74723e3c2f7461626c653e3c687265663d22687474703a
      2f2f7777772e696e746572707265746174696f6e206f6672656c3d227374796c
      6573686565742220646f63756d656e742e777269746528273c63686172736574
      3d227574662d38223e0a626567696e6e696e67206f6620746865207265766561
      6c656420746861742074686574656c65766973696f6e20736572696573222072
      656c3d226e6f666f6c6c6f77223e207461726765743d225f626c616e6b223e63
      6c61696d696e6720746861742074686568747470253341253246253246777777
      2e6d616e69666573746174696f6e73206f665072696d65204d696e6973746572
      206f66696e666c75656e63656420627920746865636c6173733d22636c656172
      666978223e2f6469763e0d0a3c2f6469763e0d0a0d0a74687265652d64696d65
      6e73696f6e616c436875726368206f6620456e676c616e646f66204e6f727468
      204361726f6c696e61737175617265206b696c6f6d65747265732e6164644576
      656e744c697374656e657264697374696e63742066726f6d20746865636f6d6d
      6f6e6c79206b6e6f776e20617350686f6e6574696320416c7068616265746465
      636c61726564207468617420746865636f6e74726f6c6c656420627920746865
      42656e6a616d696e204672616e6b6c696e726f6c652d706c6179696e67206761
      6d6574686520556e6976657273697479206f66696e205765737465726e204575
      726f7065706572736f6e616c20636f6d707574657250726f6a65637420477574
      656e626572677265676172646c657373206f6620746865686173206265656e20
      70726f706f736564746f6765746865722077697468207468653e3c2f6c693e3c
      6c6920636c6173733d22696e20736f6d6520636f756e74726965736d696e2e6a
      73223e3c2f7363726970743e6f662074686520706f70756c6174696f6e6f6666
      696369616c206c616e67756167653c696d67207372633d22696d616765732f69
      64656e746966696564206279207468656e61747572616c207265736f75726365
      73636c617373696669636174696f6e206f6663616e20626520636f6e73696465
      7265647175616e74756d206d656368616e6963734e657665727468656c657373
      2c207468656d696c6c696f6e2079656172732061676f3c2f626f64793e0d0a3c
      2f68746d6c3e0dce95cebbcebbceb7cebdceb9cebaceac0a74616b6520616476
      616e74616765206f66616e642c206163636f7264696e6720746f617474726962
      7574656420746f207468654d6963726f736f66742057696e646f777374686520
      66697273742063656e74757279756e6465722074686520636f6e74726f6c6469
      7620636c6173733d2268656164657273686f72746c7920616674657220746865
      6e6f7461626c6520657863657074696f6e74656e73206f662074686f7573616e
      64737365766572616c20646966666572656e7461726f756e642074686520776f
      726c642e7265616368696e67206d696c697461727969736f6c61746564206672
      6f6d207468656f70706f736974696f6e20746f20746865746865204f6c642054
      657374616d656e744166726963616e20416d65726963616e73696e7365727465
      6420696e746f2074686573657061726174652066726f6d207468656d6574726f
      706f6c6974616e20617265616d616b657320697420706f737369626c6561636b
      6e6f776c656467656420746861746172677561626c7920746865206d6f737474
      7970653d22746578742f637373223e0a74686520496e7465726e6174696f6e61
      6c4163636f7264696e6720746f207468652070653d22746578742f6373732220
      2f3e0a636f696e6369646520776974682074686574776f2d746869726473206f
      6620746865447572696e6720746869732074696d652c647572696e6720746865
      20706572696f64616e6e6f756e636564207468617420686574686520696e7465
      726e6174696f6e616c616e64206d6f726520726563656e746c7962656c696576
      6564207468617420746865636f6e7363696f75736e65737320616e64666f726d



Alakuijala & Szabadka         Informational                   [Page 114]

RFC 7932                         Brotli                        July 2016


      65726c79206b6e6f776e206173737572726f756e646564206279207468656669
      72737420617070656172656420696e6f63636173696f6e616c6c792075736564
      706f736974696f6e3a6162736f6c7574653b22207461726765743d225f626c61
      6e6b2220706f736974696f6e3a72656c61746976653b746578742d616c69676e
      3a63656e7465723b6a61782f6c6962732f6a71756572792f312e6261636b6772
      6f756e642d636f6c6f723a23747970653d226170706c69636174696f6e2f616e
      67756167652220636f6e74656e743d223c6d65746120687474702d6571756976
      3d225072697661637920506f6c6963793c2f613e652822253343736372697074
      207372633d2722207461726765743d225f626c616e6b223e4f6e20746865206f
      746865722068616e642c2e6a70677c7468756d627c72696768747c323c2f6469
      763e3c64697620636c6173733d223c646976207374796c653d22666c6f61743a
      6e696e657465656e74682063656e747572793c2f626f64793e0d0a3c2f68746d
      6c3e0d0a3c696d67207372633d22687474703a2f2f733b746578742d616c6967
      6e3a63656e746572666f6e742d7765696768743a20626f6c643b204163636f72
      64696e6720746f2074686520646966666572656e6365206265747765656e2220
      6672616d65626f726465723d2230222022207374796c653d22706f736974696f
      6e3a6c696e6b20687265663d22687474703a2f2f68746d6c342f6c6f6f73652e
      647464223e0a647572696e67207468697320706572696f643c2f74643e3c2f74
      723e3c2f7461626c653e636c6f73656c792072656c6174656420746f666f7220
      7468652066697273742074696d653b666f6e742d7765696768743a626f6c643b
      696e70757420747970653d227465787422203c7370616e207374796c653d2266
      6f6e742d6f6e726561647973746174656368616e6765093c64697620636c6173
      733d22636c656172646f63756d656e742e6c6f636174696f6e2e20466f722065
      78616d706c652c20746865206120776964652076617269657479206f66203c21
      444f43545950452068746d6c3e0d0a3c266e6273703b266e6273703b266e6273
      703b223e3c6120687265663d22687474703a2f2f7374796c653d22666c6f6174
      3a6c6566743b636f6e6365726e65642077697468207468653d68747470253341
      2532462532467777772e696e20706f70756c61722063756c7475726574797065
      3d22746578742f63737322202f3e697420697320706f737369626c6520746f20
      4861727661726420556e697665727369747974796c6573686565742220687265
      663d222f746865206d61696e206368617261637465724f78666f726420556e69
      7665727369747920206e616d653d226b6579776f7264732220637374796c653d
      22746578742d616c69676e3a74686520556e69746564204b696e67646f6d6665
      646572616c20676f7665726e6d656e743c646976207374796c653d226d617267
      696e20646570656e64696e67206f6e20746865206465736372697074696f6e20
      6f66207468653c64697620636c6173733d226865616465722e6d696e2e6a7322
      3e3c2f7363726970743e6465737472756374696f6e206f6620746865736c6967
      68746c7920646966666572656e74696e206163636f7264616e63652077697468
      74656c65636f6d6d756e69636174696f6e73696e646963617465732074686174
      2074686573686f72746c792074686572656166746572657370656369616c6c79
      20696e20746865204575726f7065616e20636f756e7472696573486f77657665
      722c207468657265206172657372633d22687474703a2f2f7374617469637375
      6767657374656420746861742074686522207372633d22687474703a2f2f7777
      772e61206c61726765206e756d626572206f662054656c65636f6d6d756e6963
      6174696f6e73222072656c3d226e6f666f6c6c6f77222074486f6c7920526f6d
      616e20456d7065726f72616c6d6f7374206578636c75736976656c792220626f
      726465723d22302220616c743d22536563726574617279206f66205374617465
      63756c6d696e6174696e6720696e2074686543494120576f726c642046616374



Alakuijala & Szabadka         Informational                   [Page 115]

RFC 7932                         Brotli                        July 2016


      626f6f6b746865206d6f737420696d706f7274616e74616e6e69766572736172
      79206f66207468657374796c653d226261636b67726f756e642d3c6c693e3c65
      6d3e3c6120687265663d222f7468652041746c616e746963204f6365616e7374
      726963746c7920737065616b696e672c73686f72746c79206265666f72652074
      6865646966666572656e74207479706573206f66746865204f74746f6d616e20
      456d706972653e3c696d67207372633d22687474703a2f2f416e20496e74726f
      64756374696f6e20746f636f6e73657175656e6365206f662074686564657061
      72747572652066726f6d20746865436f6e666564657261746520537461746573
      696e646967656e6f75732070656f706c657350726f63656564696e6773206f66
      20746865696e666f726d6174696f6e206f6e207468657468656f726965732068
      617665206265656e696e766f6c76656d656e7420696e20746865646976696465
      6420696e746f20746872656561646a6163656e7420636f756e74726965736973
      20726573706f6e7369626c6520666f72646973736f6c7574696f6e206f662074
      6865636f6c6c61626f726174696f6e2077697468776964656c79207265676172
      64656420617368697320636f6e74656d706f726172696573666f756e64696e67
      206d656d626572206f66446f6d696e6963616e2052657075626c696367656e65
      72616c6c7920616363657074656474686520706f73736962696c697479206f66
      61726520616c736f20617661696c61626c65756e64657220636f6e7374727563
      74696f6e726573746f726174696f6e206f66207468657468652067656e657261
      6c207075626c6963697320616c6d6f737420656e746972656c79706173736573
      207468726f75676820746865686173206265656e20737567676573746564636f
      6d707574657220616e6420766964656f4765726d616e6963206c616e67756167
      6573206163636f7264696e6720746f2074686520646966666572656e74206672
      6f6d2074686573686f72746c792061667465727761726473687265663d226874
      7470733a2f2f7777772e726563656e7420646576656c6f706d656e74426f6172
      64206f66204469726563746f72733c64697620636c6173733d22736561726368
      7c203c6120687265663d22687474703a2f2f496e20706172746963756c61722c
      207468654d756c7469706c6520666f6f746e6f7465736f72206f746865722073
      75627374616e636574686f7573616e6473206f662079656172737472616e736c
      6174696f6e206f66207468653c2f6469763e0d0a3c2f6469763e0d0a0d0a3c61
      20687265663d22696e6465782e7068707761732065737461626c697368656420
      696e6d696e2e6a73223e3c2f7363726970743e0a706172746963697061746520
      696e2074686561207374726f6e6720696e666c75656e63657374796c653d226d
      617267696e2d746f703a726570726573656e7465642062792074686567726164
      75617465642066726f6d20746865547261646974696f6e616c6c792c20746865
      456c656d656e74282273637269707422293b486f77657665722c2073696e6365
      207468652f6469763e0a3c2f6469763e0a3c646976206c6566743b206d617267
      696e2d6c6566743a70726f74656374696f6e20616761696e7374303b20766572
      746963616c2d616c69676e3a556e666f7274756e6174656c792c207468657479
      70653d22696d6167652f782d69636f6e2f6469763e0a3c64697620636c617373
      3d2220636c6173733d22636c656172666978223e3c64697620636c6173733d22
      666f6f74657209093c2f6469763e0a09093c2f6469763e0a746865206d6f7469
      6f6e2070696374757265d091d18ad0bbd0b3d0b0d180d181d0bad0b8d0b1d18a
      d0bbd0b3d0b0d180d181d0bad0b8d0a4d0b5d0b4d0b5d180d0b0d186d0b8d0b8
      d0bdd0b5d181d0bad0bed0bbd18cd0bad0bed181d0bed0bed0b1d189d0b5d0bd
      d0b8d0b5d181d0bed0bed0b1d189d0b5d0bdd0b8d18fd0bfd180d0bed0b3d180
      d0b0d0bcd0bcd18bd09ed182d0bfd180d0b0d0b2d0b8d182d18cd0b1d0b5d181
      d0bfd0bbd0b0d182d0bdd0bed0bcd0b0d182d0b5d180d0b8d0b0d0bbd18bd0bf



Alakuijala & Szabadka         Informational                   [Page 116]

RFC 7932                         Brotli                        July 2016


      d0bed0b7d0b2d0bed0bbd18fd0b5d182d0bfd0bed181d0bbd0b5d0b4d0bdd0b8
      d0b5d180d0b0d0b7d0bbd0b8d187d0bdd18bd185d0bfd180d0bed0b4d183d0ba
      d186d0b8d0b8d0bfd180d0bed0b3d180d0b0d0bcd0bcd0b0d0bfd0bed0bbd0bd
      d0bed181d182d18cd18ed0bdd0b0d185d0bed0b4d0b8d182d181d18fd0b8d0b7
      d0b1d180d0b0d0bdd0bdd0bed0b5d0bdd0b0d181d0b5d0bbd0b5d0bdd0b8d18f
      d0b8d0b7d0bcd0b5d0bdd0b5d0bdd0b8d18fd0bad0b0d182d0b5d0b3d0bed180
      d0b8d0b8d090d0bbd0b5d0bad181d0b0d0bdd0b4d180e0a4a6e0a58de0a4b5e0
      a4bee0a4b0e0a4bee0a4aee0a588e0a4a8e0a581e0a485e0a4b2e0a4aae0a58d
      e0a4b0e0a4a6e0a4bee0a4a8e0a4ade0a4bee0a4b0e0a4a4e0a580e0a4afe0a4
      85e0a4a8e0a581e0a4a6e0a587e0a4b6e0a4b9e0a4bfe0a4a8e0a58de0a4a6e0
      a580e0a487e0a482e0a4a1e0a4bfe0a4afe0a4bee0a4a6e0a4bfe0a4b2e0a58d
      e0a4b2e0a580e0a485e0a4a7e0a4bfe0a495e0a4bee0a4b0e0a4b5e0a580e0a4
      a1e0a4bfe0a4afe0a58be0a49ae0a4bfe0a49fe0a58de0a4a0e0a587e0a4b8e0
      a4aee0a4bee0a49ae0a4bee0a4b0e0a49ce0a482e0a495e0a58de0a4b6e0a4a8
      e0a4a6e0a581e0a4a8e0a4bfe0a4afe0a4bee0a4aae0a58de0a4b0e0a4afe0a5
      8be0a497e0a485e0a4a8e0a581e0a4b8e0a4bee0a4b0e0a491e0a4a8e0a4b2e0
      a4bee0a487e0a4a8e0a4aae0a4bee0a4b0e0a58de0a49fe0a580e0a4b6e0a4b0
      e0a58de0a4a4e0a58be0a482e0a4b2e0a58be0a495e0a4b8e0a4ade0a4bee0a4
      abe0a4bce0a58de0a4b2e0a588e0a4b6e0a4b6e0a4b0e0a58de0a4a4e0a587e0
      a482e0a4aae0a58de0a4b0e0a4a6e0a587e0a4b6e0a4aae0a58de0a4b2e0a587
      e0a4afe0a4b0e0a495e0a587e0a482e0a4a6e0a58de0a4b0e0a4b8e0a58de0a4
      a5e0a4bfe0a4a4e0a4bfe0a489e0a4a4e0a58de0a4aae0a4bee0a4a6e0a489e0
      a4a8e0a58de0a4b9e0a587e0a482e0a49ae0a4bfe0a49fe0a58de0a4a0e0a4be
      e0a4afe0a4bee0a4a4e0a58de0a4b0e0a4bee0a49ce0a58de0a4afe0a4bee0a4
      a6e0a4bee0a4aae0a581e0a4b0e0a4bee0a4a8e0a587e0a49ce0a58be0a4a1e0
      a4bce0a587e0a482e0a485e0a4a8e0a581e0a4b5e0a4bee0a4a6e0a4b6e0a58d
      e0a4b0e0a587e0a4a3e0a580e0a4b6e0a4bfe0a495e0a58de0a4b7e0a4bee0a4
      b8e0a4b0e0a495e0a4bee0a4b0e0a580e0a4b8e0a482e0a497e0a58de0a4b0e0
      a4b9e0a4aae0a4b0e0a4bfe0a4a3e0a4bee0a4aee0a4ace0a58de0a4b0e0a4be
      e0a482e0a4a1e0a4ace0a49ae0a58de0a49ae0a58be0a482e0a489e0a4aae0a4
      b2e0a4ace0a58de0a4a7e0a4aee0a482e0a4a4e0a58de0a4b0e0a580e0a4b8e0
      a482e0a4aae0a4b0e0a58de0a495e0a489e0a4aee0a58de0a4aee0a580e0a4a6
      e0a4aee0a4bee0a4a7e0a58de0a4afe0a4aee0a4b8e0a4b9e0a4bee0a4afe0a4
      a4e0a4bee0a4b6e0a4ace0a58de0a4a6e0a58be0a482e0a4aee0a580e0a4a1e0
      a4bfe0a4afe0a4bee0a486e0a488e0a4aae0a580e0a48fe0a4b2e0a4aee0a58b
      e0a4ace0a4bee0a487e0a4b2e0a4b8e0a482e0a496e0a58de0a4afe0a4bee0a4
      86e0a4aae0a4b0e0a587e0a4b6e0a4a8e0a485e0a4a8e0a581e0a4ace0a482e0
      a4a7e0a4ace0a4bee0a49ce0a4bce0a4bee0a4b0e0a4a8e0a4b5e0a580e0a4a8
      e0a4a4e0a4aee0a4aae0a58de0a4b0e0a4aee0a581e0a496e0a4aae0a58de0a4
      b0e0a4b6e0a58de0a4a8e0a4aae0a4b0e0a4bfe0a4b5e0a4bee0a4b0e0a4a8e0
      a581e0a495e0a4b8e0a4bee0a4a8e0a4b8e0a4aee0a4b0e0a58de0a4a5e0a4a8
      e0a486e0a4afe0a58be0a49ce0a4bfe0a4a4e0a4b8e0a58be0a4aee0a4b5e0a4
      bee0a4b0d8a7d984d985d8b4d8a7d8b1d983d8a7d8aad8a7d984d985d986d8aa
      d8afd98ad8a7d8aad8a7d984d983d985d8a8d98ad988d8aad8b1d8a7d984d985
      d8b4d8a7d987d8afd8a7d8aad8b9d8afd8afd8a7d984d8b2d988d8a7d8b1d8b9
      d8afd8afd8a7d984d8b1d8afd988d8afd8a7d984d8a5d8b3d984d8a7d985d98a
      d8a9d8a7d984d981d988d8aad988d8b4d988d8a8d8a7d984d985d8b3d8a7d8a8
      d982d8a7d8aad8a7d984d985d8b9d984d988d985d8a7d8aad8a7d984d985d8b3



Alakuijala & Szabadka         Informational                   [Page 117]

RFC 7932                         Brotli                        July 2016


      d984d8b3d984d8a7d8aad8a7d984d8acd8b1d8a7d981d98ad983d8b3d8a7d984
      d8a7d8b3d984d8a7d985d98ad8a9d8a7d984d8a7d8aad8b5d8a7d984d8a7d8aa
      6b6579776f7264732220636f6e74656e743d2277332e6f72672f313939392f78
      68746d6c223e3c61207461726765743d225f626c616e6b2220746578742f6874
      6d6c3b20636861727365743d22207461726765743d225f626c616e6b223e3c74
      61626c652063656c6c70616464696e673d226175746f636f6d706c6574653d22
      6f66662220746578742d616c69676e3a2063656e7465723b746f206c61737420
      76657273696f6e206279206261636b67726f756e642d636f6c6f723a20232220
      687265663d22687474703a2f2f7777772e2f6469763e3c2f6469763e3c646976
      2069643d3c6120687265663d22232220636c6173733d22223e3c696d67207372
      633d22687474703a2f2f637269707422207372633d22687474703a2f2f0a3c73
      6372697074206c616e67756167653d222f2f454e222022687474703a2f2f7777
      772e77656e636f6465555249436f6d706f6e656e74282220687265663d226a61
      76617363726970743a3c64697620636c6173733d22636f6e74656e74646f6375
      6d656e742e777269746528273c7363706f736974696f6e3a206162736f6c7574
      653b736372697074207372633d22687474703a2f2f207374796c653d226d6172
      67696e2d746f703a2e6d696e2e6a73223e3c2f7363726970743e0a3c2f646976
      3e0a3c64697620636c6173733d2277332e6f72672f313939392f7868746d6c22
      200a0d0a3c2f626f64793e0d0a3c2f68746d6c3e64697374696e6374696f6e20
      6265747765656e2f22207461726765743d225f626c616e6b223e3c6c696e6b20
      687265663d22687474703a2f2f656e636f64696e673d227574662d38223f3e0a
      772e6164644576656e744c697374656e65723f616374696f6e3d22687474703a
      2f2f7777772e69636f6e2220687265663d22687474703a2f2f207374796c653d
      226261636b67726f756e643a747970653d22746578742f63737322202f3e0a6d
      6574612070726f70657274793d226f673a743c696e70757420747970653d2274
      6578742220207374796c653d22746578742d616c69676e3a7468652064657665
      6c6f706d656e74206f662074796c6573686565742220747970653d2274656874
      6d6c3b20636861727365743d7574662d38697320636f6e736964657265642074
      6f2062657461626c652077696474683d22313030252220496e20616464697469
      6f6e20746f2074686520636f6e747269627574656420746f2074686520646966
      666572656e636573206265747765656e646576656c6f706d656e74206f662074
      686520497420697320696d706f7274616e7420746f203c2f7363726970743e0a
      0a3c73637269707420207374796c653d22666f6e742d73697a653a313e3c2f73
      70616e3e3c7370616e2069643d67624c696272617279206f6620436f6e677265
      73733c696d67207372633d22687474703a2f2f696d456e676c69736820747261
      6e736c6174696f6e41636164656d79206f6620536369656e6365736469762073
      74796c653d22646973706c61793a636f6e737472756374696f6e206f66207468
      652e676574456c656d656e744279496428696429696e20636f6e6a756e637469
      6f6e2077697468456c656d656e74282773637269707427293b203c6d65746120
      70726f70657274793d226f673ad091d18ad0bbd0b3d0b0d180d181d0bad0b80a
      20747970653d227465787422206e616d653d223e5072697661637920506f6c69
      63793c2f613e61646d696e6973746572656420627920746865656e61626c6553
      696e676c65526571756573747374796c653d2671756f743b6d617267696e3a3c
      2f6469763e3c2f6469763e3c2f6469763e3c3e3c696d67207372633d22687474
      703a2f2f69207374796c653d2671756f743b666c6f61743a7265666572726564
      20746f2061732074686520746f74616c20706f70756c6174696f6e206f66696e
      2057617368696e67746f6e2c20442e432e207374796c653d226261636b67726f
      756e642d616d6f6e67206f74686572207468696e67732c6f7267616e697a6174



Alakuijala & Szabadka         Informational                   [Page 118]

RFC 7932                         Brotli                        July 2016


      696f6e206f662074686570617274696369706174656420696e20746865746865
      20696e74726f64756374696f6e206f666964656e746966696564207769746820
      74686566696374696f6e616c20636861726163746572204f78666f726420556e
      6976657273697479206d6973756e6465727374616e64696e67206f6654686572
      65206172652c20686f77657665722c7374796c6573686565742220687265663d
      222f436f6c756d62696120556e6976657273697479657870616e64656420746f
      20696e636c756465757375616c6c7920726566657272656420746f696e646963
      6174696e67207468617420746865686176652073756767657374656420746861
      74616666696c6961746564207769746820746865636f7272656c6174696f6e20
      6265747765656e6e756d626572206f6620646966666572656e743e3c2f74643e
      3c2f74723e3c2f7461626c653e52657075626c6963206f66204972656c616e64
      0a3c2f7363726970743e0a3c73637269707420756e6465722074686520696e66
      6c75656e6365636f6e747269627574696f6e20746f207468654f666669636961
      6c2077656273697465206f66686561647175617274657273206f662074686563
      656e74657265642061726f756e6420746865696d706c69636174696f6e73206f
      662074686568617665206265656e20646576656c6f7065644665646572616c20
      52657075626c6963206f66626563616d6520696e6372656173696e676c79636f
      6e74696e756174696f6e206f66207468654e6f74652c20686f77657665722c20
      7468617473696d696c617220746f2074686174206f66206361706162696c6974
      696573206f66207468656163636f7264616e6365207769746820746865706172
      7469636970616e747320696e207468656675727468657220646576656c6f706d
      656e74756e6465722074686520646972656374696f6e6973206f6674656e2063
      6f6e7369646572656468697320796f756e6765722062726f746865723c2f7464
      3e3c2f74723e3c2f7461626c653e3c6120687474702d65717569763d22582d55
      412d706879736963616c2070726f706572746965736f66204272697469736820
      436f6c756d626961686173206265656e20637269746963697a65642877697468
      2074686520657863657074696f6e7175657374696f6e732061626f7574207468
      6570617373696e67207468726f7567682074686530222063656c6c7061646469
      6e673d2230222074686f7573616e6473206f662070656f706c65726564697265
      63747320686572652e20466f7268617665206368696c6472656e20756e646572
      2533452533432f7363726970742533452229293b3c6120687265663d22687474
      703a2f2f7777772e3c6c693e3c6120687265663d22687474703a2f2f73697465
      5f6e616d652220636f6e74656e743d22746578742d6465636f726174696f6e3a
      6e6f6e657374796c653d22646973706c61793a206e6f6e653c6d657461206874
      74702d65717569763d22582d6e6577204461746528292e67657454696d652829
      20747970653d22696d6167652f782d69636f6e223c2f7370616e3e3c7370616e
      20636c6173733d226c616e67756167653d226a61766173637269707477696e64
      6f772e6c6f636174696f6e2e687265663c6120687265663d226a617661736372
      6970743a2d2d3e0d0a3c73637269707420747970653d22743c6120687265663d
      27687474703a2f2f7777772e686f72746375742069636f6e2220687265663d22
      3c2f6469763e0d0a3c64697620636c6173733d223c736372697074207372633d
      22687474703a2f2f222072656c3d227374796c6573686565742220743c2f6469
      763e0a3c73637269707420747970653d2f613e203c6120687265663d22687474
      703a2f2f20616c6c6f775472616e73706172656e63793d22582d55412d436f6d
      70617469626c652220636f6e72656c6174696f6e73686970206265747765656e
      0a3c2f7363726970743e0d0a3c736372697074203c2f613e3c2f6c693e3c2f75
      6c3e3c2f6469763e6173736f6369617465642077697468207468652070726f67
      72616d6d696e67206c616e67756167653c2f613e3c6120687265663d22687474



Alakuijala & Szabadka         Informational                   [Page 119]

RFC 7932                         Brotli                        July 2016


      703a2f2f3c2f613e3c2f6c693e3c6c6920636c6173733d22666f726d20616374
      696f6e3d22687474703a2f2f3c646976207374796c653d22646973706c61793a
      747970653d227465787422206e616d653d2271223c7461626c65207769647468
      3d223130302522206261636b67726f756e642d706f736974696f6e3a2220626f
      726465723d2230222077696474683d2272656c3d2273686f7274637574206963
      6f6e222068363e3c756c3e3c6c693e3c6120687265663d2220203c6d65746120
      687474702d65717569763d2263737322206d656469613d2273637265656e2220
      726573706f6e7369626c6520666f7220746865202220747970653d226170706c
      69636174696f6e2f22207374796c653d226261636b67726f756e642d68746d6c
      3b20636861727365743d7574662d382220616c6c6f777472616e73706172656e
      63793d227374796c6573686565742220747970653d2274650d0a3c6d65746120
      687474702d65717569763d223e3c2f7370616e3e3c7370616e20636c6173733d
      2230222063656c6c73706163696e673d2230223e3b0a3c2f7363726970743e0a
      3c73637269707420736f6d6574696d65732063616c6c656420746865646f6573
      206e6f74206e65636573736172696c79466f72206d6f726520696e666f726d61
      74696f6e61742074686520626567696e6e696e67206f66203c21444f43545950
      452068746d6c3e3c68746d6c706172746963756c61726c7920696e2074686520
      747970653d2268696464656e22206e616d653d226a6176617363726970743a76
      6f69642830293b226566666563746976656e657373206f662074686520617574
      6f636f6d706c6574653d226f6666222067656e6572616c6c7920636f6e736964
      657265643e3c696e70757420747970653d22746578742220223e3c2f73637269
      70743e0d0a3c7363726970747468726f7567686f75742074686520776f726c64
      636f6d6d6f6e206d6973636f6e63657074696f6e6173736f63696174696f6e20
      77697468207468653c2f6469763e0a3c2f6469763e0a3c646976206364757269
      6e6720686973206c69666574696d652c636f72726573706f6e64696e6720746f
      20746865747970653d22696d6167652f782d69636f6e2220616e20696e637265
      6173696e67206e756d6265726469706c6f6d617469632072656c6174696f6e73
      617265206f6674656e20636f6e736964657265646d6574612063686172736574
      3d227574662d3822203c696e70757420747970653d227465787422206578616d
      706c657320696e636c75646520746865223e3c696d67207372633d2268747470
      3a2f2f6970617274696369706174696f6e20696e207468657468652065737461
      626c6973686d656e74206f660a3c2f6469763e0a3c64697620636c6173733d22
      26616d703b6e6273703b26616d703b6e6273703b746f2064657465726d696e65
      2077686574686572717569746520646966666572656e742066726f6d6d61726b
      65642074686520626567696e6e696e6764697374616e6365206265747765656e
      20746865636f6e747269627574696f6e7320746f20746865636f6e666c696374
      206265747765656e20746865776964656c7920636f6e7369646572656420746f
      776173206f6e65206f6620746865206669727374776974682076617279696e67
      2064656772656573686176652073706563756c61746564207468617428646f63
      756d656e742e676574456c656d656e7470617274696369706174696e6720696e
      207468656f726967696e616c6c7920646576656c6f7065646574612063686172
      7365743d227574662d38223e20747970653d22746578742f63737322202f3e0a
      696e7465726368616e676561626c7920776974686d6f726520636c6f73656c79
      2072656c61746564736f6369616c20616e6420706f6c69746963616c74686174
      20776f756c64206f746865727769736570657270656e646963756c617220746f
      207468657374796c6520747970653d22746578742f637373747970653d227375
      626d697422206e616d653d2266616d696c696573207265736964696e6720696e
      646576656c6f70696e6720636f756e7472696573636f6d70757465722070726f



Alakuijala & Szabadka         Informational                   [Page 120]

RFC 7932                         Brotli                        July 2016


      6772616d6d696e6765636f6e6f6d696320646576656c6f706d656e7464657465
      726d696e6174696f6e206f6620746865666f72206d6f726520696e666f726d61
      74696f6e6f6e207365766572616c206f63636173696f6e73706f7274756775c3
      aa7320284575726f70657529d0a3d0bad180d0b0d197d0bdd181d18cd0bad0b0
      d183d0bad180d0b0d197d0bdd181d18cd0bad0b0d0a0d0bed181d181d0b8d0b9
      d181d0bad0bed0b9d0bcd0b0d182d0b5d180d0b8d0b0d0bbd0bed0b2d0b8d0bd
      d184d0bed180d0bcd0b0d186d0b8d0b8d183d0bfd180d0b0d0b2d0bbd0b5d0bd
      d0b8d18fd0bdd0b5d0bed0b1d185d0bed0b4d0b8d0bcd0bed0b8d0bdd184d0be
      d180d0bcd0b0d186d0b8d18fd098d0bdd184d0bed180d0bcd0b0d186d0b8d18f
      d0a0d0b5d181d0bfd183d0b1d0bbd0b8d0bad0b8d0bad0bed0bbd0b8d187d0b5
      d181d182d0b2d0bed0b8d0bdd184d0bed180d0bcd0b0d186d0b8d18ed182d0b5
      d180d180d0b8d182d0bed180d0b8d0b8d0b4d0bed181d182d0b0d182d0bed187
      d0bdd0bed8a7d984d985d8aad988d8a7d8acd8afd988d986d8a7d984d8a7d8b4
      d8aad8b1d8a7d983d8a7d8aad8a7d984d8a7d982d8aad8b1d8a7d8add8a7d8aa
      68746d6c3b20636861727365743d5554462d38222073657454696d656f757428
      66756e6374696f6e2829646973706c61793a696e6c696e652d626c6f636b3b3c
      696e70757420747970653d227375626d6974222074797065203d202774657874
      2f6a617661736372693c696d67207372633d22687474703a2f2f7777772e2220
      22687474703a2f2f7777772e77332e6f72672f73686f72746375742069636f6e
      2220687265663d2222206175746f636f6d706c6574653d226f666622203c2f61
      3e3c2f6469763e3c64697620636c6173733d3c2f613e3c2f6c693e0a3c6c6920
      636c6173733d226373732220747970653d22746578742f63737322203c666f72
      6d20616374696f6e3d22687474703a2f2f78742f6373732220687265663d2268
      7474703a2f2f6c696e6b2072656c3d22616c7465726e61746522200d0a3c7363
      7269707420747970653d22746578742f206f6e636c69636b3d226a6176617363
      726970743a286e65772044617465292e67657454696d6528297d686569676874
      3d2231222077696474683d2231222050656f706c6527732052657075626c6963
      206f6620203c6120687265663d22687474703a2f2f7777772e746578742d6465
      636f726174696f6e3a756e64657274686520626567696e6e696e67206f662074
      6865203c2f6469763e0a3c2f6469763e0a3c2f6469763e0a65737461626c6973
      686d656e74206f6620746865203c2f6469763e3c2f6469763e3c2f6469763e3c
      2f642376696577706f72747b6d696e2d6865696768743a0a3c73637269707420
      7372633d22687474703a2f2f6f7074696f6e3e3c6f7074696f6e2076616c7565
      3d6f6674656e20726566657272656420746f206173202f6f7074696f6e3e0a3c
      6f7074696f6e2076616c753c21444f43545950452068746d6c3e0a3c212d2d5b
      496e7465726e6174696f6e616c20416972706f72743e0a3c6120687265663d22
      687474703a2f2f7777773c2f613e3c6120687265663d22687474703a2f2f77e0
      b8a0e0b8b2e0b8a9e0b8b2e0b984e0b897e0b8a2e183a5e18390e183a0e18397
      e183a3e1839ae18398e6ada3e9ab94e4b8ade696872028e7b981e9ab9429e0a4
      a8e0a4bfe0a4b0e0a58de0a4a6e0a587e0a4b6e0a4a1e0a4bee0a489e0a4a8e0
      a4b2e0a58be0a4a1e0a495e0a58de0a4b7e0a587e0a4a4e0a58de0a4b0e0a49c
      e0a4bee0a4a8e0a495e0a4bee0a4b0e0a580e0a4b8e0a482e0a4ace0a482e0a4
      a7e0a4bfe0a4a4e0a4b8e0a58de0a4a5e0a4bee0a4aae0a4a8e0a4bee0a4b8e0
      a58de0a4b5e0a580e0a495e0a4bee0a4b0e0a4b8e0a482e0a4b8e0a58de0a495
      e0a4b0e0a4a3e0a4b8e0a4bee0a4aee0a497e0a58de0a4b0e0a580e0a49ae0a4
      bfe0a49fe0a58de0a4a0e0a58be0a482e0a4b5e0a4bfe0a49ce0a58de0a49ee0
      a4bee0a4a8e0a485e0a4aee0a587e0a4b0e0a4bfe0a495e0a4bee0a4b5e0a4bf
      e0a4ade0a4bfe0a4a8e0a58de0a4a8e0a497e0a4bee0a4a1e0a4bfe0a4afe0a4



Alakuijala & Szabadka         Informational                   [Page 121]

RFC 7932                         Brotli                        July 2016


      bee0a481e0a495e0a58de0a4afe0a58be0a482e0a495e0a4bfe0a4b8e0a581e0
      a4b0e0a495e0a58de0a4b7e0a4bee0a4aae0a4b9e0a581e0a481e0a49ae0a4a4
      e0a580e0a4aae0a58de0a4b0e0a4ace0a482e0a4a7e0a4a8e0a49fe0a4bfe0a4
      aae0a58de0a4aae0a4a3e0a580e0a495e0a58de0a4b0e0a4bfe0a495e0a587e0
      a49fe0a4aae0a58de0a4b0e0a4bee0a4b0e0a482e0a4ade0a4aae0a58de0a4b0
      e0a4bee0a4aae0a58de0a4a4e0a4aee0a4bee0a4b2e0a4bfe0a495e0a58be0a4
      82e0a4b0e0a4abe0a4bce0a58de0a4a4e0a4bee0a4b0e0a4a8e0a4bfe0a4b0e0
      a58de0a4aee0a4bee0a4a3e0a4b2e0a4bfe0a4aee0a4bfe0a49fe0a587e0a4a1
      6465736372697074696f6e2220636f6e74656e743d22646f63756d656e742e6c
      6f636174696f6e2e70726f742e676574456c656d656e747342795461674e616d
      65283c21444f43545950452068746d6c3e0a3c68746d6c203c6d657461206368
      61727365743d227574662d38223e3a75726c2220636f6e74656e743d22687474
      703a2f2f2e637373222072656c3d227374796c657368656574227374796c6520
      747970653d22746578742f637373223e747970653d22746578742f6373732220
      687265663d2277332e6f72672f313939392f7868746d6c2220786d6c74797065
      3d22746578742f6a61766173637269707422206d6574686f643d226765742220
      616374696f6e3d226c696e6b2072656c3d227374796c6573686565742220203d
      20646f63756d656e742e676574456c656d656e74747970653d22696d6167652f
      782d69636f6e22202f3e63656c6c70616464696e673d2230222063656c6c7370
      2e6373732220747970653d22746578742f63737322203c2f613e3c2f6c693e3c
      6c693e3c6120687265663d22222077696474683d223122206865696768743d22
      3122223e3c6120687265663d22687474703a2f2f7777772e7374796c653d2264
      6973706c61793a6e6f6e653b223e616c7465726e6174652220747970653d2261
      70706c692d2f2f5733432f2f445444205848544d4c20312e3020656c6c737061
      63696e673d2230222063656c6c70616420747970653d2268696464656e222076
      616c75653d222f613e266e6273703b3c7370616e20726f6c653d22730a3c696e
      70757420747970653d2268696464656e22206c616e67756167653d224a617661
      536372697074222020646f63756d656e742e676574456c656d656e747342673d
      2230222063656c6c73706163696e673d223022207970653d22746578742f6373
      7322206d656469613d22747970653d27746578742f6a61766173637269707427
      776974682074686520657863657074696f6e206f66207970653d22746578742f
      637373222072656c3d227374206865696768743d2231222077696474683d2231
      22203d272b656e636f6465555249436f6d706f6e656e74283c6c696e6b207265
      6c3d22616c7465726e61746522200a626f64792c2074722c20696e7075742c20
      746578746d657461206e616d653d22726f626f74732220636f6e6d6574686f64
      3d22706f73742220616374696f6e3d223e0a3c6120687265663d22687474703a
      2f2f7777772e637373222072656c3d227374796c65736865657422203c2f6469
      763e3c2f6469763e3c64697620636c6173736c616e67756167653d226a617661
      736372697074223e617269612d68696464656e3d2274727565223ec2b73c7269
      70742220747970653d22746578742f6a617661736c3d303b7d2928293b0a2866
      756e6374696f6e28297b6261636b67726f756e642d696d6167653a2075726c28
      2f613e3c2f6c693e3c6c693e3c6120687265663d226809093c6c693e3c612068
      7265663d22687474703a2f2f61746f722220617269612d68696464656e3d2274
      72753e203c6120687265663d22687474703a2f2f7777772e6c616e6775616765
      3d226a61766173637269707422202f6f7074696f6e3e0a3c6f7074696f6e2076
      616c75652f6469763e3c2f6469763e3c64697620636c6173733d7261746f7222
      20617269612d68696464656e3d227472653d286e65772044617465292e676574
      54696d652829706f7274756775c3aa732028646f2042726173696c29d0bed180



Alakuijala & Szabadka         Informational                   [Page 122]

RFC 7932                         Brotli                        July 2016


      d0b3d0b0d0bdd0b8d0b7d0b0d186d0b8d0b8d0b2d0bed0b7d0bcd0bed0b6d0bd
      d0bed181d182d18cd0bed0b1d180d0b0d0b7d0bed0b2d0b0d0bdd0b8d18fd180
      d0b5d0b3d0b8d181d182d180d0b0d186d0b8d0b8d0b2d0bed0b7d0bcd0bed0b6
      d0bdd0bed181d182d0b8d0bed0b1d18fd0b7d0b0d182d0b5d0bbd18cd0bdd0b0
      3c21444f43545950452068746d6c205055424c494320226e742d547970652220
      636f6e74656e743d22746578742f3c6d65746120687474702d65717569763d22
      436f6e746572616e736974696f6e616c2f2f454e222022687474703a3c68746d
      6c20786d6c6e733d22687474703a2f2f7777772d2f2f5733432f2f4454442058
      48544d4c20312e3020544454442f7868746d6c312d7472616e736974696f6e61
      6c2f2f7777772e77332e6f72672f54522f7868746d6c312f7065203d20277465
      78742f6a617661736372697074273b3c6d657461206e616d653d226465736372
      697074696f6e706172656e744e6f64652e696e736572744265666f72653c696e
      70757420747970653d2268696464656e22206e616a732220747970653d227465
      78742f6a6176617363726928646f63756d656e74292e72656164792866756e63
      746973637269707420747970653d22746578742f6a61766173696d6167652220
      636f6e74656e743d22687474703a2f2f55412d436f6d70617469626c65222063
      6f6e74656e743d746d6c3b20636861727365743d7574662d3822202f3e0a6c69
      6e6b2072656c3d2273686f72746375742069636f6e3c6c696e6b2072656c3d22
      7374796c65736865657422203c2f7363726970743e0a3c736372697074207479
      70653d3d20646f63756d656e742e637265617465456c656d656e3c6120746172
      6765743d225f626c616e6b2220687265663d20646f63756d656e742e67657445
      6c656d656e747342696e70757420747970653d227465787422206e616d653d61
      2e74797065203d2027746578742f6a617661736372696e70757420747970653d
      2268696464656e22206e616d6568746d6c3b20636861727365743d7574662d38
      22202f3e647464223e0a3c68746d6c20786d6c6e733d22687474702d2f2f5733
      432f2f4454442048544d4c20342e30312054656e747342795461674e616d6528
      277363726970742729696e70757420747970653d2268696464656e22206e616d
      3c73637269707420747970653d22746578742f6a6176617322207374796c653d
      22646973706c61793a6e6f6e653b223e646f63756d656e742e676574456c656d
      656e7442794964283d646f63756d656e742e637265617465456c656d656e7428
      2720747970653d27746578742f6a61766173637269707427696e707574207479
      70653d227465787422206e616d653d22642e676574456c656d656e7473427954
      61674e616d6528736e6963616c2220687265663d22687474703a2f2f7777772e
      432f2f4454442048544d4c20342e3031205472616e7369743c7374796c652074
      7970653d22746578742f637373223e0a0a3c7374796c6520747970653d227465
      78742f637373223e696f6e616c2e647464223e0a3c68746d6c20786d6c6e733d
      687474702d65717569763d22436f6e74656e742d5479706564696e673d223022
      2063656c6c73706163696e673d22302268746d6c3b20636861727365743d7574
      662d3822202f3e0a207374796c653d22646973706c61793a6e6f6e653b223e3c
      3c6c693e3c6120687265663d22687474703a2f2f7777772e20747970653d2774
      6578742f6a617661736372697074273ed0b4d0b5d18fd182d0b5d0bbd18cd0bd
      d0bed181d182d0b8d181d0bed0bed182d0b2d0b5d182d181d182d0b2d0b8d0b8
      d0bfd180d0bed0b8d0b7d0b2d0bed0b4d181d182d0b2d0b0d0b1d0b5d0b7d0be
      d0bfd0b0d181d0bdd0bed181d182d0b8e0a4aae0a581e0a4b8e0a58de0a4a4e0
      a4bfe0a495e0a4bee0a495e0a4bee0a482e0a497e0a58de0a4b0e0a587e0a4b8
      e0a489e0a4a8e0a58de0a4b9e0a58be0a482e0a4a8e0a587e0a4b5e0a4bfe0a4
      a7e0a4bee0a4a8e0a4b8e0a4ade0a4bee0a4abe0a4bfe0a495e0a58de0a4b8e0
      a4bfe0a482e0a497e0a4b8e0a581e0a4b0e0a495e0a58de0a4b7e0a4bfe0a4a4



Alakuijala & Szabadka         Informational                   [Page 123]

RFC 7932                         Brotli                        July 2016


      e0a495e0a589e0a4aae0a580e0a4b0e0a4bee0a487e0a49fe0a4b5e0a4bfe0a4
      9ce0a58de0a49ee0a4bee0a4aae0a4a8e0a495e0a4bee0a4b0e0a58de0a4b0e0
      a4b5e0a4bee0a488e0a4b8e0a495e0a58de0a4b0e0a4bfe0a4afe0a4a4e0a4be

   The number of words for each length is given by the following bit-
   depth array:

      NDBITS :=  0,  0,  0,  0, 10, 10, 11, 11, 10, 10,
                10, 10, 10,  9,  9,  8,  7,  7,  8,  7,
                 7,  6,  6,  5,  5

Appendix B.  List of Word Transformations

   The string literals are in C format, with respect to the use of
   backslash escape characters.

   In order to generate a length and check value, the transforms can be
   converted to a series of bytes, where each transform is the prefix
   sequence of bytes plus a terminating zero byte, a single-byte value
   identifying the transform, and the suffix sequence of bytes plus a
   terminating zero.  The value for the transforms are 0 for Identity, 1
   for FermentFirst, 2 for FermentAll, 3 to 11 for OmitFirst1 to
   OmitFirst9, and 12 to 20 for OmitLast1 to OmitLast9.  The byte
   sequences that represent the 121 transforms are then concatenated to
   a single sequence of bytes.  The length of that sequence is 648
   bytes, and the CRC-32 is 0x3d965f81.

          ID       Prefix     Transform            Suffix
          --       ------     ---------            ------
           0           ""     Identity                 ""
           1           ""     Identity                " "
           2          " "     Identity                " "
           3           ""     OmitFirst1               ""
           4           ""     FermentFirst            " "
           5           ""     Identity            " the "
           6          " "     Identity                 ""
           7         "s "     Identity                " "
           8           ""     Identity             " of "
           9           ""     FermentFirst             ""
          10           ""     Identity            " and "
          11           ""     OmitFirst2               ""
          12           ""     OmitLast1                ""
          13         ", "     Identity                " "
          14           ""     Identity               ", "
          15          " "     FermentFirst            " "
          16           ""     Identity             " in "
          17           ""     Identity             " to "
          18         "e "     Identity                " "



Alakuijala & Szabadka         Informational                   [Page 124]

RFC 7932                         Brotli                        July 2016


          19           ""     Identity               "\""
          20           ""     Identity                "."
          21           ""     Identity              "\">"
          22           ""     Identity               "\n"
          23           ""     OmitLast3                ""
          24           ""     Identity                "]"
          25           ""     Identity            " for "
          26           ""     OmitFirst3               ""
          27           ""     OmitLast2                ""
          28           ""     Identity              " a "
          29           ""     Identity           " that "
          30          " "     FermentFirst             ""
          31           ""     Identity               ". "
          32          "."     Identity                 ""
          33          " "     Identity               ", "
          34           ""     OmitFirst4               ""
          35           ""     Identity           " with "
          36           ""     Identity                "'"
          37           ""     Identity           " from "
          38           ""     Identity             " by "
          39           ""     OmitFirst5               ""
          40           ""     OmitFirst6               ""
          41      " the "     Identity                 ""
          42           ""     OmitLast4                ""
          43           ""     Identity           ". The "
          44           ""     FermentAll               ""
          45           ""     Identity             " on "
          46           ""     Identity             " as "
          47           ""     Identity             " is "
          48           ""     OmitLast7                ""
          49           ""     OmitLast1            "ing "
          50           ""     Identity             "\n\t"
          51           ""     Identity                ":"
          52          " "     Identity               ". "
          53           ""     Identity              "ed "
          54           ""     OmitFirst9               ""
          55           ""     OmitFirst7               ""
          56           ""     OmitLast6                ""
          57           ""     Identity                "("
          58           ""     FermentFirst           ", "
          59           ""     OmitLast8                ""
          60           ""     Identity             " at "
          61           ""     Identity              "ly "
          62      " the "     Identity             " of "
          63           ""     OmitLast5                ""
          64           ""     OmitLast9                ""
          65          " "     FermentFirst           ", "
          66           ""     FermentFirst           "\""



Alakuijala & Szabadka         Informational                   [Page 125]

RFC 7932                         Brotli                        July 2016


          67          "."     Identity                "("
          68           ""     FermentAll            " "
          69           ""     FermentFirst          "\">"
          70           ""     Identity              "=\""
          71          " "     Identity                "."
          72      ".com/"     Identity                 ""
          73      " the "     Identity         " of the "
          74           ""     FermentFirst            "'"
          75           ""     Identity          ". This "
          76           ""     Identity                ","
          77          "."     Identity                " "
          78           ""     FermentFirst            "("
          79           ""     FermentFirst            "."
          80           ""     Identity            " not "
          81          " "     Identity              "=\""
          82           ""     Identity              "er "
          83          " "     FermentAll              " "
          84           ""     Identity              "al "
          85          " "     FermentAll               ""
          86           ""     Identity               "='"
          87           ""     FermentAll             "\""
          88           ""     FermentFirst           ". "
          89          " "     Identity                "("
          90           ""     Identity             "ful "
          91          " "     FermentFirst           ". "
          92           ""     Identity             "ive "
          93           ""     Identity            "less "
          94           ""     FermentAll              "'"
          95           ""     Identity             "est "
          96          " "     FermentFirst            "."
          97           ""     FermentAll            "\">"
          98          " "     Identity               "='"
          99           ""     FermentFirst            ","
         100           ""     Identity             "ize "
         101           ""     FermentAll              "."
         102   "\xc2\xa0"   Identity                 ""
         103          " "     Identity                ","
         104           ""     FermentFirst          "=\""
         105           ""     FermentAll            "=\""
         106           ""     Identity             "ous "
         107           ""     FermentAll             ", "
         108           ""     FermentFirst           "='"
         109          " "     FermentFirst            ","
         110          " "     FermentAll            "=\""
         111          " "     FermentAll             ", "
         112           ""     FermentAll              ","
         113           ""     FermentAll              "("
         114           ""     FermentAll             ". "



Alakuijala & Szabadka         Informational                   [Page 126]

RFC 7932                         Brotli                        July 2016


         115          " "     FermentAll              "."
         116           ""     FermentAll             "='"
         117          " "     FermentAll             ". "
         118          " "     FermentFirst          "=\""
         119          " "     FermentAll             "='"
         120          " "     FermentFirst           "='"

Appendix C.  Computing CRC-32 Check Values

   For the purpose of this specification, we define the CRC-32 check
   value of a byte sequence with the following C language function:

     uint32_t CRC32(const uint8_t* v, const int len) {
        const uint32_t poly = 0xedb88320UL;
        uint32_t crc, c;
        int i, k;
        crc = 0xffffffffUL;
        for (i = 0; i < len; ++i) {
           c = (crc ^ v[i]) & 0xff;
           for (k = 0; k < 8; k++) c = c & 1 ? poly ^ (c >> 1) : c >> 1;
           crc = c ^ (crc >> 8);
        }
        return crc ^ 0xffffffffUL;
     }

Appendix D. Source Code

   Source code for a C language implementation of a brotli-compliant
   compressor and decompressor is available in the brotli open-source
   project <https://github.com/google/brotli>.

Acknowledgments

   The authors would like to thank Mark Adler, Eugene Kliuchnikov,
   Robert Obryk, Thomas Pickert, Joe Tsai, and Lode Vandevenne for
   providing helpful review comments, validating the specification by
   writing an independent decompressor, and suggesting improvements to
   the format and the text of the specification.













Alakuijala & Szabadka         Informational                   [Page 127]

RFC 7932                         Brotli                        July 2016


Authors' Addresses

   Jyrki Alakuijala
   Google, Inc.

   Email: jyrki@google.com


   Zoltan Szabadka
   Google, Inc.

   Email: szabadka@google.com







































Alakuijala & Szabadka         Informational                   [Page 128]

