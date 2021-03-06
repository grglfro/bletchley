'''
A collection of tools to manipulate buffers of encrypted content

Copyright (C) 2011-2012 Virtual Security Research, LLC
Copyright (C) 2014-2016 Blindspot Security LLC
Authors: Timothy D. Morgan, Jason A. Donenfeld

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Lesser General Public License, version 3,
 as published by the Free Software Foundation.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
'''

import sys
import zlib
import itertools

# Computes the block-wise differences between two strings
# Blobs must be the same length and their length must be a multiple of block_size
#
# Returns a list of block numbers that are different from one another.
# Examples:
# blockWiseDiff(8, '1234567812345678', '12345678XXXXXXXX')
# => [1]
#
# blockWiseDiff(1, '12345', '12345')
# => []
#

def blockWiseDiff(block_size, blob1, blob2):
    if len(blob1) != len(blob2):
        sys.stderr.write("ERROR: Ciphertexts not the same length.\n")
        return None

    if (len(blob1) % block_size) != 0:
        sys.stderr.write("ERROR: Ciphertexts do not have an even multiple of blocks.\n")
        return None

    blocks1 = [blob1[o:o+block_size] for o in range(0,len(blob1),block_size)]
    blocks2 = [blob2[o:o+block_size] for o in range(0,len(blob2),block_size)]

    ret_val = []
    for b in range(0,len(blocks1)):
        if blocks1[b] != blocks2[b]:
            ret_val.append(b)

    return ret_val



def blockWiseColorMap(block_size, blobs):
    '''
    Accepts a sequence of blobs and compares all individual blocks
    (of block_size) within those blobs.  Returns a dictionary where the
    keys are blocks from the original blobs whose values were repeated
    at least once. (Unique blocks in the original blobs will not be
    represented in the return value.) The values of the returned
    dictionary are a 32bit integer hash value of the blocks they are
    associated with.
    '''
    block_counts = {}
    for blob in blobs:
        for block_off in range(0,len(blob),block_size):
            block = blob[block_off:block_off+block_size]
            count = block_counts.get(block, None)
            if count == 0:
                block_counts[block] = 1 # more than one exists
            elif count == None:
                block_counts[block] = 0  # one exists

    colors = {}
    for block,count in block_counts.items():
        if count == 1:
            # mask needed for portability
            colors[block] = zlib.crc32(block)%0xFFFFFFFF 

    return colors



# XORs two buffers (bytes/bytearrays) and returns result
#
# If buffers not the same length, returned buffer length
# will be that of the shorter buffer.
#
def xorBuffers(buff1, buff2):
    max_len = min(len(buff1), len(buff2))

    ret_val = bytearray(buff1[0:max_len])
    other = bytearray(buff2[0:max_len])
    for i in range(0,len(ret_val)):
        ret_val[i] ^= other[i]

    return ret_val


def splitBuffer(buf, block_size):
	'''
	Splits a buffer into evenly sized blocks.
	'''
	return [buf[i:i + block_size] for i in range(0, len(buf), block_size)]

def iterBuffer(buf, block_size):
	'''
	Iterates through a buffer in evenly sized blocks.
	'''
	return (buf[i:i + block_size] for i in range(0, len(buf), block_size))

def pkcs7PadBuffer(buf, block_size):
	'''
	Pads the end of a buffer using PKCS#5/PKCS#7 padding.
	'''
	padding = block_size - (len(buf) % block_size)
	return buf + pkcs7Pad(padding)

def pkcs7Pad(length):
	return bytes([length]*length)

def stripPKCS7Pad(decrypted, block_size=16, log_file=None):
    '''
    Validates a plaintext containing a PKCS5/7 pad, then returns the plaintext 
    without the pad.
    '''
    if len(decrypted) % block_size != 0:
        if log_file:
            log_file.write("Can't strip PKCS7 pad.  Plaintext not correct length\n")
        return None

    length = decrypted[-1]
    if (length == 0) or (length > block_size):
        if log_file:
            log_file.write("Can't strip PKCS7 pad.  Final byte length (%d) too large.\n" % length)
        return None

    pad = decrypted[0-length:]
    if pad != pkcs7Pad(length):
        if log_file:
            log_file.write("Can't strip PKCS7 pad.  Pads don't match. (%s != %s)\n" % (repr(pad), repr(pkcs7Pad(length))))
        return None

    return decrypted[0:0-length]


def smartPermutateBlobs(blobs, block_size=8):
    """
    Intelligently permutates through blocks in blobs.
    If the same blob shows up in the same place for
    every blob, the resultant permutations will have
    this property as well.
    blobs should be an array containing blobs
    block_size should be an integer block_size or an
    array of block sizes.
    """

    if len(blobs) == 0:
        return

    if not isinstance(block_size, int):
        for size in block_size:
             for blob in smartPermutateBlobs(blobs, size):
                 yield blob
        return

    # First we find the indexes of the chunks that are different
    different = set()
    for combo in itertools.combinations(blobs, 2):
        different |= set(blockWiseDiff(block_size, combo[0], combo[1]))
    
    # Next we form a set containing the chunks that are different
    different_chunks = []
    for blob in blobs:
        different_chunks.extend([blob[i * block_size:(i + 1) * block_size] for i in different])
    # Remove duplicates
    different_chunks = set(different_chunks)
    
    # We want to know which chunks are the same, too
    chunk_len = len(blobs[0]) // block_size
    same = set(range(0, chunk_len)) - different

    # Now let's mix and match the differnet blocks, for all possible lengths
    for i in range(1, chunk_len + 1):
        for mix in itertools.permutations(different_chunks, i):
            # We add back in the part that stays the same
            for j in same:
                mix.insert(j, blobs[0][j * block_size:(j + 1) * block_size])
            mix = b"".join(mix)
            if mix in blobs:
                continue
            yield mix 
