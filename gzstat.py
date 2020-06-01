# gzstat.py
# 
# Utility for analyzing the structure of .gz files.
# For the most verbose output, use
#   python gzstat.py --print-block-codes --decode-blocks < your_input_file.gz
#
#
# Most of the implementation is based on the two RFC documents that describe .gz
# files and DEFLATE compression:
#   - https://tools.ietf.org/html/rfc1951
#   - https://tools.ietf.org/html/rfc1952
#
#
# Some details were determined by reverse engineering the gzip source code (https://www.gnu.org/software/gzip/).
#
# B. Bird - 03/12/2020

import sys, collections, datetime, binascii
import argparse




print_gzip_headers = True
print_block_stats = True
print_block_codes = True
decode_blocks = True


# Dictionary of possible 8 bit "compression type values" in the gzip header
compression_methods = collections.defaultdict(lambda: "(invalid)")
compression_methods[0] = 'store'
compression_methods[1] = 'compress (lzw)'
compression_methods[2] = 'pack'
compression_methods[3] = 'lzh'
compression_methods[4] = 'reserved'
compression_methods[5] = 'reserved'
compression_methods[6] = 'reserved'
compression_methods[7] = 'reserved'
compression_methods[8] = 'deflate'

# Compact representation of the length code value (257-285), length range and number
# of extra bits to use in LZ77 compression (See Section 3.2.5 of RFC 1951)
length_code_ranges = [
            [257,0,3,3],     [258,0,4,4],     [259,0,5,5],     [260,0,6,6],     [261,0,7,7],
            [262,0,8,8],     [263,0,9,9],     [264,0,10,10],   [265,1,11,12],   [266,1,13,14],
            [267,1,15,16],   [268,1,17,18],   [269,2,19,22],   [270,2,23,26],   [271,2,27,30],
            [272,2,31,34],   [273,3,35,42],   [274,3,43,50],   [275,3,51,58],   [276,3,59,66],
            [277,4,67,82],   [278,4,83,98],   [279,4,99,114],  [280,4,115,130], [281,5,131,162], 
            [282,5,163,194], [283,5,195,226], [284,5,227,257], [285,0,258,258]
    ] 

#Construct a lookup table mapping length codes to (num_bits,lower_bound) pairs
length_codes = {}
for code, num_bits, lower_bound, upper_bound in length_code_ranges:
    for i in range(lower_bound, upper_bound+1):
        length_codes[code] = (num_bits,lower_bound)

# Compact representation of the distance code value (0-31), distance range and number
# of extra bits to use in LZ77 compression (See Section 3.2.5 of RFC 1951)
distance_code_ranges = [
            [0,0,1,1],         [1,0,2,2],          [2,0,3,3],           [3,0,4,4],           [4,1,5,6],
            [5,1,7,8],         [6,2,9,12],         [7,2,13,16],         [8,3,17,24],         [9,3,25,32],
            [10,4,33,48],      [11,4,49,64],       [12,5,65,96],        [13,5,97,128],       [14,6,129,192],
            [15,6,193,256],    [16,7,257,384],     [17,7,385,512],      [18,8,513,768],      [19,8,769,1024],
            [20,9,1025,1536],  [21,9,1537,2048],   [22,10,2049,3072],   [23,10,3073,4096],   [24,11,4097,6144],
            [25,11,6145,8192], [26,12,8193,12288], [27,12,12289,16384], [28,13,16385,24576], [29,13,24577,32768],
    ]
#Construct a lookup table mapping distance codes to (num_bits,lower_bound) pairs
distance_codes = {}
for code, num_bits, lower_bound, upper_bound in distance_code_ranges:
    for i in range(lower_bound, upper_bound+1):
        distance_codes[code] = (num_bits,lower_bound)



def binary_string_big_endian(v, num_bits):
    result = ''
    for i in range(num_bits-1,-1,-1):
        result += '1' if (v&(1<<i)) != 0 else '0'
    return result



















class DecodingException(Exception):
    pass

class BuildHuffmanException(Exception):
    pass

class BitStream:
    class EndOfStream(Exception):
        pass
    buffer_size = 1024 # Number of bytes to read at a time
    def __init__(self, source_file):
        self.input_file = source_file
        self.working_bytes = bytes()
        self.working_bits_read = 0 # Number of bits already read from self.working_bytes
        self.total_bits_read = 0
    def read_bit(self):
        if self.working_bits_read//8 >= len(self.working_bytes):
            self.working_bytes = self.input_file.read(self.buffer_size)
            if len(self.working_bytes) == 0:
                raise BitStream.EndOfStream
            self.working_bits_read = 0
        byte_idx = self.working_bits_read//8
        bit_idx = self.working_bits_read%8
        self.working_bits_read += 1
        self.total_bits_read += 1
        return (self.working_bytes[byte_idx]>>bit_idx)&1
    def flush_to_byte(self):
        while self.working_bits_read%8 != 0:
            self.read_bit()

    #Read a bit sequence into an int value, with the low order bits read first
    def read_bits(self,num_bits):
        b = 0
        for i in range(num_bits):
            b = b|(self.read_bit()<<i)
        return b

    def read_byte(self):
        return self.read_bits(8)

    def read_uint16_big_endian(self):
        return (self.read_byte()<<8)|self.read_byte()
    
    def read_uint16_little_endian(self):
        return self.read_byte()|(self.read_byte()<<8)

    def read_uint32_big_endian(self):
        return (self.read_byte()<<24)|(self.read_byte()<<16)|(self.read_byte()<<8)|self.read_byte()
    
    def read_uint32_little_endian(self):
        return self.read_byte()|(self.read_byte()<<8)|(self.read_byte()<<16)|(self.read_byte()<<24)

class OutputLZBuffer:
    history_size = 32768
    def __init__(self,output_callback=lambda b: None):
        self.output_callback = output_callback
        self.bytes_written = 0
        self.crc = None
        self.history = []
    def write_byte(self, b):
        b = b&0xff
        self.output_callback(b)
        bbytes = bytes((b,))
        if self.crc is None:
            self.crc = binascii.crc32(bbytes)
        else:
            self.crc = binascii.crc32(bbytes,self.crc)
        self.bytes_written += 1
        self.history.append(b)
        while len(self.history) > self.history_size:
            del self.history[0]
        
    def write_lz77_length_distance(self, length, distance):
        # distance is 1 based relative to the history array
        # (which is nice since we use it as an offset from the end)
        if distance > len(self.history):
            raise DecodingException("Invalid length/distance (%d, %d) (history only contains %d bytes)"%(length,distance,len(self.history)))
        for i in range(length):
            self.write_byte(self.history[len(self.history) - distance]) #Note that we do not need to increment the index we use (the sequence moves along as we add bytes)

    

class HuffmanTreeNode:
    def __init__(self, symbol=-1, left=None, right=None):
        self.symbol = symbol
        self.left = left
        self.right = right


# Add a node with the provided code and symbol to the Huffman tree rooted at 
# the provided node, then return the new root
def huffman_add_node(root, code, symbol):
    if len(code) == 0:
        if root is not None:
            return None
        return HuffmanTreeNode(symbol=symbol)
    else:
        bit = code[0]
        if root is None:
            root = HuffmanTreeNode()
        if bit == 0:
            root.left = huffman_add_node(root.left,code[1:], symbol)
        else:
            root.right = huffman_add_node(root.right, code[1:], symbol)
        return root


def build_huffman_tree(code_table):
    root = None
    for i in range(len(code_table)):
        num_bits, code_bits = code_table[i]
        if num_bits == 0:
            continue #Code isn't used
        # Convert the integer code_bits to a list of bits
        # (with the highest order bit first)
        code_sequence = [ (code_bits>>(num_bits-j-1)&1) for j in range(num_bits) ]
        root = huffman_add_node(root, code_sequence, i )
        if root is None:
            raise BuildHuffmanException("Symbol 0x%02x (code %s) terminates at an internal node"%(i,''.join(int(b) for b in code_sequence)) )
    return root

def print_huffman_tree(root):
    def print_node(prefix,node):
        if node.symbol != -1:
            print('%s%s'%(prefix,node.symbol))
        else:
            print('%s+'%prefix)
            print_node(prefix+'|   ', node.left)
            print_node(prefix+'|   ', node.right)
    print(root)

def decode_huffman(stream, output_buffer, ll_tree, dist_tree):
    ll_path = []
    node = ll_tree
    if decode_blocks:
        print('%12s-- Decoded data --'%'')
    while 1:
        b = stream.read_bit()
        ll_path.append(b)
        if b == 0:
            node = node.left
        else:
            node = node.right
        if node is None:
            raise DecodingException("Reached invalid state while decoding (code lengths were probably encoded incorrectly)")
        if node.symbol == -1:
            continue

        # Terminal literal/length node
        symbol = node.symbol
        if decode_blocks:
            if symbol >= 33 and symbol <= 127:
                # If this symbol is a printable character, print both the hex and character representation
                print("%12s%s: 0x%02x (%s)"%('',''.join(str(b) for b in ll_path), symbol, chr(symbol)))
            else:
                print("%12s%s: 0x%02x"%('',''.join(str(b) for b in ll_path), symbol))
        if symbol == 256:
            break #End of stream marker
        if symbol > 256:
            # Symbols > 256 are length codes
            length_code = symbol
            if decode_blocks:
                print("%16s0x%02x is Length code %d"%('',symbol,symbol))
            num_extra_bits, lower_bound = length_codes[length_code]
            length_offset = stream.read_bits(num_extra_bits)
            length = length_offset + lower_bound
            if decode_blocks:
                print("%16s%d extra length bits: Offset %d. Total length %d"%('',num_extra_bits,length_offset, length))
            dist_path = []
            dist_node = dist_tree
            if dist_node is None:
                raise DecodingException("Can't decode length/distance pair: No distance codes exist")
            while dist_node.symbol == -1:
                b = stream.read_bit()
                dist_path.append(b)
                if b == 0:
                    dist_node = dist_node.left
                else:
                    dist_node = dist_node.right
            dist_symbol = dist_node.symbol
            if decode_blocks:
                print("%16sDistance code %s: %d"%('',''.join(str(b) for b in dist_path), dist_symbol))
            num_extra_bits, lower_bound = distance_codes[dist_symbol]
            distance_offset = stream.read_bits(num_extra_bits)
            distance = distance_offset + lower_bound
            if decode_blocks:
                print("%16s%d extra distance bits: Offset %d. Total distance %d"%('',num_extra_bits,distance_offset, distance))
            output_buffer.write_lz77_length_distance(length,distance)
            
        else:
            output_buffer.write_byte(symbol)
        node = ll_tree
        ll_path = []


def code_lengths_to_code_table(code_lengths):
    # This algorithm is based on the pseudocode in RFC 1951 (Section 3.2.2)
    # (Steps are numbered as in the RFC)

    # Step 1
    max_length = max(code_lengths)
    length_counts = [0]*(max_length+1)
    for length in code_lengths:
        length_counts[length] += 1

    # Step 2
    code = 0
    length_counts[0] = 0
    next_code = [0]*(max_length+1)
    for bits in range(1, max_length+1):
        code = (code + length_counts[bits-1]) << 1
        next_code[bits] = code
    
    # Step 3
    code_table = [(0,0)]*len(code_lengths)
    for n in range(len(code_lengths)):
        length = code_lengths[n]
        if length != 0:
            code_table[n] = (length,next_code[length])
            next_code[length] += 1
    return code_table














    

def decode_uncompressed(stream, output_buffer):
    # Type 00: Block is uncompressed data
    # Flush to a byte boundary (Type 00 only)
    stream.flush_to_byte()
    # Blocks of this type start with two 16 bit little endian values s and ns
    # (where s == ~ns) containing the size of the block and its one's complement
    # representation (for consistency checking, I guess)
    block_len = stream.read_uint16_little_endian()
    block_nlen = stream.read_uint16_little_endian()
    print("    Decoding Block Type 00 (uncompressed):")
    print("        LEN = %d (0x%04x), NLEN = %d (0x%04x)"%(block_len,block_len,block_nlen,block_nlen))
    if block_len != ((~block_nlen)&0xffff):
        raise DecodingException("Inconsistent block length values")

    for i in range(block_len):
        b = stream.read_byte()
        output_buffer.write_byte(b)

def decode_fixed(stream, output_buffer):
    # Type 01: Block uses the built-in Huffman code to encode data
    # Code is given below as per RFC 1951

    if print_block_stats:
        print("        Decoding Block Type 01 (fixed codes):")
    
    # Mapping of code values (0 - 287) to (num_bits, code_bits) pairs
    ll_code = [0]*288
    for i in range(0, 144):
        ll_code[i] = (8, 0b00110000 + i)
    for i in range(144, 256):
        ll_code[i] = (9, 0b110010000 + (i-144))
    for i in range(256, 280):
        ll_code[i] = (7, i - 256)
    for i in range(280,288):
        ll_code[i] = (8, 0b11000000 + (i-280))

    # Mapping of distance code values (0 - 31) to (num_bits, code_bits) pairs
    # Note that the distance code for the fixed Huffman code is just the regular
    # (big-endian) binary encoding of the values 0 - 31
    dist_code = [(5, i) for i in range(32)]

    ll_tree = build_huffman_tree(ll_code)
    dist_tree = build_huffman_tree(dist_code)

    decode_huffman(stream, output_buffer, ll_tree, dist_tree)

def decode_dynamic(stream,output_buffer):
    #See Section 3.2.7 of RFC 1951
    
    def decode_print(s):
        if print_block_codes:
            print('            %s'%s)
    
    #Okay, here we go
    if print_block_stats:
        print("        Decoding Block Type 10 (dynamic codes):")

    #First 14 bits: three size values (little endian)
    
    hlit = stream.read_bits(5) # ((number of LL codes) - 257)
    num_ll_codes = hlit + 257
    decode_print("Number of LL codes: %d (HLIT = %d)"%(num_ll_codes, hlit))
    hdist = stream.read_bits(5) # ((number of dist codes) - 1)
    num_dist_codes = hdist + 1
    decode_print("Number of dist codes: %d (HDIST = %d)"%(num_dist_codes, hdist))
    hclen = stream.read_bits(4) # ((number of code length codes) - 4)
    num_cl_codes = hclen + 4
    decode_print("Number of code length (CL) codes: %d (HCLEN = %d)"%(num_cl_codes, hclen))

    #Next bits: num_cl_codes*3 bits (up to 19 3-bit CL code lengths)
    #The lengths are stored in a weird order:
    CL_code_length_encoding_order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15]
    CL_code_lengths = [0]*19
    for idx in CL_code_length_encoding_order[0:num_cl_codes]:
        CL_code_lengths[idx] = stream.read_bits(3)
    

    decode_print("CL code lengths (0 - 18): " + ' '.join(str(i) for i in CL_code_lengths))
    CL_codes = code_lengths_to_code_table(CL_code_lengths)
    decode_print("CL codes:")
    for i in range(len(CL_codes)):
        length, encoded_bits = CL_codes[i]
        if length == 0:
            continue
        decode_print("    %d: %s"%(i, binary_string_big_endian(encoded_bits, length)))

    #Next bits: (num_ll_codes + num_dist_codes) code lengths for the LL and distance codes
    #(both codes are encoded together, using the CL code)
    CL_tree_root = build_huffman_tree(CL_codes)

    ll_code_lengths = [0]*288
    dist_code_lengths = [0]*32

    node = CL_tree_root
    codes_read = 0
    last_symbol = -1
    while codes_read < num_ll_codes + num_dist_codes:
        b = stream.read_bit()
        node = node.left if b == 0 else node.right
        if node.symbol == -1:
            continue
        symbol = node.symbol
        node = CL_tree_root
        assert(symbol >= 0 and symbol < 19)
        if symbol <= 15:
            #The symbol is an actual length
            if codes_read >= num_ll_codes:
                dist_code_lengths[codes_read-num_ll_codes] = symbol
            else:
                ll_code_lengths[codes_read] = symbol
            codes_read += 1
            last_symbol = symbol
        elif symbol == 16:
            # Repeat the previous symbol between 3 and 6 times based on a two bit value
            repeat_count = 3 + stream.read_bits(2)
            if last_symbol == -1:
                raise DecodingException("Repeat code (16) used for first CL code value")
            decode_print("Symbol 16 (repeat count %d, repeating %d)"%(repeat_count, last_symbol))
            for i in range(repeat_count):
                if codes_read >= num_ll_codes:
                    dist_code_lengths[codes_read-num_ll_codes] = last_symbol
                else:
                    ll_code_lengths[codes_read] = last_symbol
                codes_read += 1
            #Leave last_symbol unchanged
        elif symbol == 17:
            # Repeat a zero length between 3 and 10 times based on a three bit value
            repeat_count = 3 + stream.read_bits(3)
            decode_print("Symbol 17 (repeat count %d)"%(repeat_count))
            for i in range(repeat_count):
                if codes_read >= num_ll_codes:
                    dist_code_lengths[codes_read-num_ll_codes] = 0
                else:
                    ll_code_lengths[codes_read] = 0
                codes_read += 1
            last_symbol = 0
        else: # symbol == 18
            # Repeat a zero length between 11 and 138 times based on a seven bit value
            repeat_count = 11 + stream.read_bits(7)
            decode_print("Symbol 18 (repeat count %d)"%(repeat_count))
            for i in range(repeat_count):
                if codes_read >= num_ll_codes:
                    dist_code_lengths[codes_read-num_ll_codes] = 0
                else:
                    ll_code_lengths[codes_read] = 0
                codes_read += 1
            last_symbol = 0

    ll_codes = code_lengths_to_code_table(ll_code_lengths)
    decode_print("LL codes:")
    for i in range(len(ll_codes)):
        length, encoded_bits = ll_codes[i]
        if length == 0:
            continue
        decode_print("    %d: %s"%(i, binary_string_big_endian(encoded_bits, length)))

    dist_codes = code_lengths_to_code_table(dist_code_lengths)
    decode_print("dist codes:")
    for i in range(len(dist_codes)):
        length, encoded_bits = dist_codes[i]
        if length == 0:
            continue
        decode_print("    %d: %s"%(i, binary_string_big_endian(encoded_bits, length)))


    ll_tree = build_huffman_tree(ll_codes)
    dist_tree = build_huffman_tree(dist_codes)
    decode_huffman(stream, output_buffer, ll_tree, dist_tree)


def read_block(stream, output_buffer, block_idx):
    #First bit: Last block flag (1 = last block)
    last_block = stream.read_bit()
    #Next two bits (as a 2-bit little endian integer) are the block type
    # 00 = uncompressed, 01 = fixed codes, 10 = dynamic codes, 11 = invalid/reserved
    block_type = stream.read_bits(2)
    if print_block_stats:
        print("    -- Block %d (last = %d) --"%(block_idx, last_block))
    block_types = {0: 'uncompressed',1:'fixed codes',2:'dynamic codes',3:'invalid/reserved'}
    if print_block_stats:
        print("        Block type: %d (%s)"%(block_type, block_types[block_type]))
    if block_type == 3:
        raise DecodingException("Can't decode block type 11")

    if block_type == 0:
        decode_uncompressed(stream, output_buffer)
    elif block_type == 1:
        decode_fixed(stream, output_buffer)
    elif block_type == 2:
        decode_dynamic(stream,output_buffer)

    return not last_block

def read_member(stream, member_number):

    output_buffer = OutputLZBuffer(lambda b: None)
    # Read the gzip header
    # See http://www.onicos.com/staff/iz/formats/gzip.html for a concise description

    def header_print(s):
        if print_gzip_headers:
            print('    %s'%s)

    # Magic number
    try:
        m1 = stream.read_byte()
        m2 = stream.read_byte()
        if m1 != 0x1f or m2 != 0x8b:
            return False
    except BitStream.EndOfStream:
        #If we hit the end of the stream while checking if this is a block, ignore
        #the error and quit.
        #(If end of stream is encountered inside of the block, however, let the exception
        # propagate, since it is a real error in that case)
        return False 
    print("-- gzip member %d --"%member_number)
    compression_method = stream.read_byte()
    header_print("Compression Method: %d (%s)"%(compression_method, compression_methods[compression_method]))
    flags = stream.read_byte()
    header_print("Flags: 0x%02x"%(flags))
    mtime = stream.read_uint32_little_endian()
    header_print("Modification time: 0x%08x (%s)"%(mtime, datetime.datetime.fromtimestamp(mtime).ctime()))
    exflags = stream.read_byte()
    header_print("Extra flags: 0x%02x"%(exflags))
    ostype = stream.read_byte()
    header_print("OS Type: %d"%ostype)

    if not (print_block_stats or print_block_codes or decode_blocks):
        return True
    if compression_method != 8:
        print("Unable to read block written with compression method %d")
        print("(even the gzip decoder only reads blocks with DEFLATE compression)")
        return False

    block_idx = 0
    while read_block(stream, output_buffer, block_idx):
        block_idx += 1
    
    # Blocks can start and end at arbitrary bit locations, but the elements at the
    # end of the file (CRC and length) must be aligned on a byte boundary
    stream.flush_to_byte()
    
    crc_code = stream.read_uint32_little_endian()
    header_print("Stored CRC32: 0x%08x"%crc_code)
    total_decompressed_size = stream.read_uint32_little_endian()
    header_print("Stored Decompressed size: %d"%total_decompressed_size)

    header_print("Actual CRC32: 0x%08x"%(output_buffer.crc&0xffffffff))
    header_print("Actual Decompressed Size: %d"%(output_buffer.bytes_written))

    return True


if __name__ == '__main__':
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument('--no-headers',action="store_true",help='Don\'t print gzip headers.')
    argument_parser.add_argument('--no-block-stats',action="store_true",help='Don\'t print block stats.')
    argument_parser.add_argument('--print-block-codes',action="store_true",help='Print code information for blocks of type 2.')
    argument_parser.add_argument('--decode-blocks',action="store_true",help='Print full decoding information for each block.')

    args = argument_parser.parse_args()
    print_gzip_headers = not args.no_headers
    print_block_stats = not args.no_block_stats
    print_block_codes = args.print_block_codes
    decode_blocks = args.decode_blocks

    try:
        stream = BitStream(sys.stdin.buffer) # sys.stdin.buffer is a version of sys.stdin open in binary mode
        member_number = 0
        while read_member(stream, member_number):
            member_number += 1
        print("Read %d gzip members"%member_number)
    except BitStream.EndOfStream:
        print("Unexpected end of stream")
    except DecodingException as e:
        print("Decoding exception: %s"%e)
