# https://pypi.org/project/ar/

from ar import *
import ar
import sys
#from iced_x86 import *
import struct

# def disass(instrs):
#     # This example produces the following output:
#     # 00007FFAC46ACDA4 48895C2410           mov       [rsp+10h],rbx
#     # 00007FFAC46ACDA9 4889742418           mov       [rsp+18h],rsi
#     # 00007FFAC46ACDAE 55                   push      rbp
#     # 00007FFAC46ACDAF 57                   push      rdi
#     # 00007FFAC46ACDB0 4156                 push      r14
#     # 00007FFAC46ACDB2 488DAC2400FFFFFF     lea       rbp,[rsp-100h]
#     # 00007FFAC46ACDBA 4881EC00020000       sub       rsp,200h
#     # 00007FFAC46ACDC1 488B0518570A00       mov       rax,[rel 7FFA`C475`24E0h]
#     # 00007FFAC46ACDC8 4833C4               xor       rax,rsp
#     # 00007FFAC46ACDCB 488985F0000000       mov       [rbp+0F0h],rax
#     # 00007FFAC46ACDD2 4C8B052F240A00       mov       r8,[rel 7FFA`C474`F208h]
#     # 00007FFAC46ACDD9 488D05787C0400       lea       rax,[rel 7FFA`C46F`4A58h]
#     # 00007FFAC46ACDE0 33FF                 xor       edi,edi
#     #
#     # Format specifiers example:
#     # xchg [rdx+rsi+16h],ah
#     # xchg %ah,0x16(%rdx,%rsi)
#     # xchg [rdx+rsi+16h],ah
#     # xchg ah,[rdx+rsi+16h]
#     # xchg ah,[rdx+rsi+16h]
#     # xchgb %ah, %ds:0x16(%rdx,%rsi)

#     EXAMPLE_CODE_BITNESS = 32
#     EXAMPLE_CODE_RIP = 0x0
#     EXAMPLE_CODE = instrs
    
#     # EXAMPLE_CODE_BITNESS = 64
#     # EXAMPLE_CODE_RIP = 0x0000_7FFA_C46A_CDA4
#     # EXAMPLE_CODE = \
#     #     b"\x48\x89\x5C\x24\x10\x48\x89\x74\x24\x18\x55\x57\x41\x56\x48\x8D" \
#     #     b"\xAC\x24\x00\xFF\xFF\xFF\x48\x81\xEC\x00\x02\x00\x00\x48\x8B\x05" \
#     #     b"\x18\x57\x0A\x00\x48\x33\xC4\x48\x89\x85\xF0\x00\x00\x00\x4C\x8B" \
#     #     b"\x05\x2F\x24\x0A\x00\x48\x8D\x05\x78\x7C\x04\x00\x33\xFF"

#     # Create the decoder and initialize RIP
#     decoder = Decoder(EXAMPLE_CODE_BITNESS, EXAMPLE_CODE, ip=EXAMPLE_CODE_RIP)

#     # Formatters: MASM, NASM, GAS (AT&T) and INTEL (XED).
#     # There's also `FastFormatter` which is ~1.25x faster. Use it if formatting
#     # speed is more important than being able to re-assemble formatted
#     # instructions.
#     #    formatter = FastFormatter()
#     formatter = Formatter(FormatterSyntax.NASM)

#     # Change some options, there are many more
#     formatter.digit_separator = "`"
#     formatter.first_operand_char_index = 10

#     # You can also call decoder.can_decode + decoder.decode()/decode_out(instr)
#     # but the iterator is faster
#     for instr in decoder:
#         disasm = formatter.format(instr)
#         # You can also get only the mnemonic string, or only one or more of the operands:
#         #   mnemonic_str = formatter.format_mnemonic(instr, FormatMnemonicOptions.NO_PREFIXES)
#         #   op0_str = formatter.format_operand(instr, 0)
#         #   operands_str = formatter.format_all_operands(instr)

#         start_index = instr.ip - EXAMPLE_CODE_RIP
#         bytes_str = EXAMPLE_CODE[start_index:start_index + instr.len].hex().upper()
#         # Eg. "00007FFAC46ACDB2 488DAC2400FFFFFF     lea       rbp,[rsp-100h]"
#         print(f"{instr.ip:016X} {bytes_str:20} {disasm}")

#     # Instruction also supports format specifiers, see the table below
#     decoder = Decoder(64, b"\x86\x64\x32\x16", ip=0x1234_5678)
#     instr = decoder.decode()

# with open(sys.argv[1], 'rb') as f:
#     # instrs=f.read()
#     # disass(instrs)
    
#     archive = Archive(f)
#     i=iter(archive)
#     counter=0
#     # for entry in i:
#     #     counter += 1
#     #     if counter == 7:
#     #         break
#     for entry in i:
#         #print(entry.name)
#         print(hex(entry.offset))
#         # import code
#         # code.InteractiveConsole(locals=locals()).interact()
#         sub = entry.get_stream(f)
#         instrs = sub.read()
#         #disass(instrs)
#         print(instrs)
#         #break

# with open(sys.argv[1], 'rb') as f:
#     print(f.read())

def encodedLength(origSize, b):
    # Pad out if needed
    if int(origSize.decode().rstrip()) & 1 > 0:
        encodedLength_ = len(b) - 1
    else:
        encodedLength_ = len(b)
    return encodedLength_

def encodeTable(type2, contents, dataLengthSubtractedAcc):
    def encodeTable_():
        if type2 == 'public-symbols-table':
            # Write number of offsets and the offset numbers
            # print(contents)
            # exit()
            b = struct.pack(f'>I{len(contents)}I', len(contents), *[x[0] - dataLengthSubtractedAcc for x in contents])
            # Write names of functions
            for x in contents:
                b += x[1] + b'\x00'
            return b
        elif type2 == 'offsets-table':
            (offsetsTable, offsets) = contents
            # Write number of offsets and the offset numbers
            b = struct.pack(f'<I{len(offsets)}I', len(offsets), *[x - dataLengthSubtractedAcc for x in offsets])
            # Write num public symbols and the public symbols' indices
            b += struct.pack(f'<I{len(offsetsTable)}H', len(offsetsTable), *[x[0] for x in offsetsTable])
            # Write the public symbols' names
            for x in offsetsTable:
                b += x[1] + b'\x00'
            return b
        else:
            assert False
    b = encodeTable_()
    # Pad out if needed
    if len(b) & 1 > 0:
        encodedLength = len(b)
        # print(encodedLength)
        assert len(b) + (len(b) & 1) == len(b) + 1
        b += b'\n'
    else:
        encodedLength = len(b)
    return b, encodedLength

debug=False
verbose=False
output = open(sys.argv[2], 'wb')
try:
    with open(sys.argv[1], 'rb') as f:
        archive = Archive(f)
        lastStartEntry = []
        lastStartEntryWillBeRemoved = False
        dataBeginningsSeenSoFar = 0
        nextStartEntryContents = None
        dataLengthSubtractedAcc = 0 # Used in encodeTable() to update offsets due to removing parts of tables before what those offsets refer to.

        toFind = []
        toFind += ['??0?$vec@$01M$0A@@glm@@QAE@ABU01@@Z', '??0?$vec@$01M$0A@@glm@@QAE@MM@Z']
        #toFind += ['??0ATest@@QAE@XZ'] #['__IMPORT_DESCRIPTOR_TheDLL']
        #toFind += ['??0ATest@@QAE@ABU0@@Z']
        toFind.extend(["__imp_" + x for x in toFind])
        if verbose:
            import pprint
            pp=pprint.PrettyPrinter(indent=2)
            pp.pprint(list(archive))

        for x in toFind:
            check = bytes(x, 'ascii')
            archive.removeRegularEntriesMatchingLambda(lambda y: check in y.data)
            archive.applyRemovals()

        if verbose:
            pp.pprint(list(archive))

        # Write it out
        output.write(archive.encode())
finally:
    output.close()
