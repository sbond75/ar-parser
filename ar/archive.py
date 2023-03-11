"""Loads AR files"""
import struct
import codecs

from ar.substream import Substream

MAGIC = b"!<arch>\n"


def padding(n, pad_size):
    reminder = n % pad_size
    return pad_size - reminder if reminder else 0


def pad(n, pad_size):
    return n + padding(n, pad_size)


class ArchiveError(Exception):
    pass


class ArPath:
    def __init__(self, name, offset, size):
        self.name = name
        self.offset = offset
        self.size = size

    def get_stream(self, f):
        return Substream(f, self.offset, self.size)


class Mode:
    MODES = 'rbt'
    def __init__(self, mode):
        if any(character not in Mode.MODES for character in mode):
            raise ValueError("invalid mode: '{}'".format(mode))
        self._mode = mode

    def is_binary(self):
        return 'b' in self._mode


class Archive:
    class Entry:
        def __init__(self, type_=None, fileName=None, modificationTimestamp=None, ownerID=None, groupID=None, fileMode=None, fileSize=None, endMarker1=None, endMarker2=None):
            # Bookkeeping stuff: #
            self.type_ = type_
            self.kind_ = None # The type of `type_` like 'data' or 'data-beginning'
            self.data = None # "Contents" of the entry besides all the other stuff
            self.entryHeaderSize = None # Size of the "header" part of the entry (everything except `self.data`)
            self.offsetInFile = None # Position of this entry in bytes from the start of the file
            self.hasPadding = None # Whether this entry has one byte of padding which can be ignored at the end of `self.data`.
            # Depends on `kind_`: #
            self.publicSymbolsTable = None
            self.offsetsTable = None
            self.offsets = None
            # #
            # #

            # Entry itself contains: #
            self.fileName = fileName
            self.modificationTimestamp = modificationTimestamp
            self.ownerID = ownerID
            self.groupID = groupID
            self.fileMode = fileMode
            self.fileSize = fileSize
            self.endMarker1 = endMarker1
            self.endMarker2 = endMarker2
            # #

        # Returns the size of the entire entry.
        def size(self):
            return self.entryHeaderSize + len(self.data)

        def __repr__(self):
            import pprint
            pp=pprint.PrettyPrinter(indent=2)
            def pformat(x):
                return pp.pformat(x)
            return (f"{(self.type_ + ' e') if self.type_ is not None else 'E'}ntry:\n"
                    f"    Kind: {self.kind_}\n"
                    #f"    Data: {self.data}\n"
                    f"    Offset: {self.offsetInFile} ({hex(self.offsetInFile)})\n"
                    f"    Public symbols table: {pformat(self.publicSymbolsTable)}\n"
                    f"    Offsets table: {pformat(self.offsetsTable)}\n"
                    f"    Offsets: {pformat(self.offsets)}\n"
                    f"    File name: {self.fileName}\n"
                    f"    Modified: {self.modificationTimestamp}\n"
                    f"    Owner ID: {self.ownerID}\n"
                    f"    Group ID: {self.groupID}\n"
                    f"    File mode: {self.fileMode}\n"
                    f"    File size: {self.fileSize}\n"
                    f"    End markers: {self.endMarker1} {self.endMarker2}\n")
        
        def setKindAndData(self, kind_, data):
            self.kind_ = kind_
            self.data = data
            hasData = self.data is not None
            
            # Check for offsets table
            if self.type_ == 'public-symbols-table':
                assert hasData
                # NOTE: endianness is big endian here! (`>`)
                numPublicSymbols, = struct.unpack('>I', data[:4])
                #print(numPublicSymbols)
                numOffsets = numPublicSymbols
                offsetsToPublicSymbols = struct.unpack(f'>{numPublicSymbols}I', data[4:4+4*numPublicSymbols])
                #print("offsetsToPublicSymbols:", offsetsToPublicSymbols)
                offsets = offsetsToPublicSymbols

                # Read symbol names and put them into `offsetsTable` as the second element of a pair. First element is the offset of that symbol's "data" in the file.
                offsetsTable = []
                namesData = data[4+4*numOffsets:]
                names = namesData.split(b'\x00')
                for i in range(numOffsets):
                    name_ = names[i]
                    offsetsTable.append((offsets[i],name_))
                #print("publicSymbolsTable:", offsetsTable)
                self.publicSymbolsTable = offsetsTable
            elif self.type_ == 'offsets-table':
                assert hasData
                # NOTE: endianness switches to little endian here! (`<`)
                numOffsets, = struct.unpack('<I', data[:4])
                # print(numOffsets)
                offsets = struct.unpack(f'<{numOffsets}I', data[4:4+4*numOffsets])
                #print("offsets:", offsets)
                base1 = 4+4*numOffsets

                # Not sure why this is here again..
                numPublicSymbols, = struct.unpack('<I', data[base1:base1+4])
                # print(numPublicSymbols)
                base2 = base1+4

                # The public symbols' indices.. (u16's)
                numIndices = numPublicSymbols
                publicSymbolsIndices = struct.unpack(f'<{numIndices}H', data[base2:base2 + numIndices * 2])
                base3 = base2 + numIndices * 2

                # Read indices stuff: an indice when used as an index into the `offsets` variable will give the offset like 0x5f6. In other words, publicSymbolsIndices[0] gives 0xA for example, and offsets[0xA - 1] (`- 1` for 1-based to 0-based index conversion) gives 0xAA2. This is the address of `??0ATest@@QAE@$$QAU0@@Z` in TheDLL.lib (the example in `../../DLLTesting/Debug`)
                # print("test 1:", hex(publicSymbolsIndices[0]), hex(offsets[publicSymbolsIndices[0]-1]))
                offsetsTable = []
                namesData = data[base3:]
                # print(namesData)
                names = namesData.split(b'\x00')
                for i in range(numIndices):
                    name_ = names[i]
                    offsetsTable.append((publicSymbolsIndices[i],name_))
                #print("offsetsTable:", offsetsTable)
                # exit(0)
                self.offsetsTable = offsetsTable
                self.offsets = list(offsets)

        # Returns a `bytes` object encoding `self`, and update `self.data` to contain the data after the header in the returned bytes.
        def encode(self):
            def encodeData(): # <-- encodes data *without* padding
                if self.type_ == 'public-symbols-table':
                    # Write number of offsets and the offset numbers
                    contents = self.publicSymbolsTable
                    # print(contents)
                    # exit()
                    b = struct.pack(f'>I{len(contents)}I', len(contents), *[x[0] for x in contents])
                    # Write names of functions
                    for x in contents:
                        b += x[1] + b'\x00'
                    return b
                elif self.type_ == 'offsets-table':
                    contents = (self.offsetsTable, self.offsets)
                    (offsetsTable, offsets) = contents
                    # Write number of offsets and the offset numbers
                    b = struct.pack(f'<I{len(offsets)}I', len(offsets), *offsets)
                    # Write num public symbols and the public symbols' indices
                    b += struct.pack(f'<I{len(offsetsTable)}H', len(offsetsTable), *[x[0] for x in offsetsTable])
                    # Write the public symbols' names
                    for x in offsetsTable:
                        b += x[1] + b'\x00'
                    return b
                elif self.type_ is None:
                    return self.data[:-1] if self.hasPadding else self.data # Remove padding if needed
                else:
                    assert False

            # Encode contents
            b = encodeData()

            # Compute size
            def encodedLength(b):
                return len(b)
            dataEncodedLength = encodedLength(b)
            
            # Save contents
            self.data = b + (b'\n' if dataEncodedLength & 1 == 1 else b'') # Trailing padding if needed
            self.hasPadding = dataEncodedLength & 1 == 1

            # Wrap the data in a header with size included
            fmt = '16s12s6s6s8s10s1s1s'
            size = struct.pack('10s', bytes(str(dataEncodedLength), 'ascii'))
            # Replace null bytes with spaces
            size = size.replace(b'\x00', b' ')

            self.fileSize = size # Update fileSize
            bHeader = struct.pack(fmt, self.fileName, self.modificationTimestamp, self.ownerID, self.groupID, self.fileMode, size, self.endMarker1, self.endMarker2)

            # Trailing padding if needed
            if dataEncodedLength & 1 == 1:
                b += b'\n'
            
            return bHeader + b

    class DataEntryRemoval:
        def __init__(self, index):
            self.index = index
    
    def __init__(self, f):
        self.f = f
        self.header = None

        # Entry object references: #
        self.publicSymbolsTableEntry = None
        self.offsetsTableEntry = None
        self.offsetsEntry = None
        # #

        # For removing items: #
        self.dataEntryRemovals = []
        # #
        
        self.entries = []
        nextType = None
        state = 0
        def append(type_, *args):
            nonlocal nextType
            nonlocal state

            # It goes `None`, public-symbols-table, start-entry, 4x `None`'s, size, 2x `None`'s, data-beginning, offsets-table, start-entry, 4x None, size, 2x None, data-beginning, {start-entry, 4x None, size, 2x None, data} repeats N times for unknown N.
            if type_ == 'public-symbols-table':
                assert len(args) == 1 and args[0] is None
                nextType = type_
            elif type_ == 'offsets-table':
                assert len(args) == 1 and args[0] is None
                nextType = type_
            elif type_ == 'start-entry':
                assert len(args) == 3
                fileName = args[0]
                self.addEntry(nextType, fileName)
                self.getLastEntry().offsetInFile = args[1]
                self.getLastEntry().hasPadding = args[2]
                if nextType == 'public-symbols-table':
                    self.publicSymbolsTableEntry = self.getLastEntry()
                elif nextType == 'offsets-table':
                    self.offsetsTableEntry = self.getLastEntry()
                    self.offsetsEntry = self.getLastEntry()
                nextType = None
            elif type_ is None and state == 0:
                self.header = args[0]
                state = 1
            elif type_ is None and state == 1:
                assert len(args) == 4
                self.getLastEntry().modificationTimestamp = args[0]
                self.getLastEntry().ownerID = args[1]
                self.getLastEntry().groupID = args[2]
                self.getLastEntry().fileMode = args[3]
                state = 2
            elif type_ == 'size':
                assert len(args) == 2
                self.getLastEntry().fileSize = args[0]
                self.getLastEntry().entryHeaderSize = args[1]
            elif type_ is None and state == 2:
                assert len(args) == 2
                self.getLastEntry().endMarker1 = args[0]
                self.getLastEntry().endMarker2 = args[1]
                state = 1
            elif type_ == 'data-beginning' or type_ == 'data':
                assert len(args) == 1
                self.getLastEntry().setKindAndData(type_, args[0])
            else:
                assert False
        load(self.f, append)

    def addEntry(self, type_=None, fileName=None, modificationTimestamp=None, ownerID=None, groupID=None, fileMode=None, fileSize=None, endMarker1=None, endMarker2=None):
        self.entries.append(Archive.Entry(type_, fileName, modificationTimestamp, ownerID, groupID, fileMode, fileSize, endMarker1, endMarker2))

    def getLastEntry(self):
        return self.entries[-1]

    # Removes all `data` (not `data-beginning`) entries if `fn`
    # returns true when given an entry from this Archive. When you
    # call `self.applyRemovals()` afterwards, the `data-beginning`
    # entries will be updated to reflect this change accordingly.
    # Returns True if any matching entries were found, False if not.
    def removeRegularEntriesMatchingLambda(self, fn):
        anyFound = False
        try:
            it = iter(self.entries)
            index = 0
            item = next(it)
            while item.kind_ == 'data-beginning':
                # Skip it
                index += 1
                item = next(it)

            # Now `item` is the first `data` entry.
            found = fn(item)
            anyFound |= found
            if found:
                # Enqueue a removal of it:
                self.dataEntryRemovals.append(Archive.DataEntryRemoval(index))
            
            while True:
                index += 1
                item = next(it)
                found = fn(item)
                anyFound |= found

                if found:
                    # Enqueue a removal of it:
                    self.dataEntryRemovals.append(Archive.DataEntryRemoval(index))
            
            return anyFound
        except StopIteration:
            return anyFound

    # Applies all removals performed to the data in the Archive, making it ready to write.
    def applyRemovals(self):
        # NOTE: I just realized I may have overcomplicated this a bit... we could just regenerate the table with new offsets since we will have the size of each entry in self.entries anyway...

        # 1. Update the `data-beginning`'s to have the new info due to these removals, and shift entries' `offestInFile`'s:
        for der in self.dataEntryRemovals:
            index = der.index
            item = self.entries[index]
            print("Removing", item)

            prevDataBeginningLengths = [len(self.publicSymbolsTableEntry.encode()), len(self.offsetsTableEntry.encode())]

            # Remove items with that offset from the public symbols table
            self.publicSymbolsTableEntry.publicSymbolsTable = filter(lambda x: x[0] != item.offsetInFile, self.publicSymbolsTableEntry.publicSymbolsTable)

            # Find the item with that offset in the `offsetsTable`
            oneBased = next((x[0] for x in self.offsetsTableEntry.offsetsTable if self.offsetsTableEntry.offsets[x[0] - 1] == item.offsetInFile))
            # Remove items with that offset from the `offsetsTable`
            self.offsetsTableEntry.offsetsTable = list(filter(lambda x: self.offsetsTableEntry.offsets[x[0] - 1] != item.offsetInFile, self.offsetsTableEntry.offsetsTable))
            # Shift down those greater than `oneBased`
            self.offsetsTableEntry.offsetsTable = [(offsetIndex - 1, name) if offsetIndex > oneBased else (offsetIndex, name) for offsetIndex, name in self.offsetsTableEntry.offsetsTable]

            # Remove items with that offset from the `offsets`
            self.offsetsTableEntry.offsets = filter(lambda x: x != item.offsetInFile, self.offsetsTableEntry.offsets)

            # Finalize objects for len() computations below this
            self.publicSymbolsTableEntry.publicSymbolsTable = list(self.publicSymbolsTableEntry.publicSymbolsTable)
            self.offsetsTableEntry.offsets = list(self.offsetsTableEntry.offsets)
            # Compute new lengths
            newDataBeginningLengths = [len(self.publicSymbolsTableEntry.encode()), len(self.offsetsTableEntry.encode())]
            lengthSub = sum(prevDataBeginningLengths) - sum(newDataBeginningLengths)
            
            assert item.size() == len(item.encode())
            # Shift items with greater offset in `offsets` than the one we're removing
            self.offsetsTableEntry.offsets = [(x - item.size()) if x > item.offsetInFile else x for x in self.offsetsTableEntry.offsets]
            # Shift all offsets in `offsets` by the beginning lengths
            self.offsetsTableEntry.offsets = [x - lengthSub for x in self.offsetsTableEntry.offsets]
            # Shift in the public symbols table the same way as above
            self.publicSymbolsTableEntry.publicSymbolsTable = [(x - item.size(), name) if x > item.offsetInFile else (x, name) for (x, name) in self.publicSymbolsTableEntry.publicSymbolsTable]
            self.publicSymbolsTableEntry.publicSymbolsTable = [(x - lengthSub, name) for (x, name) in self.publicSymbolsTableEntry.publicSymbolsTable]
            # Shift all entries in the Archive in the same way as above
            for x in self.entries:
                if x.offsetInFile > item.offsetInFile:
                    x.offsetInFile -= item.size()
            for x, y, z in zip(self.entries[1:2], prevDataBeginningLengths, newDataBeginningLengths): # (the first two data-beginnings are a special case; we only need to shift the second data-beginning though)
                x.offsetInFile -= y - z
            for x in self.entries[2:]: # (skip the first two data-beginnings)
                x.offsetInFile -= lengthSub
        
        # 2. Now remove the data entries:
        for der in self.dataEntryRemovals:
            index = der.index
            del self.entries[index]

        # 3. Reset removals
        self.dataEntryRemovals = []

    # Returns a `bytes` object encoding `self`.
    def encode(self):
        b = b'' + self.header # (Makes a copy)
        for x in self.entries:
            b += x.encode()
        return b
    
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass

    def __iter__(self):
        return iter(self.entries)

    def open(self, path, mode='r', encoding='utf-8'):
        modef = Mode(mode)
        arpath = path
        if not isinstance(arpath, ArPath):
            arpath = next((entry for entry in self.entries if entry.name == arpath), None)
            if arpath is None:
                raise ArchiveError('No such entry: {}'.format(arpath))
        binary = arpath.get_stream(self.f)
        if modef.is_binary():
            return binary
        return codecs.getreader(encoding)(binary)


def lookup(data, offset):
    start = offset
    end = data.index(b"\n", start)
    return data[start:end - 1].decode()

def error():
    print("Error")
    exit(1)

debug=False
def load(stream, proc):
    actual = stream.read(len(MAGIC))
    proc(None,actual)
    if actual != MAGIC:
        raise ArchiveError("Unexpected magic: {magic}".format(magic=actual))

    lookup_data = None
    count = 0
    while True:
        pos_ = stream.tell()
        if debug:
            print("offset before:", hex(pos_))
        
        fmt = '16s12s6s6s8s10s1s1s'
        expectedEntryHeaderSize = struct.calcsize(fmt)
        buffer = stream.read(expectedEntryHeaderSize)
        if len(buffer) < expectedEntryHeaderSize:
            break
        if debug:
            print("buffer:",buffer)
        name, timestamp, owner, group, mode, size, t1, t2 = struct.unpack(fmt, buffer)
        # del timestamp, owner, group, mode
        name_ = name.decode().rstrip()
        isBeginningParts = name_ == '/'
        if debug:
            print("stream's current position:", hex(stream.tell()))
        size_ = int(size.decode().rstrip())
        hasData = t1 + t2 == b'`\n'
        assert hasData # new thing..
        hasPadding = False # Assume False
        if hasData: # (concatenate bytes)
            # pad out more by rounding to a multiple of 2
            if size_ & 1 == 1:
                hasPadding = True
            size_ += size_ & 1

        # if name == '/':
        #     stream.seek(pad(size, 2), 1)
        # elif name == '//':
        #     # load the lookup
        #     lookup_data = stream.read(size)
        #     stream.seek(padding(size, 2), 1)
        # elif name.startswith('/'):
        #     lookup_offset = int(name[1:])
        #     expanded_name = lookup(lookup_data, lookup_offset)
        #     offset = stream.tell()
        #     stream.seek(pad(size, 2), 1)
        #     yield ArPath(expanded_name, offset, size)
        # else:
        #     offset = stream.tell()
        #     stream.seek(pad(size, 2), 1)
        #     yield ArPath(name.rstrip('/'), offset, size)

        if debug:
            print("name_:",name_)
            print("size_:",size_)
        
        # import code
        # code.InteractiveConsole(locals=locals()).interact()

        if hasData: #if name_.endswith('/'):
            fmt = f'{size_}s'
            buffer = stream.read(struct.calcsize(fmt))
            if len(buffer) < struct.calcsize(fmt):
                error()
                break
            if debug:
                print("buffer size:", len(buffer))
            data, = struct.unpack(fmt, buffer)
            if debug:
                print("data size:", len(data))
        else:
            data = None
            print("Error: no data") # This should be rare..
            exit(1)

        # Check for offsets table
        if isBeginningParts and count == 0: # public symbols table
            assert hasData
            proc("public-symbols-table", None)
        elif isBeginningParts and count == 1: # offsets table
            assert hasData
            proc("offsets-table", None)

        if debug:
            print('name, etc.:', name, timestamp, owner, group, mode, size, t1, t2, sep='\n\n\n')
        proc('start-entry', name, pos_, hasPadding); proc(None, timestamp, owner, group, mode); proc("size", size, expectedEntryHeaderSize); proc(None, t1, t2)
        if data is not None:
            if debug:# and count >= 1:
                print("data:",data)
            proc('data' + ('-beginning' if isBeginningParts else ''), data)
            count+=1
        if debug:
            print("offset:", hex(stream.tell()))
    if debug:
        print("COUNT:",count)

    # Add placeholder entry to flush the rest
    #proc('start-entry', None)
