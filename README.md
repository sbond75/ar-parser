# ar-parser
Parses and removes matching symbols from Visual C++ static libraries (.lib files)

Based on a modified version of [ar](https://github.com/vidstige/ar/).

## Usage

In [ar-parser.py](ar-parser.py), change the `toFind` list to what you want to remove from a static library. All entries in the static library provided that contain an entry in `toFind` will get removed, writing the resulting static library to an output file and leaving the original file unchanged. To run, provide an input static library to read from and an output which will be patched using `python3 ar-parser.py inputLib outputLib`. The static library is expected to be the result of compiling a DLL with Visual Studio 2015's v140 toolset; that is, its extension is usually `.lib` and it contains public symbol stubs to exported DLL functions. Other versions of MSVC are untested and may not work properly.

## Notes

The `.lib` file format seems to be based on `.ar` files, but with additional binary data in each file entry within it. See [this Wikipedia page](https://en.wikipedia.org/wiki/Ar_(Unix)) and [this ImHex pattern](https://github.com/WerWolv/ImHex-Patterns/blob/master/patterns/ar.hexpat) for more information on the general structure of the file entries.
