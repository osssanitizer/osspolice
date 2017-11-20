# http://stackoverflow.com/questions/13044562/python-mechanism-to-identify-compressed-file-type-and-uncompress
# All the magic numbers for file types: http://www.garykessler.net/library/file_sigs.html
import zipfile
import tarfile
# pip install rarfile
import rarfile
import bz2
import gzip
import sys

# python 3.3+
try:
    import lzma
except:
    print ("Using Python 2.7 and lzma is not available!")


class CompressedFile(object):
    magic = None
    file_type = None
    mime_type = None
    proper_extension = None

    def __init__(self, f):
        # f is an open file or file like object
        self.f = f
        self.accessor = self.open()

    @classmethod
    def is_magic(self, data):
        return data.startswith(self.magic)

    def open(self):
        return None


class ZIPFile(CompressedFile):
    magic = '\x50\x4b\x03\x04'
    file_type = 'zip'
    mime_type = 'compressed/zip'

    def open(self):
        return zipfile.ZipFile(self.f)


class BZ2File(CompressedFile):
    magic = '\x42\x5a\x68'
    file_type = 'bz2'
    mime_type = 'compressed/bz2'

    def open(self):
        return bz2.BZ2File(self.f)


class GZFile(CompressedFile):
    magic = '\x1f\x8b\x08'
    file_type = 'gz'
    mime_type = 'compressed/gz'

    def open(self):
        return gzip.GzipFile(self.f)


class SevenZFile(CompressedFile):
    magic = '\x37\x7A\xBC\xAF\x27\x1C'
    file_type = '7z'
    mime_type = 'compressed/7z'

    def open(self):
        raise Exception("Unhandled mime_type: %s" % self.mime_type)
        return None


class TarFile(CompressedFile):
    magic = '\x75\x73\x74\x61\x72'
    file_type = 'tar'
    mime_type = 'compressed/tar'

    def open(self):
        return tarfile.TarFile(self.f)


class XZFile(CompressedFile):
    # This only works in python 3.3+
    magic = '\xFD\x37\x7A\x58\x5A\x00'
    file_type = 'xz'
    mime_type = 'compressed/xz'

    def open(self):
        return lzma.LZMAFile(self.f)


class JARCSFile(CompressedFile):
    magic = '\x4A\x41\x52\x43\x53\x00'
    file_type = 'jarcs'
    mime_type = 'compressed/jarcs'

    def open(self):
        raise Exception("Unhandled file type: %s" % self.file_type)


class MARFile(CompressedFile):
    magic = '\x4D\x41\x52\x31\x00'
    file_type = 'mar'
    mime_type = 'compressed/mar'

    def open(self):
        raise Exception("Unhandled file type: %s" % self.file_type)


class RARFile(CompressedFile):
    magic = '\x52\x61\x72\x21\x1A\x07'  # 52 61 72 21 1A 07 00, RAR (V4.x), 52 61 72 21 1A 07 01 00, RAR (V5)
    file_type = 'rar'
    mime_type = 'compressed/rar'

    def open(self):
        return rarfile.RarFile(self.f)


class WinZIPFile(CompressedFile):
    magic = '\x57\x69\x6E\x5A\x69\x70'
    file_type = 'winzip'
    mime_type = 'compressed/winzip'

    def open(self):
        return zipfile.ZipFile(self.f)


# This is used for decompression
MIME_TO_ZIPTYPE_FOR_DECOMPRESSION = {
    'application/zip': ZIPFile,  # This may have false positive
    'application/x-bzip2': BZ2File,
    'application/bzip2': BZ2File,
    'application/x-gzip': GZFile,
    'application/gzip': GZFile,
    'application/x-tar': TarFile,
    'application/tar': TarFile,
    'application/x-xz': XZFile,
    'application/xz': XZFile,
}


# factory function to create a suitable instance for accessing files
def get_compressed_file(filename):
    f = open(filename, 'rb')
    start_of_file = f.read(1024)
    f.seek(0)
    for cls in (ZIPFile, BZ2File, GZFile, SevenZFile, TarFile, XZFile, JARCSFile, MARFile, RARFile, WinZIPFile):
        if cls.is_magic(start_of_file):
            if cls in (GZFile, BZ2File, TarFile):
                return cls(filename)
            else:
                return cls(f)
    return None


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise Exception("python compress_files.py $compressed_filename")
    filename = sys.argv[1]
    cf = get_compressed_file(filename)
    if cf is not None:
        print (filename, 'is a', cf.mime_type, 'file')
        print (cf.accessor)
