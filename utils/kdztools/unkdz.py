import os
import argparse
import sys
from binascii import b2a_hex

# our tools are in "libexec"
sys.path.append(os.path.join(sys.path[0], "libexec"))

import kdz


class KDZFileTools(kdz.KDZFile):
    """
    LGE KDZ File tools
    """

    partitions = []
    outdir = "kdzextracted"
    infile = None

    kdz_header = {
        b"\x28\x05\x00\x00" + b"\x34\x31\x25\x80": 0,
        b"\x18\x05\x00\x00" + b"\x32\x79\x44\x50": 1,
        kdz.KDZFile._dz_header: 2,
    }

    def readKDZHeader(self):
        buf = self.infile.read(self._dz_length)
        kdz_item = dict(zip(self._dz_format_dict.keys(), self._dz_struct.unpack(buf)))

        for key in self._dz_collapsibles:
            value = kdz_item[key]
            if isinstance(value, (str, bytes)):
                value = value.rstrip(b'\x00') if isinstance(value, bytes) else value.rstrip('\x00')
                kdz_item[key] = value
                if b'\x00' in value if isinstance(value, bytes) else '\x00' in value:
                    print(f"[!] Warning: extraneous data found IN {key}", file=sys.stderr)
            elif isinstance(value, int):
                if value != 0:
                    byte_val = value.to_bytes((value.bit_length() + 7) // 8 or 1, byteorder='little')
                    print(f'[!] Error: field "{key}" is non-zero ({b2a_hex(byte_val)})', file=sys.stderr)
                    sys.exit(1)
            else:
                print("[!] Error: internal error", file=sys.stderr)
                sys.exit(-1)

        return kdz_item

    def getPartitions(self):
        last = False
        cont = not last
        self.dataStart = 1 << 63

        while cont:
            kdz_sub = self.readKDZHeader()
            self.partitions.append(kdz_sub)
            if kdz_sub['offset'] < self.dataStart:
                self.dataStart = kdz_sub['offset']

            cont = not last

            nextchar = self.infile.read(1)
            if nextchar == b'\x03':
                last = True
            elif nextchar == b'\x00':
                cont = False
            else:
                self.infile.seek(-1, os.SEEK_CUR)

        self.headerEnd = self.infile.tell()

        gap = self.dataStart - self.headerEnd - 1
        if gap > 0:
            buf = self.infile.read(gap)
            if len(buf.lstrip(b'\x00')) > 0:
                print(f"[!] Warning: Data between headers and payload! (offsets {self.headerEnd} to {self.dataStart})", file=sys.stderr)
                self.hasExtra = True

        return [(x['name'], x['length']) for x in self.partitions]

    def extractPartition(self, index):
        currentPartition = self.partitions[index]
        self.infile.seek(currentPartition['offset'], os.SEEK_SET)

        if not os.path.exists(self.outdir):
            os.makedirs(self.outdir)

        name = currentPartition['name']
        if isinstance(name, bytes):
            name = name.decode("utf8")

        with open(os.path.join(self.outdir, name), 'wb') as outfile:
            chunkSize = 1024
            while True:
                outfile.write(self.infile.read(chunkSize))
                if outfile.tell() + chunkSize >= currentPartition['length']:
                    outfile.write(self.infile.read(currentPartition['length'] - outfile.tell()))
                    break

    def saveExtra(self):
        if not getattr(self, 'hasExtra', False):
            return

        filename = os.path.join(self.outdir, "kdz_extras.bin")
        print(f"[+] Extracting extra data to {filename}")

        with open(filename, "wb") as extra:
            self.infile.seek(self.headerEnd, os.SEEK_SET)
            total = self.dataStart - self.headerEnd
            while total > 0:
                count = min(4096, total)
                buf = self.infile.read(count)
                extra.write(buf)
                total -= count

    def saveParams(self):
        with open(os.path.join(self.outdir, ".kdz.params"), "w", encoding="utf-8") as params:
            params.write(f'# saved parameters from the file "{self.kdzfile}"\n')
            params.write(f"version={self.header_type}\n")
            params.write("# note, this is actually quite fluid, dataStart just needs to be large enough\n")
            params.write("# for headers not to overwrite data; roughly 16 bytes for overhead plus 272\n")
            params.write("# bytes per file should be sufficient (but not match original)\n")
            params.write(f"dataStart={self.dataStart}\n")
            params.write("# embedded files\n")

            out = [{'name': p['name'], 'data': p['offset'], 'header': i} for i, p in enumerate(self.partitions)]
            out.sort(key=lambda p: p['data'])

            for i, p in enumerate(out):
                name = p['name']
                if isinstance(name, bytes):
                    name = name.decode("utf8")
                params.write(f"payload{i}={name}\n")
                params.write(f"payload{i}head={p['header']}\n")

    def parseArgs(self):
        parser = argparse.ArgumentParser(description='LG KDZ File Extractor originally by IOMonster')
        parser.add_argument('-f', '--file', required=True, dest='kdzfile', help='KDZ File to read')
        group = parser.add_mutually_exclusive_group(required=True)
        group.add_argument('-l', '--list', action='store_true', dest='listOnly', help='list partitions')
        group.add_argument('-x', '--extract', action='store_true', dest='extractAll', help='extract all partitions')
        group.add_argument('-s', '--single', type=int, dest='extractID', help='single Extract by ID')
        parser.add_argument('-d', '--dir', '-o', '--out', dest='outdir', help='output directory')
        return parser.parse_args()

    def openFile(self, kdzfile):
        try:
            self.infile = open(kdzfile, "rb")
        except IOError as err:
            print(err, file=sys.stderr)
            sys.exit(1)

        self.infile.seek(0, os.SEEK_END)
        self.kdz_length = self.infile.tell()
        self.infile.seek(0, os.SEEK_SET)

        verify_header = self.infile.read(8)
        if verify_header not in self.kdz_header:
            print("[!] Error: Unsupported KDZ file format.")
            print('[ ] Received header "{:s}".'.format(" ".join(b2a_hex(n.to_bytes(1, 'little')).decode() for n in verify_header)))
            sys.exit(1)

        self.header_type = self.kdz_header[verify_header]

    def cmdExtractSingle(self, partID):
        print(f"[+] Extracting single partition from v{self.header_type} file!\n")
        name = self.partList[partID][0]
        if isinstance(name, bytes):
            name = name.decode("utf8")
        print(f"[+] Extracting {name} to {os.path.join(self.outdir, name)}")
        self.extractPartition(partID)

    def cmdExtractAll(self):
        print(f"[+] Extracting all partitions from v{self.header_type} file!\n")
        for idx, part in enumerate(self.partList):
            name = part[0]
            if isinstance(name, bytes):
                name = name.decode("utf8")
            print(f"[+] Extracting {name} to {os.path.join(self.outdir, name)}")
            self.extractPartition(idx)
        self.saveExtra()
        self.saveParams()

    def cmdListPartitions(self):
        print(f"[+] KDZ Partition List (format v{self.header_type})\n{'='*40}")
        for idx, part in enumerate(self.partList):
            name = part[0]
            if isinstance(name, bytes):
                name = name.decode("utf8")
            print(f"{idx:2d} : {name} ({part[1]} bytes)")

    def main(self):
        args = self.parseArgs()
        self.kdzfile = args.kdzfile
        self.openFile(args.kdzfile)
        self.partList = self.getPartitions()

        if args.outdir:
            self.outdir = args.outdir

        if args.listOnly:
            self.cmdListPartitions()
        elif args.extractID is not None:
            if 0 <= args.extractID < len(self.partList):
                self.cmdExtractSingle(args.extractID)
            else:
                print(f"[!] Segment {args.extractID} is out of range!", file=sys.stderr)
        elif args.extractAll:
            self.cmdExtractAll()


if __name__ == "__main__":
    kdztools = KDZFileTools()
    kdztools.main()
