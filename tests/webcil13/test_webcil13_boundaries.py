"""CoreCLR WebCIL #13: NON-EXPLOIT format-model/source regression checks.

Does NOT run CoreCLR, establish native execution, or demonstrate RCE.
"""
import collections
import json
import pathlib
import random
import struct
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
CORE = ROOT / "scan-target-v11.0.100/src/runtime/src/coreclr"
H0 = struct.Struct("<4sHHHHIIII")
H1 = struct.Struct("<4sHHHHIIIII")
SEC = struct.Struct("<IIII")
BLK = struct.Struct("<II")

def fixture(total=96, raw=48, raw_size=12, target=52, block_size=10,
            version=1, virtual=48):
    """Synthetic headers, NOT a runnable or deployable managed assembly."""
    h = H1 if version == 1 else H0
    blob = bytearray(total)
    fields = [b"WbIL", version, 0, 1, 1, 0, 0, 0, 0]
    if version == 1:
        fields.append(1)
    blob[:h.size] = h.pack(*fields)
    blob[h.size:h.size + SEC.size] = SEC.pack(raw_size, virtual, raw_size, raw)
    if 0 <= raw and raw + 10 <= total:
        struct.pack_into("<IIH", blob, raw, target, block_size, 0)
    return bytes(blob)

def shallow(blob):
    if len(blob) < H0.size or blob[:4] != b"WbIL":
        return False
    major, minor, nsec, reloc = struct.unpack_from("<HHHH", blob, 4)
    hsize = H1.size if major == 1 else H0.size
    return (major in (0, 1) and minor == 0 and
            1 <= nsec <= 16 and 1 <= reloc <= nsec and
            len(blob) >= hsize + nsec * SEC.size)

def model_hazards(blob, width=4):
    """Compute structural violations before applying additive relocations."""
    if not shallow(blob):
        return ["early_header_rejected"]
    major = struct.unpack_from("<H", blob, 4)[0]
    hdrsize = H1.size if major == 1 else H0.size
    vsize, vaddr, raw_size, raw = SEC.unpack_from(blob, hdrsize)
    if raw > len(blob) or raw_size > len(blob) - raw:
        return ["raw_range_out_of_image"]
    if raw_size < BLK.size:
        return ["relocation_directory_too_short"]
    issues = []
    pos = 0
    while pos + BLK.size <= raw_size:
        target_rva, size = BLK.unpack_from(blob, raw + pos)
        if size == 0:
            break
        if size < BLK.size:
            issues.append("block_underflow")
            break
        if size & 1:
            issues.append("block_odd_length")
            break
        if size > raw_size - pos:
            issues.append("block_over_directory")
            break
        for j in range((size - BLK.size)//2):
            fixup = struct.unpack_from("<H", blob, raw + pos + 8 + 2*j)[0]
            off = target_rva + (fixup & 0xfff)
            if off > len(blob) or width > len(blob) - off:
                issues.append("relocation_write_outside_image")
                break
            if off < vaddr or off+width > vaddr+vsize:
                issues.append("relocation_write_outside_section")
                break
        pos += size
    return issues

class SourceChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.layout = (CORE / "vm/peimagelayout.cpp").read_text()
        cls.decoder = (CORE / "utilcode/webcildecoder.cpp").read_text()
        cls.assembly = (CORE / "vm/assemblynative.cpp").read_text()
        cls.header = (CORE / "inc/webcildecoder.h").read_text()

    def test_structure_sizes(self):
        self.assertEqual((H0.size, H1.size, SEC.size), (28,32,16))
        for s in ("sizeof(WebcilHeader) == 28", "sizeof(WebcilHeader_1) == 32",
                  "sizeof(WebcilSectionHeader) == 16"):
            self.assertIn(s, self.header)

    def test_prevalidation_relocation_order(self):
        s = self.layout.index("void PEImageLayout::InitDecoders")
        e = self.layout.index("// IMAGE_REL_BASED_PTR", s)
        part = self.layout[s:e]
        self.assertLess(part.index("m_webcilDecoder.Init(data, size)"),
                        part.index("ApplyBaseRelocations(true)"))
        self.assertNotIn("CheckWebcilHeaders()", part)
        part = self.assembly[self.assembly.index("AssemblyNative_LoadFromStream"):]
        self.assertLess(part.index("PEImage::CreateFromByteArray"),
                        part.index("pILImage->CheckILFormat()"))

    def test_directory_pointer_no_full_bounds_guard(self):
        s = self.decoder.index("TADDR WebcilDecoder::GetDirectoryEntryData(")
        e = self.decoder.index("PTR_IMAGE_DEBUG_DIRECTORY", s)
        part = self.decoder[s:e]
        self.assertIn("return (TADDR)(m_base + relocSection->PointerToRawData)",part)
        self.assertNotIn("CHECK(CheckOverflow(relocSection->PointerToRawData",part)
        self.assertIn("CHECK(sections[i].PointerToRawData + sections[i].SizeOfRawData <= m_size)",self.decoder)

    def test_debug_assertions_only_for_block_size(self):
        s = self.layout.index("void PEImageLayout::ApplyBaseRelocations")
        e = self.layout.index("static SIZE_T AllocatedPart",s)
        part = self.layout[s:e]
        self.assertIn("_ASSERTE((BYTE *)(fixups + fixupsCount) <=",part)
        self.assertIn("BYTE * address = pageAddress + (fixup & 0xfff)",part)
        self.assertIn("*(uint32_t *)address +=",part)

class BoundedModels(unittest.TestCase):
    def check(self, reason, **args):
        data = fixture(**args)
        self.assertTrue(shallow(data))
        self.assertIn(reason,model_hazards(data))

    def test_directory_beyond_buffer(self):
        self.check("raw_range_out_of_image",raw=120)

    def test_section_truncated(self):
        self.check("raw_range_out_of_image",raw=90,raw_size=24)

    def test_short_directory(self):
        self.check("relocation_directory_too_short",raw_size=4)

    def test_underlength_block(self):
        self.check("block_underflow",block_size=4)

    def test_odd_block(self):
        self.check("block_odd_length",block_size=9)

    def test_block_extending_past_dir(self):
        self.check("block_over_directory",block_size=1000)

    def test_write_at_end(self):
        self.check("relocation_write_outside_image",target=96)

    def test_write_crosses_end(self):
        self.check("relocation_write_outside_image",target=94)

    def test_write_outside_section(self):
        self.check("relocation_write_outside_section",target=80)

    def test_wellformed_format_model(self):
        self.assertEqual([],model_hazards(fixture(target=52)))

    def test_v0_header_model(self):
        self.assertEqual([],model_hazards(fixture(version=0,raw=44,virtual=44,target=48)))

    def test_seeded_twenty_thousand_cases(self):
        rnd = random.Random(13)
        counts = collections.Counter()
        for _ in range(20000):
            f = fixture(raw=rnd.choice((48,64,82,90,96,120)),
                        raw_size=rnd.choice((4,8,10,12,15,24,64)),
                        block_size=rnd.choice((0,4,8,9,10,11,16,64,1000)),
                        target=rnd.choice((32,48,52,64,94,96,300)))
            counts.update(model_hazards(f))
        self.assertGreater(sum(counts.values()),1000)
        self.assertGreater(counts["raw_range_out_of_image"],0)
        self.assertGreater(counts["relocation_write_outside_image"],0)
        print("WEB CIL13 MODEL ONLY: "+json.dumps(counts,sort_keys=True))

if __name__ == "__main__":
    unittest.main(verbosity=2)
