import 'dart:convert';
import 'dart:typed_data';

import '../models/analysis.dart';

const int mhMagic64 = 0xFEEDFACF;
const int fatMagic = 0xCAFEBABE;
const int fatMagic64 = 0xCAFEBABF;

const int lcSegment64 = 0x19;
const int lcSymtab = 0x2;
const int lcDysymtab = 0xB;
const int lcIdDylib = 0xD;
const int lcLoadDylib = 0xC;
const int lcLoadWeakDylib = 0x80000018;
const int lcReexportDylib = 0x8000001F;
const int lcLazyLoadDylib = 0x20;
const int lcUuid = 0x1B;
const int lcEncryptionInfo64 = 0x2C;
const int lcFunctionStarts = 0x26;
const int lcDyldInfo = 0x22;
const int lcDyldInfoOnly = 0x80000022;
const int lcDyldChainedFixups = 0x80000034;

class SymbolEntry {
  const SymbolEntry(this.name, this.type, this.value);
  final String name;
  final int type;
  final int value;
}

class MachOFile {
  MachOFile._(this.data) {
    _parse();
  }

  factory MachOFile.parse(Uint8List raw) {
    if (raw.length < 8) {
      throw const FormatException('文件太小，不是 Mach-O');
    }
    final be = ByteData.view(raw.buffer, raw.offsetInBytes, raw.lengthInBytes);
    final magicBig = be.getUint32(0, Endian.big);
    if (magicBig == fatMagic || magicBig == fatMagic64) {
      final slice = _pickFatSlice(raw, magicBig == fatMagic64);
      return MachOFile._(slice);
    }
    return MachOFile._(raw);
  }

  static Uint8List _pickFatSlice(Uint8List raw, bool is64) {
    final bd = ByteData.view(raw.buffer, raw.offsetInBytes, raw.lengthInBytes);
    final n = bd.getUint32(4, Endian.big);
    var off = 8;
    int? bestOffset;
    int? bestSize;
    for (var i = 0; i < n; i++) {
      if (off + (is64 ? 32 : 20) > raw.length) break;
      final cpu = bd.getUint32(off, Endian.big);
      final sub = bd.getUint32(off + 4, Endian.big);
      final fileOff = is64
          ? bd.getUint64(off + 8, Endian.big).toInt()
          : bd.getUint32(off + 8, Endian.big);
      final size = is64
          ? bd.getUint64(off + 16, Endian.big).toInt()
          : bd.getUint32(off + 12, Endian.big);
      if (cpu == 0x0100000C) {
        bestOffset = fileOff;
        bestSize = size;
        // Prefer arm64e (subtype 2) if present, but arm64 is fine too.
        if (sub == 2) break;
      }
      off += is64 ? 32 : 20;
    }
    if (bestOffset == null || bestSize == null) {
      throw const FormatException('fat 文件里没有 arm64 slice');
    }
    final end = (bestOffset + bestSize).clamp(0, raw.length).toInt();
    return Uint8List.sublistView(raw, bestOffset, end);
  }

  final Uint8List data;
  final List<SegmentInfo> segments = [];
  final List<SectionInfo> sections = [];
  final List<SymbolEntry> symbols = [];
  // Indexed by raw nlist entry, including empty names, so LC_DYSYMTAB
  // indirect-symbol indexes stay aligned with the symbol table.
  final List<String> _symbolNames = [];
  final List<String> imports = [];
  final List<int> functionStarts = [];
  final List<int> initFunctions = [];
  final Map<int, String> stubs = {};
  final Map<int, String> gotImports = {};

  int cpuType = 0;
  int cpuSubType = 0;
  int fileType = 0;
  int flags = 0;
  int cryptid = 0;
  String uuid = '';
  String installName = '';
  final List<String> dylibs = [];
  int textStart = 0;
  int textEnd = 0;

  int _symoff = 0;
  int _nsyms = 0;
  int _stroff = 0;
  int _strsize = 0;
  int _indirectSymoff = 0;
  int _nindirect = 0;
  int _fsDataOff = 0;
  int _fsDataSize = 0;
  int _chainedOff = 0;
  int _chainedSize = 0;
  int _bindOff = 0;
  int _bindSize = 0;
  int _lazyBindOff = 0;
  int _lazyBindSize = 0;
  int _textBase = 0;
  final Map<int, int> _fixups = {};
  final Map<int, String> _bindNames = {};

  ByteData get _bd => ByteData.view(data.buffer, data.offsetInBytes, data.lengthInBytes);

  int u16(int off) {
    if (off < 0 || off + 2 > data.length) return 0;
    return _bd.getUint16(off, Endian.little);
  }

  int u32(int off) {
    if (off < 0 || off + 4 > data.length) return 0;
    return _bd.getUint32(off, Endian.little);
  }

  int u64(int off) {
    if (off < 0 || off + 8 > data.length) return 0;
    return _bd.getUint64(off, Endian.little);
  }

  Uint8List bytes(int off, int length) {
    final start = off.clamp(0, data.length).toInt();
    final end = (off + length).clamp(0, data.length).toInt();
    return Uint8List.sublistView(data, start, end);
  }

  String cString(int off, {int max = 512}) {
    if (off < 0 || off >= data.length) return '';
    var end = off;
    final limit = (off + max).clamp(0, data.length).toInt();
    while (end < limit && data[end] != 0) {
      end++;
    }
    if (end <= off) return '';
    return utf8.decode(Uint8List.sublistView(data, off, end), allowMalformed: true);
  }

  SectionInfo? section(String segment, String name) {
    for (final s in sections) {
      if (s.segmentName == segment && s.name == name) return s;
    }
    return null;
  }

  List<SectionInfo> sectionsNamed(String name) =>
      sections.where((s) => s.name == name).toList();

  Uint8List sectionBytes(SectionInfo s) => bytes(s.offset, s.size);

  int? vmToFileOffset(int addr) {
    for (final seg in segments) {
      if (addr >= seg.vmAddr && addr < seg.vmAddr + seg.vmSize) {
        final delta = addr - seg.vmAddr;
        if (delta < seg.fileSize) return seg.fileOffset + delta;
        return null;
      }
    }
    return null;
  }

  Uint8List? readVm(int addr, int length) {
    final off = vmToFileOffset(addr);
    if (off == null) return null;
    return bytes(off, length);
  }

  int? readU32Vm(int addr) {
    final off = vmToFileOffset(addr);
    if (off == null) return null;
    return u32(off);
  }

  int? readU64Vm(int addr) {
    final off = vmToFileOffset(addr);
    if (off == null) return null;
    final fixed = _fixups[off];
    if (fixed != null) return fixed;
    if (_bindNames.containsKey(off)) return 0;
    return u64(off);
  }

  String? bindNameAtVm(int addr) {
    final off = vmToFileOffset(addr);
    if (off == null) return null;
    return _bindNames[off];
  }

  String? cStringVm(int addr, {int max = 256}) {
    final off = vmToFileOffset(addr);
    if (off == null) return null;
    final s = cString(off, max: max);
    if (s.isEmpty) return null;
    return s;
  }

  void _parse() {
    if (data.length < 32) throw const FormatException('Mach-O 头不完整');
    final magic = u32(0);
    if (magic != mhMagic64) {
      throw FormatException('不是 little-endian 64-bit Mach-O: 0x${magic.toRadixString(16)}');
    }
    cpuType = u32(4);
    cpuSubType = u32(8);
    fileType = u32(12);
    final ncmds = u32(16);
    flags = u32(24);

    var off = 32;
    for (var i = 0; i < ncmds && off + 8 <= data.length; i++) {
      final cmd = u32(off);
      final cmdsize = u32(off + 4);
      if (cmdsize < 8 || off + cmdsize > data.length) break;
      _parseCommand(cmd, off, cmdsize);
      off += cmdsize;
    }

    _parseSymbols();
    _parseFunctionStarts();
    _applyChainedFixups();
    _applyClassicBind(_bindOff, _bindSize);
    _applyClassicBind(_lazyBindOff, _lazyBindSize);
    _parseInitFunctions();
    _parseStubs();
    _parseGotImports();

    final text = section('__TEXT', '__text');
    if (text != null) {
      textStart = text.addr;
      textEnd = text.addr + text.size;
    }
  }

  void _parseCommand(int cmd, int off, int cmdsize) {
    if (cmd == lcSegment64) {
      final name = _fixedString(off + 8, 16);
      final vmaddr = u64(off + 24);
      final vmsize = u64(off + 32);
      final fileoff = u64(off + 40);
      final filesize = u64(off + 48);
      if (name == '__TEXT') _textBase = vmaddr;
      segments.add(SegmentInfo(
        name: name,
        vmAddr: vmaddr,
        vmSize: vmsize,
        fileOffset: fileoff,
        fileSize: filesize,
      ));
      final nsects = u32(off + 64);
      var so = off + 72;
      for (var i = 0; i < nsects && so + 80 <= off + cmdsize; i++) {
        final sectName = _fixedString(so, 16);
        final segName = _fixedString(so + 16, 16);
        sections.add(SectionInfo(
          segmentName: segName,
          name: sectName,
          addr: u64(so + 32),
          size: u64(so + 40),
          offset: u32(so + 48),
          flags: u32(so + 64),
          reserved1: u32(so + 68),
          reserved2: u32(so + 72),
        ));
        so += 80;
      }
    } else if (cmd == lcSymtab) {
      _symoff = u32(off + 8);
      _nsyms = u32(off + 12);
      _stroff = u32(off + 16);
      _strsize = u32(off + 20);
    } else if (cmd == lcDysymtab) {
      _indirectSymoff = u32(off + 56);
      _nindirect = u32(off + 60);
    } else if (cmd == lcIdDylib) {
      installName = _cmdString(off, u32(off + 8));
    } else if (cmd == lcLoadDylib ||
        cmd == lcLoadWeakDylib ||
        cmd == lcReexportDylib ||
        cmd == lcLazyLoadDylib) {
      final s = _cmdString(off, u32(off + 8));
      if (s.isNotEmpty) dylibs.add(s);
    } else if (cmd == lcUuid) {
      final b = bytes(off + 8, 16);
      uuid = b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();
    } else if (cmd == lcEncryptionInfo64) {
      cryptid = u32(off + 16);
    } else if (cmd == lcFunctionStarts) {
      _fsDataOff = u32(off + 8);
      _fsDataSize = u32(off + 12);
    } else if (cmd == lcDyldChainedFixups) {
      _chainedOff = u32(off + 8);
      _chainedSize = u32(off + 12);
    } else if (cmd == lcDyldInfo || cmd == lcDyldInfoOnly) {
      _bindOff = u32(off + 16);
      _bindSize = u32(off + 20);
      _lazyBindOff = u32(off + 32);
      _lazyBindSize = u32(off + 36);
    }
  }

  String _fixedString(int off, int length) {
    final b = bytes(off, length);
    var end = b.length;
    for (var i = 0; i < b.length; i++) {
      if (b[i] == 0) {
        end = i;
        break;
      }
    }
    return utf8.decode(Uint8List.sublistView(b, 0, end), allowMalformed: true);
  }

  String _cmdString(int cmdOff, int nameOff) {
    if (nameOff <= 0 || nameOff >= u32(cmdOff + 4)) return '';
    return cString(cmdOff + nameOff, max: 512);
  }

  void _parseFunctionStarts() {
    if (_fsDataSize == 0) return;
    // LC_FUNCTION_STARTS store offsets from the __TEXT image base. For most
    // dylibs that base is 0, but app binaries use 0x100000000, so add it.
    var base = 0;
    for (final s in segments) {
      if (s.name == '__TEXT') {
        base = s.vmAddr;
        break;
      }
    }
    final start = _fsDataOff.clamp(0, data.length).toInt();
    final end = (_fsDataOff + _fsDataSize).clamp(0, data.length).toInt();
    var i = start;
    var addr = 0;
    while (i < end) {
      var value = 0;
      var shift = 0;
      while (i < end) {
        final c = data[i++];
        value |= (c & 0x7F) << shift;
        shift += 7;
        if ((c & 0x80) == 0) break;
      }
      if (value == 0) break;
      addr += value;
      functionStarts.add(base + addr);
    }
  }

  void _parseSymbols() {
    if (_nsyms <= 0) return;
    for (var i = 0; i < _nsyms; i++) {
      final o = _symoff + i * 16;
      if (o + 16 > data.length) break;
      final strx = u32(o);
      final type = data[o + 4];
      final value = u64(o + 8);
      final name = cString(_stroff + strx, max: 1024);
      _symbolNames.add(name);
      if (name.isEmpty) continue;
      symbols.add(SymbolEntry(name, type, value));
      if ((type & 0x0E) == 0 && value == 0) {
        imports.add(name);
      }
    }
  }

  void _parseInitFunctions() {
    for (final s in sectionsNamed('__mod_init_func')) {
      for (var i = 0; i + 8 <= s.size; i += 8) {
        final ptr = readU64Vm(s.addr + i) ?? 0;
        if (ptr != 0) initFunctions.add(ptr);
      }
    }
  }

  void _parseStubs() {
    if (_indirectSymoff == 0 || _nindirect == 0) return;
    // arm64e binaries use __auth_stubs in addition to __stubs. Both store the
    // stub size in section reserved2; fall back to the classic 12 bytes.
    final stubSections = [
      ...sectionsNamed('__stubs'),
      ...sectionsNamed('__auth_stubs'),
    ];
    for (final s in stubSections) {
      final stubSize = s.reserved2 > 0 ? s.reserved2 : 12;
      final count = s.size ~/ stubSize;
      final baseIndex = s.reserved1;
      for (var i = 0; i < count; i++) {
        final index = baseIndex + i;
        if (index >= _nindirect) break;
        final idxOff = _indirectSymoff + index * 4;
        if (idxOff + 4 > data.length) break;
        final symIndex = u32(idxOff);
        // 0x80000000/0x40000000 mark LOCAL/ABS indirect entries.
        if ((symIndex & 0xC0000000) != 0 || symIndex >= _symbolNames.length) {
          continue;
        }
        final name = _symbolNames[symIndex];
        if (name.isNotEmpty) {
          stubs[s.addr + i * stubSize] = name;
        }
      }
    }
  }

  Map<String, SectionInfo> get sectionMap => {
        for (final s in sections) '${s.segmentName},${s.name}': s,
      };

  void _parseGotImports() {
    for (final s in [
      ...sectionsNamed('__got'),
      ...sectionsNamed('__auth_got'),
      ...sectionsNamed('__la_symbol_ptr'),
      ...sectionsNamed('__nl_symbol_ptr'),
    ]) {
      for (var i = 0; i + 8 <= s.size; i += 8) {
        final name = bindNameAtVm(s.addr + i);
        if (name != null && name.isNotEmpty) {
          gotImports[s.addr + i] = name;
        }
      }
    }
  }

  int _readUleb(int start, int end, List<int> cursor) {
    var value = 0;
    var shift = 0;
    var i = cursor[0];
    while (i < end) {
      final c = data[i++];
      value |= (c & 0x7F) << shift;
      shift += 7;
      if ((c & 0x80) == 0) break;
    }
    cursor[0] = i;
    return value;
  }

  int _readSleb(int start, int end, List<int> cursor) {
    var value = 0;
    var shift = 0;
    var i = cursor[0];
    var c = 0;
    while (i < end) {
      c = data[i++];
      value |= (c & 0x7F) << shift;
      shift += 7;
      if ((c & 0x80) == 0) break;
    }
    cursor[0] = i;
    if (shift < 64 && (c & 0x40) != 0) {
      value |= (~0) << shift;
    }
    return value;
  }

  void _applyClassicBind(int off, int size) {
    if (size == 0) return;
    final start = off.clamp(0, data.length).toInt();
    final end = (off + size).clamp(0, data.length).toInt();
    final cursor = [start];
    var segIndex = 0;
    var segOff = 0;
    var symbol = '';
    while (cursor[0] < end) {
      final b = data[cursor[0]++];
      final op = b & 0xF0;
      final imm = b & 0x0F;
      switch (op) {
        case 0x00:
          return;
        case 0x10:
        case 0x20:
          _readUleb(start, end, cursor);
          break;
        case 0x30:
          break;
        case 0x40:
          symbol = cString(cursor[0], max: 1024);
          cursor[0] += symbol.length + 1;
          break;
        case 0x50:
          break;
        case 0x60:
          _readSleb(start, end, cursor);
          break;
        case 0x70:
          segIndex = imm;
          segOff = _readUleb(start, end, cursor);
          break;
        case 0x80:
          segOff += _readUleb(start, end, cursor);
          break;
        case 0x90:
          _bindAt(segIndex, segOff, symbol);
          segOff += 8;
          break;
        case 0xA0:
          _bindAt(segIndex, segOff, symbol);
          segOff += _readUleb(start, end, cursor) + 8;
          break;
        case 0xB0:
          _bindAt(segIndex, segOff, symbol);
          segOff += imm * 8 + 8;
          break;
        case 0xC0:
          final times = _readUleb(start, end, cursor);
          final skip = _readUleb(start, end, cursor);
          for (var i = 0; i < times; i++) {
            _bindAt(segIndex, segOff, symbol);
            segOff += skip + 8;
          }
          break;
      }
    }
  }

  void _bindAt(int segIndex, int segOff, String symbol) {
    if (segIndex < 0 || segIndex >= segments.length) return;
    final seg = segments[segIndex];
    if (segOff < 0 || segOff + 8 > seg.fileSize) return;
    final fileOff = seg.fileOffset + segOff;
    if (symbol.isNotEmpty) _bindNames[fileOff] = symbol;
  }

  void _applyChainedFixups() {
    if (_chainedSize < 28) return;
    final base = _chainedOff;
    if (base < 0 || base + 28 > data.length) return;
    final startsOffset = u32(base + 4);
    final importsOffset = u32(base + 8);
    final symbolsOffset = u32(base + 12);
    final importsCount = u32(base + 16);
    final importsFormat = u32(base + 20);
    final importNames = _chainedImportNames(
      base,
      importsOffset,
      symbolsOffset,
      importsCount,
      importsFormat,
    );

    final startsAt = base + startsOffset;
    if (startsAt + 4 > data.length) return;
    final segCount = u32(startsAt);
    for (var segIndex = 0; segIndex < segCount; segIndex++) {
      final infoRel = u32(startsAt + 4 + segIndex * 4);
      if (infoRel == 0) continue;
      _walkChainedSegment(startsAt + infoRel, importNames);
    }
  }

  List<String> _chainedImportNames(
    int base,
    int importsOffset,
    int symbolsOffset,
    int importsCount,
    int importsFormat,
  ) {
    final names = List<String>.filled(importsCount, '');
    var entrySize = 4;
    if (importsFormat == 2) entrySize = 8;
    if (importsFormat == 3) entrySize = 16;
    for (var i = 0; i < importsCount; i++) {
      final entryOff = base + importsOffset + i * entrySize;
      if (entryOff + entrySize > data.length) break;
      int nameOff;
      if (importsFormat == 3) {
        final raw = u64(entryOff);
        nameOff = ((raw >> 32) & 0xFFFFFFFF).toInt();
      } else {
        final raw = u32(entryOff);
        nameOff = (raw >> 9) & 0x7FFFFF;
      }
      names[i] = cString(base + symbolsOffset + nameOff, max: 1024);
    }
    return names;
  }

  void _walkChainedSegment(int infoOff, List<String> importNames) {
    if (infoOff + 22 > data.length) return;
    final pageSize = u16(infoOff + 4);
    final pointerFormat = u16(infoOff + 6);
    final segmentOffset = u64(infoOff + 8);
    final pageCount = u16(infoOff + 20);
    if (pageSize == 0 || pageCount == 0) return;
    final stride = _chainedStride(pointerFormat);
    final starts = infoOff + 22;
    for (var page = 0; page < pageCount; page++) {
      final startOff = starts + page * 2;
      if (startOff + 2 > data.length) break;
      var pageStart = u16(startOff);
      if (pageStart == 0xFFFF) continue;
      if ((pageStart & 0x8000) != 0) {
        var idx = pageStart & 0x7FFF;
        while (true) {
          final overflowOff = starts + pageCount * 2 + idx * 2;
          if (overflowOff + 2 > data.length) break;
          final ov = u16(overflowOff);
          if ((ov & 0x8000) == 0) {
            _walkChainVm(
              _textBase + segmentOffset + page * pageSize + ov,
              pointerFormat,
              stride,
              importNames,
            );
            break;
          }
          _walkChainVm(
            _textBase + segmentOffset + page * pageSize + (ov & 0x7FFF),
            pointerFormat,
            stride,
            importNames,
          );
          idx++;
        }
      } else {
        _walkChainVm(
          _textBase + segmentOffset + page * pageSize + pageStart,
          pointerFormat,
          stride,
          importNames,
        );
      }
    }
  }

  int _chainedStride(int format) {
    switch (format) {
      case 1:
      case 9:
      case 12:
        return 8;
      default:
        return 4;
    }
  }

  void _walkChainVm(
    int vmAddr,
    int format,
    int stride,
    List<String> importNames,
  ) {
    var addr = vmAddr;
    final seen = <int>{};
    while (addr > 0 && seen.add(addr)) {
      final fileOff = vmToFileOffset(addr);
      if (fileOff == null || fileOff + 8 > data.length) break;
      final raw = u64(fileOff);
      final next = _chainedNext(raw, format);
      final decoded = _decodeChained(raw, format, importNames);
      if (decoded.$1 != null) _fixups[fileOff] = decoded.$1!;
      if (decoded.$2 != null && decoded.$2!.isNotEmpty) {
        _bindNames[fileOff] = decoded.$2!;
      }
      if (next == 0) break;
      addr += next * stride;
    }
  }

  int _chainedNext(int raw, int format) {
    switch (format) {
      case 1:
      case 7:
      case 9:
      case 10:
      case 12:
        return (raw >> 51) & 0x7FF;
      case 2:
      case 6:
        return (raw >> 51) & 0xFFF;
      default:
        return 0;
    }
  }

  (int?, String?) _decodeChained(int raw, int format, List<String> importNames) {
    switch (format) {
      case 2:
      case 6:
        final bind = (raw >> 63) & 1;
        if (bind != 0) {
          final ordinal = raw & 0xFFFFFF;
          final name = ordinal < importNames.length ? importNames[ordinal] : '';
          return (null, name);
        }
        final target = raw & 0xFFFFFFFFF;
        final high8 = (raw >> 36) & 0xFF;
        var vm = (high8 << 56) | target;
        if (format == 6) vm += _textBase;
        return (vm, null);
      case 1:
      case 7:
      case 9:
      case 10:
      case 12:
        final bind = (raw >> 62) & 1;
        final auth = (raw >> 63) & 1;
        if (bind != 0) {
          final ordinal = format == 12 ? (raw & 0xFFFFFF) : (raw & 0xFFFF);
          final name = ordinal < importNames.length ? importNames[ordinal] : '';
          return (null, name);
        }
        if (auth != 0) {
          final target = raw & 0xFFFFFFFF;
          return (target + _textBase, null);
        }
        if (format == 9 || format == 12) {
          final target = raw & 0x7FFFFFFFFFF;
          return (target + _textBase, null);
        }
        final target = raw & 0x7FFFFFFFFFF;
        final high8 = (raw >> 43) & 0xFF;
        return ((high8 << 56) | target, null);
      default:
        return (null, null);
    }
  }
}
