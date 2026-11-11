import 'dart:convert';
import 'dart:typed_data';

import '../models/analysis.dart';
import 'macho_parser.dart';

/// Best-effort Objective-C metadata reader.
///
/// The dylib only contains metadata for classes it defines. Classes that it
/// hooks from the host app are not in this list; HookScanner adds those names
/// with confidence "medium" or "unknown".
class ObjCParser {
  ObjCParser(this.macho);

  final MachOFile macho;

  List<ObjCClassInfo> parseClasses() {
    final out = <ObjCClassInfo>[];
    final seen = <int>{};
    for (final section in macho.sectionsNamed('__objc_classlist')) {
      final raw = macho.sectionBytes(section);
      for (var i = 0; i + 8 <= raw.length; i += 8) {
        final ptr = ByteData.view(raw.buffer, raw.offsetInBytes + i, 8)
            .getUint64(0, Endian.little);
        if (ptr == 0 || seen.contains(ptr)) continue;
        seen.add(ptr);
        final c = _parseClass(ptr);
        if (c != null && c.name.isNotEmpty) out.add(c);
      }
    }
    for (final section in [
      ...macho.sectionsNamed('__objc_catlist'),
      ...macho.sectionsNamed('__objc_catlist2'),
    ]) {
      final raw = macho.sectionBytes(section);
      for (var i = 0; i + 8 <= raw.length; i += 8) {
        final ptr = ByteData.view(raw.buffer, raw.offsetInBytes + i, 8)
            .getUint64(0, Endian.little);
        if (ptr == 0) continue;
        final c = _parseCategory(ptr);
        if (c != null && c.name.isNotEmpty) out.add(c);
      }
    }
    out.sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));
    return out;
  }

  ObjCClassInfo? _parseClass(int addr) {
    final raw = _readVm(addr, 40);
    if (raw == null) return null;
    final bd = ByteData.view(raw.buffer, raw.offsetInBytes, raw.lengthInBytes);
    final superclass = bd.getUint64(8, Endian.little);
    final data = bd.getUint64(32, Endian.little);
    final name = _className(addr);
    if (name.isEmpty) return null;
    final methods = _parseMethods(_roField(data, 32));
    return ObjCClassInfo(
      name: name,
      superclass: _className(superclass),
      address: addr,
      methods: methods,
    );
  }

  ObjCClassInfo? _parseCategory(int addr) {
    final raw = _readVm(addr, 7 * 8);
    if (raw == null) return null;
    final bd = ByteData.view(raw.buffer, raw.offsetInBytes, raw.lengthInBytes);
    final catName = _stringAt(bd.getUint64(0, Endian.little));
    final cls = bd.getUint64(8, Endian.little);
    final instanceMethods = bd.getUint64(16, Endian.little);
    final classMethods = bd.getUint64(24, Endian.little);
    final methods = <ObjCMethodInfo>[
      ..._parseMethods(instanceMethods),
      ..._parseMethods(classMethods),
    ];
    final name = _className(cls);
    if (name.isEmpty) return null;
    return ObjCClassInfo(
      name: '$name($catName)',
      superclass: '',
      address: addr,
      methods: methods,
    );
  }

  String _className(int classAddr) {
    if (classAddr == 0) return '';
    final data = macho.readU64Vm(classAddr + 32);
    if (data == null || data == 0) return '';
    final namePtr = _roField(data, 24);
    return _stringAt(namePtr);
  }

  int _roField(int ro, int offset) {
    final raw = _readVm(ro + offset, 8);
    if (raw == null) return 0;
    return ByteData.view(raw.buffer, raw.offsetInBytes, 8)
        .getUint64(0, Endian.little);
  }

  List<ObjCMethodInfo> _parseMethods(int listAddr) {
    if (listAddr == 0) return const [];
    final header = _readVm(listAddr, 8);
    if (header == null) return const [];
    final hb = ByteData.view(header.buffer, header.offsetInBytes, 8);
    final rawEntsize = hb.getUint32(0, Endian.little);
    final count = hb.getUint32(4, Endian.little);
    if (count == 0 || count > 10000) return const [];

    final isRelative = (rawEntsize & 0x80000000) != 0;
    final entsize = rawEntsize & 0x7FFFFFFF;
    final out = <ObjCMethodInfo>[];
    for (var i = 0; i < count; i++) {
      if (isRelative) {
        final entrySize = entsize == 0 ? 12 : entsize;
        final entryAddr = listAddr + 8 + i * entrySize;
        final entry = _readVm(entryAddr, 12);
        if (entry == null) break;
        final eb = ByteData.view(entry.buffer, entry.offsetInBytes, 12);
        final nameOff = eb.getInt32(0, Endian.little);
        final typesOff = eb.getInt32(4, Endian.little);
        final impOff = eb.getInt32(8, Endian.little);
        out.add(ObjCMethodInfo(
          selector: _stringAt(entryAddr + nameOff),
          types: _stringAt(entryAddr + 4 + typesOff),
          imp: entryAddr + 8 + impOff,
        ));
      } else {
        final entrySize = entsize < 24 ? 24 : entsize;
        final entry = _readVm(listAddr + 8 + i * entrySize, 24);
        if (entry == null) break;
        final eb = ByteData.view(entry.buffer, entry.offsetInBytes, 24);
        out.add(ObjCMethodInfo(
          selector: _stringAt(eb.getUint64(0, Endian.little)),
          types: _stringAt(eb.getUint64(8, Endian.little)),
          imp: eb.getUint64(16, Endian.little),
        ));
      }
    }
    return out;
  }

  Uint8List? _readVm(int addr, int length) => macho.readVm(addr, length);

  String _stringAt(int addr) {
    if (addr == 0) return '';
    final s = macho.cStringVm(addr, max: 512);
    if (s == null) return '';
    return s.replaceAll(RegExp(r'[\u0000-\u001f]'), '');
  }
}
