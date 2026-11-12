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
      for (var i = 0; i + 8 <= section.size; i += 8) {
        final ptr = macho.readU64Vm(section.addr + i) ?? 0;
        if (ptr == 0 || seen.contains(ptr)) continue;
        seen.add(ptr);
        final c = _parseClass(ptr);
        if (c != null && c.name.isNotEmpty) out.add(c);
      }
    }
    for (final section in [
      ...macho.sectionsNamed('__objc_nlclslist'),
    ]) {
      for (var i = 0; i + 8 <= section.size; i += 8) {
        final ptr = macho.readU64Vm(section.addr + i) ?? 0;
        if (ptr == 0 || seen.contains(ptr)) continue;
        seen.add(ptr);
        final c = _parseClass(ptr);
        if (c != null && c.name.isNotEmpty) out.add(c);
      }
    }
    for (final section in [
      ...macho.sectionsNamed('__objc_catlist'),
      ...macho.sectionsNamed('__objc_catlist2'),
      ...macho.sectionsNamed('__objc_nlcatlist'),
    ]) {
      for (var i = 0; i + 8 <= section.size; i += 8) {
        final ptr = macho.readU64Vm(section.addr + i) ?? 0;
        if (ptr == 0) continue;
        final c = _parseCategory(ptr);
        if (c != null && c.name.isNotEmpty) out.add(c);
      }
    }
    out.sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));
    return out;
  }

  static int _classData(int bits) => bits & 0x00007FFFFFFFFFF8;

  ObjCClassInfo? _parseClass(int addr) {
    if (macho.readVm(addr, 40) == null) return null;
    final data = _roOfClass(addr);
    final name = _className(addr);
    if (name.isEmpty) return null;
    final isa = macho.readU64Vm(addr) ?? 0;
    final methods = [
      ..._parseMethods(_roField(data, 32)),
      ..._parseMethods(_roField(_roOfClass(isa), 32)),
    ];
    return ObjCClassInfo(
      name: name,
      superclass: _superclassName(addr + 8),
      address: addr,
      methods: methods,
    );
  }

  ObjCClassInfo? _parseCategory(int addr) {
    if (macho.readVm(addr, 7 * 8) == null) return null;
    final catName = _stringAt(macho.readU64Vm(addr) ?? 0);
    final cls = macho.readU64Vm(addr + 8) ?? 0;
    final instanceMethods = macho.readU64Vm(addr + 16) ?? 0;
    final classMethods = macho.readU64Vm(addr + 24) ?? 0;
    final methods = <ObjCMethodInfo>[
      ..._parseMethods(instanceMethods),
      ..._parseMethods(classMethods),
    ];
    var name = _className(cls);
    if (name.isEmpty) name = _stringAt(cls);
    if (name.isEmpty && catName.isEmpty) return null;
    final label = name.isEmpty ? catName : (catName.isEmpty ? name : '$name($catName)');
    return ObjCClassInfo(
      name: label,
      superclass: '',
      address: addr,
      methods: methods,
    );
  }

  int _roOfClass(int classAddr) {
    if (classAddr == 0) return 0;
    final data = _classData(macho.readU64Vm(classAddr + 32) ?? 0);
    if (data == 0) return 0;
    if (_stringAt(_roField(data, 24)).isNotEmpty) return data;
    for (final off in [8, 16, 32]) {
      final ro = _classData(_roField(data, off));
      if (ro != 0 && _stringAt(_roField(ro, 24)).isNotEmpty) return ro;
    }
    return data;
  }

  String _className(int classAddr) {
    if (classAddr == 0) return '';
    return _stringAt(_roField(_roOfClass(classAddr), 24));
  }

  String _superclassName(int slotAddr) {
    final ptr = macho.readU64Vm(slotAddr) ?? 0;
    final name = _className(ptr);
    if (name.isNotEmpty) return name;
    final bind = macho.bindNameAtVm(slotAddr) ?? '';
    const prefix = '_OBJC_CLASS_\$_';
    if (bind.startsWith(prefix)) return bind.substring(prefix.length);
    return '';
  }

  int _roField(int ro, int offset) {
    if (ro == 0) return 0;
    return macho.readU64Vm(ro + offset) ?? 0;
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
    final directSels = (rawEntsize & 0x40000000) != 0;
    final entsize = rawEntsize & 0x0000FFFC;
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
          selector: _stringAtRel(entryAddr, nameOff, direct: directSels),
          types: _stringAtRel(entryAddr + 4, typesOff, direct: true),
          imp: entryAddr + 8 + impOff,
        ));
      } else {
        final entrySize = entsize < 24 ? 24 : entsize;
        final entryAddr = listAddr + 8 + i * entrySize;
        if (_readVm(entryAddr, 24) == null) break;
        out.add(ObjCMethodInfo(
          selector: _stringAt(macho.readU64Vm(entryAddr) ?? 0),
          types: _stringAt(macho.readU64Vm(entryAddr + 8) ?? 0),
          imp: macho.readU64Vm(entryAddr + 16) ?? 0,
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

  String _stringAtRel(int fieldAddr, int rel, {required bool direct}) {
    final target = fieldAddr + rel;
    if (direct) return _stringAt(target);
    final ptr = macho.readU64Vm(target);
    if (ptr != null && ptr != 0) {
      final s = _stringAt(ptr);
      if (s.isNotEmpty) return s;
    }
    return _stringAt(target);
  }
}
