import 'dart:typed_data';

/// File-level Mach-O information.
class FileInfo {
  const FileInfo({
    required this.name,
    required this.path,
    required this.size,
    required this.sha256,
    required this.uuid,
    required this.installName,
    required this.cpuType,
    required this.cpuSubType,
    required this.encrypted,
    required this.dylibs,
    required this.functionCount,
    required this.symbolCount,
  });

  final String name;
  final String path;
  final int size;
  final String sha256;
  final String uuid;
  final String installName;
  final int cpuType;
  final int cpuSubType;
  final bool encrypted;
  final List<String> dylibs;
  final int functionCount;
  final int symbolCount;

  Map<String, dynamic> toJson() => {
        'name': name,
        'path': path,
        'size': size,
        'sha256': sha256,
        'uuid': uuid,
        'install_name': installName,
        'cputype': cpuType,
        'cpusubtype': cpuSubType,
        'encrypted': encrypted,
        'dylibs': dylibs,
        'function_count': functionCount,
        'symbol_count': symbolCount,
      };
}

class SegmentInfo {
  const SegmentInfo({
    required this.name,
    required this.vmAddr,
    required this.vmSize,
    required this.fileOffset,
    required this.fileSize,
  });

  final String name;
  final int vmAddr;
  final int vmSize;
  final int fileOffset;
  final int fileSize;

  Map<String, dynamic> toJson() => {
        'name': name,
        'vmaddr': vmAddr,
        'vmsize': vmSize,
        'fileoff': fileOffset,
        'filesize': fileSize,
      };
}

class SectionInfo {
  const SectionInfo({
    required this.segmentName,
    required this.name,
    required this.addr,
    required this.size,
    required this.offset,
    required this.flags,
    required this.reserved1,
    this.reserved2 = 0,
  });

  final String segmentName;
  final String name;
  final int addr;
  final int size;
  final int offset;
  final int flags;
  final int reserved1;
  final int reserved2;

  Map<String, dynamic> toJson() => {
        'segname': segmentName,
        'name': name,
        'addr': addr,
        'size': size,
        'offset': offset,
        'flags': flags,
        'reserved2': reserved2,
      };
}

class ObjCMethodInfo {
  const ObjCMethodInfo({
    required this.selector,
    required this.types,
    required this.imp,
  });

  final String selector;
  final String types;
  final int imp;

  Map<String, dynamic> toJson() => {
        'selector': selector,
        'types': types,
        'imp': '0x${imp.toRadixString(16)}',
      };
}

class ObjCClassInfo {
  const ObjCClassInfo({
    required this.name,
    required this.superclass,
    required this.address,
    required this.methods,
  });

  final String name;
  final String superclass;
  final int address;
  final List<ObjCMethodInfo> methods;

  Map<String, dynamic> toJson() => {
        'name': name,
        'superclass': superclass,
        'address': '0x${address.toRadixString(16)}',
        'methods': methods.map((m) => m.toJson()).toList(),
      };
}

class HookInfo {
  const HookInfo({
    required this.site,
    required this.className,
    required this.selector,
    required this.imp,
    required this.size,
    required this.module,
    required this.group,
    required this.confidence,
    required this.evidence,
  });

  final int site;
  final String className;
  final String selector;
  final int imp;
  final int? size;
  final String module;
  final String group;
  final String confidence;
  final List<String> evidence;

  String get impHex => '0x${imp.toRadixString(16)}';
  String get siteHex => '0x${site.toRadixString(16)}';
  String get sizeHex => size == null ? '?' : '0x${size!.toRadixString(16)}';

  Map<String, dynamic> toJson() => {
        'site': siteHex,
        'class': className,
        'selector': selector,
        'imp': impHex,
        'size': sizeHex,
        'module': module,
        'group': group,
        'confidence': confidence,
        'evidence': evidence,
      };
}

class SettingItem {
  const SettingItem({
    required this.address,
    required this.key,
    required this.defaultValue,
    required this.description,
  });

  final int address;
  final String key;
  final bool defaultValue;
  final String description;

  String get addressHex => '0x${address.toRadixString(16)}';

  Map<String, dynamic> toJson() => {
        'global': addressHex,
        'key': key,
        'default': defaultValue,
        'description': description,
      };
}

class RiskItem {
  const RiskItem({
    required this.level,
    required this.title,
    required this.why,
    this.evidence = const [],
    this.ruleId = '',
  });

  final String level;
  final String title;
  final String why;
  final List<String> evidence;
  final String ruleId;

  Map<String, dynamic> toJson() => {
        'level': level,
        'title': title,
        'why': why,
        'evidence': evidence,
        'rule_id': ruleId,
      };
}

class StringHit {
  const StringHit({
    required this.address,
    required this.value,
    required this.kind,
  });

  final int address;
  final String value;
  final String kind;

  String get addressHex => '0x${address.toRadixString(16)}';

  Map<String, dynamic> toJson() => {
        'address': addressHex,
        'value': value,
        'kind': kind,
      };
}

class AnalysisResult {
  const AnalysisResult({
    required this.file,
    required this.segments,
    required this.sections,
    required this.classes,
    required this.hooks,
    required this.enableSettings,
    required this.disableSettings,
    required this.preferenceDomain,
    required this.preferenceNotification,
    required this.wallpaperNotification,
    required this.strings,
    required this.risks,
    required this.imports,
    required this.textStart,
    required this.textEnd,
    required this.bytes,
    this.warnings = const [],
  });

  final FileInfo file;
  final List<SegmentInfo> segments;
  final List<SectionInfo> sections;
  final List<ObjCClassInfo> classes;
  final List<HookInfo> hooks;
  final List<SettingItem> enableSettings;
  final List<SettingItem> disableSettings;
  final String preferenceDomain;
  final String preferenceNotification;
  final String wallpaperNotification;
  final List<StringHit> strings;
  final List<RiskItem> risks;
  final List<String> imports;
  final int textStart;
  final int textEnd;
  final Uint8List bytes;
  final List<String> warnings;

  List<HookInfo> hooksInGroup(String group) =>
      hooks.where((h) => h.group == group).toList();

  Map<String, dynamic> toJson() => {
        'schema': 'dylib-feature-summary/v1',
        'file': file.toJson(),
        'segments': segments.map((s) => s.toJson()).toList(),
        'sections': sections.map((s) => s.toJson()).toList(),
        'classes': classes.map((c) => c.toJson()).toList(),
        'hooks': hooks.map((h) => h.toJson()).toList(),
        'settings': {
          'domain': preferenceDomain,
          'notification': preferenceNotification,
          'wallpaper_notification': wallpaperNotification,
          'enable': enableSettings.map((s) => s.toJson()).toList(),
          'disable': disableSettings.map((s) => s.toJson()).toList(),
        },
        'strings': strings.map((s) => s.toJson()).toList(),
        'risks': risks.map((r) => r.toJson()).toList(),
        'imports': imports,
        'warnings': warnings,
      };
}
