import 'dart:io';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import '../models/analysis.dart';
import '../parsers/hook_scanner.dart';
import '../parsers/macho_parser.dart';
import '../parsers/objc_parser.dart';
import '../parsers/string_scanner.dart';
import 'hook_grouper.dart';
import 'risk_engine.dart';
import 'setting_scanner.dart';
import 'xor_recovery.dart';

class Analyzer {
  AnalysisResult analyzeFile(File file) {
    final bytes = file.readAsBytesSync();
    return analyzeBytes(bytes, name: file.uri.pathSegments.last, path: file.path);
  }

  AnalysisResult analyzeBytes(
    Uint8List bytes, {
    required String name,
    required String path,
  }) {
    final digest = sha256.convert(bytes).toString();
    final originalMacho = MachOFile.parse(bytes);
    // Compiler-emitted XOR routines hide class names/selectors inside __DATA.
    // Recover them on a copy first; code bytes are not changed. Encrypted
    // binaries are skipped because their __DATA is not readable statically.
    // Recovery is best-effort: a malformed pattern must not stop the rest of
    // the analysis, so fall back to the original image on any failure.
    XorRecoveryResult? recovered;
    if (originalMacho.cryptid == 0) {
      try {
        recovered = XorRecovery(originalMacho).recover();
      } catch (_) {
        recovered = null;
      }
    }
    final macho = recovered != null && recovered.touched > 0
        ? MachOFile.parse(recovered.bytes)
        : originalMacho;
    final objc = ObjCParser(macho).parseClasses();
    final strings = StringScanner(macho).scan();
    final settings = SettingScanner().scan(strings);

    final rawHooks = HookScanner(macho).scan();
    final grouped = HookGrouper().group(rawHooks);
    final hooks = grouped.expand((g) => g.hooks).toList()
      ..sort((a, b) => a.imp.compareTo(b.imp));

    final fileInfo = FileInfo(
      name: name,
      path: path,
      size: bytes.length,
      sha256: digest,
      uuid: macho.uuid,
      installName: macho.installName,
      cpuType: macho.cpuType,
      cpuSubType: macho.cpuSubType,
      encrypted: macho.cryptid != 0,
      dylibs: macho.dylibs,
      functionCount: macho.functionStarts.length,
      symbolCount: macho.symbols.length,
    );

    final risks = RiskEngine().evaluate(
      file: fileInfo,
      hooks: hooks,
      strings: strings,
      imports: macho.imports,
      preferenceDomain: settings.domain,
    );

    final warnings = <String>[];
    if (macho.cryptid != 0) {
      warnings.add('二进制已加密（cryptid=${macho.cryptid}），无法看到真实代码。');
    }
    if (recovered != null && recovered.touched > 0) {
      warnings.add(
        '已静态恢复 ${recovered.touched} 字节 XOR 混淆字符串；'
        '类名/字符串按恢复后的副本解析，原文件未被修改。',
      );
    }
    if (hooks.isEmpty) {
      warnings.add('没有识别到 Hook。可能是纯 Swift/C++，或 Hook 方式不是 method_setImplementation。');
    }
    if (macho.functionStarts.isEmpty) {
      warnings.add('没有 LC_FUNCTION_STARTS，函数边界只能按 __text 推断。');
    }

    return AnalysisResult(
      file: fileInfo,
      segments: macho.segments,
      sections: macho.sections,
      classes: objc,
      hooks: hooks,
      enableSettings: settings.enable,
      disableSettings: settings.disable,
      preferenceDomain: settings.domain,
      preferenceNotification: settings.notification,
      wallpaperNotification: settings.wallpaperNotification,
      strings: strings,
      risks: risks,
      imports: macho.imports,
      textStart: macho.textStart,
      textEnd: macho.textEnd,
      bytes: bytes,
      warnings: warnings,
    );
  }
}
