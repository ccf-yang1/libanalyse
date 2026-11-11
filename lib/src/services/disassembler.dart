import 'dart:typed_data';

import '../parsers/arm64_decoder.dart';
import '../parsers/macho_parser.dart';

class DisassemblyLine {
  const DisassemblyLine({
    required this.pc,
    required this.raw,
    required this.text,
    this.comment = '',
  });

  final int pc;
  final int raw;
  final String text;
  final String comment;

  String get pcHex => '0x${pc.toRadixString(16)}';
  String get rawHex => raw.toRadixString(16).padLeft(8, '0');
}

class Disassembler {
  Disassembler(this.macho);

  final MachOFile macho;

  List<DisassemblyLine> function(int start, int? size, {int maxLines = 2000}) {
    final end = size != null && size > 0 ? start + size : _nextFunction(start);
    final out = <DisassemblyLine>[];
    for (var pc = start; pc + 4 <= end && out.length < maxLines; pc += 4) {
      final insn = macho.readU32Vm(pc);
      if (insn == null) break;
      out.add(DisassemblyLine(
        pc: pc,
        raw: insn,
        text: Arm64Decoder.disassemble(pc, insn),
        comment: _comment(pc, insn),
      ));
    }
    return out;
  }

  int _nextFunction(int start) {
    var ans = macho.textEnd;
    for (final s in macho.functionStarts) {
      if (s > start && s < ans) ans = s;
    }
    return ans;
  }

  String _comment(int pc, int insn) {
    if (Arm64Decoder.isBl(insn) || Arm64Decoder.isB(insn)) {
      final target = Arm64Decoder.branchTarget(pc, insn);
      final name = macho.stubs[target];
      if (name != null) return 'symbol stub: $name';
      final sym = macho.symbols.where((s) => s.value == target).toList();
      if (sym.isNotEmpty) return 'symbol: ${sym.first.name}';
    }
    if (Arm64Decoder.isLdrLiteral(insn)) {
      final target = Arm64Decoder.ldrLiteralTarget(pc, insn);
      final ptr = macho.readU64Vm(target);
      if (ptr != null) {
        final s = macho.cStringVm(ptr);
        if (s != null && s.isNotEmpty && _printable(s)) {
          return 'ref: $s';
        }
      }
      final direct = macho.cStringVm(target);
      if (direct != null && direct.isNotEmpty && _printable(direct)) {
        return 'string: $direct';
      }
    }
    return '';
  }

  bool _printable(String s) {
    if (s.length < 2 || s.length > 120) return false;
    for (final r in s.runes) {
      if (r < 0x20 || (r > 0x7E && (r < 0x4E00 || r > 0x9FFF))) return false;
    }
    return true;
  }

  Uint8List bytesAt(int pc, int length) => macho.bytes(
        macho.vmToFileOffset(pc) ?? 0,
        length,
      );
}
