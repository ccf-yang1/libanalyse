/// A small, dependency-free ARM64 decoder.
///
/// It is intentionally not a full disassembler. It covers the instructions the
/// analyzer needs for function boundaries, ADRP/ADD string references, and a
/// readable function view. Unknown instructions are rendered as `.word`.
class Arm64Decoder {
  static const List<String> _xregs = [
    'x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7',
    'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14', 'x15',
    'x16', 'x17', 'x18', 'x19', 'x20', 'x21', 'x22', 'x23',
    'x24', 'x25', 'x26', 'x27', 'x28', 'x29', 'x30', 'sp',
  ];

  static const List<String> _wregs = [
    'w0', 'w1', 'w2', 'w3', 'w4', 'w5', 'w6', 'w7',
    'w8', 'w9', 'w10', 'w11', 'w12', 'w13', 'w14', 'w15',
    'w16', 'w17', 'w18', 'w19', 'w20', 'w21', 'w22', 'w23',
    'w24', 'w25', 'w26', 'w27', 'w28', 'w29', 'w30', 'wzr',
  ];

  static const List<String> _conds = [
    'eq', 'ne', 'hs', 'lo', 'mi', 'pl', 'vs', 'vc',
    'hi', 'ls', 'ge', 'lt', 'gt', 'le', 'al', 'nv',
  ];

  static int signExtend(int value, int bits) {
    final sign = 1 << (bits - 1);
    return (value & sign) != 0 ? value - (1 << bits) : value;
  }

  static int regNameIndex(int r) => r & 0x1F;

  static String xreg(int r) => _xregs[regNameIndex(r)];
  static String wreg(int r) => _wregs[regNameIndex(r)];

  static bool isBl(int insn) => (insn & 0xFC000000) == 0x94000000;
  static bool isB(int insn) => (insn & 0xFC000000) == 0x14000000;

  static int branchTarget(int pc, int insn) {
    final imm = signExtend(insn & 0x03FFFFFF, 26) * 4;
    return pc + imm;
  }

  static bool isAdrp(int insn) => (insn & 0x9F000000) == 0x90000000;
  static bool isAdr(int insn) => (insn & 0x9F000000) == 0x10000000;

  static int adrpTarget(int pc, int insn) {
    final immlo = (insn >> 29) & 0x3;
    final immhi = (insn >> 5) & 0x7FFFF;
    final imm = signExtend((immhi << 2) | immlo, 21) << 12;
    return (pc & ~0xFFF) + imm;
  }

  static int adrTarget(int pc, int insn) {
    final immlo = (insn >> 29) & 0x3;
    final immhi = (insn >> 5) & 0x7FFFF;
    return pc + signExtend((immhi << 2) | immlo, 21);
  }

  static bool isAddImm(int insn) {
    final masked = insn & 0x7F800000;
    return masked == 0x11000000 || masked == 0x51000000;
  }

  static bool isAdd(int insn) => (insn & 0x7F800000) == 0x11000000;

  static int imm12(int insn) => (insn >> 10) & 0xFFF;

  static int addImmValue(int insn) {
    var value = imm12(insn);
    if (((insn >> 22) & 1) != 0) value <<= 12;
    return value;
  }

  static bool isLdrLiteral(int insn) {
    final op = insn & 0xFF000000;
    return op == 0x58000000 || op == 0x18000000;
  }

  static int ldrLiteralTarget(int pc, int insn) {
    return pc + signExtend((insn >> 5) & 0x7FFFF, 19) * 4;
  }

  static bool isLoadStoreUnsigned(int insn) {
    final op = insn & 0xFFC00000;
    return const {
      0xF9400000, 0xF9000000,
      0xB9400000, 0xB9000000,
      0x39400000, 0x39000000,
      0x79400000, 0x79000000,
    }.contains(op);
  }

  static String disassemble(int pc, int insn) {
    if (insn == 0xD503201F) return 'nop';
    if ((insn & 0xFFFFFC1F) == 0xD65F0000) return 'ret ${xreg(insn >> 5)}';
    if (isBl(insn)) return 'bl ${hex(branchTarget(pc, insn))}';
    if (isB(insn)) return 'b ${hex(branchTarget(pc, insn))}';
    if ((insn & 0xFFFFFC1F) == 0xD63F0000) return 'blr ${xreg(insn >> 5)}';
    if ((insn & 0xFFFFFC1F) == 0xD61F0000) return 'br ${xreg(insn >> 5)}';

    if (isAdrp(insn)) {
      final rd = regNameIndex(insn);
      return 'adrp ${xreg(rd)}, ${hex(adrpTarget(pc, insn))}';
    }
    if (isAdr(insn)) {
      final rd = regNameIndex(insn);
      return 'adr ${xreg(rd)}, ${hex(adrTarget(pc, insn))}';
    }

    if ((insn & 0xFF000010) == 0x54000000) {
      final cond = _conds[insn & 0xF];
      return 'b.$cond ${hex(pc + signExtend((insn >> 5) & 0x7FFFF, 19) * 4)}';
    }

    final cbzOp = insn & 0x7F000000;
    if (cbzOp == 0x34000000 || cbzOp == 0x35000000 ||
        cbzOp == 0xB4000000 || cbzOp == 0xB5000000) {
      final is64 = (insn & 0x80000000) != 0;
      final isNz = (insn & 0x01000000) != 0;
      final rt = regNameIndex(insn);
      final target = pc + signExtend((insn >> 5) & 0x7FFFF, 19) * 4;
      return '${isNz ? 'cbnz' : 'cbz'} ${is64 ? xreg(rt) : wreg(rt)}, ${hex(target)}';
    }

    if (isAddImm(insn)) {
      final is64 = (insn & 0x80000000) != 0;
      final isSub = (insn & 0x40000000) != 0;
      final rd = regNameIndex(insn);
      final rn = regNameIndex(insn >> 5);
      final imm = addImmValue(insn);
      final r = is64 ? xreg : wreg;
      return '${isSub ? 'sub' : 'add'} ${r(rd)}, ${r(rn)}, #${hex(imm)}';
    }

    if (isLdrLiteral(insn)) {
      final is64 = (insn & 0x40000000) != 0;
      final rt = regNameIndex(insn);
      return 'ldr ${is64 ? xreg(rt) : wreg(rt)}, ${hex(ldrLiteralTarget(pc, insn))}';
    }

    if (isLoadStoreUnsigned(insn)) {
      final op = insn & 0xFFC00000;
      final size = _memSize(op);
      final isLoad = _isLoad(op);
      final rt = regNameIndex(insn);
      final rn = regNameIndex(insn >> 5);
      final imm = imm12(insn) * size;
      final r = size == 8 ? xreg : wreg;
      final suffix = size == 1 ? 'b' : (size == 2 ? 'h' : '');
      return '${isLoad ? 'ldr' : 'str'}$suffix ${r(rt)}, [${xreg(rn)}, #${hex(imm)}]';
    }

    final pair = insn & 0xFFC00000;
    if (pair == 0xA9400000 || pair == 0xA9000000 ||
        pair == 0xA8C00000 || pair == 0xA8800000 ||
        pair == 0xA9800000 || pair == 0xA9000000) {
      return _decodePair(pc, insn, pair);
    }

    if ((insn & 0x7FE0FFE0) == 0x2A0003E0) {
      final is64 = (insn & 0x80000000) != 0;
      final rd = regNameIndex(insn);
      final rm = regNameIndex(insn >> 16);
      return 'mov ${is64 ? xreg(rd) : wreg(rd)}, ${is64 ? xreg(rm) : wreg(rm)}';
    }

    // MOVN/MOVZ/MOVK share the same mask; bits 30:29 select the opcode.
    final mov = insn & 0x7F800000;
    if (mov == 0x52800000 || mov == 0x12800000 || mov == 0x72800000) {
      final is64 = (insn & 0x80000000) != 0;
      final opc = (insn >> 29) & 0x3;
      final rd = regNameIndex(insn);
      final imm = (insn >> 5) & 0xFFFF;
      final shift = ((insn >> 21) & 0x3) * 16;
      final r = is64 ? xreg : wreg;
      final op = opc == 3 ? 'movk' : (opc == 0 ? 'movn' : 'movz');
      final shown = op == 'movn' ? '~${hex(imm)}' : hex(imm);
      return '$op ${r(rd)}, #$shown${shift == 0 ? '' : ', lsl #$shift'}';
    }

    if ((insn & 0x7F200000) == 0x4A000000) {
      final is64 = (insn & 0x80000000) != 0;
      final rd = regNameIndex(insn);
      final rn = regNameIndex(insn >> 5);
      final rm = regNameIndex(insn >> 16);
      final r = is64 ? xreg : wreg;
      return 'eor ${r(rd)}, ${r(rn)}, ${r(rm)}';
    }

    return '.word ${hex(insn)}';
  }

  static String _decodePair(int pc, int insn, int pair) {
    final isLoad = (insn & 0x00400000) != 0;
    final rt = regNameIndex(insn);
    final rn = regNameIndex(insn >> 5);
    final rt2 = regNameIndex(insn >> 10);
    var imm = signExtend((insn >> 15) & 0x7F, 7) * 8;
    final mode = (insn >> 23) & 0x3;
    var suffix = '';
    if (mode == 1) suffix = '!';
    if (mode == 2) suffix = ', #${hex(imm)}';
    return '${isLoad ? 'ldp' : 'stp'} ${xreg(rt)}, ${xreg(rt2)}, '
        '[${xreg(rn)}, #${hex(imm)}]$suffix';
  }

  static bool _isLoad(int op) =>
      op == 0xF9400000 || op == 0xB9400000 ||
      op == 0x39400000 || op == 0x79400000;

  static int _memSize(int op) {
    if (op == 0xF9400000 || op == 0xF9000000) return 8;
    if (op == 0xB9400000 || op == 0xB9000000) return 4;
    if (op == 0x79400000 || op == 0x79000000) return 2;
    return 1;
  }

  static String hex(int value) => '0x${value.toRadixString(16)}';
}
