import 'dart:convert';
import 'dart:typed_data';

import '../parsers/arm64_decoder.dart';
import '../parsers/macho_parser.dart';

class RecoveredString {
  const RecoveredString({
    required this.address,
    required this.value,
    required this.length,
  });

  final int address;
  final String value;
  final int length;

  String get addressHex => '0x${address.toRadixString(16)}';
}

class XorRecoveryResult {
  const XorRecoveryResult({
    required this.bytes,
    required this.strings,
    required this.touched,
  });

  final Uint8List bytes;
  final List<RecoveredString> strings;
  final int touched;
}

/// Limited, static XOR recovery for compiler-emitted patterns:
///
///   adrp/add          -> address
///   ldrb/ldrh + eor   -> scalar byte/half key, replayed on strb/strh
///   ldr q/d + eor.16b -> vector key, replayed at the eor
///
/// It never executes the target. Only __data/__const/__bss/__common addresses
/// are patched, so code and ObjC __objc_* metadata stay untouched.
class _VecValue {
  const _VecValue(this.literal, this.address, this.size);

  /// Non-null for literal/key vectors.
  final Uint8List? literal;

  /// Target address for memory-loaded vectors (0 for literals).
  final int address;

  final int size;
}

class XorRecovery {
  XorRecovery(this.macho);

  final MachOFile macho;
  late final List<int> _starts = () {
    final starts = [...macho.functionStarts]..sort();
    if (starts.isEmpty && macho.textEnd > macho.textStart) {
      starts.add(macho.textStart);
    }
    return starts;
  }();

  XorRecoveryResult recover() {
    final data = Uint8List.fromList(macho.data);
    final touched = <int>{};
    final applied = <String>{};

    for (final start in _starts) {
      final end = _functionEnd(start);
      final pages = <int, int>{};
      final addrs = <int, int>{};
      final imms = <int, int>{};
      final keys = <int, int>{};
      final vec = <int, _VecValue>{};

      for (var pc = start; pc + 4 <= end; pc += 4) {
        final insn = macho.readU32Vm(pc);
        if (insn == null) break;
        final rd = Arm64Decoder.regNameIndex(insn);

        if (Arm64Decoder.isAdrp(insn)) {
          pages[rd] = Arm64Decoder.adrpTarget(pc, insn);
          continue;
        }
        if (Arm64Decoder.isAdr(insn)) {
          addrs[rd] = Arm64Decoder.adrTarget(pc, insn);
          continue;
        }
        if (Arm64Decoder.isAdd(insn) && (insn & 0x80000000) != 0) {
          final rn = Arm64Decoder.regNameIndex(insn >> 5);
          final page = pages[rn];
          if (page != null) addrs[rd] = page + Arm64Decoder.addImmValue(insn);
          continue;
        }

        // SIMD&FP load, literal (q/d).
        final litOp = insn & 0xFF000000;
        if (litOp == 0x9C000000 || litOp == 0x5C000000) {
          final size = litOp == 0x9C000000 ? 16 : 8;
          final target = pc +
              Arm64Decoder.signExtend((insn >> 5) & 0x7FFFF, 19) * 4;
          final raw = macho.readVm(target, size);
          if (raw != null) {
            vec[rd] = _VecValue(Uint8List.fromList(raw), 0, size);
          }
          continue;
        }

        // SIMD&FP load, unsigned immediate (q/d). 0x3D400000 is LDR B,
        // not LDR D; including it would read eight bytes at a byte-load
        // offset and poison the vector state.
        final simdOp = insn & 0xFFC00000;
        if (simdOp == 0x3DC00000 || simdOp == 0xFD400000) {
          final size = simdOp == 0x3DC00000 ? 16 : 8;
          final rn = Arm64Decoder.regNameIndex(insn >> 5);
          final base = addrs[rn];
          if (base != null) {
            final addr = base + Arm64Decoder.imm12(insn) * size;
            if (macho.readVm(addr, size) != null) {
              vec[rd] = _VecValue(null, addr, size);
            }
          }
          continue;
        }

        // SIMD&FP LDP q/d, signed offset.
        if (simdOp == 0xAD400000 || simdOp == 0x6D400000) {
          final size = simdOp == 0xAD400000 ? 16 : 8;
          final rn = Arm64Decoder.regNameIndex(insn >> 5);
          final base = addrs[rn];
          if (base != null) {
            final addr = base +
                Arm64Decoder.signExtend((insn >> 15) & 0x7F, 7) * size;
            final rt2 = (insn >> 10) & 0x1F;
            if (macho.readVm(addr, size) != null) {
              vec[rd] = _VecValue(null, addr, size);
            }
            if (macho.readVm(addr + size, size) != null) {
              vec[rt2] = _VecValue(null, addr + size, size);
            }
          }
          continue;
        }

        // eor.16b / eor.8b: one literal key, one memory buffer.
        if ((insn & 0xBFE0FC00) == 0x2E201C00) {
          final size = ((insn >> 30) & 1) != 0 ? 16 : 8;
          final rn = Arm64Decoder.regNameIndex(insn >> 5);
          final rm = Arm64Decoder.regNameIndex(insn >> 16);
          final a = vec[rn];
          final b = vec[rm];
          Uint8List? key;
          int? addr;
          var memSize = size;
          if (a?.literal != null && b != null && b.literal == null) {
            key = a!.literal;
            addr = b.address;
            memSize = b.size;
          } else if (b?.literal != null && a != null && a.literal == null) {
            key = b!.literal;
            addr = a.address;
            memSize = a.size;
          }
          if (key != null && addr != null) {
            var n = size;
            if (key.length < n) n = key.length;
            if (memSize < n) n = memSize;
            // Read the working buffer, not the original image, so chained
            // eor operations see bytes patched by an earlier vector op.
            final current = _readData(data, addr, n);
            if (current != null) {
              _applyXor(data, touched, applied, addr, key, n);
              final out = Uint8List(n);
              for (var i = 0; i < n; i++) {
                out[i] = current[i] ^ key[i];
              }
              vec[rd] = _VecValue(out, 0, n);
            }
          }
          continue;
        }

        if (_isMovz(insn)) {
          imms[rd] = _movzValue(insn);
          continue;
        }
        if (_isLdrByteHalf(insn)) {
          final rn = Arm64Decoder.regNameIndex(insn >> 5);
          final base = addrs[rn];
          if (base != null) {
            final size = _memSize(insn);
            addrs[rd] = base + Arm64Decoder.imm12(insn) * size;
          }
          continue;
        }
        if (_isEorReg(insn)) {
          final rn = Arm64Decoder.regNameIndex(insn >> 5);
          final rm = Arm64Decoder.regNameIndex(insn >> 16);
          final key = imms[rm] ?? imms[rn];
          if (key != null) keys[rd] = key;
          continue;
        }
        if (_isStoreByteHalf(insn)) {
          final rt = Arm64Decoder.regNameIndex(insn);
          final rn = Arm64Decoder.regNameIndex(insn >> 5);
          final base = addrs[rn];
          final key = keys[rt];
          if (base != null && key != null) {
            final size = _memSize(insn);
            final addr = base + Arm64Decoder.imm12(insn) * size;
            final keyBytes = [
              for (var i = 0; i < size; i++) (key >> (8 * i)) & 0xFF,
            ];
            _applyXor(data, touched, applied, addr, keyBytes, size);
          }
        }
      }
    }

    final strings = <RecoveredString>[];
    final seen = <String>{};
    for (final addr in touched.toList()..sort()) {
      final off = macho.vmToFileOffset(addr);
      if (off == null) continue;
      final bytes = <int>[];
      for (var i = 0; i < 256 && off + i < data.length; i++) {
        final b = data[off + i];
        if (b == 0) break;
        if (b < 0x20 || b > 0x7E) {
          bytes.clear();
          break;
        }
        bytes.add(b);
      }
      if (bytes.length < 2) continue;
      final s = latin1.decode(bytes);
      if (!seen.add(s)) continue;
      strings.add(RecoveredString(address: addr, value: s, length: bytes.length));
    }

    return XorRecoveryResult(
      bytes: data,
      strings: strings,
      touched: touched.length,
    );
  }

  Uint8List? _readData(Uint8List data, int addr, int size) {
    final off = macho.vmToFileOffset(addr);
    if (off == null || off < 0 || off + size > data.length) return null;
    return Uint8List.fromList(Uint8List.sublistView(data, off, off + size));
  }

  void _applyXor(
    Uint8List data,
    Set<int> touched,
    Set<String> applied,
    int addr,
    List<int> key,
    int size,
  ) {
    if (!_isDataAddress(addr)) return;
    if (key.length < size) return;
    final sig = '$addr:$size:${key.take(size).join(',')}';
    if (!applied.add(sig)) return;
    final off = macho.vmToFileOffset(addr);
    if (off == null) return;
    for (var i = 0; i < size; i++) {
      final o = off + i;
      if (o >= data.length) break;
      data[o] ^= key[i] & 0xFF;
      touched.add(addr + i);
    }
  }

  bool _isDataAddress(int addr) {
    // Restrict patching to mutable data/const sections. This keeps the
    // ObjC class/method metadata in __objc_* sections intact.
    for (final s in macho.sections) {
      if (addr >= s.addr && addr < s.addr + s.size) {
        return s.name == '__data' ||
            s.name == '__const' ||
            s.name == '__bss' ||
            s.name == '__common';
      }
    }
    return false;
  }

  int _functionEnd(int start) {
    var lo = 0, hi = _starts.length - 1, ans = macho.textEnd;
    while (lo <= hi) {
      final mid = (lo + hi) >> 1;
      if (_starts[mid] > start) {
        ans = _starts[mid];
        hi = mid - 1;
      } else {
        lo = mid + 1;
      }
    }
    return ans;
  }

  bool _isMovz(int insn) {
    final op = insn & 0x7F800000;
    return op == 0x52800000 || op == 0xD2800000;
  }

  int _movzValue(int insn) {
    final imm = (insn >> 5) & 0xFFFF;
    final shift = ((insn >> 21) & 0x3) * 16;
    return (imm << shift) & 0xFFFFFFFF;
  }

  bool _isEorReg(int insn) {
    return (insn & 0x7F200000) == 0x4A000000;
  }

  bool _isLdrByteHalf(int insn) {
    final op = insn & 0xFFC00000;
    return op == 0x39400000 || op == 0x79400000;
  }

  bool _isStoreByteHalf(int insn) {
    final op = insn & 0xFFC00000;
    return op == 0x39000000 || op == 0x79000000;
  }

  int _memSize(int insn) {
    final op = insn & 0xFFC00000;
    return op == 0x79400000 || op == 0x79000000 ? 2 : 1;
  }
}
