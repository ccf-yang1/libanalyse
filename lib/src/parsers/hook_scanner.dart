import '../models/analysis.dart';
import 'arm64_decoder.dart';
import 'macho_parser.dart';

class _StringCandidate {
  const _StringCandidate(this.pc, this.reg, this.value);
  final int pc;
  final int reg;
  final String value;
}

/// Heuristic hook scanner.
///
/// It finds helper functions that call method_setImplementation /
/// class_copyMethodList, then finds BL call sites to those helpers and looks
/// backward for ADRP/ADD string references. This is deliberately conservative:
/// a hook with no class/selector is still reported, with confidence "unknown".
class HookScanner {
  HookScanner(this.macho);

  final MachOFile macho;

  static const Set<String> _hookSymbols = {
    '_class_copyMethodList',
    '_method_setImplementation',
    '_method_getName',
    '_class_addMethod',
    '_class_getMethodImplementation',
    '_objc_getClass',
  };

  List<HookInfo> scan() {
    final starts = _sortedStarts();
    final helperStarts = _findHelpers(starts);
    final sites = _findHookSites(starts, helperStarts);
    final cache = <int, List<_StringCandidate>>{};
    final out = <HookInfo>[];
    final seen = <String>{};

    for (final site in sites) {
      final functionStart = _functionStartAt(site, starts);
      final candidates = cache.putIfAbsent(
        functionStart,
        () => _collectCandidates(functionStart, _functionEnd(functionStart, starts)),
      );
      final context = _pickContext(site, candidates);
      final className = context.$1 ?? 'UnknownClass';
      final selector = context.$2 ?? 'unknown';
      final imp = functionStart;
      final size = _functionEnd(functionStart, starts) - functionStart;
      final module = _moduleAt(site);
      final key = '$imp|$className|$selector';
      if (!seen.add(key)) continue;
      final confidence = context.$1 != null && context.$2 != null
          ? 'high'
          : (context.$1 != null || context.$2 != null ? 'medium' : 'unknown');
      out.add(HookInfo(
        site: site,
        className: className,
        selector: selector,
        imp: imp,
        size: size > 0 ? size : null,
        module: module,
        group: '',
        confidence: confidence,
        evidence: [
          'BL call site 0x${site.toRadixString(16)}',
          'via detected hook helper',
          if (context.$3 != null) 'class ref 0x${context.$3!.toRadixString(16)}',
          if (context.$4 != null) 'selector ref 0x${context.$4!.toRadixString(16)}',
        ],
      ));
    }
    out.sort((a, b) => a.imp.compareTo(b.imp));
    return out;
  }

  List<int> _sortedStarts() {
    final starts = [...macho.functionStarts];
    if (starts.isEmpty) starts.add(macho.textStart);
    starts.sort();
    return starts;
  }

  Set<int> _findHelpers(List<int> starts) {
    final interesting = <int, String>{};
    macho.stubs.forEach((addr, name) {
      if (_hookSymbols.contains(name)) interesting[addr] = name;
    });
    final helpers = <int>{};
    for (var i = 0; i < starts.length; i++) {
      final start = starts[i];
      final end = _functionEnd(start, starts);
      final calls = <String>{};
      for (var pc = start; pc + 4 <= end; pc += 4) {
        final insn = macho.readU32Vm(pc);
        if (insn == null || !Arm64Decoder.isBl(insn)) continue;
        final target = Arm64Decoder.branchTarget(pc, insn);
        final name = interesting[target];
        if (name != null) calls.add(name);
      }
      if (calls.contains('_method_setImplementation') ||
          calls.contains('_class_addMethod') ||
          (calls.contains('_class_copyMethodList') && calls.length >= 2)) {
        helpers.add(start);
      }
    }

    return helpers;
  }

  List<int> _findHookSites(List<int> starts, Set<int> helpers) {
    final sites = <int>[];
    final siteSet = <int>{};

    // Fallback: if no helper was recognized, treat direct calls to the
    // method-replacement stub as hook sites. Confidence will be lower.
    if (helpers.isEmpty) {
      final directTargets = <int>{};
      macho.stubs.forEach((addr, name) {
        if (name == '_method_setImplementation' ||
            name == '_class_addMethod') {
          directTargets.add(addr);
        }
      });
      if (directTargets.isEmpty) return sites;
      for (var i = 0; i < starts.length; i++) {
        final start = starts[i];
        final end = _functionEnd(start, starts);
        for (var pc = start; pc + 4 <= end; pc += 4) {
          final insn = macho.readU32Vm(pc);
          if (insn == null || !Arm64Decoder.isBl(insn)) continue;
          if (directTargets.contains(Arm64Decoder.branchTarget(pc, insn))) {
            if (siteSet.add(pc)) sites.add(pc);
          }
        }
      }
      return sites;
    }
    for (var i = 0; i < starts.length; i++) {
      final start = starts[i];
      final end = _functionEnd(start, starts);
      for (var pc = start; pc + 4 <= end; pc += 4) {
        final insn = macho.readU32Vm(pc);
        if (insn == null || !Arm64Decoder.isBl(insn)) continue;
        if (helpers.contains(Arm64Decoder.branchTarget(pc, insn))) {
          if (siteSet.add(pc)) sites.add(pc);
        }
      }
    }
    return sites;
  }

  List<_StringCandidate> _collectCandidates(int start, int end) {
    final out = <_StringCandidate>[];
    final pages = <int, int>{};
    for (var pc = start; pc + 4 <= end; pc += 4) {
      final insn = macho.readU32Vm(pc);
      if (insn == null) break;
      final rd = Arm64Decoder.regNameIndex(insn);
      if (Arm64Decoder.isAdrp(insn)) {
        pages[rd] = Arm64Decoder.adrpTarget(pc, insn);
      } else if (Arm64Decoder.isAdr(insn)) {
        _tryAdd(out, pc, rd, Arm64Decoder.adrTarget(pc, insn));
      } else if (Arm64Decoder.isAdd(insn) && (insn & 0x80000000) != 0) {
        final rn = Arm64Decoder.regNameIndex(insn >> 5);
        final page = pages[rn];
        if (page != null) {
          _tryAdd(out, pc, rd, page + Arm64Decoder.addImmValue(insn));
        }
      } else if (Arm64Decoder.isLdrLiteral(insn)) {
        _tryAdd(out, pc, rd, Arm64Decoder.ldrLiteralTarget(pc, insn));
      } else if (Arm64Decoder.isLoadStoreUnsigned(insn)) {
        final rn = Arm64Decoder.regNameIndex(insn >> 5);
        final page = pages[rn];
        if (page != null) {
          final size = _loadSize(insn);
          final addr = page + Arm64Decoder.imm12(insn) * size;
          _tryAdd(out, pc, rd, addr);
        }
      }
    }
    return out;
  }

  void _tryAdd(
    List<_StringCandidate> out,
    int pc,
    int reg,
    int address,
  ) {
    final value = _resolveString(address);
    if (value != null) out.add(_StringCandidate(pc, reg, value));
  }

  String? _resolveString(int address) {
    final direct = _clean(macho.cStringVm(address));
    if (direct != null && _plausible(direct)) return direct;

    final ptr = macho.readU64Vm(address);
    if (ptr == null || ptr == 0) return null;
    final pointed = _clean(macho.cStringVm(ptr));
    if (pointed != null && _plausible(pointed)) return pointed;

    // Class reference -> class_t -> class_ro_t.name
    final data = macho.readU64Vm(ptr + 32);
    if (data != null && data != 0) {
      final namePtr = macho.readU64Vm(data + 24);
      if (namePtr != null && namePtr != 0) {
        final name = _clean(macho.cStringVm(namePtr));
        if (name != null && _plausible(name)) return name;
      }
    }
    return null;
  }

  String? _clean(String? s) {
    if (s == null) return null;
    final t = s.trim();
    if (t.isEmpty || t.length > 256) return null;
    return t;
  }

  bool _plausible(String s) {
    if (s.contains('�')) return false;
    return RegExp(r'^[A-Za-z_$][A-Za-z0-9_$:]*$').hasMatch(s);
  }

  bool _looksLikeClass(String s) {
    return RegExp(r'^[A-Z][A-Za-z0-9_$]{2,}$').hasMatch(s) &&
        !s.contains(':');
  }

  bool _looksLikeSelector(String s) {
    if (s.isEmpty || !s.contains(RegExp(r'[a-zA-Z_]'))) return false;
    return RegExp(r'^[A-Za-z_$][A-Za-z0-9_$]*(:[A-Za-z0-9_$]*)*$')
        .hasMatch(s);
  }

  (String?, String?, int?, int?) _pickContext(
    int site,
    List<_StringCandidate> candidates,
  ) {
    final nearby = candidates.where((c) => c.pc < site && c.pc >= site - 0x600).toList()
      ..sort((a, b) => b.pc.compareTo(a.pc));

    _StringCandidate? classC;
    for (final c in nearby) {
      if (_looksLikeClass(c.value)) {
        classC = c;
        break;
      }
    }
    _StringCandidate? selectorC;
    for (final c in nearby) {
      if (_looksLikeSelector(c.value) &&
          !_looksLikeClass(c.value) &&
          c.value != classC?.value) {
        selectorC = c;
        break;
      }
    }
    return (classC?.value, selectorC?.value, classC?.pc, selectorC?.pc);
  }

  int _functionStartAt(int site, List<int> starts) {
    var lo = 0, hi = starts.length - 1, ans = starts.first;
    while (lo <= hi) {
      final mid = (lo + hi) >> 1;
      if (starts[mid] <= site) {
        ans = starts[mid];
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    return ans;
  }

  int _functionEnd(int start, List<int> starts) {
    var lo = 0, hi = starts.length - 1, ans = macho.textEnd;
    while (lo <= hi) {
      final mid = (lo + hi) >> 1;
      if (starts[mid] > start) {
        ans = starts[mid];
        hi = mid - 1;
      } else {
        lo = mid + 1;
      }
    }
    return ans;
  }

  String _moduleAt(int site) {
    var best = 0;
    for (final init in macho.initFunctions) {
      if (init <= site && init > best) best = init;
    }
    return '0x${best.toRadixString(16)}';
  }

  int _loadSize(int insn) {
    final op = insn & 0xFFC00000;
    if (op == 0xF9400000 || op == 0xF9000000) return 8;
    if (op == 0xB9400000 || op == 0xB9000000) return 4;
    if (op == 0x79400000 || op == 0x79000000) return 2;
    return 1;
  }
}
