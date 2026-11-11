import 'dart:convert';

import '../models/analysis.dart';
import '../parsers/macho_parser.dart';
import 'disassembler.dart';
import 'hook_grouper.dart';

class SummaryBuilder {
  SummaryBuilder(this.result)
      : macho = MachOFile.parse(result.bytes);

  final AnalysisResult result;
  final MachOFile macho;
  late final Disassembler disassembler = Disassembler(macho);

  late final List<HookGroup> groups = HookGrouper().group(result.hooks);

  int estimateTokens(String text) => (text.length / 4).ceil();

  String buildCompact() {
    final b = StringBuffer();
    final f = result.file;
    b.writeln('# 功能汇总（摘要）');
    b.writeln();
    b.writeln('> 由 DylibAnalyzer 静态分析生成。目标文件未执行。');
    b.writeln();
    b.writeln('## 1. 文件信息');
    b.writeln();
    b.writeln('| 项目 | 值 |');
    b.writeln('|---|---|');
    b.writeln('| 文件 | `${f.name}` |');
    b.writeln('| 大小 | ${f.size} 字节 |');
    b.writeln('| SHA-256 | `${f.sha256}` |');
    b.writeln('| UUID | `${f.uuid}` |');
    b.writeln('| Install Name | `${f.installName}` |');
    b.writeln('| 加密 | ${f.encrypted ? '是' : '否'} |');
    b.writeln('| 依赖库 | ${f.dylibs.isEmpty ? '无' : f.dylibs.map((e) => '`$e`').join(', ')} |');
    b.writeln('| 函数数 | ${f.functionCount} |');
    b.writeln('| Hook 数 | ${result.hooks.length} |');
    b.writeln();
    b.writeln('## 2. 一段话结论');
    b.writeln();
    b.writeln('这是一个包含 ${result.hooks.length} 个 ObjC 方法替换点的 dylib，功能集中在：');
    b.writeln(groups.map((g) => '${g.name}（${g.hooks.length}）').join('、'));
    b.writeln();
    b.writeln('注意：静态分析只能说明它“能做什么”，不能证明它“运行时一定做了什么”。');
    b.writeln();
    b.writeln('## 3. 模块与初始化器');
    b.writeln();
    final moduleCounts = <String, int>{};
    for (final h in result.hooks) {
      moduleCounts[h.module] = (moduleCounts[h.module] ?? 0) + 1;
    }
    moduleCounts.forEach((module, count) {
      b.writeln('- `$module`：$count 个 hook');
    });
    b.writeln();
    b.writeln('## 4. 功能分组');
    b.writeln();
    b.writeln('> 类型编码为空表示被 hook 的类属于目标 App，不在当前 dylib 的元数据里。');
    b.writeln();
    for (var i = 0; i < groups.length; i++) {
      final g = groups[i];
      b.writeln('### 4.${i + 1} ${g.name}（${g.hooks.length}）');
      b.writeln();
      b.writeln('| 类 | 方法 | IMP | 大小 | 置信度 |');
      b.writeln('|---|---|---|---|---|');
      for (final h in g.hooks) {
        b.writeln('| `${_escape(h.className)}` | `${_escape(h.selector)}` | `${h.impHex}` | `${h.sizeHex}` | ${h.confidence} |');
      }
      b.writeln();
    }

    b.writeln('## 5. 设置项与通知');
    b.writeln();
    b.writeln('- 偏好域：`${result.preferenceDomain}`');
    b.writeln('- 刷新通知：`${result.preferenceNotification}`');
    if (result.wallpaperNotification.isNotEmpty) {
      b.writeln('- 壁纸通知：`${result.wallpaperNotification}`');
    }
    b.writeln();
    b.writeln('### Enable*');
    b.writeln();
    b.writeln('| 全局地址 | Key | 默认 | 含义 |');
    b.writeln('|---|---|---|---|');
    for (final s in result.enableSettings) {
      b.writeln('| `${s.addressHex}` | `${s.key}` | ${s.defaultValue ? 1 : 0} | ${s.description} |');
    }
    b.writeln();
    b.writeln('### Disable*（默认 0）');
    b.writeln();
    b.writeln('| 全局地址 | Key | 含义 |');
    b.writeln('|---|---|---|');
    for (final s in result.disableSettings) {
      b.writeln('| `${s.addressHex}` | `${s.key}` | ${s.description} |');
    }
    b.writeln();

    b.writeln('## 6. 关键字符串（节选）');
    b.writeln();
    final urls = _stringsOfKind('url');
    final paths = _stringsOfKind('path');
    final ui = _stringsOfKind('ui');
    if (urls.isNotEmpty) {
      b.writeln('### URL / 域名');
      for (final s in urls.take(30)) {
        b.writeln('- `${s.value}`');
      }
      b.writeln();
    }
    if (paths.isNotEmpty) {
      b.writeln('### 文件路径');
      for (final s in paths.take(30)) {
        b.writeln('- `${s.value}`');
      }
      b.writeln();
    }
    if (ui.isNotEmpty) {
      b.writeln('### 界面 / 设置文案');
      for (final s in ui.take(100)) {
        b.writeln('- ${s.value}');
      }
      b.writeln();
    }

    b.writeln('## 7. 风险提示（静态）');
    b.writeln();
    b.writeln('**综合（静态）：${_overallRisk()}。** 这不是安全判决，只是线索汇总。');
    b.writeln();
    for (final r in result.risks) {
      b.writeln('- **[${r.level}]** ${r.title}');
      b.writeln('  - ${r.why}');
      for (final e in r.evidence) {
        b.writeln('  - 证据：$e');
      }
    }
    b.writeln();
    b.writeln('## 8. 静态分析的边界');
    b.writeln();
    b.writeln('- 只能看到“代码里写了什么”，看不到运行时拼接的 URL、远程配置、逻辑炸弹。');
    b.writeln('- 加密的 dylib 无法分析；本文件${result.file.encrypted ? '已加密' : '未加密'}。');
    b.writeln('- 目标 App 类的方法类型编码通常不在 dylib 里，无法给出准确签名。');
    b.writeln('- 结论不是“安全认证”，只是风险线索。');
    b.writeln();
    b.writeln('<!-- 估算 token：约 ${estimateTokens(b.toString())} -->');
    return b.toString();
  }

  String buildStandard(HookGroup group) {
    final b = StringBuffer();
    b.writeln('# 功能汇总（标准）：${group.name}');
    b.writeln();
    b.writeln('> 文件：`${result.file.name}`；该功能组共 ${group.hooks.length} 个 hook。');
    b.writeln('> 类型编码为空：被 hook 的类属于目标 App，不在当前 dylib 的元数据里。');
    b.writeln();
    b.writeln('## Hook 清单');
    b.writeln();
    b.writeln('| 类 | 方法 | IMP | 大小 | 置信度 |');
    b.writeln('|---|---|---|---|---|');
    for (final h in group.hooks) {
      b.writeln('| `${_escape(h.className)}` | `${_escape(h.selector)}` | `${h.impHex}` | `${h.sizeHex}` | ${h.confidence} |');
    }
    b.writeln();
    b.writeln('## 关键函数汇编（节选）');
    b.writeln();
    for (final h in _pickKeyFunctions(group.hooks)) {
      final lines = disassembler.function(h.imp, h.size, maxLines: 250);
      b.writeln('### `${h.className}` - `${h.selector}` @ `${h.impHex}`（${lines.length} 行）');
      b.writeln();
      b.writeln('```asm');
      for (final line in lines) {
        b.writeln(_asmLine(line));
      }
      b.writeln('```');
      b.writeln();
    }
    b.writeln('<!-- 估算 token：约 ${estimateTokens(b.toString())} -->');
    return b.toString();
  }

  List<({int index, String text})> buildComplete(
    HookGroup group, {
    int maxTokens = 28000,
  }) {
    final header = StringBuffer();
    header.writeln('# 功能汇总（完整）：${group.name}');
    header.writeln();
    header.writeln('> 文件：`${result.file.name}`；该功能组共 ${group.hooks.length} 个 hook。');
    header.writeln('> 完整级别包含该组全部 Hook 和全部可定位函数汇编；单个函数最多 400 行。');
    header.writeln();
    header.writeln('## 文件与设置');
    header.writeln();
    header.writeln('| 项目 | 值 |');
    header.writeln('|---|---|');
    header.writeln('| 文件 | `${result.file.name}` |');
    header.writeln('| SHA-256 | `${result.file.sha256}` |');
    header.writeln('| 偏好域 | `${result.preferenceDomain}` |');
    header.writeln('| 刷新通知 | `${result.preferenceNotification}` |');
    header.writeln();
    if (result.enableSettings.isNotEmpty || result.disableSettings.isNotEmpty) {
      header.writeln('| 类型 | Key | 默认 | 含义 |');
      header.writeln('|---|---|---|---|');
      for (final s in result.enableSettings) {
        header.writeln('| Enable | `${s.key}` | ${s.defaultValue ? 1 : 0} | ${s.description} |');
      }
      for (final s in result.disableSettings) {
        header.writeln('| Disable | `${s.key}` | 0 | ${s.description} |');
      }
      header.writeln();
    }
    header.writeln('## Hook 清单');
    header.writeln();
    header.writeln('| 类 | 方法 | IMP | 大小 | 模块 |');
    header.writeln('|---|---|---|---|---|');
    for (final h in group.hooks) {
      header.writeln('| `${_escape(h.className)}` | `${_escape(h.selector)}` | `${h.impHex}` | `${h.sizeHex}` | `${h.module}` |');
    }
    header.writeln();
    header.writeln('## 函数汇编');
    header.writeln();

    final sections = <String>[];
    final seen = <int>{};
    for (final h in group.hooks) {
      if (!seen.add(h.imp)) continue;
      final lines = disassembler.function(h.imp, h.size, maxLines: 400);
      final sb = StringBuffer();
      sb.writeln('### `${h.className}` - `${h.selector}` @ `${h.impHex}`（${lines.length} 行）');
      sb.writeln();
      sb.writeln('```asm');
      for (final line in lines) {
        sb.writeln(_asmLine(line));
      }
      sb.writeln('```');
      sb.writeln();
      sections.add(sb.toString());
    }

    final baseTokens = estimateTokens(header.toString());
    final chunks = <List<String>>[];
    var current = <String>[];
    var currentTokens = baseTokens;
    for (final section in sections) {
      final t = estimateTokens(section);
      if (current.isNotEmpty && currentTokens + t > maxTokens) {
        chunks.add(current);
        current = [];
        currentTokens = baseTokens;
      }
      current.add(section);
      currentTokens += t;
    }
    if (current.isNotEmpty) chunks.add(current);

    return [
      for (var i = 0; i < chunks.length; i++)
        (
          index: i + 1,
          text: '<!-- 第 ${i + 1}/${chunks.length} 块 -->\n'
              '${header.toString()}${chunks[i].join()}'
              '\n<!-- 估算 token：约 ${estimateTokens(header.toString() + chunks[i].join())} -->\n',
        ),
    ];
  }

  String buildJson() {
    final data = result.toJson();
    data['groups'] = groups
        .map((g) => {
              'id': g.id,
              'name': g.name,
              'hooks': g.hooks.map((h) => h.toJson()).toList(),
            })
        .toList();
    return JsonEncoder.withIndent('  ').convert(data);
  }

  List<HookInfo> _pickKeyFunctions(List<HookInfo> hooks) {
    int score(HookInfo h) {
      final s = h.selector.toLowerCase();
      if (s == 'downloadurl') return 0;
      if (s.contains('doubleclick')) return 1;
      if (s.contains('didfinishsaving')) return 2;
      if (s.contains('downloadprogress')) return 3;
      if (s == 'preventdownload') return 4;
      if (s == 'showsavebutton') return 5;
      if (s.contains('collectionview') && s.contains('didselect')) return 6;
      if (s.contains('didfinishdownloaded')) return 7;
      if (s.contains('allowdownload')) return 8;
      return 9;
    }

    final candidates = hooks
        .where((h) => h.size != null && h.size! > 0 && h.size! <= 0x2000)
        .toList()
      ..sort((a, b) => score(a).compareTo(score(b)));
    return candidates.take(5).toList();
  }

  List<StringHit> _stringsOfKind(String kind) =>
      result.strings.where((s) => s.kind == kind).toList();

  String _overallRisk() {
    const rank = {'高': 3, '中': 2, '低': 1, '需验证': 0, 'info': 0};
    var max = 0;
    for (final r in result.risks) {
      final v = rank[r.level] ?? 0;
      if (v > max) max = v;
    }
    return switch (max) {
      3 => '高',
      2 => '中',
      1 => '低',
      _ => '待验证',
    };
  }

  String _asmLine(DisassemblyLine line) {
    final c = line.comment.isEmpty ? '' : ' ; ${line.comment}';
    return '${line.pcHex}: ${line.rawHex}  ${line.text}$c';
  }

  String _escape(String s) => s.replaceAll('|', r'\|');
}
