import 'package:flutter/material.dart';

import '../models/analysis.dart';
import '../services/disassembler.dart';
import '../services/export_service.dart';
import '../services/prompt_builder.dart';
import '../state/analysis_controller.dart';

class FunctionDetailPage extends StatefulWidget {
  const FunctionDetailPage({
    super.key,
    required this.controller,
    required this.hook,
  });

  final AnalysisController controller;
  final HookInfo hook;

  @override
  State<FunctionDetailPage> createState() => _FunctionDetailPageState();
}

class _FunctionDetailPageState extends State<FunctionDetailPage> {
  late final List<DisassemblyLine> _lines =
      widget.controller.summary!.disassembler.function(
    widget.hook.imp,
    widget.hook.size,
    maxLines: 2000,
  );

  @override
  Widget build(BuildContext context) {
    final h = widget.hook;
    final r = widget.controller.result!;
    final asm = _lines.map((l) => l.text).join('\n');
    final globals = [...r.enableSettings, ...r.disableSettings].where((s) {
      final off = s.address & 0xFFF;
      return asm.contains('#0x${off.toRadixString(16)}');
    }).toList();
    final callees = _lines
        .where((l) => l.comment.startsWith('symbol stub: '))
        .map((l) => l.comment.substring('symbol stub: '.length))
        .toSet()
        .toList();

    return Scaffold(
      appBar: AppBar(title: Text(h.selector)),
      body: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(h.className, style: Theme.of(context).textTheme.titleLarge),
                  const SizedBox(height: 6),
                  _kv('selector', h.selector),
                  _kv('IMP', h.impHex),
                  _kv('大小', h.sizeHex),
                  _kv('模块', h.module),
                  _kv('功能组', h.group),
                  _kv('置信度', h.confidence),
                  for (final e in h.evidence) _kv('证据', e),
                ],
              ),
            ),
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              FilledButton.icon(
                onPressed: () => _copy(context, widget.controller.functionPrompt(h)),
                icon: const Icon(Icons.copy),
                label: const Text('复制函数上下文'),
              ),
              OutlinedButton.icon(
                onPressed: () => _importAi(context),
                icon: const Icon(Icons.content_paste),
                label: const Text('导入 AI 结果'),
              ),
              OutlinedButton.icon(
                onPressed: () => _copy(
                  context,
                  _lines.map((l) => '${l.pcHex}: ${l.rawHex}  ${l.text}').join('\n'),
                ),
                icon: const Icon(Icons.code),
                label: const Text('复制汇编'),
              ),
            ],
          ),
          if (globals.isNotEmpty) ...[
            const SizedBox(height: 20),
            Text('可能读取的设置', style: Theme.of(context).textTheme.titleMedium),
            ...globals.map((s) => ListTile(
                  dense: true,
                  leading: const Icon(Icons.toggle_on),
                  title: Text(s.key),
                  subtitle: Text('${s.addressHex} · ${s.description}'),
                )),
          ],
          if (callees.isNotEmpty) ...[
            const SizedBox(height: 16),
            Text('调用的符号（静态识别）', style: Theme.of(context).textTheme.titleMedium),
            ...callees.map((s) => ListTile(
                  dense: true,
                  leading: const Icon(Icons.call_made),
                  title: Text(s),
                )),
          ],
          const SizedBox(height: 16),
          ExpansionTile(
            initiallyExpanded: true,
            title: Text('ARM64 汇编（${_lines.length} 行）'),
            children: [
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(12),
                color: Theme.of(context).colorScheme.surfaceVariant,
                child: SelectableText(
                  _lines.map(_format).join('\n'),
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
                ),
              ),
            ],
          ),
          if (_lines.length >= 2000)
            const Padding(
              padding: EdgeInsets.all(12),
              child: Text('已截断到 2000 行；可按需缩小范围。'),
            ),
        ],
      ),
    );
  }

  String _format(DisassemblyLine line) {
    final comment = line.comment.isEmpty ? '' : ' ; ${line.comment}';
    return '${line.pcHex}: ${line.rawHex}  ${line.text}$comment';
  }

  Widget _kv(String k, String v) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 2),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            SizedBox(width: 76, child: Text(k, style: const TextStyle(color: Colors.grey))),
            Expanded(child: SelectableText(v)),
          ],
        ),
      );

  Future<void> _copy(BuildContext context, String text) async {
    await ExportService.copy(text);
    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('已复制')));
    }
  }

  Future<void> _importAi(BuildContext context) async {
    final raw = await ExportService.readClipboard();
    if (raw == null || raw.trim().isEmpty) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('剪贴板为空')));
      }
      return;
    }
    final obj = PromptBuilder.parseJsonObject(raw);
    if (obj == null) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(content: Text('没有找到有效 JSON；请让 AI 只返回一个 JSON 对象')),
        );
      }
      return;
    }
    final pretty = PromptBuilder.extractPrettyJson(raw) ?? raw;
    if (!context.mounted) return;
    await showDialog<void>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('AI 函数分析结果'),
        content: SizedBox(
          width: double.maxFinite,
          child: SingleChildScrollView(
            child: SelectableText(
              pretty,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
            ),
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('关闭'),
          ),
        ],
      ),
    );
  }
}
