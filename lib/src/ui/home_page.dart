import 'package:flutter/material.dart';

import '../models/analysis.dart';
import '../parsers/macho_parser.dart';
import '../services/export_service.dart';
import '../services/hook_grouper.dart';
import '../services/xor_recovery.dart';
import '../state/analysis_controller.dart';
import 'function_detail_page.dart';

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  final AnalysisController _controller = AnalysisController();
  int _index = 0;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _controller,
      builder: (context, _) {
        final result = _controller.result;
        return Scaffold(
          appBar: AppBar(
            title: const Text('DylibAnalyzer'),
            actions: [
              IconButton(
                tooltip: '导入 dylib',
                onPressed: _controller.loading ? null : () => _controller.pickFile(),
                icon: const Icon(Icons.file_open_outlined),
              ),
              if (result != null)
                IconButton(
                  tooltip: '关闭当前文件',
                  onPressed: _controller.clear,
                  icon: const Icon(Icons.close),
                ),
              IconButton(
                tooltip: '设置',
                onPressed: () => _showSettings(context),
                icon: const Icon(Icons.settings_outlined),
              ),
            ],
          ),
          body: Column(
            children: [
              if (_controller.loading) const LinearProgressIndicator(),
              if (_controller.error != null)
                Container(
                  width: double.infinity,
                  color: Colors.red.shade50,
                  padding: const EdgeInsets.all(12),
                  child: Text(
                    _controller.error!,
                    style: TextStyle(color: Colors.red.shade900),
                  ),
                ),
              Expanded(
                child: result == null
                    ? _WelcomeView(controller: _controller)
                    : IndexedStack(
                        index: _index,
                        children: [
                          _OverviewPage(
                            controller: _controller,
                            onOpenHooks: () => setState(() => _index = 3),
                            onOpenSummary: () => setState(() => _index = 4),
                          ),
                          _ClassesPage(controller: _controller),
                          _StringsPage(controller: _controller),
                          _HooksPage(controller: _controller),
                          _SummaryPage(controller: _controller),
                        ],
                      ),
              ),
            ],
          ),
          bottomNavigationBar: result == null
              ? null
              : NavigationBar(
                  selectedIndex: _index,
                  onDestinationSelected: (i) => setState(() => _index = i),
                  destinations: const [
                    NavigationDestination(
                      icon: Icon(Icons.dashboard_outlined),
                      selectedIcon: Icon(Icons.dashboard),
                      label: '概览',
                    ),
                    NavigationDestination(
                      icon: Icon(Icons.account_tree_outlined),
                      selectedIcon: Icon(Icons.account_tree),
                      label: '类/方法',
                    ),
                    NavigationDestination(
                      icon: Icon(Icons.text_fields_outlined),
                      selectedIcon: Icon(Icons.text_fields),
                      label: '字符串',
                    ),
                    NavigationDestination(
                      icon: Icon(Icons.link_outlined),
                      selectedIcon: Icon(Icons.link),
                      label: 'Hook',
                    ),
                    NavigationDestination(
                      icon: Icon(Icons.summarize),
                      selectedIcon: Icon(Icons.summarize),
                      label: '汇总',
                    ),
                  ],
                ),
        );
      },
    );
  }

  void _showSettings(BuildContext context) {
    showModalBottomSheet<void>(
      context: context,
      showDragHandle: true,
      builder: (_) => SafeArea(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const ListTile(
              leading: Icon(Icons.lock_outline),
              title: Text('隐私'),
              subtitle: Text('App 不联网、不上传文件。AI 功能只做复制/粘贴，由你决定发给谁。'),
            ),
            const ListTile(
              leading: Icon(Icons.warning_amber_outlined),
              title: Text('静态分析的边界'),
              subtitle: Text('只分析文件内容，不执行 dylib；看不到运行时拼接的 URL、远程配置、逻辑炸弹。'),
            ),
            ListTile(
              leading: const Icon(Icons.copy_all_outlined),
              title: const Text('复制“功能汇总”AI 提示词'),
              onTap: () async {
                await ExportService.copy(_controller.featureSummaryPrompt());
                if (context.mounted) Navigator.pop(context);
                if (context.mounted) _snack(context, '已复制');
              },
            ),
            if (_controller.result != null)
              ListTile(
                leading: const Icon(Icons.delete_outline),
                title: const Text('关闭当前文件'),
                onTap: () {
                  Navigator.pop(context);
                  _controller.clear();
                },
              ),
            ListTile(
              leading: const Icon(Icons.info_outline),
              title: const Text('关于'),
              subtitle: const Text('DylibAnalyzer 0.1.0 · Flutter static analyzer'),
              onTap: () => Navigator.pop(context),
            ),
            const SizedBox(height: 8),
          ],
        ),
      ),
    );
  }

  static void _snack(BuildContext context, String text) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(text)));
  }
}

class _WelcomeView extends StatelessWidget {
  const _WelcomeView({required this.controller});
  final AnalysisController controller;

  @override
  Widget build(BuildContext context) {
    return Center(
      child: SingleChildScrollView(
        padding: const EdgeInsets.all(28),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(Icons.manage_search, size: 72, color: Theme.of(context).colorScheme.primary),
            const SizedBox(height: 16),
            Text('导入一个 dylib', style: Theme.of(context).textTheme.headlineSmall),
            const SizedBox(height: 12),
            const Text(
              '静态分析文件信息、类/方法、字符串、Hook、设置和风险。\n'
              '不执行、不注入、不联网。',
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 24),
            FilledButton.icon(
              onPressed: () => controller.pickFile(),
              icon: const Icon(Icons.file_open),
              label: const Text('选择 .dylib'),
            ),
            const SizedBox(height: 16),
            Text(
              '建议先用小文件（< 50 MB）验证；大文件只做概览。',
              style: Theme.of(context).textTheme.bodySmall,
            ),
          ],
        ),
      ),
    );
  }
}

class _OverviewPage extends StatelessWidget {
  const _OverviewPage({
    required this.controller,
    required this.onOpenHooks,
    required this.onOpenSummary,
  });

  final AnalysisController controller;
  final VoidCallback onOpenHooks;
  final VoidCallback onOpenSummary;

  @override
  Widget build(BuildContext context) {
    final r = controller.result!;
    final riskColor = switch (controller.overallRisk) {
      '高' => Colors.red,
      '中' => Colors.orange,
      '低' => Colors.green,
      _ => Colors.blueGrey,
    };
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Expanded(
                      child: Text(r.file.name,
                          style: Theme.of(context).textTheme.titleLarge),
                    ),
                    Chip(
                      label: Text('综合 ${controller.overallRisk}'),
                      backgroundColor: riskColor.withOpacity(0.12),
                      side: BorderSide(color: riskColor.withOpacity(0.4)),
                    ),
                  ],
                ),
                const SizedBox(height: 8),
                _kv('大小', '${r.file.size} 字节'),
                _kv('SHA-256', r.file.sha256),
                _kv('UUID', r.file.uuid.isEmpty ? '—' : r.file.uuid),
                _kv('Install Name', r.file.installName.isEmpty ? '—' : r.file.installName),
                _kv('加密', r.file.encrypted ? '是' : '否'),
                _kv('函数数', '${r.file.functionCount}'),
                _kv('Hook 数', '${r.hooks.length}'),
              ],
            ),
          ),
        ),
        const SizedBox(height: 12),
        Row(
          children: [
            Expanded(
              child: FilledButton.tonalIcon(
                onPressed: onOpenHooks,
                icon: const Icon(Icons.link),
                label: Text('查看 ${r.hooks.length} 个 Hook'),
              ),
            ),
            const SizedBox(width: 8),
            Expanded(
              child: FilledButton.tonalIcon(
                onPressed: onOpenSummary,
                icon: const Icon(Icons.summarize),
                label: const Text('生成功能汇总'),
              ),
            ),
          ],
        ),
        const SizedBox(height: 20),
        Text('功能分组', style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 8),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: controller.groups
              .map((g) => Chip(label: Text('${g.name} · ${g.hooks.length}')))
              .toList(),
        ),
        const SizedBox(height: 20),
        Text('风险卡片', style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: 8),
        ...r.risks.map((risk) => Card(
              child: ListTile(
                leading: _riskIcon(risk.level),
                title: Text(risk.title),
                subtitle: Text(risk.why),
                trailing: Text(risk.level),
              ),
            )),
        if (r.warnings.isNotEmpty) ...[
          const SizedBox(height: 16),
          Text('警告', style: Theme.of(context).textTheme.titleMedium),
          ...r.warnings.map((w) => ListTile(
                leading: const Icon(Icons.warning_amber),
                title: Text(w),
              )),
        ],
        const SizedBox(height: 24),
      ],
    );
  }

  static Widget _riskIcon(String level) {
    final color = switch (level) {
      '高' => Colors.red,
      '中' => Colors.orange,
      '低' => Colors.green,
      _ => Colors.blueGrey,
    };
    return Icon(Icons.shield_outlined, color: color);
  }

  static Widget _kv(String k, String v) => Padding(
        padding: const EdgeInsets.symmetric(vertical: 3),
        child: Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            SizedBox(width: 92, child: Text(k, style: const TextStyle(color: Colors.grey))),
            Expanded(child: SelectableText(v)),
          ],
        ),
      );
}

class _ClassesPage extends StatefulWidget {
  const _ClassesPage({required this.controller});
  final AnalysisController controller;

  @override
  State<_ClassesPage> createState() => _ClassesPageState();
}

class _ClassesPageState extends State<_ClassesPage> {
  String _query = '';

  @override
  Widget build(BuildContext context) {
    final r = widget.controller.result!;
    final map = <String, ObjCClassInfo>{};
    for (final c in r.classes) {
      map[c.name] = c;
    }
    for (final h in r.hooks) {
      map.putIfAbsent(
        h.className,
        () => ObjCClassInfo(
          name: h.className,
          superclass: '',
          address: 0,
          methods: const [],
        ),
      );
    }
    final all = map.values.toList()
      ..sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));
    final q = _query.trim().toLowerCase();
    final list = q.isEmpty
        ? all
        : all
            .where((c) =>
                c.name.toLowerCase().contains(q) ||
                c.methods.any((m) => m.selector.toLowerCase().contains(q)))
            .toList();

    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 12, 12, 4),
          child: TextField(
            decoration: const InputDecoration(
              prefixIcon: Icon(Icons.search),
              hintText: '搜索类名或方法名',
              border: OutlineInputBorder(),
              isDense: true,
            ),
            onChanged: (v) => setState(() => _query = v),
          ),
        ),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12),
          child: Align(
            alignment: Alignment.centerLeft,
            child: Text(
              '${list.length} 个类（含被 Hook 的外部类）',
              style: Theme.of(context).textTheme.bodySmall,
            ),
          ),
        ),
        Expanded(
          child: ListView.builder(
            itemCount: list.length,
            itemBuilder: (context, i) {
              final c = list[i];
              final hooked = r.hooks.where((h) => h.className == c.name).length;
              return ListTile(
                leading: Icon(c.methods.isEmpty ? Icons.link : Icons.class_outlined),
                title: Text(c.name),
                subtitle: Text(
                  c.methods.isEmpty
                      ? '目标 App 类 · 元数据不在 dylib'
                      : '${c.methods.length} 个方法${hooked > 0 ? ' · 被 Hook $hooked' : ''}',
                ),
                onTap: () => _showClass(context, c),
              );
            },
          ),
        ),
      ],
    );
  }

  void _showClass(BuildContext context, ObjCClassInfo c) {
    showModalBottomSheet<void>(
      context: context,
      isScrollControlled: true,
      showDragHandle: true,
      builder: (_) => DraggableScrollableSheet(
        expand: false,
        initialChildSize: 0.65,
        builder: (context, scrollController) => ListView(
          controller: scrollController,
          children: [
            ListTile(
              title: Text(c.name),
              subtitle: Text(c.superclass.isEmpty ? '外部/分类类' : 'super: ${c.superclass}'),
            ),
            const Divider(height: 1),
            if (c.methods.isEmpty)
              const Padding(
                padding: EdgeInsets.all(20),
                child: Text('这个类属于目标 App，dylib 里没有它的完整方法元数据；\n可在 Hook 页查看被替换的方法。'),
              )
            else
              ...c.methods.map((m) => ListTile(
                    title: Text(m.selector),
                    subtitle: Text(
                      '${m.types.isEmpty ? '类型编码未知' : m.types}\nIMP: 0x${m.imp.toRadixString(16)}',
                    ),
                  )),
          ],
        ),
      ),
    );
  }
}

class _StringsPage extends StatefulWidget {
  const _StringsPage({required this.controller});
  final AnalysisController controller;

  @override
  State<_StringsPage> createState() => _StringsPageState();
}

class _StringsPageState extends State<_StringsPage> {
  String? _kind;
  String _query = '';
  bool _recovering = false;

  @override
  Widget build(BuildContext context) {
    final r = widget.controller.result!;
    final q = _query.trim().toLowerCase();
    final list = r.strings.where((s) {
      if (_kind != null && s.kind != _kind) return false;
      if (q.isNotEmpty && !s.value.toLowerCase().contains(q)) return false;
      return true;
    }).toList();

    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 12, 12, 4),
          child: TextField(
            decoration: const InputDecoration(
              prefixIcon: Icon(Icons.search),
              hintText: '搜索字符串',
              border: OutlineInputBorder(),
              isDense: true,
            ),
            onChanged: (v) => setState(() => _query = v),
          ),
        ),
        SingleChildScrollView(
          scrollDirection: Axis.horizontal,
          padding: const EdgeInsets.symmetric(horizontal: 12),
          child: Row(
            children: [
              _kindChip('全部', null),
              _kindChip('URL', 'url'),
              _kindChip('路径', 'path'),
              _kindChip('界面', 'ui'),
              _kindChip('设置', 'setting'),
              const SizedBox(width: 8),
              OutlinedButton.icon(
                onPressed: _recovering ? null : _recoverXor,
                icon: _recovering
                    ? const SizedBox(
                        width: 14,
                        height: 14,
                        child: CircularProgressIndicator(strokeWidth: 2),
                      )
                    : const Icon(Icons.lock_open_outlined, size: 18),
                label: const Text('恢复 XOR'),
              ),
            ],
          ),
        ),
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 6, 12, 0),
          child: Align(
            alignment: Alignment.centerLeft,
            child: Text('${list.length} 条',
                style: Theme.of(context).textTheme.bodySmall),
          ),
        ),
        Expanded(
          child: ListView.builder(
            itemCount: list.length,
            itemBuilder: (context, i) {
              final s = list[i];
              return ListTile(
                dense: true,
                leading: Text(s.addressHex,
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 11)),
                title: Text(s.value, maxLines: 2, overflow: TextOverflow.ellipsis),
                subtitle: Text(s.kind),
                onTap: () async {
                  await ExportService.copy(s.value);
                  if (context.mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('已复制')),
                    );
                  }
                },
              );
            },
          ),
        ),
      ],
    );
  }

  Widget _kindChip(String label, String? kind) {
    return Padding(
      padding: const EdgeInsets.only(right: 6),
      child: FilterChip(
        label: Text(label),
        selected: _kind == kind,
        onSelected: (_) => setState(() => _kind = kind),
      ),
    );
  }

  Future<void> _recoverXor() async {
    setState(() => _recovering = true);
    try {
      final r = widget.controller.result!;
      final recovered = await Future(() {
        final macho = MachOFile.parse(r.bytes);
        return XorRecovery(macho).recover();
      });
      if (!mounted) return;
      await showDialog<void>(
        context: context,
        builder: (context) => AlertDialog(
          title: Text('恢复 XOR 字符串（${recovered.strings.length} 条）'),
          content: SizedBox(
            width: double.maxFinite,
            child: recovered.strings.isEmpty
                ? const Text('没有恢复出可打印字符串。\n\n'
                    '已尝试标量 ldrb/ldrh + eor + strb/strh 和向量 '
                    'ldr q/d + eor.16b/8b 模式；运行时自定义解密、异或立即数链'
                    '或跨函数状态可能漏检。')
                : ListView(
                    shrinkWrap: true,
                    children: recovered.strings
                        .take(50)
                        .map((s) => ListTile(
                              dense: true,
                              title: Text(s.value),
                              subtitle: Text('${s.addressHex} · ${s.length} 字节'),
                            ))
                        .toList(),
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
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('恢复失败：$e')),
        );
      }
    } finally {
      if (mounted) setState(() => _recovering = false);
    }
  }
}

class _HooksPage extends StatefulWidget {
  const _HooksPage({required this.controller});
  final AnalysisController controller;

  @override
  State<_HooksPage> createState() => _HooksPageState();
}

class _HooksPageState extends State<_HooksPage> {
  String _query = '';

  @override
  Widget build(BuildContext context) {
    final q = _query.trim().toLowerCase();
    final groups = widget.controller.groups;
    final filtered = <HookGroup>[];
    for (final g in groups) {
      final hs = g.hooks.where((h) {
        if (q.isEmpty) return true;
        return h.className.toLowerCase().contains(q) ||
            h.selector.toLowerCase().contains(q);
      }).toList();
      if (hs.isNotEmpty) {
        filtered.add(HookGroup(id: g.id, name: g.name, hooks: hs));
      }
    }

    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 12, 12, 4),
          child: TextField(
            decoration: const InputDecoration(
              prefixIcon: Icon(Icons.search),
              hintText: '搜索类名或 selector',
              border: OutlineInputBorder(),
              isDense: true,
            ),
            onChanged: (v) => setState(() => _query = v),
          ),
        ),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12),
          child: Align(
            alignment: Alignment.centerLeft,
            child: Text(
              '${widget.controller.result!.hooks.length} 个 Hook · ${groups.length} 组',
              style: Theme.of(context).textTheme.bodySmall,
            ),
          ),
        ),
        Expanded(
          child: ListView.builder(
            itemCount: filtered.length,
            itemBuilder: (context, i) {
              final g = filtered[i];
              return ExpansionTile(
                title: Text('${g.name} (${g.hooks.length})'),
                children: g.hooks.map((h) => ListTile(
                      title: Text(h.className),
                      subtitle: Text(h.selector),
                      trailing: Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        crossAxisAlignment: CrossAxisAlignment.end,
                        children: [
                          Text(h.impHex,
                              style: const TextStyle(fontFamily: 'monospace', fontSize: 11)),
                          Text(h.confidence,
                              style: Theme.of(context).textTheme.labelSmall),
                        ],
                      ),
                      onTap: () => Navigator.of(context).push(
                        MaterialPageRoute<void>(
                          builder: (_) => FunctionDetailPage(
                            controller: widget.controller,
                            hook: h,
                          ),
                        ),
                      ),
                    )).toList(),
              );
            },
          ),
        ),
      ],
    );
  }
}

class _SummaryPage extends StatefulWidget {
  const _SummaryPage({required this.controller});
  final AnalysisController controller;

  @override
  State<_SummaryPage> createState() => _SummaryPageState();
}

class _SummaryPageState extends State<_SummaryPage> {
  int _level = 0;
  String? _groupId;
  int _chunk = 0;

  @override
  Widget build(BuildContext context) {
    final c = widget.controller;
    final groups = c.groups;
    final options = [
      ...groups,
      if (_level > 0 && groups.isNotEmpty && c.result != null)
        HookGroup(id: '__all__', name: '全部功能', hooks: c.result!.hooks),
    ];
    final gid = options.any((g) => g.id == _groupId)
        ? _groupId!
        : (options.isNotEmpty ? options.first.id : '');
    final text = _textFor(c, gid);
    final chunks = _level == 2 && gid.isNotEmpty ? c.completeFor(gid) : const <String>[];
    final token = (text.length / 4).ceil();

    return Column(
      children: [
        SingleChildScrollView(
          scrollDirection: Axis.horizontal,
          padding: const EdgeInsets.fromLTRB(12, 12, 12, 4),
          child: Row(
            children: [
              SegmentedButton<int>(
                segments: const [
                  ButtonSegment(value: 0, label: Text('摘要')),
                  ButtonSegment(value: 1, label: Text('标准')),
                  ButtonSegment(value: 2, label: Text('完整')),
                ],
                selected: {_level},
                onSelectionChanged: (v) => setState(() {
                  _level = v.first;
                  _chunk = 0;
                }),
              ),
            ],
          ),
        ),
        if (options.isNotEmpty)
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12),
            child: DropdownButtonFormField<String>(
              value: gid,
              decoration: const InputDecoration(
                labelText: '功能组',
                border: OutlineInputBorder(),
                isDense: true,
              ),
              items: options
                  .map((g) => DropdownMenuItem(
                        value: g.id,
                        child: Text('${g.name} (${g.hooks.length})'),
                      ))
                  .toList(),
              onChanged: (v) => setState(() {
                _groupId = v;
                _chunk = 0;
              }),
            ),
          ),
        if (_level == 2 && chunks.length > 1)
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
            child: DropdownButtonFormField<int>(
              value: _chunk,
              decoration: const InputDecoration(
                labelText: '分块',
                border: OutlineInputBorder(),
                isDense: true,
              ),
              items: [
                for (var i = 0; i < chunks.length; i++)
                  DropdownMenuItem(value: i, child: Text('第 ${i + 1}/${chunks.length} 块')),
              ],
              onChanged: (v) => setState(() => _chunk = v ?? 0),
            ),
          ),
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
          child: Row(
            children: [
              Text('约 $token tokens',
                  style: Theme.of(context).textTheme.bodySmall),
              const Spacer(),
              Text('${text.length} chars',
                  style: Theme.of(context).textTheme.bodySmall),
            ],
          ),
        ),
        Expanded(
          child: Container(
            margin: const EdgeInsets.symmetric(horizontal: 12),
            decoration: BoxDecoration(
              border: Border.all(color: Theme.of(context).dividerColor),
              borderRadius: BorderRadius.circular(8),
            ),
            child: SingleChildScrollView(
              padding: const EdgeInsets.all(12),
              child: SelectableText(
                text,
                style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
              ),
            ),
          ),
        ),
        Padding(
          padding: const EdgeInsets.all(12),
          child: Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              FilledButton.icon(
                onPressed: text.isEmpty ? null : () => _copy(context, text),
                icon: const Icon(Icons.copy),
                label: const Text('复制'),
              ),
              OutlinedButton.icon(
                onPressed: text.isEmpty ? null : () => _share(context, text),
                icon: const Icon(Icons.ios_share),
                label: const Text('导出/分享'),
              ),
              OutlinedButton.icon(
                onPressed: c.json.isEmpty ? null : () => _shareJson(context, c.json),
                icon: const Icon(Icons.code),
                label: const Text('导出 JSON'),
              ),
              OutlinedButton.icon(
                onPressed: gid.isEmpty
                    ? null
                    : () => _copyPrompt(context, c.reimplementationPrompt(gid)),
                icon: const Icon(Icons.auto_awesome),
                label: const Text('AI 重建提示词'),
              ),
            ],
          ),
        ),
      ],
    );
  }

  String _textFor(AnalysisController c, String gid) {
    if (_level == 0) return c.compact;
    if (gid.isEmpty) return '';
    if (_level == 1) return c.standardFor(gid);
    final chunks = c.completeFor(gid);
    if (chunks.isEmpty) return '';
    final i = _chunk.clamp(0, chunks.length - 1).toInt();
    return chunks[i];
  }

  Future<void> _copy(BuildContext context, String text) async {
    await ExportService.copy(text);
    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('已复制')));
    }
  }

  Future<void> _copyPrompt(BuildContext context, String text) async {
    await ExportService.copy(text);
    if (context.mounted) {
      ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content: Text('提示词已复制')));
    }
  }

  Rect? _shareAnchor(BuildContext context) {
    final box = context.findRenderObject();
    if (box is RenderBox && box.hasSize) {
      return box.localToGlobal(Offset.zero) & box.size;
    }
    return null;
  }

  Future<void> _share(BuildContext context, String text) async {
    try {
      await ExportService.shareText(
        'dylib_summary.md',
        text,
        sharePositionOrigin: _shareAnchor(context),
      );
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('导出失败：$e')));
      }
    }
  }

  Future<void> _shareJson(BuildContext context, String text) async {
    try {
      await ExportService.shareJson(
        'dylib_summary.json',
        text,
        sharePositionOrigin: _shareAnchor(context),
      );
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('导出失败：$e')));
      }
    }
  }
}
