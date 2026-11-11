import '../models/analysis.dart';

class RiskEngine {
  List<RiskItem> evaluate({
    required FileInfo file,
    required List<HookInfo> hooks,
    required List<StringHit> strings,
    required List<String> imports,
    required String preferenceDomain,
  }) {
    final out = <RiskItem>[];
    final text = strings.map((s) => s.value).join('\n');
    final lowerImports = imports.map((e) => e.toLowerCase()).toList();

    if (file.encrypted) {
      out.add(const RiskItem(
        level: '高',
        title: '二进制已加密',
        why: 'cryptid 非 0，静态分析无法看到真实代码。',
        ruleId: 'encrypted',
      ));
    }

    final processApis = _matchAny(lowerImports, const [
      '_fork', '_execve', '_posix_spawn', '_system', '_ptrace',
    ]);
    if (processApis.isNotEmpty) {
      out.add(RiskItem(
        level: '高',
        title: '进程/执行相关 API',
        why: '可能启动外部进程或调试目标。',
        evidence: processApis,
        ruleId: 'process-api',
      ));
    }

    final dynamicApis = _matchAny(lowerImports, const [
      '_dlopen', '_dlsym',
    ]);
    if (dynamicApis.isNotEmpty) {
      out.add(RiskItem(
        level: '中',
        title: '动态加载/查找符号',
        why: '可能在运行时加载额外代码或隐藏调用。',
        evidence: dynamicApis,
        ruleId: 'dynamic-load',
      ));
    }

    final networkApis = _matchAny(lowerImports, const [
      'nsurlsession', 'nsurlconnection', 'cfnetwork',
    ]);
    if (networkApis.isNotEmpty) {
      out.add(RiskItem(
        level: '中',
        title: '网络会话',
        why: '可能发起网络请求；需要确认目标地址和数据。',
        evidence: networkApis,
        ruleId: 'network',
      ));
    }

    final photoApis = _matchAny(lowerImports, const [
      'phphotolibrary', 'uisavevideoatpathtosavedphotosalbum',
      'uiimagewritetosavedphotosalbum', 'phasset',
    ]);
    if (photoApis.isNotEmpty) {
      out.add(RiskItem(
        level: '中',
        title: '相册/照片访问',
        why: '可能读写相册；保存视频/图片属于此类。',
        evidence: photoApis,
        ruleId: 'photo',
      ));
    }

    final fileApis = _matchAny(lowerImports, const [
      'nsfilemanager', 'writetofile', 'nsdatawriting',
    ]);
    if (fileApis.isNotEmpty) {
      out.add(RiskItem(
        level: '低',
        title: '文件系统访问',
        why: '可能读写沙盒或系统文件。',
        evidence: fileApis,
        ruleId: 'filesystem',
      ));
    }

    if (hooks.length > 100) {
      out.add(RiskItem(
        level: hooks.length > 300 ? '高' : '中',
        title: 'Hook 面较大',
        why: '共 ${hooks.length} 个方法替换点，能改动 App 的很多行为。',
        ruleId: 'hook-count',
      ));
    }

    final watermark = hooks.where((h) => h.group == 'watermark').length;
    if (watermark > 0) {
      out.add(RiskItem(
        level: '中',
        title: '修改水印判断',
        why: '$watermark 个方法涉及水印/下载配置，可能用于去水印下载。',
        ruleId: 'watermark',
      ));
    }

    final statusbar = hooks.where((h) => h.group == 'statusbar').length;
    if (statusbar > 50) {
      out.add(RiskItem(
        level: '低',
        title: '接管状态栏',
        why: '$statusbar 个方法用于隐藏/显示状态栏，通常只影响界面。',
        ruleId: 'statusbar',
      ));
    }

    final urls = strings
        .where((s) => s.value.startsWith('http://') || s.value.startsWith('https://'))
        .map((s) => s.value)
        .toSet()
        .take(8)
        .toList();
    if (urls.isNotEmpty) {
      out.add(RiskItem(
        level: '中',
        title: '包含硬编码 URL/域名',
        why: '需要确认这些地址是否可信、是否上传数据。',
        evidence: urls,
        ruleId: 'hardcoded-url',
      ));
    } else {
      out.add(const RiskItem(
        level: '需验证',
        title: '未发现明显的硬编码 URL',
        why: '运行时的下载地址可能来自 App 自身或远程配置，静态看不到。',
        ruleId: 'no-url',
      ));
    }

    if (preferenceDomain.isNotEmpty) {
      out.add(RiskItem(
        level: '低',
        title: '读取自己的偏好设置',
        why: '偏好域 $preferenceDomain，用于保存插件开关，属于正常行为。',
        ruleId: 'preferences',
      ));
    }

    final xorHint = text.contains('eor') && text.contains('ldrb');
    if (xorHint) {
      out.add(const RiskItem(
        level: '中',
        title: '可能存在 XOR 字符串混淆',
        why: '检测到 eor/ldrb 相关文本线索；请用“恢复 XOR 字符串”功能确认。',
        ruleId: 'xor',
      ));
    }

    return out;
  }

  String overall(List<RiskItem> risks) {
    const rank = {'高': 3, '中': 2, '低': 1, '需验证': 0, 'info': 0};
    var max = 0;
    for (final r in risks) {
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

  List<String> _matchAny(List<String> haystack, List<String> needles) {
    final out = <String>[];
    for (final n in needles) {
      for (final h in haystack) {
        if (h.contains(n)) {
          if (!out.contains(n)) out.add(n);
          break;
        }
      }
    }
    return out;
  }
}
