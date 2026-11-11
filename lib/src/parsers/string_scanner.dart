import 'dart:convert';
import 'dart:typed_data';

import '../models/analysis.dart';
import 'macho_parser.dart';

class StringScanner {
  StringScanner(this.macho);

  final MachOFile macho;

  static const String _commonCjk =
      '是否无水晶保存视频下载分享评论关注状态栏自动播放复制关闭开启首页'
      '朋友消息直播搜索按钮进度条红包广告文案双击浅色纯净模式壁纸联动'
      '设置网络其他时间相册图片清除缓存退出重启生效提示确定取消成功失败'
      '错误加载更多全部选择清除恢复默认当前版本更新检查安装说明使用'
      '左右滑动长按点击进入返回相册保存至成功失败正在处理请稍候'
      '音视频图集作品作者昵称头像挂件定位同城朋友推荐热门最新';

  List<StringHit> scan({int limit = 30000}) {
    final hits = <StringHit>[];
    final seen = <String>{};

    void add(int address, String value, String kind) {
      final s = value.trim();
      if (s.length < 2 || s.length > 4000) return;
      if (s.contains('�')) return;
      final key = '$address:$s';
      if (!seen.add(key)) return;
      hits.add(StringHit(address: address, value: s, kind: kind));
    }

    for (final section in macho.sections) {
      if (hits.length >= limit) break;
      final shouldScan = const {
        '__cstring',
        '__objc_methname',
        '__objc_classname',
        '__objc_methtype',
        '__data',
        '__const',
        '__ustring',
      }.contains(section.name);
      if (!shouldScan) continue;
      final raw = macho.sectionBytes(section);
      _scanAscii(raw, section.addr, add);
      _scanUtf16(raw, section.addr, add);
      if (section.name == '__cstring') {
        _scanUtf8Chunks(raw, section.addr, add);
      }
    }
    return hits;
  }

  void _scanAscii(
    Uint8List raw,
    int base,
    void Function(int, String, String) add,
  ) {
    var start = -1;
    for (var i = 0; i <= raw.length; i++) {
      final b = i < raw.length ? raw[i] : 0;
      final ok = b >= 0x20 && b <= 0x7E;
      if (ok && start < 0) start = i;
      if (!ok && start >= 0) {
        final length = i - start;
        if (length >= 4) {
          final s = String.fromCharCodes(raw.sublist(start, i));
          add(base + start, s, _kindOf(s));
        }
        start = -1;
      }
    }
  }

  void _scanUtf16(
    Uint8List raw,
    int base,
    void Function(int, String, String) add,
  ) {
    var sb = StringBuffer();
    var start = -1;
    for (var i = 0; i + 1 < raw.length; i += 2) {
      final code = raw[i] | (raw[i + 1] << 8);
      final isCjk = code >= 0x4E00 && code <= 0x9FFF;
      if (isCjk) {
        if (start < 0) start = i;
        sb.writeCharCode(code);
      } else {
        if (start >= 0) {
          final s = sb.toString();
          if (_isRealCjk(s)) add(base + start, s, 'ui');
          sb = StringBuffer();
          start = -1;
        }
      }
    }
    if (start >= 0) {
      final s = sb.toString();
      if (_isRealCjk(s)) add(base + start, s, 'ui');
    }
  }

  void _scanUtf8Chunks(
    Uint8List raw,
    int base,
    void Function(int, String, String) add,
  ) {
    var start = 0;
    for (var i = 0; i <= raw.length; i++) {
      if (i < raw.length && raw[i] != 0) continue;
      if (i > start) {
        final chunk = Uint8List.sublistView(raw, start, i);
        if (chunk.any((b) => b >= 0x80)) {
          final s = utf8.decode(chunk, allowMalformed: true);
          if (_isRealCjk(s)) add(base + start, s, 'ui');
        }
      }
      start = i + 1;
    }
  }

  bool _isRealCjk(String s) {
    if (s.isEmpty || s.contains('�')) return false;
    var cjk = 0;
    var common = 0;
    for (final r in s.runes) {
      if (r >= 0x4E00 && r <= 0x9FFF) cjk++;
      if (_commonCjk.contains(String.fromCharCode(r))) common++;
    }
    return cjk >= 2 && common >= 2;
  }

  String _kindOf(String s) {
    if (s.startsWith('http://') || s.startsWith('https://')) return 'url';
    if (s.startsWith('/')) return 'path';
    if (s.startsWith('Enable') || s.startsWith('Disable')) return 'setting';
    if (s.contains('@@') || s.contains(':')) return 'selector';
    return 'other';
  }
}
