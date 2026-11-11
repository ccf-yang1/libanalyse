import 'dart:io';
import 'dart:typed_data';

import 'package:file_picker/file_picker.dart';
import 'package:flutter/foundation.dart';

import '../models/analysis.dart';
import '../services/analyzer.dart';
import '../services/hook_grouper.dart';
import '../services/prompt_builder.dart';
import '../services/risk_engine.dart';
import '../services/summary_builder.dart';

class AnalysisController extends ChangeNotifier {
  final Analyzer _analyzer = Analyzer();

  AnalysisResult? result;
  SummaryBuilder? summary;
  PromptBuilder? promptBuilder;
  String? error;
  bool loading = false;
  String? currentPath;

  String? _compact;
  String? _json;
  final Map<String, String> _standardCache = {};
  final Map<String, List<String>> _completeCache = {};

  List<HookGroup> get groups => summary?.groups ?? const [];
  String get compact => _compact ?? '';
  String get json => _json ?? '';
  String get overallRisk =>
      result == null ? '待验证' : RiskEngine().overall(result!.risks);

  Future<void> pickFile() async {
    error = null;
    try {
      final picked = await FilePicker.platform.pickFiles(
        type: FileType.any,
        allowMultiple: false,
        withData: false,
      );
      if (picked == null || picked.files.isEmpty) return;
      final f = picked.files.single;
      if (f.path != null) {
        await analyzeFile(File(f.path!));
      } else if (f.bytes != null) {
        await analyzeBytes(f.bytes!, name: f.name, path: f.name);
      } else {
        error = '无法读取文件路径';
        notifyListeners();
      }
    } catch (e) {
      error = '选择文件失败：$e';
      notifyListeners();
    }
  }

  Future<void> analyzeFile(File file) async {
    loading = true;
    error = null;
    notifyListeners();
    // Let the progress bar paint before the synchronous parse starts.
    await Future<void>.delayed(Duration.zero);
    try {
      final r = _analyzer.analyzeFile(file);
      _setResult(r, file.path);
    } catch (e) {
      error = '解析失败：$e';
    } finally {
      loading = false;
      notifyListeners();
    }
  }

  Future<void> analyzeBytes(
    Uint8List bytes, {
    required String name,
    required String path,
  }) async {
    loading = true;
    error = null;
    notifyListeners();
    await Future<void>.delayed(Duration.zero);
    try {
      final r = _analyzer.analyzeBytes(bytes, name: name, path: path);
      _setResult(r, path);
    } catch (e) {
      error = '解析失败：$e';
    } finally {
      loading = false;
      notifyListeners();
    }
  }

  void _setResult(AnalysisResult r, String path) {
    result = r;
    currentPath = path;
    final b = SummaryBuilder(r);
    summary = b;
    promptBuilder = PromptBuilder(r);
    _compact = b.buildCompact();
    _json = b.buildJson();
    _standardCache.clear();
    _completeCache.clear();
  }

  HookGroup? _groupFor(String groupId) {
    if (groupId == '__all__' && result != null) {
      return HookGroup(id: '__all__', name: '全部功能', hooks: result!.hooks);
    }
    for (final g in groups) {
      if (g.id == groupId) return g;
    }
    return null;
  }

  String standardFor(String groupId) {
    if (_standardCache.containsKey(groupId)) return _standardCache[groupId]!;
    final g = _groupFor(groupId);
    if (g == null) return '';
    final text = summary!.buildStandard(g);
    _standardCache[groupId] = text;
    return text;
  }

  List<String> completeFor(String groupId) {
    if (_completeCache.containsKey(groupId)) return _completeCache[groupId]!;
    final g = _groupFor(groupId);
    if (g == null) return const [];
    final chunks = summary!.buildComplete(g).map((e) => e.text).toList();
    _completeCache[groupId] = chunks;
    return chunks;
  }

  String functionPrompt(HookInfo hook) =>
      promptBuilder?.functionPrompt(hook) ?? '';

  String reimplementationPrompt(String groupId) {
    final text = standardFor(groupId);
    return promptBuilder?.reimplementationPrompt(text) ?? '';
  }

  String featureSummaryPrompt() =>
      promptBuilder?.featureSummaryPrompt(compact) ?? '';

  void clear() {
    result = null;
    summary = null;
    promptBuilder = null;
    error = null;
    currentPath = null;
    _compact = null;
    _json = null;
    _standardCache.clear();
    _completeCache.clear();
    notifyListeners();
  }
}
