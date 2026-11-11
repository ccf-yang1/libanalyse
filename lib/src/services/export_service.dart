import 'dart:io';
import 'dart:ui';

import 'package:cross_file/cross_file.dart';
import 'package:flutter/services.dart';
import 'package:path/path.dart' as p;
import 'package:path_provider/path_provider.dart';
import 'package:share_plus/share_plus.dart';

class ExportService {
  static Future<void> copy(String text) async {
    await Clipboard.setData(ClipboardData(text: text));
  }

  static Future<String?> readClipboard() async {
    final data = await Clipboard.getData(Clipboard.kTextPlain);
    return data?.text;
  }

  static Future<File> writeToDocuments(String name, String text) async {
    final dir = await getApplicationDocumentsDirectory();
    final file = File(p.join(dir.path, name));
    await file.writeAsString(text);
    return file;
  }

  static Future<void> shareText(
    String name,
    String text, {
    Rect? sharePositionOrigin,
  }) async {
    final file = await writeToDocuments(name, text);
    await Share.shareXFiles(
      [XFile(file.path)],
      subject: name,
      // iPad requires an anchor rect; without it share_plus throws.
      sharePositionOrigin: sharePositionOrigin ??
          const Rect.fromLTWH(0, 0, 1, 1),
    );
  }

  static Future<void> shareJson(
    String name,
    String json, {
    Rect? sharePositionOrigin,
  }) =>
      shareText(name, json, sharePositionOrigin: sharePositionOrigin);
}
