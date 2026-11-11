import '../models/analysis.dart';

class HookGroup {
  const HookGroup({
    required this.id,
    required this.name,
    required this.hooks,
  });

  final String id;
  final String name;
  final List<HookInfo> hooks;
}

class HookGrouper {
  static const List<({String id, String name})> definitions = [
    (id: 'statusbar', name: '状态栏'),
    (id: 'watermark', name: '无水印'),
    (id: 'download', name: '下载与保存'),
    (id: 'ads', name: '评论 / 广告 / 红包'),
    (id: 'share', name: '分享 / 长按 / 私信'),
    (id: 'play', name: '播放 / 关注 / 主题 / 纯净'),
    (id: 'ui', name: '首页 / 标签栏 / 界面元素'),
    (id: 'other', name: '设置 / 网络 / 其他'),
  ];

  static String nameOf(String id) =>
      definitions.firstWhere((d) => d.id == id, orElse: () => definitions.last).name;

  List<HookGroup> group(List<HookInfo> hooks) {
    final buckets = <String, List<HookInfo>>{
      for (final d in definitions) d.id: <HookInfo>[],
    };

    for (final h in hooks) {
      final gid = _groupOf(h);
      buckets[gid]!.add(HookInfo(
        site: h.site,
        className: h.className,
        selector: h.selector,
        imp: h.imp,
        size: h.size,
        module: h.module,
        group: gid,
        confidence: h.confidence,
        evidence: h.evidence,
      ));
    }

    return [
      for (final d in definitions)
        if (buckets[d.id]!.isNotEmpty)
          HookGroup(id: d.id, name: d.name, hooks: buckets[d.id]!),
    ];
  }

  String _groupOf(HookInfo h) {
    final c = h.className;
    final s = h.selector;
    final l = '$c $s'.toLowerCase();

    if (const {
      'AWEAdAvatarView',
    }.contains(c)) {
      return 'ui';
    }
    if (const {
      'AWEShareSaveAlbumDataCenter',
    }.contains(c)) {
      return 'share';
    }
    if (c == 'MTLModel') return 'ads';

    if (l.contains('statusbar') || l.contains('prefersstatusbarhidden')) {
      return 'statusbar';
    }
    if (l.contains('watermark') ||
        c == 'IESWaterMarkData' ||
        c == 'AWEMediaDownloadConfigCommon') {
      return 'watermark';
    }
    if (l.contains('download') ||
        l.contains('save') ||
        l.contains('album') ||
        l.contains('cancel') ||
        l.contains('progress') ||
        l.contains('didfinish') ||
        l.contains('doubleclick') ||
        l.contains('imagesave') ||
        l.contains('videosave') ||
        c == 'AWEShareRowView' ||
        c == 'AWEVideoModel' ||
        c == 'AWEImageAlbumImageModel' ||
        c == 'AWEFeedAlbumBrowserViewController' ||
        c == 'AWEUserModel' ||
        c == 'AWEMusicModel' ||
        c == 'ACCMusicModel' ||
        c == 'AWEAwemeModel') {
      return 'download';
    }
    if (l.contains('comment') ||
        l.contains('campaign') ||
        l.contains('redpacket') ||
        l.contains('splash') ||
        l.contains('uman') ||
        l.contains('prompt') ||
        l.contains('mtlmodel') ||
        l.contains('adprompt') ||
        c == 'AWECommentModel' ||
        c == 'AWECommentListViewController') {
      return 'ads';
    }
    if (l.contains('share') ||
        l.contains('longpress') ||
        l.contains('transpond') ||
        l.contains('msginbox') ||
        l.contains('imshare') ||
        l.contains('reasonmodels') ||
        l.contains('firstrowitems') ||
        l.contains('secondrowitems') ||
        l.contains('cellmodels') ||
        c == 'AWESharePanelViewModel' ||
        c == 'AWESharePanelController' ||
        c == 'AWEAwemeLongPressViewModel' ||
        c == 'AWEIMTranspondListViewController') {
      return 'share';
    }
    if (l.contains('autoplay') ||
        l.contains('follow') ||
        l.contains('theme') ||
        l.contains('colorsuit') ||
        l.contains('colormode') ||
        l.contains('sethide') ||
        l.contains('playerwillloop') ||
        l.contains('player') ||
        l.contains('pure') ||
        l.contains('longvideo')) {
      return 'play';
    }
    if (l.contains('tabbar') ||
        l.contains('segmented') ||
        l.contains('feedcontainer') ||
        l.contains('landing') ||
        l.contains('livefeed') ||
        l.contains('discoverfeed') ||
        l.contains('feedguide') ||
        l.contains('refresh') ||
        l.contains('entrance') ||
        l.contains('button') ||
        l.contains('anchor') ||
        l.contains('decoration') ||
        l.contains('avatar')) {
      return 'ui';
    }
    return 'other';
  }
}
