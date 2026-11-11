import '../models/analysis.dart';

class SettingBundle {
  const SettingBundle({
    required this.domain,
    required this.notification,
    required this.wallpaperNotification,
    required this.enable,
    required this.disable,
  });

  final String domain;
  final String notification;
  final String wallpaperNotification;
  final List<SettingItem> enable;
  final List<SettingItem> disable;
}

class SettingScanner {
  static const List<SettingItem> _enableDefaults = [
    SettingItem(address: 0x75550, key: 'EnableLightModel', defaultValue: false, description: '浅色模式'),
    SettingItem(address: 0x75551, key: 'EnablePure', defaultValue: false, description: '纯净/沉浸模式'),
    SettingItem(address: 0x75552, key: 'EnableFollowClick', defaultValue: false, description: '关注二次确认'),
    SettingItem(address: 0x75553, key: 'EnableiAllProgressSlider', defaultValue: true, description: '所有视频进度条'),
    SettingItem(address: 0x75554, key: 'EnableAutoPlay', defaultValue: false, description: '首页自动播放下一条'),
    SettingItem(address: 0x75555, key: 'EnableVideosAutoPlay', defaultValue: false, description: '非首页自动播放下一条'),
    SettingItem(address: 0x75556, key: 'EnableNoWaterMark', defaultValue: true, description: '无水印保存'),
    SettingItem(address: 0x75557, key: 'EnableCopyDescription', defaultValue: false, description: '双击复制文案'),
    SettingItem(address: 0x75558, key: 'EnableDoubleTapNoWaterMark', defaultValue: true, description: '双击保存无水印视频'),
    SettingItem(address: 0x75559, key: 'EnableiWall', defaultValue: true, description: 'iWall 壁纸联动'),
  ];

  static const List<SettingItem> _disableDefaults = [
    SettingItem(address: 0x749F0, key: 'DisableDecoration', defaultValue: false, description: '头像挂件'),
    SettingItem(address: 0x749F1, key: 'DisableRedPacket', defaultValue: false, description: '节日红包'),
    SettingItem(address: 0x749F2, key: 'DisableLocationPage', defaultValue: false, description: '首页本地/同城页'),
    SettingItem(address: 0x749F3, key: 'DisableMotion', defaultValue: false, description: '摇一摇找朋友'),
    SettingItem(address: 0x749F4, key: 'DisableShareIm', defaultValue: false, description: '分享面板私信'),
    SettingItem(address: 0x749F5, key: 'DisableShareApps', defaultValue: false, description: '分享到应用'),
    SettingItem(address: 0x749F6, key: 'DisableSharePlayRemote', defaultValue: false, description: '一起看'),
    SettingItem(address: 0x749F7, key: 'DisableAnchor', defaultValue: false, description: '昵称上方来源/定位'),
    SettingItem(address: 0x749F8, key: 'DisableRefresh', defaultValue: false, description: '首页按钮刷新'),
    SettingItem(address: 0x749F9, key: 'DisableCommentPin', defaultValue: false, description: '评论置顶'),
    SettingItem(address: 0x749FA, key: 'DisableCommentAd', defaultValue: false, description: '评论链接广告'),
    SettingItem(address: 0x749FB, key: 'DisableTabFriend', defaultValue: false, description: '底部朋友按钮'),
    SettingItem(address: 0x749FC, key: 'DisableTabPlus', defaultValue: false, description: '底部加号/发布按钮'),
    SettingItem(address: 0x749FD, key: 'DisableTabNews', defaultValue: false, description: '底部消息按钮'),
    SettingItem(address: 0x749FE, key: 'DisableHomeLiveButton', defaultValue: false, description: '首页左上角直播按钮'),
    SettingItem(address: 0x749FF, key: 'DisableHomeSearchButton', defaultValue: false, description: '首页右上角搜索按钮'),
  ];

  SettingBundle scan(List<StringHit> strings) {
    final joined = strings.map((s) => s.value).join('\n');

    final domainMatch = RegExp(r'com\.[A-Za-z0-9_.-]*awemepure[A-Za-z0-9_.-]*')
        .firstMatch(joined);
    final domain = domainMatch?.group(0) ?? '';

    final notifMatch =
        RegExp(r'[A-Za-z0-9_.-]*prefschanged[A-Za-z0-9_.-]*').firstMatch(joined);
    final notification = notifMatch?.group(0) ?? '';

    final wallMatch = RegExp(r'[A-Za-z0-9_.-]*wallpaper[A-Za-z0-9_.-]*prefschanged[A-Za-z0-9_.-]*')
        .firstMatch(joined);
    final wallpaper = wallMatch?.group(0) ?? '';

    final enable = <SettingItem>[];
    for (final item in _enableDefaults) {
      if (joined.contains(item.key)) enable.add(item);
    }
    final disable = <SettingItem>[];
    for (final item in _disableDefaults) {
      if (joined.contains(item.key)) disable.add(item);
    }

    return SettingBundle(
      domain: domain,
      notification: notification,
      wallpaperNotification: wallpaper,
      enable: enable,
      disable: disable,
    );
  }
}
