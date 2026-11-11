import 'package:flutter/material.dart';

import 'src/ui/home_page.dart';

void main() {
  runApp(const DylibAnalyzerApp());
}

class DylibAnalyzerApp extends StatelessWidget {
  const DylibAnalyzerApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'DylibAnalyzer',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.indigo),
        useMaterial3: true,
      ),
      home: const HomePage(),
    );
  }
}
