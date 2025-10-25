import 'package:flutter/material.dart';
import 'screens/home_screen.dart';

void main() {
  runApp(const VulnerableFlutterApp());
}

class VulnerableFlutterApp extends StatelessWidget {
  const VulnerableFlutterApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Vulnerable Flutter Demo',
      theme: ThemeData(
        primarySwatch: Colors.red, // Red theme to indicate danger
      ),
      home: const HomeScreen(),
      debugShowCheckedModeBanner: false,
    );
  }
}
