import 'dart:convert';
import 'dart:math';
import 'package:crypto/crypto.dart';

class CryptoService {
  // VULNERABILITY: Hardcoded secret key
  static const String _secretKey = "my-super-secret-key-12345-flutter-app";
  
  // VULNERABILITY: Using weak MD5 hashing
  String hashPassword(String password) {
    var bytes = utf8.encode(password);
    var digest = md5.convert(bytes);
    return digest.toString();
  }
  
  // VULNERABILITY: Using weak SHA1 hashing
  String hashData(String data) {
    var bytes = utf8.encode(data);
    var digest = sha1.convert(bytes);
    return digest.toString();
  }
  
  // VULNERABILITY: Using weak random number generation
  String generateToken() {
    final random = Random();
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    final randomPart = random.nextInt(999999);
    return 'token_${timestamp}_${randomPart}';
  }
  
  // VULNERABILITY: Weak encryption using simple XOR
  String encryptData(String data) {
    final key = _secretKey;
    final keyBytes = utf8.encode(key);
    final dataBytes = utf8.encode(data);
    
    final encrypted = <int>[];
    for (int i = 0; i < dataBytes.length; i++) {
      encrypted.add(dataBytes[i] ^ keyBytes[i % keyBytes.length]);
    }
    
    return base64.encode(encrypted);
  }
  
  // VULNERABILITY: Weak decryption
  String decryptData(String encryptedData) {
    final key = _secretKey;
    final keyBytes = utf8.encode(key);
    final encryptedBytes = base64.decode(encryptedData);
    
    final decrypted = <int>[];
    for (int i = 0; i < encryptedBytes.length; i++) {
      decrypted.add(encryptedBytes[i] ^ keyBytes[i % keyBytes.length]);
    }
    
    return utf8.decode(decrypted);
  }
  
  // VULNERABILITY: Insecure password comparison
  bool verifyPassword(String plainPassword, String hashedPassword) {
    final hashed = hashPassword(plainPassword);
    return hashed == hashedPassword;
  }
  
  // VULNERABILITY: Using weak UUID generation
  String generateUUID() {
    final random = Random();
    final timestamp = DateTime.now().millisecondsSinceEpoch;
    final random1 = random.nextInt(0xFFFF);
    final random2 = random.nextInt(0xFFFF);
    final random3 = random.nextInt(0xFFFF);
    
    return '${timestamp.toRadixString(16)}-${random1.toRadixString(16)}-${random2.toRadixString(16)}-${random3.toRadixString(16)}';
  }
}
