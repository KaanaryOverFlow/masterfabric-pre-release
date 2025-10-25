import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:sqflite/sqflite.dart';
import 'package:path/path.dart';

class StorageService {
  // VULNERABILITY: Hardcoded database password
  static const String _dbPassword = "insecure_db_password_123";
  
  // VULNERABILITY: Storing sensitive data in plain text
  Future<void> saveUserData(String email, String hashedPassword) async {
    final prefs = await SharedPreferences.getInstance();
    
    // VULNERABILITY: Storing password in plain text in SharedPreferences
    await prefs.setString('user_email', email);
    await prefs.setString('user_password', hashedPassword);
    await prefs.setString('last_login', DateTime.now().toIso8601String());
    
    // VULNERABILITY: Storing in SQLite without encryption
    await _saveToDatabase(email, hashedPassword);
  }
  
  // VULNERABILITY: Insecure database operations
  Future<void> _saveToDatabase(String email, String password) async {
    final database = await _getDatabase();
    
    // VULNERABILITY: SQL injection vulnerability
    final query = "INSERT INTO users (email, password, created_at) VALUES ('$email', '$password', '${DateTime.now().toIso8601String()}')";
    await database.rawInsert(query);
  }
  
  // VULNERABILITY: No database encryption
  Future<Database> _getDatabase() async {
    final databasesPath = await getDatabasesPath();
    final path = join(databasesPath, 'vulnerable_app.db');
    
    return await openDatabase(
      path,
      version: 1,
      onCreate: (db, version) {
        // VULNERABILITY: No password protection on database
        return db.execute(
          'CREATE TABLE users(id INTEGER PRIMARY KEY, email TEXT, password TEXT, created_at TEXT)',
        );
      },
    );
  }
  
  // VULNERABILITY: Insecure data retrieval
  Future<Map<String, dynamic>?> getUserData(String email) async {
    final database = await _getDatabase();
    
    // VULNERABILITY: SQL injection vulnerability
    final result = await database.rawQuery("SELECT * FROM users WHERE email = '$email'");
    
    if (result.isNotEmpty) {
      return result.first;
    }
    return null;
  }
  
  // VULNERABILITY: Storing API keys in plain text
  Future<void> saveApiKey(String apiKey) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('api_key', apiKey);
  }
  
  // VULNERABILITY: Retrieving sensitive data without encryption
  Future<String?> getApiKey() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString('api_key');
  }
  
  // VULNERABILITY: No data validation or sanitization
  Future<void> saveUserPreferences(Map<String, dynamic> preferences) async {
    final prefs = await SharedPreferences.getInstance();
    
    // VULNERABILITY: Storing complex data as JSON string without validation
    final jsonString = json.encode(preferences);
    await prefs.setString('user_preferences', jsonString);
  }
  
  // VULNERABILITY: No error handling for corrupted data
  Future<Map<String, dynamic>?> getUserPreferences() async {
    final prefs = await SharedPreferences.getInstance();
    final jsonString = prefs.getString('user_preferences');
    
    if (jsonString != null) {
      return json.decode(jsonString);
    }
    return null;
  }
  
  // VULNERABILITY: Insecure data deletion
  Future<void> deleteUserData(String email) async {
    final database = await _getDatabase();
    
    // VULNERABILITY: SQL injection vulnerability
    await database.rawDelete("DELETE FROM users WHERE email = '$email'");
    
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('user_email');
    await prefs.remove('user_password');
  }
}
