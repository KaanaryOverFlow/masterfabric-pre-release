import 'dart:convert';
import 'package:http/http.dart' as http;

class ApiService {
  // VULNERABILITY: Hardcoded API key
  static const String _apiKey = "sk-1234567890abcdef1234567890abcdef12345678";
  
  // VULNERABILITY: Using HTTP instead of HTTPS
  static const String _baseUrl = "http://insecure-api.example.com";
  
  // VULNERABILITY: No input validation
  Future<String> loginUser(String email, String hashedPassword) async {
    final url = Uri.parse('$_baseUrl/login');
    
    // VULNERABILITY: SQL injection vulnerability (simulated)
    final query = "SELECT * FROM users WHERE email = '$email' AND password = '$hashedPassword'";
    
    final response = await http.post(
      url,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer $_apiKey', // VULNERABILITY: Hardcoded API key
      },
      body: json.encode({
        'email': email,
        'password': hashedPassword,
        'query': query, // VULNERABILITY: Exposing SQL query
      }),
    );
    
    if (response.statusCode == 200) {
      return response.body;
    } else {
      throw Exception('Login failed: ${response.statusCode}');
    }
  }
  
  // VULNERABILITY: Insecure data transmission
  Future<String> getUserData(String userId) async {
    final url = Uri.parse('$_baseUrl/user/$userId');
    
    final response = await http.get(
      url,
      headers: {
        'Authorization': 'Bearer $_apiKey',
        'X-API-Key': _apiKey, // VULNERABILITY: Duplicate API key exposure
      },
    );
    
    if (response.statusCode == 200) {
      return response.body;
    } else {
      throw Exception('Failed to fetch user data: ${response.statusCode}');
    }
  }
  
  // VULNERABILITY: No rate limiting or request validation
  Future<String> updateUserProfile(String userId, Map<String, dynamic> profileData) async {
    final url = Uri.parse('$_baseUrl/user/$userId/profile');
    
    // VULNERABILITY: No input sanitization
    final response = await http.put(
      url,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer $_apiKey',
      },
      body: json.encode(profileData),
    );
    
    if (response.statusCode == 200) {
      return response.body;
    } else {
      throw Exception('Failed to update profile: ${response.statusCode}');
    }
  }
  
  // VULNERABILITY: Insecure file upload
  Future<String> uploadFile(List<int> fileData, String fileName) async {
    final url = Uri.parse('$_baseUrl/upload');
    
    // VULNERABILITY: No file type validation or size limits
    final request = http.MultipartRequest('POST', url);
    request.headers['Authorization'] = 'Bearer $_apiKey';
    request.files.add(http.MultipartFile.fromBytes(
      'file',
      fileData,
      filename: fileName,
    ));
    
    final response = await request.send();
    
    if (response.statusCode == 200) {
      final responseBody = await response.stream.bytesToString();
      return responseBody;
    } else {
      throw Exception('File upload failed: ${response.statusCode}');
    }
  }
}
