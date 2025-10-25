import crypto from 'crypto'

// VULNERABILITY: Using weak MD5 hashing algorithm
export function hashPassword(password: string): string {
  return crypto.createHash('md5').update(password).digest('hex')
}

// VULNERABILITY: Using weak random number generation
export function generateToken(userId: string): string {
  const randomPart = Math.random().toString(36).substring(2, 15)
  return `${userId}_${randomPart}_${Date.now()}`
}

// VULNERABILITY: Hardcoded secret key
const SECRET_KEY = "my-super-secret-key-12345"

// VULNERABILITY: Using weak SHA1 hashing
export function signData(data: string): string {
  return crypto.createHash('sha1').update(data + SECRET_KEY).digest('hex')
}

// VULNERABILITY: Insecure password comparison
export function verifyPassword(plainPassword: string, hashedPassword: string): boolean {
  const hashed = hashPassword(plainPassword)
  return hashed === hashedPassword
}

// VULNERABILITY: Using weak encryption
export function encryptData(data: string): string {
  // This is a mock implementation - in real code this would be even more vulnerable
  const cipher = crypto.createCipher('aes-128-cbc', SECRET_KEY)
  let encrypted = cipher.update(data, 'utf8', 'hex')
  encrypted += cipher.final('hex')
  return encrypted
}

// VULNERABILITY: Insecure decryption
export function decryptData(encryptedData: string): string {
  const decipher = crypto.createDecipher('aes-128-cbc', SECRET_KEY)
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8')
  decrypted += decipher.final('utf8')
  return decrypted
}

// VULNERABILITY: Hardcoded API endpoint
const API_BASE_URL = "http://insecure-api.example.com"

export async function fetchUserData(apiKey: string, token: string) {
  // VULNERABILITY: No input validation
  const response = await fetch(`${API_BASE_URL}/user?token=${token}`, {
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json'
    }
  })
  
  if (!response.ok) {
    throw new Error('Failed to fetch user data')
  }
  
  return response.json()
}

// VULNERABILITY: SQL injection vulnerability (simulated)
export function buildUserQuery(userId: string): string {
  // This would be vulnerable to SQL injection
  return `SELECT * FROM users WHERE id = '${userId}'`
}

// VULNERABILITY: XSS vulnerability (simulated)
export function renderUserContent(userContent: string): string {
  // This would be vulnerable to XSS
  return `<div>${userContent}</div>`
}
