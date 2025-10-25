import { useState } from 'react'
import Head from 'next/head'
import { hashPassword, generateToken, fetchUserData } from '../lib/crypto-utils'

export default function Home() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [userData, setUserData] = useState(null)

  const handleLogin = async () => {
    // VULNERABILITY: Using weak hashing algorithm
    const hashedPassword = hashPassword(password)
    
    // VULNERABILITY: Hardcoded API key
    const apiKey = "sk-1234567890abcdef1234567890abcdef12345678"
    
    // VULNERABILITY: Using weak random for token generation
    const token = generateToken(email)
    
    try {
      const data = await fetchUserData(apiKey, token)
      setUserData(data)
    } catch (error) {
      console.error('Login failed:', error)
    }
  }

  return (
    <div className="container">
      <Head>
        <title>Vulnerable Demo App</title>
        <meta name="description" content="Demo app with intentional security vulnerabilities" />
        <link rel="icon" href="/favicon.ico" />
      </Head>

      <main className="main">
        <h1 className="title">
          Vulnerable Demo Application
        </h1>

        <p className="description">
          This application contains intentional security vulnerabilities for testing the MasterFabric Security Checker.
        </p>

        <div className="login-form">
          <h2>Login Form</h2>
          <div className="form-group">
            <label htmlFor="email">Email:</label>
            <input
              type="email"
              id="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="Enter your email"
            />
          </div>
          <div className="form-group">
            <label htmlFor="password">Password:</label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter your password"
            />
          </div>
          <button onClick={handleLogin} className="login-button">
            Login
          </button>
        </div>

        {userData && (
          <div className="user-data">
            <h3>User Data:</h3>
            <pre>{JSON.stringify(userData, null, 2)}</pre>
          </div>
        )}

        <div className="vulnerabilities">
          <h2>Known Vulnerabilities in This App:</h2>
          <ul>
            <li><strong>Weak Dependencies:</strong> Using outdated versions of lodash, node-fetch, bcrypt, and jsonwebtoken</li>
            <li><strong>Weak Cryptography:</strong> Using MD5 hashing instead of secure algorithms</li>
            <li><strong>Hardcoded Secrets:</strong> API key hardcoded in source code</li>
            <li><strong>Weak Random:</strong> Using Math.random() for token generation</li>
            <li><strong>Insecure Dependencies:</strong> Several packages with known CVEs</li>
          </ul>
        </div>
      </main>

      <style jsx>{`
        .container {
          padding: 0 2rem;
        }

        .main {
          min-height: 100vh;
          padding: 4rem 0;
          flex: 1;
          display: flex;
          flex-direction: column;
          justify-content: center;
          align-items: center;
        }

        .title {
          margin: 0;
          line-height: 1.15;
          font-size: 4rem;
          text-align: center;
          color: #e74c3c;
        }

        .description {
          margin: 4rem 0;
          line-height: 1.5;
          font-size: 1.5rem;
          text-align: center;
          max-width: 800px;
        }

        .login-form {
          background: #f8f9fa;
          padding: 2rem;
          border-radius: 8px;
          box-shadow: 0 2px 4px rgba(0,0,0,0.1);
          margin: 2rem 0;
          min-width: 400px;
        }

        .form-group {
          margin-bottom: 1rem;
        }

        .form-group label {
          display: block;
          margin-bottom: 0.5rem;
          font-weight: bold;
        }

        .form-group input {
          width: 100%;
          padding: 0.5rem;
          border: 1px solid #ddd;
          border-radius: 4px;
          font-size: 1rem;
        }

        .login-button {
          background: #0070f3;
          color: white;
          border: none;
          padding: 0.75rem 1.5rem;
          border-radius: 4px;
          font-size: 1rem;
          cursor: pointer;
          width: 100%;
        }

        .login-button:hover {
          background: #0051a2;
        }

        .user-data {
          background: #e8f5e8;
          padding: 1rem;
          border-radius: 4px;
          margin: 1rem 0;
          max-width: 600px;
        }

        .vulnerabilities {
          background: #fff3cd;
          border: 1px solid #ffeaa7;
          padding: 1.5rem;
          border-radius: 8px;
          margin: 2rem 0;
          max-width: 800px;
        }

        .vulnerabilities h2 {
          color: #856404;
          margin-top: 0;
        }

        .vulnerabilities ul {
          color: #856404;
        }

        .vulnerabilities li {
          margin-bottom: 0.5rem;
        }
      `}</style>
    </div>
  )
}
