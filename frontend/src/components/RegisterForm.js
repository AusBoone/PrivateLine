// Generates a key pair for each user during registration. 
// The public key is sent to the server, and the private key should be securely stored on the user's device. 
// The form itself includes input fields for the username, email, and password, as well as a submit button
import React, { useState } from 'react';
import { useHistory } from 'react-router-dom';
import api from '../api';

async function generateKeyPair() {
  const keyPair = await window.crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt']
  );

  return keyPair;
}

function RegisterForm() {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const history = useHistory();

  const handleSubmit = async (event) => {
    event.preventDefault();

    // Generate key pair for the user
    const keyPair = await generateKeyPair();

    // Export the public key to PEM format
    const exportedPublicKey = await window.crypto.subtle.exportKey(
      'spki',
      keyPair.publicKey
    );
    const publicKeyPem = Buffer.from(exportedPublicKey).toString('base64');

    // Send the registration data to the server
    try {
      const response = await api.post('/api/register', {
        username,
        email,
        password,
        publicKey: publicKeyPem,
      });

      if (response.status === 201) {
        // Export the private key and store it for later message decryption
        const exportedPrivateKey = await window.crypto.subtle.exportKey(
          'pkcs8',
          keyPair.privateKey
        );
        const privateKeyPem = Buffer.from(exportedPrivateKey).toString('base64');
        localStorage.setItem('private_key', privateKeyPem);
        // Redirect the user to the login page after successful registration
        history.push('/login');
      } else {
        // Handle registration errors
      }
    } catch (error) {
      // Handle network or server errors
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <h2>Register</h2>
      <input
        type="text"
        placeholder="Username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
      />
      <input
        type="email"
        placeholder="Email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
      />
      <input
        type="password"
        placeholder="Password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <button type="submit">Register</button>
    </form>
  );
}

export default RegisterForm;
