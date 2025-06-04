import React, { useState } from 'react';
import { Box, Button, TextField, Typography } from '@mui/material';
import api from '../api';
import { loadKeyMaterial } from '../utils/secureStore';
import { base64ToArrayBuffer } from '../utils/encoding';

/**
 * LoginForm Component
 * 
 * This component handles user login by providing a form for entering username
 * and password, and then sends a POST request to the server with the provided credentials.
 * Upon successful login, it redirects the user to an appropriate page.
 *
 * @returns {React.Component} The LoginForm component
 */
function LoginForm() {
  // State variables to hold the user's input for username and password
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  /**
   * handleSubmit Function
   * 
   * This function is called when the login form is submitted.
   * It sends a POST request to the login endpoint with the username and password,
   * and handles the response accordingly.
   *
   * @param {Event} event - The submit event object
   * @returns {Promise<void>}
   */
  const handleSubmit = async (event) => {
    // Prevent the default behavior of the form submission, e.g., page reload
    event.preventDefault();

    try {
      // Send a POST request to the login endpoint with the username and password
      const response = await api.post('/api/login', {
        username,
        password,
      });

      // Check if the login was successful (response status 200)
      if (response.status === 200) {
        // Store the received JWT so it can be attached to future requests
        localStorage.setItem('access_token', response.data.access_token);

        try {
          const material = await loadKeyMaterial();
          const { encrypted_private_key, salt, nonce } = material;
          if (encrypted_private_key && salt && nonce) {
            const passwordBytes = new TextEncoder().encode(password);
            const saltBytes = base64ToArrayBuffer(salt);
            const keyMaterial = await window.crypto.subtle.importKey(
              'raw',
              passwordBytes,
              'PBKDF2',
              false,
              ['deriveKey']
            );
            const aesKey = await window.crypto.subtle.deriveKey(
              { name: 'PBKDF2', salt: saltBytes, iterations: 200000, hash: 'SHA-256' },
              keyMaterial,
              { name: 'AES-GCM', length: 256 },
              false,
              ['decrypt']
            );
            const nonceBytes = base64ToArrayBuffer(nonce);
            const ciphertext = base64ToArrayBuffer(encrypted_private_key);
            const pkBuffer = await window.crypto.subtle.decrypt(
              { name: 'AES-GCM', iv: nonceBytes },
              aesKey,
              ciphertext
            );
            const privateKeyPem = new TextDecoder().decode(pkBuffer);
            sessionStorage.setItem('private_key_pem', privateKeyPem);
          }
        } catch (e) {
          console.error('Failed to load private key', e);
        }

        // Redirect to the chat page or another appropriate page
      } else {
        // Handle login errors
        // You may want to update the component state or show a notification to the user
      }
    } catch (error) {
      // Handle network or server errors
      // You may want to log the error or show an error message to the user
    }
  };

  return (
    <Box
      component="form"
      onSubmit={handleSubmit}
      sx={{ display: 'flex', flexDirection: 'column', maxWidth: 320, m: 'auto' }}
    >
      <Typography variant="h5" sx={{ mb: 2 }}>
        Login
      </Typography>
      <TextField
        label="Username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
        required
        margin="normal"
      />
      <TextField
        label="Password"
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        required
        margin="normal"
      />
      <Button variant="contained" type="submit" sx={{ mt: 2 }}>
        Login
      </Button>
    </Box>
  );
}

export default LoginForm;
