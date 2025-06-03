// Generates a key pair for each user during registration. 
// The public key is sent to the server, and the private key should be securely stored on the user's device. 
// The form itself includes input fields for the username, email, and password, as well as a submit button
import React, { useState } from 'react';
import { Box, Button, TextField, Typography } from '@mui/material';
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

      if (response.status === 200) {
        // Save the private key securely on the user's device
        // Implement a secure storage mechanism, e.g., IndexedDB

        // Redirect to the login page or another appropriate page
      } else {
        // Handle registration errors
      }
    } catch (error) {
      // Handle network or server errors
    }
  };

  return (
    <Box
      component="form"
      onSubmit={handleSubmit}
      sx={{ display: 'flex', flexDirection: 'column', maxWidth: 320, m: 'auto' }}
    >
      <Typography variant="h5" sx={{ mb: 2 }}>
        Register
      </Typography>
      <TextField
        label="Username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
        required
        margin="normal"
      />
      <TextField
        label="Email"
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
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
        Register
      </Button>
    </Box>
  );
}

export default RegisterForm;
