// Registration form for creating a new account.
// Sends username, email and password to the backend API.
import React, { useState } from 'react';
import { Box, Button, TextField, Typography } from '@mui/material';
import api from '../api';
import { saveKeyMaterial } from '../utils/secureStore';

function RegisterForm() {
  const [username, setUsername] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const handleSubmit = async (event) => {
    event.preventDefault();

    // Send the registration data to the server
    try {
      const response = await api.post('/api/register', {
        username,
        email,
        password,
      });

      if (response.status === 201) {
        const { encrypted_private_key, salt, nonce } = response.data;
        await saveKeyMaterial({ encrypted_private_key, salt, nonce });

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
