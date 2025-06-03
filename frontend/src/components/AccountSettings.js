// A part of the user account management interface, focusing on updating account information.
import React, { useState } from 'react';
import { Box, Button, TextField, Typography } from '@mui/material';
import api from '../api';

/*
Adds a form to update the email and password. 
When the form is submitted, it sends a request to the server with 
the new email, current password, and new password. 
If the update is successful, it handles the response accordingly, 
like showing a success message or redirecting the user to another page.
*/
function AccountSettings() {
  const [email, setEmail] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');

  const handleSubmit = async (event) => {
    event.preventDefault();

    try {
      const response = await api.put('/api/account-settings', {
        email,
        currentPassword,
        newPassword,
      });

      if (response.status === 200) {
        // Handle successful account update, e.g., show a success message

        // Redirect to another appropriate page or update the interface
      } else {
        // Handle account update errors
      }
    } catch (error) {
      // Handle network or server errors
    }
  };

  return (
    <Box
      component="form"
      onSubmit={handleSubmit}
      sx={{ display: 'flex', flexDirection: 'column', maxWidth: 320 }}
    >
      <Typography variant="h6" sx={{ mb: 2 }}>
        Account Settings
      </Typography>
      <TextField
        label="New email"
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        margin="normal"
      />
      <TextField
        label="Current password"
        type="password"
        value={currentPassword}
        onChange={(e) => setCurrentPassword(e.target.value)}
        margin="normal"
      />
      <TextField
        label="New password"
        type="password"
        value={newPassword}
        onChange={(e) => setNewPassword(e.target.value)}
        margin="normal"
      />
      <Button type="submit" variant="contained" sx={{ mt: 2 }}>
        Update
      </Button>
    </Box>
  );
}

export default AccountSettings;
