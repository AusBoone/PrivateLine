// A part of the user account management interface, focusing on updating account information.
import React, { useState } from 'react';
import { Box, Button, TextField, Typography, Snackbar, Alert } from '@mui/material';
import api from '../api';

/**
 * AccountSettings component exposes a simple form for updating the user's
 * email or password. On success a brief snackbar notification is shown.
 */
function AccountSettings() {
  const [email, setEmail] = useState('');
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [retention, setRetention] = useState('');
  const [error, setError] = useState('');
  const [openSuccess, setOpenSuccess] = useState(false);

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError('');

    try {
      const response = await api.put('/api/account-settings', {
        email,
        currentPassword,
        newPassword,
        messageRetentionDays: retention ? parseInt(retention, 10) : undefined,
      });

      if (response.status === 200) {
        setOpenSuccess(true);
        setEmail('');
        setCurrentPassword('');
        setNewPassword('');
        setRetention('');
      } else {
        setError(response.data.message || 'Account update failed');
      }
    } catch (error) {
      if (error.response && error.response.data && error.response.data.message) {
        setError(error.response.data.message);
      } else {
        setError('An error occurred while updating the account');
      }
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
      <TextField
        label="Retention days"
        type="number"
        value={retention}
        onChange={(e) => setRetention(e.target.value)}
        margin="normal"
        inputProps={{ min: 1, max: 365 }}
      />
      {error && (
        <Typography color="error" sx={{ mt: 1 }}>
          {error}
        </Typography>
      )}
      <Button type="submit" variant="contained" sx={{ mt: 2 }}>
        Update
      </Button>
      <Snackbar
        open={openSuccess}
        autoHideDuration={6000}
        onClose={() => setOpenSuccess(false)}
      >
        <Alert
          onClose={() => setOpenSuccess(false)}
          severity="success"
          sx={{ width: '100%' }}
        >
          Account updated successfully!
        </Alert>
      </Snackbar>
    </Box>
  );
}

export default AccountSettings;
