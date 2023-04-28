// A part of the user account management interface, focusing on updating account information.
import React, { useState } from 'react';
import axios from 'axios';

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
      const response = await axios.put('https://your-api-url/account-settings', {
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
    <form onSubmit={handleSubmit}>
      <h3>Account Settings</h3>
      <input
        type="email"
        placeholder="New email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
      />
      <input
        type="password"
        placeholder="Current password"
        value={currentPassword}
        onChange={(e) => setCurrentPassword(e.target.value)}
      />
      <input
        type="password"
        placeholder="New password"
        value={newPassword}
        onChange={(e) => setNewPassword(e.target.value)}
      />
      <button type="submit">Update</button>
    </form>
  );
}

export default AccountSettings;
