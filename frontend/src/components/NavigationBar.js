// Navigation bar component providing navigation links, logout handling and a
// dark/light theme toggle across the app.
import React from 'react';
import { Link, useHistory } from 'react-router-dom';
import api from '../api';
import { removeWebPush } from '../utils/push';
import {
  AppBar,
  Toolbar,
  Button,
  IconButton,
  Typography,
} from '@mui/material';
import Brightness4Icon from '@mui/icons-material/Brightness4';
import Brightness7Icon from '@mui/icons-material/Brightness7';

function NavigationBar({ onToggleTheme, currentTheme }) {
  const history = useHistory();

  /**
   * Log out the current user by revoking the refresh token and clearing any
   * client-side storage related to authentication. The user is redirected back
   * to the login page once cleanup completes.
   *
   * @async
   * @returns {Promise<void>} resolves when the logout process has finished
   */
  const handleLogout = async () => {
    try {
      await removeWebPush();
      await api.post('/api/revoke');
    } catch (e) {
      console.error('Failed to revoke token', e);
    } finally {
      sessionStorage.removeItem('pinned_keys');
      sessionStorage.removeItem('private_key_pem');
      sessionStorage.removeItem('user_id');
      history.push('/login');
    }
  };

  return (
    <AppBar position="static">
      <Toolbar>
        <Typography variant="h6" sx={{ flexGrow: 1 }}>
          PrivateLine
        </Typography>
        {/* Main navigation links */}
        <Button color="inherit" component={Link} to="/login">
          Login
        </Button>
        <Button color="inherit" component={Link} to="/register">
          Register
        </Button>
        <Button color="inherit" component={Link} to="/chat">
          Chat
        </Button>
        <Button color="inherit" component={Link} to="/account">
          Account
        </Button>
        <Button color="inherit" onClick={handleLogout}>
          Logout
        </Button>
        {/* Switch between light and dark themes */}
        <IconButton color="inherit" onClick={onToggleTheme} sx={{ ml: 1 }}>
          {currentTheme === 'dark' ? <Brightness7Icon /> : <Brightness4Icon />}
        </IconButton>
      </Toolbar>
    </AppBar>
  );
}

export default NavigationBar;
