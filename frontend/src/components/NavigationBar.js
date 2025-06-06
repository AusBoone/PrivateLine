import React from 'react';
import { Link, useHistory } from 'react-router-dom';
import api from '../api';
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

  const handleLogout = async () => {
    try {
      await api.post('/api/revoke');
    } catch (e) {
      console.error('Failed to revoke token', e);
    } finally {
      localStorage.removeItem('access_token');
      localStorage.removeItem('pinned_keys');
      sessionStorage.removeItem('private_key_pem');
      history.push('/login');
    }
  };

  return (
    <AppBar position="static">
      <Toolbar>
        <Typography variant="h6" sx={{ flexGrow: 1 }}>
          PrivateLine
        </Typography>
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
        <IconButton color="inherit" onClick={onToggleTheme} sx={{ ml: 1 }}>
          {currentTheme === 'dark' ? <Brightness7Icon /> : <Brightness4Icon />}
        </IconButton>
      </Toolbar>
    </AppBar>
  );
}

export default NavigationBar;
