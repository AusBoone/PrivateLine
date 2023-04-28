import React from 'react';
import { Link } from 'react-router-dom';

function NavigationBar() {
  return (
    <nav>
      <Link to="/login">Login</Link>
      <Link to="/register">Register</Link>
      <Link to="/chat">Chat</Link>
      <Link to="/account">User Account</Link>
    </nav>
  );
}

export default NavigationBar;
