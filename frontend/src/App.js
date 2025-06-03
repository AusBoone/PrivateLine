// Importing necessary dependencies and components
import React, { useEffect, useMemo, useState } from 'react';
import './App.css';
import { BrowserRouter as Router, Route, Switch } from 'react-router-dom';
import { createTheme, CssBaseline, ThemeProvider } from '@mui/material';
import LoginForm from './components/LoginForm';
import RegisterForm from './components/RegisterForm';
import Chat from './components/Chat';
import UserAccount from './components/UserAccount';
import NavigationBar from './components/NavigationBar';

// Main App component
function App() {
  const [mode, setMode] = useState('light');

  const theme = useMemo(
    () =>
      createTheme({
        palette: {
          mode,
        },
      }),
    [mode]
  );

  const toggleTheme = () => {
    setMode((prev) => (prev === 'light' ? 'dark' : 'light'));
  };

  useEffect(() => {
    document.body.dataset.theme = mode;
  }, [mode]);

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Router>
        <NavigationBar onToggleTheme={toggleTheme} currentTheme={mode} />
        <Switch>
          <Route path="/login" component={LoginForm} />
          <Route path="/register" component={RegisterForm} />
          <Route path="/chat" component={Chat} />
          <Route path="/account" component={UserAccount} />
        </Switch>
      </Router>
    </ThemeProvider>
  );
}

// Exporting the App component to be used in other parts of the application
export default App;
