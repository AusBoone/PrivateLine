import React from 'react';
import { BrowserRouter as Router, Route, Switch } from 'react-router-dom';
import LoginForm from './components/LoginForm';
import RegisterForm from './components/RegisterForm';
import Chat from './components/Chat';
import UserAccount from './components/UserAccount';
import NavigationBar from './components/NavigationBar';

function App() {
  return (
    <Router>
      <NavigationBar />
      <Switch>
        <Route path="/login" component={LoginForm} />
        <Route path="/register" component={RegisterForm} />
        <Route path="/chat" component={Chat} />
        <Route path="/account" component={UserAccount} />
        {/* Add other routes as needed */}
      </Switch>
    </Router>
  );
}

export default App;
