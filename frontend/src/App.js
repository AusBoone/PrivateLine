// Importing necessary dependencies and components
import React from 'react';
import './App.css';
import { BrowserRouter as Router, Route, Switch } from 'react-router-dom'; // Importing React Router components
import LoginForm from './components/LoginForm';      // Importing LoginForm component
import RegisterForm from './components/RegisterForm';// Importing RegisterForm component
import Chat from './components/Chat';                // Importing Chat component
import UserAccount from './components/UserAccount';  // Importing UserAccount component
import NavigationBar from './components/NavigationBar'; // Importing NavigationBar component

// Main App component
function App() {
  return (
    // Wrapping the application inside a Router component to enable routing
    <Router>
      <NavigationBar /> // NavigationBar component for handling navigation links
      <Switch> // Switch component to render the first matching route exclusively
        <Route path="/login" component={LoginForm} />      // Route for the login page
        <Route path="/register" component={RegisterForm} />// Route for the registration page
        <Route path="/chat" component={Chat} />            // Route for the chat page
        <Route path="/account" component={UserAccount} />  // Route for the user account page
        {/* Add other routes as needed */}
      </Switch>
    </Router>
  );
}

// Exporting the App component to be used in other parts of the application
export default App;
