import React, { useState } from 'react';
import axios from 'axios';

/**
 * LoginForm Component
 * 
 * This component handles user login by providing a form for entering username
 * and password, and then sends a POST request to the server with the provided credentials.
 * Upon successful login, it redirects the user to an appropriate page.
 *
 * @returns {React.Component} The LoginForm component
 */
function LoginForm() {
  // State variables to hold the user's input for username and password
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  /**
   * handleSubmit Function
   * 
   * This function is called when the login form is submitted.
   * It sends a POST request to the login endpoint with the username and password,
   * and handles the response accordingly.
   *
   * @param {Event} event - The submit event object
   * @returns {Promise<void>}
   */
  const handleSubmit = async (event) => {
    // Prevent the default behavior of the form submission, e.g., page reload
    event.preventDefault();

    try {
      // Send a POST request to the login endpoint with the username and password
      const response = await axios.post('https://your-api-url/login', {
        username,
        password,
      });

      // Check if the login was successful (response status 200)
      if (response.status === 200) {
        // Handle successful login, e.g., store user session or access token
        // Implement a secure storage mechanism for storing sensitive data like tokens

        // Redirect to the chat page or another appropriate page
      } else {
        // Handle login errors
        // You may want to update the component state or show a notification to the user
      }
    } catch (error) {
      // Handle network or server errors
      // You may want to log the error or show an error message to the user
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <h2>Login</h2>
      <input
        type="text"
        placeholder="Username"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
        required // Make this field required to prevent empty submission
      />
      <input
        type="password"
        placeholder="Password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        required // Make this field required to prevent empty submission
      />
      <button type="submit">Login</button>
    </form>
  );
}

export default LoginForm;
