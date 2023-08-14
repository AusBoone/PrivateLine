// Importing React for creating the component
import React from 'react';

// Importing the AccountSettings component, which will handle the functionality related to updating account information
import AccountSettings from './AccountSettings';

// UserAccount component function
function UserAccount() {
  return (
    // Wrapping the content inside a <div> container
    <div>
      <h2>User Account</h2>              // Header for the user account section
      <AccountSettings />                // Rendering the AccountSettings component, responsible for updating account details
      {/* Implement other user account management features here */}
    
      // Additional components related to user account management can be added here
    
    </div>
  );
}

// Exporting the UserAccount component to be used in other parts of the application
export default UserAccount;
