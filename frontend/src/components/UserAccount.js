import React from 'react';
import AccountSettings from './AccountSettings';
import KeyVerification from './KeyVerification';

/**
 * Page container for user account management screens.
 */
function UserAccount() {
  return (
    <div>
      <h2>User Account</h2>
      <AccountSettings />
      <KeyVerification />
    </div>
  );
}

export default UserAccount;
