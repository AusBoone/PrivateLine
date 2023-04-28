// Includes the utility functions for encrypting and decrypting messages using RSA-OAEP,
// as well as the logic for sending encrypted messages and decrypting received messages.
import React, { useState } from 'react';
import axios from 'axios';

async function encryptMessage(publicKeyPem, message) {
    const publicKeyBuffer = new Uint8Array(Buffer.from(publicKeyPem, 'base64'));
    const publicKey = await window.crypto.subtle.importKey(
      'spki',
      publicKeyBuffer,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256',
      },
      true,
      ['encrypt']
    );
  
    const messageBuffer = new TextEncoder().encode(message);
    const encryptedMessageBuffer = await window.crypto.subtle.encrypt(
      {
        name: 'RSA-OAEP',
      },
      publicKey,
      messageBuffer
    );
  
    return Buffer.from(encryptedMessageBuffer).toString('base64');
}
  
async function decryptMessage(privateKey, encryptedMessage) {
    const encryptedMessageBuffer = new Uint8Array(Buffer.from(encryptedMessage, 'base64'));
  
    const decryptedMessageBuffer = await window.crypto.subtle.decrypt(
      {
        name: 'RSA-OAEP',
      },
      privateKey,
      encryptedMessageBuffer
    );
  
    return new TextDecoder().decode(decryptedMessageBuffer);
}
  
function Chat() {
    const [message, setMessage] = useState('');

    // Takes care of encrypting the message using the recipient's public key before sending it to the server
    const handleSubmit = async (event) => {
      event.preventDefault();
  
      // Load the recipient's public key from the server or local storage
      const recipientPublicKeyPem = '...';
      /*
      Just a quick note, in this example, the recipient's public key is hardcoded as '...'. 
      In a real-world implementation, you would fetch the 
      recipient's public key from the server or local storage based on the selected recipient.
      */
  
      // Encrypt the message using the recipient's public key
      const encryptedMessage = await encryptMessage(recipientPublicKeyPem, message);
  
      // Send the encrypted message to the server
      try {
        const response = await axios.post('https://your-api-url/send-message', {
          // ... (add other required data)
          message: encryptedMessage,
        });
  
        if (response.status === 200) {
          // Handle successful message sending
        } else {
          // Handle errors
        }
      } catch (error) {
        // Handle network or server errors
      }
    };
  
    // ... (add other Chat component logic, like fetching and displaying messages)
  
    return (
      <div>
        <h2>Chat</h2>
        <form onSubmit={handleSubmit}>
          <input
            type="text"
            placeholder="Type your message"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
          />
          <button type="submit">Send</button>
        </form>
        {/* Add logic to display messages here */}
      </div>
    );
}
  
export default Chat;
