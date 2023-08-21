// Includes the utility functions for encrypting and decrypting messages using RSA-OAEP,
// as well as the logic for sending encrypted messages and decrypting received messages.
import React, { useState } from 'react';
import axios from 'axios';

/**
 * Encrypts a given message using the recipient's public key.
 * 
 * @param {string} publicKeyPem - Recipient's public key in PEM format.
 * @param {string} message - The plaintext message to be encrypted.
 * @returns {Promise<string>} The encrypted message in base64 encoding.
 */
async function encryptMessage(publicKeyPem, message) {
    // Convert the public key from PEM (base64) to Uint8Array buffer
    const publicKeyBuffer = new Uint8Array(Buffer.from(publicKeyPem, 'base64'));

    // Import the public key to be used with the RSA-OAEP algorithm, specifying SHA-256 as the hash function
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

    // Convert the plaintext message into a buffer using the TextEncoder
    const messageBuffer = new TextEncoder().encode(message);

    // Encrypt the message buffer using the public key and RSA-OAEP algorithm
    const encryptedMessageBuffer = await window.crypto.subtle.encrypt(
      {
        name: 'RSA-OAEP',
      },
      publicKey,
      messageBuffer
    );

    // Return the encrypted message as a base64 encoded string
    return Buffer.from(encryptedMessageBuffer).toString('base64');
}

/**
 * Decrypts an encrypted message using the provided private key.
 * 
 * @param {CryptoKey} privateKey - The private key to be used for decryption.
 * @param {string} encryptedMessage - The encrypted message in base64 encoding.
 * @returns {Promise<string>} The decrypted message in plaintext.
 */
async function decryptMessage(privateKey, encryptedMessage) {
    // Convert the encrypted message from base64 to a Uint8Array buffer
    const encryptedMessageBuffer = new Uint8Array(Buffer.from(encryptedMessage, 'base64'));

    // Decrypt the message buffer using the private key and RSA-OAEP algorithm
    const decryptedMessageBuffer = await window.crypto.subtle.decrypt(
      {
        name: 'RSA-OAEP',
      },
      privateKey,
      encryptedMessageBuffer
    );

    // Return the decrypted message as a plaintext string
    return new TextDecoder().decode(decryptedMessageBuffer);
}

// React functional component for the chat interface
function Chat() {
    // State variable to manage the message input field
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
