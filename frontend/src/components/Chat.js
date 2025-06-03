// Includes the utility functions for encrypting and decrypting messages using RSA-OAEP,
// as well as the logic for sending encrypted messages and decrypting received messages.
import React, { useState, useEffect } from 'react';
import io from 'socket.io-client';
import api from '../api';
import './Chat.css';

/**
 * Encrypts a given message using the recipient's public key.
 * 
 * @param {string} publicKeyPem - Recipient's public key in PEM format.
 * @param {string} message - The plaintext message to be encrypted.
 * @returns {Promise<string>} The encrypted message in base64 encoding.
 */
async function encryptMessage(publicKeyPem, message) {
    // Extract the base64-encoded portion of the PEM key
    const pemHeader = '-----BEGIN PUBLIC KEY-----';
    const pemFooter = '-----END PUBLIC KEY-----';
    const b64 = publicKeyPem
      .replace(pemHeader, '')
      .replace(pemFooter, '')
      .replace(/\s/g, '');

    // Convert the base64 string into a Uint8Array buffer
    const publicKeyBuffer = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

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
    const [messages, setMessages] = useState([
      { id: 1, text: 'Welcome to PrivateLine!', type: 'received' }
    ]);
    const [socket, setSocket] = useState(null);

    // Cache for recipient public keys.  In a real app this might live in a
    // Redux store or other global cache.
    const publicKeyCache = React.useRef(new Map());

    useEffect(() => {
      // Connect to the Socket.IO backend when the component mounts
      const s = io(process.env.REACT_APP_API_URL || 'http://localhost:5000');
      setSocket(s);

      // Append new messages received from the server
      s.on('new_message', (payload) => {
        setMessages((prev) => [
          ...prev,
          { id: Date.now(), text: payload.content, type: 'received' },
        ]);
      });

      return () => s.disconnect();
    }, []);

    // Takes care of encrypting the message using the recipient's public key before sending it to the server
    const handleSubmit = async (event) => {
      event.preventDefault();

      const recipient = 'alice'; // Placeholder - would be selected in the UI

      // Attempt to load the recipient's public key from the cache; otherwise fetch from API
      let recipientPublicKeyPem = publicKeyCache.current.get(recipient);
      if (!recipientPublicKeyPem) {
        const response = await api.get(`/api/public_key/${recipient}`);
        recipientPublicKeyPem = response.data.public_key;
        publicKeyCache.current.set(recipient, recipientPublicKeyPem);
      }

      // Encrypt the message using the recipient's public key
      const encryptedMessage = await encryptMessage(recipientPublicKeyPem, message);

      // Send the encrypted message to the server
      try {
        const response = await api.post('/api/messages', {
          content: encryptedMessage,
        });

        if (response.status === 200) {
          // Append the sent message locally
          setMessages([...messages, { id: Date.now(), text: message, type: 'sent' }]);
          setMessage('');
        } else {
          // Handle errors
        }
      } catch (error) {
        // Handle network or server errors
      }
    };

    // ... (add other Chat component logic, like fetching and displaying messages)

    return (
      <div className="chat-container">
        <div className="message-list">
          {messages.map((msg) => (
            <div key={msg.id} className={`message ${msg.type}`}>
              {msg.text}
            </div>
          ))}
        </div>
        <form className="message-input" onSubmit={handleSubmit}>
          <input
            type="text"
            placeholder="Type your message"
            value={message}
            onChange={(e) => setMessage(e.target.value)}
          />
          <button type="submit">Send</button>
        </form>
      </div>
    );
}

export default Chat;
