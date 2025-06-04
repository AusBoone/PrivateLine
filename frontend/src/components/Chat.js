// Includes the utility functions for encrypting and decrypting messages using RSA-OAEP,
// as well as the logic for sending encrypted messages and decrypting received messages.
import React, { useState, useEffect } from 'react';
import io from 'socket.io-client';
import api from '../api';
import {
  Box,
  Drawer,
  List,
  ListItem,
  ListItemText,
  TextField,
  Button,
} from '@mui/material';
import './Chat.css';
import { arrayBufferToBase64, base64ToArrayBuffer } from '../utils/encoding';
import { loadKeyMaterial } from '../utils/secureStore';

function pemToCryptoKey(pem) {
  const b64 = pem
    .replace('-----BEGIN PRIVATE KEY-----', '')
    .replace('-----END PRIVATE KEY-----', '')
    .replace(/\s/g, '');
  const binary = atob(b64);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return window.crypto.subtle.importKey(
    'pkcs8',
    bytes,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['decrypt']
  );
}

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
    return arrayBufferToBase64(encryptedMessageBuffer);
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
    const encryptedMessageBuffer = base64ToArrayBuffer(encryptedMessage);

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
  const [messages, setMessages] = useState([]);
    const [socket, setSocket] = useState(null);
    const [privateKey, setPrivateKey] = useState(null);

    // Cache for recipient public keys.  In a real app this might live in a
    // Redux store or other global cache.
    const publicKeyCache = React.useRef(new Map());

    useEffect(() => {
      let s;

      async function init() {
        try {
          const resp = await api.get('/api/messages');
          if (resp.status === 200 && Array.isArray(resp.data.messages)) {
            setMessages(
              resp.data.messages.map((m) => ({
                id: m.id,
                text: m.content,
                type: 'received',
              }))
            );
          }
        } catch (err) {
          console.error('Failed to fetch messages', err);
        }

        const pem = sessionStorage.getItem('private_key_pem');
        if (pem) {
          try {
            const key = await pemToCryptoKey(pem);
            setPrivateKey(key);
          } catch (e) {
            console.error('Failed to import private key', e);
          }
        } else {
          // Ensure IndexedDB is initialized
          await loadKeyMaterial();
        }

        s = io(process.env.REACT_APP_API_URL || 'http://localhost:5000');
        setSocket(s);

        s.on('new_message', (payload) => {
          // The server already returns plaintext so we simply display it.
          setMessages((prev) => [
            ...prev,
            { id: Date.now(), text: payload.content, type: 'received' },
          ]);
        });
      }

      init();

      return () => {
        if (s) s.disconnect();
      };
    }, []);

    // Send the plaintext message to the server. End-to-end encryption will be added in the future.
    const handleSubmit = async (event) => {
      event.preventDefault();

      // Send the plaintext message to the server
      try {
        const formData = new URLSearchParams();
        formData.append('content', message);

        const response = await api.post('/api/messages', formData);

        if (response.status === 201) {
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
      <Box sx={{ display: 'flex', height: 'calc(100vh - 64px)' }}>
        <Drawer variant="permanent" sx={{ width: 240, flexShrink: 0 }}>
          <List sx={{ width: 240 }}>
            <ListItem>
              <ListItemText primary="Conversations" />
            </ListItem>
            {/* Future conversation items here */}
          </List>
        </Drawer>
        <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
          <Box className="message-list" sx={{ flex: 1, overflowY: 'auto', p: 2 }}>
            {messages.map((msg) => (
              <Box
                key={msg.id}
                className={`message ${msg.type}`}
                sx={{ mb: 1 }}
              >
                {msg.text}
              </Box>
            ))}
          </Box>
          <Box
            component="form"
            onSubmit={handleSubmit}
            className="message-input"
            sx={{ p: 1, display: 'flex', borderTop: 1, borderColor: 'divider' }}
          >
            <TextField
              fullWidth
              placeholder="Type your message"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              size="small"
            />
            <Button type="submit" variant="contained" sx={{ ml: 1 }}>
              Send
            </Button>
          </Box>
        </Box>
      </Box>
    );
}

export default Chat;
