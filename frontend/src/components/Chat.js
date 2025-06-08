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
  IconButton,
  TextField,
  Button,
} from '@mui/material';
import DeleteIcon from '@mui/icons-material/Delete';
import './Chat.css';
import { arrayBufferToBase64, base64ToArrayBuffer } from '../utils/encoding';
import { loadKeyMaterial } from '../utils/secureStore';
import { setupWebPush } from '../utils/push';

// Chat groups loaded from the backend
// Each has {id, name}


function pemToCryptoKey(pem, usage = 'decrypt') {
  const b64 = pem
    .replace('-----BEGIN PRIVATE KEY-----', '')
    .replace('-----END PRIVATE KEY-----', '')
    .replace(/\s/g, '');
  const binary = atob(b64);
  const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
  return window.crypto.subtle.importKey(
    'pkcs8',
    bytes,
    usage === 'decrypt'
      ? { name: 'RSA-OAEP', hash: 'SHA-256' }
      : { name: 'RSA-PSS', hash: 'SHA-256' },
    true,
    [usage]
  );
}

async function fingerprintPem(pem) {
  const b64 = pem
    .replace('-----BEGIN PUBLIC KEY-----', '')
    .replace('-----END PUBLIC KEY-----', '')
    .replace(/\s/g, '');
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const digest = await window.crypto.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
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

const groupKeyCache = new Map();

/**
 * Retrieve and cache the AES key for a group from the backend.
 * @param {number} groupId - Identifier of the group.
 * @returns {Promise<CryptoKey>} Imported AES-GCM key.
 */
async function fetchGroupKey(groupId) {
  let key = groupKeyCache.get(groupId);
  if (key) return key;
  const resp = await api.get(`/api/groups/${groupId}/key`);
  if (resp.status === 200 && resp.data.key) {
    key = await window.crypto.subtle.importKey(
      'raw',
      base64ToArrayBuffer(resp.data.key),
      'AES-GCM',
      false,
      ['encrypt', 'decrypt']
    );
    groupKeyCache.set(groupId, key);
    return key;
  }
  throw new Error('failed to fetch group key');
}

/**
 * Encrypt text using the shared group key and return base64 ciphertext.
 * @param {string} message - Plaintext message.
 * @param {number} groupId - Group identifier.
 * @returns {Promise<string>} Base64 encoded encrypted payload.
 */
async function encryptGroupMessage(message, groupId) {
  const key = await fetchGroupKey(groupId);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const plaintext = new TextEncoder().encode(message);
  const cipher = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    plaintext
  );
  const combined = new Uint8Array(iv.length + cipher.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(cipher), iv.length);
  return arrayBufferToBase64(combined.buffer);
}

/**
 * Decrypt a base64 encoded group message using the cached key.
 * @param {string} b64 - Base64 ciphertext.
 * @param {number} groupId - Group identifier.
 * @returns {Promise<string>} Decrypted plaintext.
 */
async function decryptGroupMessage(b64, groupId) {
  const key = await fetchGroupKey(groupId);
  const data = base64ToArrayBuffer(b64);
  const iv = data.slice(0, 12);
  const ct = data.slice(12);
  const plain = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: new Uint8Array(iv) },
    key,
    ct
  );
  return new TextDecoder().decode(plain);
}

/**
 * Encrypt a File/Blob using the group key. The returned blob contains the IV
 * prepended so it can later be decrypted.
 */
async function encryptFileBlob(blob, groupId) {
  if (groupId == null) {
    return blob;
  }
  const key = await fetchGroupKey(groupId);
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  const data = new Uint8Array(await blob.arrayBuffer());
  const cipher = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    data
  );
  const combined = new Uint8Array(iv.length + cipher.byteLength);
  combined.set(iv);
  combined.set(new Uint8Array(cipher), iv.length);
  return new Blob([combined], { type: 'application/octet-stream' });
}

/**
 * Decrypt binary data previously encrypted with ``encryptFileBlob``.
 */
async function decryptFileData(buffer, groupId) {
  if (groupId == null) {
    return new Uint8Array(buffer);
  }
  const key = await fetchGroupKey(groupId);
  const data = new Uint8Array(buffer);
  const iv = data.slice(0, 12);
  const ct = data.slice(12);
  const plain = await window.crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ct
  );
  return new Uint8Array(plain);
}

/**
 * Chat component implementing the end-to-end encrypted conversation UI.
 *
 * The component handles loading messages, connecting to the WebSocket for
 * realtime updates and performing all encryption/decryption in the browser.
 */
function Chat() {
    // State variable to manage the message input field
    const [message, setMessage] = useState('');
  const [messages, setMessages] = useState([]);
  const [socket, setSocket] = useState(null);
  const [privateKey, setPrivateKey] = useState(null);
  const [signKey, setSignKey] = useState(null);
  const [recipient, setRecipient] = useState('');
  const [groups, setGroups] = useState([]);
  const [users, setUsers] = useState([]);
  const [selectedGroup, setSelectedGroup] = useState(null);
  const [file, setFile] = useState(null);

    // Cache for recipient public keys.  In a real app this might live in a
    // Redux store or other global cache.
    const publicKeyCache = React.useRef(new Map());

    useEffect(() => {
      let s;

      async function init() {
        setupWebPush();
        let key = null;
        const pem = sessionStorage.getItem('private_key_pem');
        if (pem) {
          try {
            key = await pemToCryptoKey(pem);
            setPrivateKey(key);
            const sk = await pemToCryptoKey(pem, 'sign');
            setSignKey(sk);
          } catch (e) {
            console.error('Failed to import private key', e);
          }
        } else {
          // Ensure IndexedDB is initialized
          await loadKeyMaterial();
        }

        try {
          const respGroups = await api.get('/api/groups');
          if (respGroups.status === 200 && Array.isArray(respGroups.data.groups)) {
            setGroups(respGroups.data.groups);
          }
          const resp = selectedGroup
            ? await api.get(`/api/groups/${selectedGroup}/messages`)
            : await api.get('/api/messages');
          if (resp.status === 200 && Array.isArray(resp.data.messages)) {
            const decrypted = await Promise.all(
              resp.data.messages.map(async (m) => {
                let text = m.content;
                if (selectedGroup || m.group_id) {
                  try {
                    text = await decryptGroupMessage(
                      m.content,
                      selectedGroup || m.group_id
                    );
                  } catch (e) {
                    console.error('Failed to decrypt group message', e);
                  }
                } else if (privateKey) {
                  try {
                    text = await decryptMessage(privateKey, m.content);
                  } catch (e) {
                    console.error('Failed to decrypt message', e);
                  }
                }
                return {
                  id: m.id,
                  text,
                  type: 'received',
                  file_id: m.file_id,
                  read: m.read,
                };
              })
            );
            setMessages(decrypted);
          }
        } catch (err) {
          console.error('Failed to fetch messages', err);
        }

        s = io(process.env.REACT_APP_API_URL || 'http://localhost:5000');
        setSocket(s);

        s.on('new_message', async (payload) => {
          let text = payload.content;
          if (payload.group_id) {
            try {
              text = await decryptGroupMessage(payload.content, payload.group_id);
            } catch (e) {
              console.error('Failed to decrypt incoming group message', e);
            }
          } else if (privateKey) {
            try {
              text = await decryptMessage(privateKey, payload.content);
            } catch (e) {
              console.error('Failed to decrypt incoming message', e);
            }
          }
          if (
            (payload.group_id && payload.group_id === selectedGroup) ||
            (!payload.group_id && !selectedGroup && payload.recipient_id === recipient)
          ) {
            setMessages((prev) => [
              ...prev,
              { id: Date.now(), text, type: 'received', file_id: payload.file_id, read: true },
            ]);
          }
        });
      }

      init();

      return () => {
        if (s) s.disconnect();
      };
    }, [selectedGroup, recipient]);

    useEffect(() => {
      async function fetchUsers() {
        try {
          const resp = await api.get('/api/users');
          if (resp.status === 200 && Array.isArray(resp.data.users)) {
            setUsers(resp.data.users);
          }
        } catch (e) {
          console.error('Failed to fetch users', e);
        }
      }
      fetchUsers();
    }, []);

    const deleteMessage = async (id) => {
      try {
        await api.delete(`/api/messages/${id}`);
        setMessages((prev) => prev.filter((m) => m.id !== id));
      } catch (e) {
        console.error('Delete failed', e);
      }
    };

    const markRead = async (id) => {
      try {
        await api.post(`/api/messages/${id}/read`);
      } catch (e) {
        // ignore
      }
    };

    const handleSubmit = async (event) => {
      event.preventDefault();

      try {
        if (!recipient && !selectedGroup) return;
        let ciphertext;
        const formData = new URLSearchParams();
        if (recipient && !selectedGroup) {
          let publicKeyPem = publicKeyCache.current.get(recipient);
          if (!publicKeyPem) {
            const resp = await api.get(`/api/public_key/${recipient}`);
            if (resp.status === 200 && resp.data.public_key) {
              publicKeyPem = resp.data.public_key;
              publicKeyCache.current.set(recipient, publicKeyPem);
            } else {
              throw new Error('Failed to fetch recipient key');
            }
          }

          const pinned = JSON.parse(localStorage.getItem('pinned_keys') || '[]');
          const entry = pinned.find((p) => p.username === recipient);
          if (entry) {
            const fp = await fingerprintPem(publicKeyPem);
            if (fp !== entry.fingerprint) {
              throw new Error('Recipient key mismatch');
            }
          }

          ciphertext = await encryptMessage(publicKeyPem, message);
          formData.append('recipient', recipient);
        } else {
          ciphertext = await encryptGroupMessage(message, selectedGroup);
        }

        formData.append('content', ciphertext);
        if (signKey) {
          const buf = await window.crypto.subtle.sign(
            { name: 'RSA-PSS', saltLength: 32 },
            signKey,
            new TextEncoder().encode(ciphertext)
          );
          formData.append('signature', arrayBufferToBase64(buf));
        } else {
          formData.append('signature', '');
        }

        let url = '/api/messages';
        if (selectedGroup) {
          url = `/api/groups/${selectedGroup}/messages`;
          formData.append('group_id', selectedGroup);
          formData.delete('recipient');
        }
        if (file) {
          const fd = new FormData();
          const enc = await encryptFileBlob(file, selectedGroup);
          fd.append('file', new File([enc], file.name));
          const upload = await api.post('/api/files', fd);
          if (upload.status === 201) {
            formData.append('file_id', upload.data.file_id);
          }
        }
        const response = await api.post(url, formData);

        if (response.status === 201) {
          const newId = response.data && response.data.id;
          setMessages([
            ...messages,
            {
              id: newId || Date.now(),
              text: message,
              type: 'sent',
              file_id: formData.get('file_id'),
              read: true,
            },
          ]);
          setMessage('');
          setFile(null);
        }
      } catch (error) {
        console.error('Failed to send message', error);
      }
    };

    // ... (add other Chat component logic, like fetching and displaying messages)

    return (
      <Box sx={{ display: 'flex', height: 'calc(100vh - 64px)' }}>
        <Drawer variant="permanent" sx={{ width: 240, flexShrink: 0 }}>
          <List className="conversation-list" sx={{ width: 240 }}>
            <ListItem>
              <ListItemText primary="Conversations" />
            </ListItem>
            {users.map((user) => (
              <ListItem
                button
                className={`conversation-item${!selectedGroup && recipient === user ? ' active' : ''}`}
                key={user}
                selected={!selectedGroup && recipient === user}
                onClick={() => { setSelectedGroup(null); setRecipient(user); }}
              >
                <ListItemText primary={user} />
              </ListItem>
            ))}
            {groups.map((g) => (
              <ListItem
                button
                className={`conversation-item${selectedGroup === g.id ? ' active' : ''}`}
                key={`g-${g.id}`}
                selected={selectedGroup === g.id}
                onClick={() => { setSelectedGroup(g.id); }}
              >
                <ListItemText primary={g.name} />
              </ListItem>
            ))}
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
                {msg.type === 'sent' && (
                  <span className="read-receipt" style={{ marginLeft: 4 }}>
                    {msg.read ? '✓✓' : '✓'}
                  </span>
                )}
                {msg.file_id && (
                  <a
                    href="#"
                    onClick={async (e) => {
                      e.preventDefault();
                      try {
                        const resp = await api.get(`/api/files/${msg.file_id}`, {
                          responseType: 'arraybuffer',
                        });
                        const data = await decryptFileData(resp.data, selectedGroup);
                        let filename = 'download';
                        const disp = resp.headers['content-disposition'];
                        const match = /filename=([^;]+)/.exec(disp);
                        if (match) filename = match[1];
                        const url = window.URL.createObjectURL(
                          new Blob([data])
                        );
                        const a = document.createElement('a');
                        a.href = url;
                        a.download = filename;
                        a.click();
                        window.URL.revokeObjectURL(url);
                      } catch (err) {
                        console.error('Download failed', err);
                      }
                    }}
                    style={{ marginLeft: 8 }}
                  >
                    [attachment]
                  </a>
                )}
                <IconButton size="small" onClick={() => deleteMessage(msg.id)}>
                  <DeleteIcon fontSize="small" />
                </IconButton>
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
            <input type="file" onChange={(e) => setFile(e.target.files[0])} />
            <Button type="submit" variant="contained" sx={{ ml: 1 }}>
              Send
            </Button>
          </Box>
        </Box>
      </Box>
    );
}

export default Chat;
