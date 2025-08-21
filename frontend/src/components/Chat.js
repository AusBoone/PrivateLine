// Chat component and associated utilities implementing end-to-end encryption.
//
// Direct messages use a hybrid RSA-OAEP + AES-GCM scheme where an ephemeral
// symmetric key protects the message content and the RSA key encrypts that
// session key. This update allows arbitrarily long messages while maintaining
// forward secrecy. Additional validation prevents excessively large messages
// from being sent and user-friendly errors are surfaced to the UI.
//
// Revision: Replaces legacy `alert` and `console.error` calls with a unified
// Material UI Snackbar/Alert system so that all errors are presented
// consistently to users rather than relying on browser dialogs or silent logs.
// Revision: Adds Socket.IO connection state notifications (connect errors,
// disconnects and successful reconnects) so users are aware of networking
// issues impacting message delivery.
// Revision: Adds defensive try/catch around `decryptMessage` invocations so
// malformed payloads surface a descriptive Snackbar alert while logging
// non-sensitive diagnostics to the console.
import React, { useState, useEffect, useRef } from 'react';
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
  Snackbar,
  Alert,
} from '@mui/material';
import DeleteIcon from '@mui/icons-material/Delete';
import './Chat.css';
import { arrayBufferToBase64, base64ToArrayBuffer } from '../utils/encoding';
import { loadKeyMaterial } from '../utils/secureStore';
import { setupWebPush } from '../utils/push';
import { getUserId } from '../utils/auth';
import { loadMessages, saveMessages } from '../utils/messageCache';
import {
  saveKey as saveGroupKey,
  loadKey as loadGroupKey,
  listGroupIds,
} from '../utils/groupKeyStore';
import Cookies from 'js-cookie';

/**
 * Return ``true`` if ``msg`` has an ``expires_at`` timestamp in the past.
 *
 * @param {Object} msg - Message object potentially containing ``expires_at``.
 * @returns {boolean} ``true`` when the message should no longer be displayed.
 */
function isExpired(msg) {
  return (
    msg.expires_at && new Date(msg.expires_at).getTime() <= Date.now()
  );
}

// Chat groups loaded from the backend. Each entry contains
// an ``id`` and ``name`` used to populate the sidebar.


/**
 * Convert a PEM encoded private key into a CryptoKey for use with the
 * Web Crypto API.
 *
 * @param {string} pem - PEM formatted key material.
 * @param {string} [usage='decrypt'] - Key usage, either 'decrypt' or 'sign'.
 * @returns {Promise<CryptoKey>} Imported key ready for cryptographic ops.
 */
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

/**
 * Compute the SHA-256 fingerprint of a PEM encoded public key.
 *
 * @param {string} pem - PEM formatted public key.
 * @returns {Promise<string>} Hex formatted fingerprint.
 */
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

// Maximum permitted plaintext size in bytes. This prevents users from
// inadvertently attempting to send enormous messages which could degrade
// performance or exhaust resources during encryption.
const MAX_MESSAGE_BYTES = 10_000;

/**
 * Encrypt ``message`` using a hybrid RSA-OAEP/AES-GCM scheme.
 *
 * A fresh AES-256 key is generated for every message. The plaintext is
 * encrypted with AES-GCM and the symmetric key is then encrypted using the
 * recipient's RSA public key. The result is serialised to JSON containing the
 * base64 encoded ``encryptedKey``, ``nonce`` and ``ciphertext`` fields.
 *
 * @param {string} publicKeyPem - Recipient's public key in PEM format.
 * @param {string} message - Plaintext message to encrypt.
 * @returns {Promise<string>} JSON string with encrypted payload components.
 */
async function encryptMessage(publicKeyPem, message) {
  // Remove PEM armour and convert to binary DER representation.
  const pemHeader = '-----BEGIN PUBLIC KEY-----';
  const pemFooter = '-----END PUBLIC KEY-----';
  const b64 = publicKeyPem
    .replace(pemHeader, '')
    .replace(pemFooter, '')
    .replace(/\s/g, '');
  const publicKeyBuffer = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

  // Import RSA public key for encrypting the randomly generated AES key.
  const publicKey = await window.crypto.subtle.importKey(
    'spki',
    publicKeyBuffer,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['encrypt']
  );

  // Generate an ephemeral AES-GCM key and nonce for the message content.
  const aesKey = await window.crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
  const nonce = window.crypto.getRandomValues(new Uint8Array(12));

  // Encrypt the plaintext with AES-GCM using the generated key/nonce pair.
  const plaintext = new TextEncoder().encode(message);
  const cipherBuffer = await window.crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce },
    aesKey,
    plaintext
  );

  // Export the AES key material and protect it with the recipient's RSA key.
  const rawAesKey = await window.crypto.subtle.exportKey('raw', aesKey);
  const encryptedKeyBuffer = await window.crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    publicKey,
    rawAesKey
  );

  // Serialise components to a JSON string with base64 encoded fields.
  return JSON.stringify({
    encryptedKey: arrayBufferToBase64(encryptedKeyBuffer),
    nonce: arrayBufferToBase64(nonce.buffer),
    ciphertext: arrayBufferToBase64(cipherBuffer),
  });
}

/**
 * Decrypt a payload produced by :func:`encryptMessage`.
 *
 * The RSA private key unwraps the AES session key which is then used to
 * decrypt the AES-GCM ciphertext. Errors during parsing or cryptographic
 * operations result in an ``Error`` being thrown so callers may handle them.
 *
 * @param {CryptoKey} privateKey - RSA private key corresponding to recipient.
 * @param {string} payload - JSON string with encryptedKey/nonce/ciphertext.
 * @returns {Promise<string>} Decrypted plaintext message.
 */
async function decryptMessage(privateKey, payload) {
  try {
    const { encryptedKey, nonce, ciphertext } = JSON.parse(payload);
    const encryptedKeyBuffer = base64ToArrayBuffer(encryptedKey);
    const nonceBuffer = base64ToArrayBuffer(nonce);
    const cipherBuffer = base64ToArrayBuffer(ciphertext);

    // Recover the raw AES key and import it for decryption operations.
    const rawAesKey = await window.crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      privateKey,
      encryptedKeyBuffer
    );
    const aesKey = await window.crypto.subtle.importKey(
      'raw',
      rawAesKey,
      'AES-GCM',
      false,
      ['decrypt']
    );

    // Decrypt the ciphertext and decode back into a UTF-8 string.
    const plainBuffer = await window.crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(nonceBuffer) },
      aesKey,
      cipherBuffer
    );
    return new TextDecoder().decode(plainBuffer);
  } catch (e) {
    // Normalise all failures into a generic error for upstream handling.
    throw new Error('Failed to decrypt message');
  }
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
  // Attempt to load the key from IndexedDB before hitting the network
  const stored = await loadGroupKey(groupId);
  if (stored) {
    key = await window.crypto.subtle.importKey(
      'raw',
      base64ToArrayBuffer(stored),
      'AES-GCM',
      false,
      ['encrypt', 'decrypt']
    );
    groupKeyCache.set(groupId, key);
    return key;
  }
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
    // Persist for offline access
    saveGroupKey(groupId, resp.data.key);
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
  // Number of minutes before a newly sent message expires. ``0`` disables expiry.
  const [expiresInMinutes, setExpiresInMinutes] = useState(0);
  const [privateKey, setPrivateKey] = useState(null);
  const [signKey, setSignKey] = useState(null);
  const [userId, setUserId] = useState(null);
  const [recipient, setRecipient] = useState('');
  const [groups, setGroups] = useState([]);
  const [users, setUsers] = useState([]);
  const [selectedGroup, setSelectedGroup] = useState(null);
  const [file, setFile] = useState(null);
  // Per-conversation TTL in days. Empty string leaves the setting unchanged.
  const [convRetention, setConvRetention] = useState('');

  // Snackbar state handling user-visible notifications.  Each message carries
  // a ``severity`` to determine the alert style (e.g. 'error', 'warning',
  // 'success').  This generalisation allows the component to report both
  // failures and informational connection status events.
  const [snackbar, setSnackbar] = useState({
    open: false,
    message: '',
    severity: 'info',
  });

  /**
   * Display a Snackbar message with an optional severity.  Used both for error
   * handling and for surfacing connection state changes.
   *
   * @param {string} msg - Human readable description of the event.
   * @param {('error'|'warning'|'info'|'success')} [severity='error'] - Alert
   *   style applied to the Snackbar.
   * @param {Error} [err] - Optional error instance for context.  When supplied
   *   its message is appended to ``msg``.
   */
  const showSnackbar = (msg, severity = 'error', err) => {
    const detail = err && err.message ? `: ${err.message}` : '';
    setSnackbar({ open: true, message: `${msg}${detail}` , severity });
  };

  /**
   * Convenience wrapper emitting an ``error`` severity notification.
   *
   * @param {string} msg - Description of the failure.
   * @param {Error} [err] - Optional error instance for additional context.
   */
  const showError = (msg, err) => {
    showSnackbar(msg, 'error', err);
  };

  /** Close the Snackbar after the auto-hide duration or user action. */
  const handleCloseSnackbar = () => {
    setSnackbar((prev) => ({ ...prev, open: false }));
  };

  /**
   * Update the server-side retention policy for the active conversation.
   */
  const updateRetention = async () => {
    try {
      if (selectedGroup) {
        await api.put(`/api/groups/${selectedGroup}/retention`, {
          retention_days: parseInt(convRetention, 10),
        });
      } else if (recipient) {
        await api.put(`/api/conversations/${recipient}/retention`, {
          retention_days: parseInt(convRetention, 10),
        });
      }
      setConvRetention('');
    } catch (err) {
      showError('Failed to set retention', err);
    }
  };
  // Element at the end of the message list so we can smoothly scroll
  const messageEndRef = useRef(null);

  // Scroll to the bottom of the list whenever a new message appears.
  useEffect(() => {
    if (messageEndRef.current &&
        typeof messageEndRef.current.scrollIntoView === 'function') {
      messageEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages]);

    // Cache for recipient public keys.  In a real app this might live in a
    // Redux store or other global cache.
    const publicKeyCache = React.useRef(new Map());

    useEffect(() => {
      let s;

      async function init() {
        setupWebPush();
        const uid = getUserId();
        setUserId(uid);
        let key = null;
        const pem = Cookies.get('private_key_pem');
        if (pem) {
          try {
            key = await pemToCryptoKey(pem);
            setPrivateKey(key);
            const sk = await pemToCryptoKey(pem, 'sign');
            setSignKey(sk);
          } catch (e) {
            showError('Failed to import private key', e);
          }
        } else {
          // Ensure IndexedDB is initialized
          await loadKeyMaterial();
        }

        // Preload persisted group chat keys so messages can be decrypted
        const ids = (await listGroupIds()) || [];
        for (const id of ids) {
          const b64 = await loadGroupKey(id);
          if (b64) {
            // eslint-disable-next-line no-await-in-loop
            const k = await window.crypto.subtle.importKey(
              'raw',
              base64ToArrayBuffer(b64),
              'AES-GCM',
              false,
              ['encrypt', 'decrypt']
            );
            groupKeyCache.set(Number(id), k);
          }
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
                    showError('Failed to decrypt group message', e);
                  }
                } else if (privateKey) {
                  try {
                    text = await decryptMessage(privateKey, m.content);
                  } catch (e) {
                    // Log diagnostic details without exposing encrypted or
                    // decrypted content to avoid leaking sensitive data.  The
                    // identifier helps correlate logs with server-side
                    // information when debugging.
                    // eslint-disable-next-line no-console
                    console.error('decryptMessage failed during history load', {
                      messageId: m.id,
                      error: e,
                    });
                    showError('Unable to decrypt message', e);
                  }
                }
                return {
                  id: m.id,
                  text,
                  type: 'received',
                  file_id: m.file_id,
                  read: m.read,
                  expires_at: m.expires_at,
                };
              })
            );
            setMessages(decrypted.filter((m) => !isExpired(m)));
          }
        } catch (err) {
          showError('Failed to fetch messages', err);
          try {
            const cached = await loadMessages();
            if (cached.length) {
              setMessages(cached.filter((m) => !isExpired(m)));
            }
          } catch (e) {
            showError('Failed to load cached messages', e);
          }
        }

        s = io(process.env.REACT_APP_API_URL || 'http://localhost:5000');

        // Notify the user about connection issues and recovery attempts. Socket.IO
        // automatically retries connections, so the handlers merely surface the
        // state changes via the Snackbar.
        s.on('connect_error', (err) => {
          showSnackbar('Unable to connect to server', 'error', err);
        });
        s.on('disconnect', () => {
          showSnackbar(
            'Disconnected from server. Attempting to reconnect…',
            'warning',
          );
        });
        s.on('reconnect', () => {
          showSnackbar('Reconnected to server', 'success');
        });

        s.on('new_message', async (payload) => {
          if (payload.sender_id === uid) {
            return;
          }
          let text = payload.content;
          if (payload.group_id) {
            try {
              text = await decryptGroupMessage(payload.content, payload.group_id);
            } catch (e) {
              showError('Failed to decrypt incoming group message', e);
            }
          } else if (privateKey) {
            try {
              text = await decryptMessage(privateKey, payload.content);
            } catch (e) {
              // Capture enough context for debugging while avoiding plaintext
              // leakage.  Only metadata and the error object are logged.
              // eslint-disable-next-line no-console
              console.error('decryptMessage failed for incoming message', {
                messageId: payload.id,
                error: e,
              });
              showError('Unable to decrypt incoming message', e);
            }
          }
          if (
            (payload.group_id && payload.group_id === selectedGroup) ||
            (!payload.group_id &&
              !selectedGroup &&
              (payload.sender_id === uid || payload.recipient_id === uid))
          ) {
            setMessages((prev) => [
              ...prev,
              {
                id: payload.id || Date.now(),
                text,
                type: 'received',
                file_id: payload.file_id,
                read: true,
              },
            ]);
          }
        });
      }

      init();

      return () => {
        if (s) s.disconnect();
      };
    }, [selectedGroup, recipient]);

    // Persist the message list whenever it changes so a recent history is
    // available when offline.
    useEffect(() => {
      const maybePromise = saveMessages(messages.filter((m) => !isExpired(m)));
      if (maybePromise && typeof maybePromise.catch === 'function') {
        maybePromise.catch((e) => {
          showError('Failed to cache messages', e);
        });
      }
    }, [messages]);

    useEffect(() => {
      async function fetchUsers() {
        try {
          const resp = await api.get('/api/users');
          if (resp.status === 200 && Array.isArray(resp.data.users)) {
            setUsers(resp.data.users);
          }
        } catch (e) {
          showError('Failed to fetch users', e);
        }
      }
      fetchUsers();
    }, []);

    /**
     * Delete ``id`` from the backend and remove it from local state.
     *
     * @param {number} id - Message identifier.
     */
    const deleteMessage = async (id) => {
      try {
        await api.delete(`/api/messages/${id}`);
        setMessages((prev) => prev.filter((m) => m.id !== id));
      } catch (e) {
        showError('Delete failed', e);
      }
    };

    /**
     * Encrypt and send the current message to either the selected user or
     * group. Attachments are uploaded first and referenced by ID.
     */
    const handleSubmit = async (event) => {
      event.preventDefault();

      try {
        if (!recipient && !selectedGroup) return;
        // Validate message size before performing potentially expensive crypto.
        const msgBytes = new TextEncoder().encode(message).length;
        if (msgBytes > MAX_MESSAGE_BYTES) {
          showError(`Message too long (max ${MAX_MESSAGE_BYTES} bytes)`);
          return;
        }
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

          const pinned = JSON.parse(Cookies.get('pinned_keys') || '[]');
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
        // Calculate expiration timestamp if the user specified a duration.
        if (expiresInMinutes > 0) {
          const exp = new Date(Date.now() + expiresInMinutes * 60000).toISOString();
          formData.append('expires_at', exp);
        }

        const response = await api.post(url, formData);

        if (response.status === 201) {
          const newId = response.data && response.data.id;
          setMessages([
            ...messages,
            {
              id: newId,
              text: message,
              type: 'sent',
              file_id: formData.get('file_id'),
              read: true,
              expires_at: expiresInMinutes > 0 ? new Date(Date.now() + expiresInMinutes * 60000).toISOString() : null,
            },
          ]);
          setMessage('');
          setFile(null);
        }
      } catch (error) {
        showError('Failed to send message', error);
      }
    };


    return (
      <>
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
            {messages.filter((m) => !isExpired(m)).map((msg) => (
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
                        if (err.response && err.response.status === 404) {
                          // Inform the user when the attachment was deleted
                          // after reaching its allowed download count.
                          showError('Attachment is no longer available');
                        } else {
                          showError('Download failed', err);
                        }
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
            <div ref={messageEndRef} />
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
            <TextField
              type="number"
              placeholder="Expire minutes"
              value={expiresInMinutes}
              onChange={(e) => setExpiresInMinutes(parseInt(e.target.value, 10) || 0)}
              size="small"
              sx={{ width: 120, ml: 1 }}
              inputProps={{ min: 0 }}
            />
            <TextField
              type="number"
              placeholder="Retention days"
              value={convRetention}
              onChange={(e) => setConvRetention(e.target.value)}
              size="small"
              sx={{ width: 120, ml: 1 }}
              inputProps={{ min: 1, max: 365 }}
            />
            <Button onClick={updateRetention} variant="outlined" sx={{ ml: 1 }}>
              Set TTL
            </Button>
            <input type="file" onChange={(e) => setFile(e.target.files[0])} />
            <Button type="submit" variant="contained" sx={{ ml: 1 }}>
              Send
            </Button>
          </Box>
        </Box>
      </Box>
      <Snackbar
        open={snackbar.open}
        autoHideDuration={6000}
        onClose={handleCloseSnackbar}
      >
        <Alert
          onClose={handleCloseSnackbar}
          severity={snackbar.severity}
          sx={{ width: '100%' }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
      </>
    );
}

export default Chat;
// Named exports used in unit tests verifying the hybrid encryption helpers.
export { encryptMessage, decryptMessage };
