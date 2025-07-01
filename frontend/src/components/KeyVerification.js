import React, { useEffect, useState } from 'react';
import QRCode from 'qrcode.react';
import { Typography, Box, TextField, Button } from '@mui/material';
import { loadKeyMaterial } from '../utils/secureStore';
import Cookies from 'js-cookie';
import { loadMessages } from '../utils/messageCache';
import QrReader from 'react-qr-reader';

/**
 * Component displaying the current user's public key fingerprint and a QR code
 * for easy sharing. Another section allows scanning a QR code to verify a
 * contact's fingerprint out-of-band.
 */
function KeyVerification() {
  const [fingerprint, setFingerprint] = useState('');
  const [scan, setScan] = useState('');
  const [result, setResult] = useState('');

  useEffect(() => {
    async function loadFingerprint() {
      const material = await loadKeyMaterial();
      if (material && material.fingerprint) {
        setFingerprint(material.fingerprint);
      }
    }
    loadFingerprint();
  }, []);

  return (
    <Box sx={{ mt: 2 }}>
      <Typography variant="h6">Public Key Fingerprint</Typography>
      {fingerprint && (
        <>
          <QRCode value={fingerprint} />
          <Typography sx={{ mt: 1 }}>{fingerprint}</Typography>
        </>
      )}
      <Box sx={{ mt: 2 }}>
        <Typography variant="subtitle1">Verify Contact</Typography>
        <QrReader
          delay={300}
          onError={(err) => console.error(err)}
          onScan={(data) => data && setScan(data)}
          style={{ width: '100%' }}
        />
        <TextField
          label="Scanned Fingerprint"
          value={scan}
          onChange={(e) => setScan(e.target.value)}
          fullWidth
          margin="normal"
        />
        <Button
          variant="contained"
          onClick={() =>
            setResult(scan === fingerprint ? 'Match' : 'Mismatch')
          }
        >
          Compare
        </Button>
        {result && (
          <Typography sx={{ mt: 1 }}>
            Result: {result}
          </Typography>
        )}
      </Box>
    </Box>
  );
}

export default KeyVerification;
