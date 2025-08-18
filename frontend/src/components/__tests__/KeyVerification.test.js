import '@testing-library/jest-dom';
import { render, screen } from '@testing-library/react';
import KeyVerification from '../KeyVerification';
import { loadKeyMaterial } from '../../utils/secureStore';

jest.mock('../../utils/secureStore', () => ({
  loadKeyMaterial: jest.fn().mockResolvedValue({ fingerprint: 'abc' })
}));
jest.mock('react-qr-reader', () => () => <div>qrreader</div>);

import { act } from '@testing-library/react';

it('renders fingerprint section', () => {
  render(<KeyVerification />);
  expect(screen.getByText('Public Key Fingerprint')).toBeInTheDocument();
});
