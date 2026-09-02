import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/preact';
import { CodeList } from '../../src/popup/components/CodeList.js';
import type { CodeEntry } from '../../src/types/index.js';

const entry: CodeEntry = {
  id: '1', issuer: 'GitHub', account: 'me', secret: 'JBSWY3DPEHPK3PXP',
  algorithm: 'SHA1', digits: 6, period: 30, createdAt: 0,
};

describe('CodeList', () => {
  it('renders issuer and account', () => {
    const { getByText } = render(<CodeList entries={[entry]} />);
    expect(getByText('GitHub')).toBeTruthy();
    expect(getByText('me')).toBeTruthy();
  });
});