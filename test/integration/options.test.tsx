import { describe, it, expect } from 'vitest';
import { render } from '@testing-library/preact';
import { ImportExport } from '../../src/options/components/ImportExport.js';

describe('options smoke', () => {
  it('ImportExport renders the export button', () => {
    const { getByText } = render(<ImportExport />);
    expect(getByText('Export .aeropad')).toBeTruthy();
  });
});