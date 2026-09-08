import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/preact';
import { CodeList } from '../../src/popup/components/CodeList.js';
import { NoteEditor } from '../../src/popup/components/NoteEditor.js';
import type { CodeEntry, Note } from '../../src/types/index.js';

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

describe('NoteEditor', () => {
  const sampleNote: Note = {
    id: 'n1',
    title: 'Original Title',
    body: 'Original Body',
    updatedAt: 1000,
  };

  it('flushes changes immediately on blur without waiting for debounce', async () => {
    const onChange = vi.fn();
    const { getByPlaceholderText } = render(
      <NoteEditor note={sampleNote} onChange={onChange} />
    );

    const titleInput = getByPlaceholderText('Note title…') as HTMLInputElement;
    fireEvent.input(titleInput, { target: { value: 'Edited Title' } });
    expect(onChange).not.toHaveBeenCalled();

    // Blur input
    fireEvent.blur(titleInput);
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Edited Title', body: 'Original Body' })
    );
  });

  it('flushes pending changes on unmount', () => {
    const onChange = vi.fn();
    const { getByPlaceholderText, unmount } = render(
      <NoteEditor note={sampleNote} onChange={onChange} />
    );

    const textarea = getByPlaceholderText(/Write your encrypted notes here/i);
    fireEvent.input(textarea, { target: { value: 'New secret body' } });
    expect(onChange).not.toHaveBeenCalled();

    unmount();
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Original Title', body: 'New secret body' })
    );
  });

  it('flushes on Save button click or Ctrl+S', () => {
    const onChange = vi.fn();
    const { getByPlaceholderText, getByTitle } = render(
      <NoteEditor note={sampleNote} onChange={onChange} />
    );

    const titleInput = getByPlaceholderText('Note title…');
    fireEvent.input(titleInput, { target: { value: 'Saved with button' } });

    const saveBtn = getByTitle(/Click to save now/i);
    fireEvent.click(saveBtn);
    expect(onChange).toHaveBeenCalledTimes(1);
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ title: 'Saved with button' })
    );
  });
});