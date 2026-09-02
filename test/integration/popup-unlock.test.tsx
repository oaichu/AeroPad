import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent, waitFor } from '@testing-library/preact';
import { UnlockDialog } from '../../src/popup/components/UnlockDialog.js';

describe('UnlockDialog', () => {
  it('calls onSubmit with the entered password', async () => {
    const onSubmit = vi.fn().mockResolvedValue({ ok: false, error: 'wrong_password' });
    const { getByLabelText, getByText } = render(<UnlockDialog onSubmit={onSubmit} />);
    fireEvent.input(getByLabelText('Master password'), { target: { value: 'secret' } });
    fireEvent.click(getByText('Unlock'));
    await waitFor(() => expect(onSubmit).toHaveBeenCalledWith('secret'));
  });

  it('shows wrong-password error', async () => {
    const onSubmit = vi.fn().mockResolvedValue({ ok: false, error: 'wrong_password' });
    const { getByLabelText, getByText, findByText } = render(<UnlockDialog onSubmit={onSubmit} />);
    fireEvent.input(getByLabelText('Master password'), { target: { value: 'x' } });
    fireEvent.click(getByText('Unlock'));
    expect(await findByText('Wrong password.')).toBeTruthy();
  });

  it('disables Unlock when password is empty', () => {
    const onSubmit = vi.fn();
    const { getByText } = render(<UnlockDialog onSubmit={onSubmit} />);
    expect((getByText('Unlock') as HTMLButtonElement).disabled).toBe(true);
  });
});
