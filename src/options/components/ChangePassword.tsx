import { useState } from 'preact/hooks';
import { sendMessage } from '../../lib/send-message.js';

export function ChangePassword() {
  const [oldPw, setOld] = useState('');
  const [newPw, setNew] = useState('');
  const [msg, setMsg] = useState('');
  return (
    <section>
      <h2>Change master password</h2>
      <input
        type="password"
        placeholder="Current"
        value={oldPw}
        onInput={(e) => setOld((e.target as HTMLInputElement).value)}
      />
      <input
        style="margin-top:6px"
        type="password"
        placeholder="New"
        value={newPw}
        onInput={(e) => setNew((e.target as HTMLInputElement).value)}
      />
      <button
        style="margin-top:6px"
        onClick={async () => {
          const r = await sendMessage({
            kind: 'changeMasterPassword',
            oldPassword: oldPw,
            newPassword: newPw,
          });
          setMsg(r.ok ? 'Updated.' : `Failed: ${r.error}`);
        }}
      >
        Change
      </button>
      {msg && <p>{msg}</p>}
    </section>
  );
}