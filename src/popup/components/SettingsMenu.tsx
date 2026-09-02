interface Props { onLock: () => void; onOpenOptions: () => void; }

export function SettingsMenu({ onLock, onOpenOptions }: Props) {
  return (
    <div style="display:flex;gap:8px;margin-top:12px">
      <button onClick={onLock}>Lock</button>
      <button onClick={onOpenOptions}>Settings</button>
    </div>
  );
}