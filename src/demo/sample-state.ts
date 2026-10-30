'use client';
import { useSyncExternalStore } from 'react';
const key = 'jls:demo:v1';
const event = 'jls:demo-change';
const empty = '{"revealed":false,"index":0}';
let memoryState = empty;
let memoryOnly = false;
function subscribe(callback: () => void) {
  window.addEventListener(event, callback); window.addEventListener('storage', callback);
  return () => { window.removeEventListener(event, callback); window.removeEventListener('storage', callback); };
}
function snapshot() { try { return memoryOnly ? memoryState : localStorage.getItem(key) || empty; } catch { return memoryState; } }
export function useSampleState() {
  const raw = useSyncExternalStore(subscribe, snapshot, () => empty);
  let state = { revealed: false, index: 0 };
  try { const parsed: unknown = JSON.parse(raw); if (typeof parsed === 'object' && parsed !== null && 'revealed' in parsed && 'index' in parsed && typeof parsed.revealed === 'boolean' && Number.isInteger(parsed.index) && Number(parsed.index) >= 0 && Number(parsed.index) < 4) state = { revealed: parsed.revealed, index: Number(parsed.index) }; } catch { /* Ignore invalid sample state. */ }
  function update(next: typeof state) { memoryState = JSON.stringify(next); try { localStorage.setItem(key, memoryState); memoryOnly = false; } catch { memoryOnly = true; } window.dispatchEvent(new Event(event)); }
  return { state, update };
}
export function resetSample() { memoryState = empty; try { localStorage.removeItem(key); memoryOnly = false; } catch { memoryOnly = true; } window.dispatchEvent(new Event(event)); }
