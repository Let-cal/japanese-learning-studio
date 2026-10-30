'use client';
import { createContext, useContext, useSyncExternalStore, type ReactNode } from 'react';
import { MotionConfig } from 'motion/react';

const preferenceKey = 'jls:effects-off';
const eventName = 'jls:effects-change';
let memoryOff = false;
let memoryOnly = false;
function subscribe(callback: () => void) {
  const media = window.matchMedia('(prefers-reduced-motion: reduce)');
  window.addEventListener('storage', callback);
  window.addEventListener(eventName, callback);
  media.addEventListener('change', callback);
  return () => { window.removeEventListener('storage', callback); window.removeEventListener(eventName, callback); media.removeEventListener('change', callback); };
}
function snapshot() {
  let userOff = false;
  try { userOff = memoryOnly ? memoryOff : localStorage.getItem(preferenceKey) === 'true'; } catch { userOff = memoryOff; }
  return `${userOff}:${window.matchMedia('(prefers-reduced-motion: reduce)').matches}`;
}
const EffectsContext = createContext({ reduced: true, userOff: false, osReduced: false, toggle: () => {} });
export function MotionProvider({ children }: { children: ReactNode }) {
  const state = useSyncExternalStore(subscribe, snapshot, () => 'false:true');
  const [userOff, osReduced] = state.split(':').map(value => value === 'true');
  const reduced = userOff || osReduced;
  function toggle() {
    memoryOff = !userOff;
    try { localStorage.setItem(preferenceKey, String(memoryOff)); memoryOnly = false; } catch { memoryOnly = true; }
    window.dispatchEvent(new Event(eventName));
  }
  return <EffectsContext value={{ reduced, userOff, osReduced, toggle }}><MotionConfig reducedMotion={reduced ? 'always' : 'user'}><div data-effects={reduced ? 'off' : 'on'}>{children}</div></MotionConfig></EffectsContext>;
}
export function EffectsToggle() {
  const { userOff, osReduced, toggle } = useContext(EffectsContext);
  return <div className="effects-control"><button type="button" aria-pressed={userOff} onClick={toggle}>Turn effects {userOff ? 'on' : 'off'}</button>{osReduced && <span className="small muted">System reduced motion is active.</span>}</div>;
}
