'use client';
import { useState } from 'react';
import Link from 'next/link';
import { PageHeading } from '@/components/ui/PageHeading';
import { screenFamilies } from '@/demo/fixtures';
import { resetSample } from '@/demo/sample-state';

export function GuideView() {
  const [reset, setReset] = useState(false);
  const screens = screenFamilies.map(screen => screen.id === 'practice'
    ? { ...screen, description: 'Choose a subset of four original words, answer Meaning, Kana or Kanji questions, and finish with visit-only results.' }
    : screen.id === 'study' ? { ...screen, description: 'Personal sessions with durable answers, pause, recovery and protected Test are available later. Public sample recall is available in Practice.' }
    : screen.id === 'results' ? { ...screen, description: 'Personal history is available later. Sample Practice already summarizes actual visit answers as matched, incorrect, pending, assisted and untested.' }
    : screen);
  return <><PageHeading eyebrow="DEMO GUIDE / WHAT’S HERE" title="A small sample. A clear boundary.">This public workspace runs on original examples. It needs no login, accepts no private uploads and makes no model or provider calls.</PageHeading>
    <section className="guide-intro"><div><h2>Try recall without a personal record</h2>
      <p>Practice lets you choose exact sample words and abilities, preview question counts, then type or confirm answers. Meaning uses curated sample phrases; other valid phrasing stays Pending because semantic AI grading is unavailable.</p>
      <p>Help before an answer stays Assisted. Finish early to see answered and untested counts separately. Answers and results last only in the current Practice view; leaving or reloading clears them. No XP, schedule or mastery changes are made.</p>
      <p>Cards still offers prepared meaning reveals. Today and Progress contain labeled illustrative data. Personal sign-in, protected Test, private imports and durable learning history remain unavailable.</p>
    </div><div className="reset-box"><h2>Start the sample again</h2><p>Reset the saved sample card and reveal state on this browser. Recall answers already clear when you leave Practice. Your effects preference and unrelated browser data stay as they are.</p><button onClick={() => { resetSample(); setReset(true); }}>Reset sample workspace</button><p role="status" className="small">{reset ? 'Sample workspace reset. You can explore again.' : ''}</p></div></section>
    <section aria-labelledby="screen-title"><h2 id="screen-title">The workspace, screen by screen</h2><ul className="screen-list">{screens.map((screen, index) => <li key={screen.id}><span className="screen-number">{String(index + 1).padStart(2, '0')}</span><div><h3><Link href={screen.href || `/demo/preview/${screen.id}`}>{screen.name} →</Link></h3><p>{screen.description}</p></div><span className="availability">{screen.href?.startsWith('/demo') ? 'Sample available' : 'Available later'}</span></li>)}</ul></section>
  </>;
}
