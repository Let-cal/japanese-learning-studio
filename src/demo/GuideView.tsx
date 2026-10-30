'use client';
import { useState } from 'react';
import Link from 'next/link';
import { PageHeading } from '@/components/ui/PageHeading';
import { screenFamilies } from '@/demo/fixtures';
import { resetSample } from '@/demo/sample-state';
export function GuideView() {
  const [reset, setReset] = useState(false);
  return <><PageHeading eyebrow="DEMO GUIDE / WHAT’S HERE" title="A small sample. A clear boundary.">This public workspace runs on original examples. It needs no login, accepts no private uploads and makes no model or provider calls.</PageHeading><section className="guide-intro"><div><h2>Explore without a learning record</h2><p>Today, Library, Practice and Progress are usable sample views. Prepared AI examples are labeled and do not call a live model. Other screen families below describe what comes later.</p></div><div className="reset-box"><h2>Start the sample again</h2><p>Reset the sample card and reveal state on this browser. Your effects preference and unrelated browser data stay as they are.</p><button onClick={() => { resetSample(); setReset(true); }}>Reset sample workspace</button><p role="status" className="small">{reset ? 'Sample workspace reset. You can explore again.' : ''}</p></div></section><section aria-labelledby="screen-title"><h2 id="screen-title">The workspace, screen by screen</h2><ul className="screen-list">{screenFamilies.map((screen, index) => <li key={screen.id}><span className="screen-number">{String(index + 1).padStart(2, '0')}</span><div><h3><Link href={screen.href || `/demo/preview/${screen.id}`}>{screen.name} →</Link></h3><p>{screen.description}</p></div><span className="availability">{screen.href?.startsWith('/demo') ? 'Sample available' : 'Available later'}</span></li>)}</ul></section></>;
}
