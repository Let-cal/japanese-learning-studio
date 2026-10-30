'use client';
import { useState } from 'react';
import Link from 'next/link';
import { PageHeading } from '@/components/ui/PageHeading';
export function TodayView() {
  const [minutes, setMinutes] = useState('30');
  return <>
    <PageHeading eyebrow="TODAY / A FRESH START" title="A little practice, a clearer tomorrow.">Make room for Japanese at your own pace. Explore what a small study plan could look like.</PageHeading>
    <section className="daily-plan panel" aria-labelledby="plan-title"><div><span className="pill">SAMPLE PLAN</span><h2 id="plan-title">Small steps. Familiar words.</h2><p>Revisit a word, notice its context, then give yourself time to recall it.</p><div className="plan-choice"><label htmlFor="minutes">Time for today</label><select id="minutes" value={minutes} onChange={event => setMinutes(event.target.value)}><option value="10">10 minutes · quick</option><option value="30">30 minutes · ordinary</option><option value="120">120 minutes · extended</option><option value="180">180 minutes · extended</option></select></div><Link className="button primary" href="/demo/practice">Explore sample practice <span aria-hidden="true">→</span></Link><p className="small muted">Preview only · Your choice does not schedule or record study.</p></div><div className="plan-art" aria-hidden="true"><span className="large-kanji">続</span><span className="art-caption">つづける<br />to keep going</span><span className="art-rule" /></div></section>
    <section className="section-space" aria-labelledby="path-title"><div className="section-heading"><h2 id="path-title">A clear place to begin</h2><span className="small muted">{minutes}-minute plan preview</span></div><ol className="study-steps"><li><span className="step-number">01</span><div><h3>Meet your words</h3><p>Four original examples, with kana and Vietnamese meanings.</p><Link href="/demo/library">Open sample wordbook →</Link></div></li><li><span className="step-number">02</span><div><h3>Notice the context</h3><p>Read a sentence and reveal a prepared explanation.</p><Link href="/demo/practice">Try the sample card →</Link></div></li><li><span className="step-number">03</span><div><h3>Understand the evidence</h3><p>See why meaning, kana and Kanji are tracked separately.</p><Link href="/demo/progress">Read the sample progress →</Link></div></li></ol></section>
    <aside className="quiet-note"><span aria-hidden="true">↗</span><p><strong>Consistency has room for rest.</strong> This sample does not track streaks, award points or predict exam readiness.</p></aside>
  </>;
}
