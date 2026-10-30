'use client';
import { useState } from 'react';
import Link from 'next/link';
import { PageHeading } from '@/components/ui/PageHeading';
import { sampleWords } from '@/demo/fixtures';
export function LibraryView() {
  const [query, setQuery] = useState('');
  const filtered = sampleWords.filter(item => `${item.word} ${item.kana} ${item.meaning}`.normalize('NFKC').toLocaleLowerCase().includes(query.normalize('NFKC').trim().toLocaleLowerCase()));
  return <><PageHeading eyebrow="LIBRARY / ORIGINAL EXAMPLES" title="Your sample wordbook">Four everyday words to explore. These are original examples, separate from any personal library or course.</PageHeading><section aria-label="Search sample words"><label className="field-label" htmlFor="word-search">Find a word, reading or Vietnamese meaning</label><input id="word-search" type="search" placeholder="Try 見直す, みなおす or xem lại" value={query} onChange={event => setQuery(event.target.value)} /><p role="status" className="small muted">{filtered.length} sample {filtered.length === 1 ? 'word' : 'words'}</p><div className="word-list">{filtered.map(item => <article key={item.id} className="word-row"><div><h2 lang="ja">{item.word}</h2><p lang="ja" className="muted">{item.kana}</p></div><div><p lang="vi" className="word-meaning">{item.meaning}</p><p lang="ja">{item.context}</p></div><span className="pill">Original sample</span></article>)}</div>{!filtered.length && <div className="empty-state"><h2>No sample words found</h2><p>Try a different spelling, kana or meaning.</p><button onClick={() => setQuery('')}>Clear search</button></div>}</section><aside className="quiet-note"><p>Source review, private imports and lesson organization become available in later tasks. <Link href="/demo/guide">See the full workspace guide →</Link></p></aside></>;
}
