'use client';
import { useState } from 'react';
import { PageHeading } from '@/components/ui/PageHeading';
import { sampleWords } from '@/demo/fixtures';
import { useSampleState } from '@/demo/sample-state';
import { selectSession, type LearningAbility, type SessionSelection } from '@/domain/learning/selectSession';
import { abilityLabels, sampleAbilities, sampleSnapshots, sampleStudyWords, shuffleSampleIds } from './study-fixtures';
import { SampleRecallSession } from './SampleRecallSession';

function SampleCards() {
  const { state, update } = useSampleState();
  const item = sampleWords[state.index];
  return <div className="practice-layout"><section className="panel practice-card" aria-labelledby="sample-word"><div className="section-heading"><span className="pill">SAMPLE CARD {state.index + 1} / 4</span><span className="small muted">Meaning preview</span></div><h2 id="sample-word" lang="ja" className="prompt-word">{item.word}</h2><p lang="ja" className="reading">{item.kana}</p><p lang="ja" className="context-sentence">{item.context}</p>{state.revealed ? <div className="sample-answer" role="status"><h3 lang="vi">{item.meaning}</h3><p lang="vi">{item.translation}</p><span className="pill">Prepared AI example · No live call</span><p lang="vi">{item.note}</p></div> : <button className="primary" onClick={() => update({ ...state, revealed: true })}>Show sample meaning</button>}<div className="card-footer"><p className="small muted">An example reveal is not evidence of recall.</p><button onClick={() => update({ index: (state.index + 1) % sampleWords.length, revealed: false })}>Next sample word →</button></div></section><aside className="scope-note"><p className="eyebrow">YOUR EXACT SAMPLE SCOPE</p><h2>4 words. No extras.</h2><p>The card browser uses only the four original words in the sample wordbook.</p><ul>{sampleWords.map(word => <li key={word.id} lang="ja">{word.word}<span>{word.kana}</span></li>)}</ul><p className="small muted">Cards reveal prepared examples. Choose Recall to answer questions.</p></aside></div>;
}

function RecallBuilder({ onStart }: { onStart: (selection: SessionSelection) => void }) {
  const [ids, setIds] = useState(sampleStudyWords.map(word => word.itemId));
  const [abilities, setAbilities] = useState<LearningAbility[]>(['meaning', 'kana', 'kanji']);
  const [order, setOrder] = useState<'source' | 'random'>('source');
  const [orderedIds, setOrderedIds] = useState(ids);
  const preview = abilities.length ? selectSession({ items: sampleSnapshots(ids), selectedItemIds: ids, abilities, order, orderedItemIds: orderedIds }) : null;
  function toggleWord(id: string) {
    const next = ids.includes(id) ? ids.filter(itemId => itemId !== id) : [...ids, id];
    setIds(next);
    setOrderedIds(order === 'random' ? shuffleSampleIds(next) : sampleStudyWords.filter(word => next.includes(word.itemId)).map(word => word.itemId));
  }
  function chooseOrder(value: 'source' | 'random') {
    setOrder(value);
    setOrderedIds(value === 'random' ? shuffleSampleIds(ids) : sampleStudyWords.filter(word => ids.includes(word.itemId)).map(word => word.itemId));
  }
  return <div className="practice-layout"><section className="panel" aria-labelledby="sample-build-title">
    <p className="eyebrow">BUILD A SAMPLE PRACTICE</p><h2 id="sample-build-title">Choose exactly what to recall.</h2>
    <fieldset><legend>1. Sample words</legend>{sampleStudyWords.map(word => <label className="sample-option" key={word.itemId}>
      <input type="checkbox" checked={ids.includes(word.itemId)} onChange={() => toggleWord(word.itemId)} /><span lang="ja">{word.word}</span><span className="small" lang="ja">{word.kana}</span>
    </label>)}</fieldset>
    <fieldset><legend>2. Abilities</legend>{sampleAbilities.map(ability => <label className="sample-option" key={ability}>
      <input type="checkbox" checked={abilities.includes(ability)} onChange={() => setAbilities(abilities.includes(ability) ? abilities.filter(value => value !== ability) : sampleAbilities.filter(value => value === ability || abilities.includes(value)))} />
      <span>{abilityLabels[ability]}</span><span className="small">{ability === 'kanji' ? 'Select, then confirm' : 'Type an answer'}</span>
    </label>)}</fieldset>
    <fieldset><legend>3. Word order</legend><label className="sample-option"><input type="radio" name="sample-order" checked={order === 'source'} onChange={() => chooseOrder('source')} /><span>Sample order</span></label>
      <label className="sample-option"><input type="radio" name="sample-order" checked={order === 'random'} onChange={() => chooseOrder('random')} /><span>Shuffle selected words</span></label>
      {order === 'random' && <button onClick={() => chooseOrder('random')}>Shuffle again</button>}
    </fieldset>
    <button className="primary" disabled={!preview?.questions.length} onClick={() => { if (preview?.questions.length) onStart(preview); }}>Start sample practice</button>
  </section><aside className="scope-note" aria-labelledby="sample-preview-title">
    <p className="eyebrow">YOUR EXACT SAMPLE SCOPE</p><h2 id="sample-preview-title">Preview before you start</h2>
    <div role="status" aria-live="polite"><p>{ids.length} selected words · {preview?.counts.uniqueQuestionItems ?? 0} words with questions · {preview?.counts.abilityQuestions ?? 0} ability questions</p>
      <p className="small">{preview?.counts.availableItems ?? ids.length} available words · 0 previously studied words in this sample. Availability is not mastery.</p>
      {!ids.length && <p>Select at least one sample word.</p>}{!abilities.length && <p>Select at least one ability.</p>}
      {!!preview?.exclusions.length && <><h3>Excluded questions</h3><ul>{preview.exclusions.map(exclusion => <li key={`${exclusion.itemId}-${exclusion.ability}`}>
        <span lang="ja">{sampleStudyWords.find(word => word.itemId === exclusion.itemId)?.word}</span> · {exclusion.ability ? abilityLabels[exclusion.ability] : 'All abilities'}: {exclusion.reason === 'insufficient_choices' ? 'Needs at least two distinct selected words; no extra words added.' : exclusion.reason}
      </li>)}</ul></>}
    </div>
    <h3>Planned word order</h3><ol>{orderedIds.map(id => <li key={id} lang="ja">{sampleStudyWords.find(word => word.itemId === id)?.word}</li>)}</ol>
    <p className="small">Each word uses the selected abilities in Meaning, Kana, Kanji order. Kanji options come only from your selected words.</p>
    <p className="small">This is Practice with public examples. Formal Test, personal records, audio, XP and scheduling are unavailable. Answers and results last only while you stay in this Practice view; reloading resets them.</p>
  </aside></div>;
}

export function PracticeView() {
  const [view, setView] = useState<'recall' | 'cards'>('recall');
  const [selection, setSelection] = useState<SessionSelection | null>(null);
  return <div className="sample-practice"><PageHeading eyebrow="PRACTICE / ORIGINAL PUBLIC SAMPLES" title="Notice. Recall. Look again.">Choose a small word set, try an answer, then review what you actually answered. This sample does not create a personal learning record.</PageHeading>
    {!selection && <div className="plan-choice" role="group" aria-label="Practice view"><button aria-pressed={view === 'recall'} onClick={() => setView('recall')}>Recall</button><button aria-pressed={view === 'cards'} onClick={() => setView('cards')}>Cards</button></div>}
    {selection ? <SampleRecallSession selection={selection} onRestart={() => setSelection(null)} /> : view === 'cards' ? <SampleCards /> : <RecallBuilder onStart={setSelection} />}
    <style>{`
      .sample-practice fieldset { min-width: 0; margin: 0 0 var(--space-6); padding: var(--space-3); border: 1px solid var(--line); border-radius: var(--radius); }
      .sample-practice legend { font-weight: 600; padding: 0 var(--space-2); }
      .sample-practice .sample-option { display: flex; align-items: center; flex-wrap: wrap; gap: var(--space-3); min-height: 44px; padding: var(--space-2); cursor: pointer; }
      .sample-practice .sample-option input { width: 24px; height: 24px; min-height: 24px; flex: 0 0 24px; margin: 0; accent-color: var(--primary); }
      .sample-practice button:disabled { cursor: default; opacity: .6; }
      .sample-practice .scope-note li { display: block; overflow-wrap: anywhere; }
      .sample-practice .scope-note h3 { margin-top: var(--space-4); }
      .sample-practice .sample-actions { display: flex; flex-wrap: wrap; gap: var(--space-3); margin: var(--space-4) 0; }
      .sample-practice .recall-prompt { margin: var(--space-6) 0; font-size: 1.3rem; overflow-wrap: anywhere; }
      .sample-practice .recall-question form { margin-top: var(--space-4); }
      .sample-practice [role=alert] { border-left: 3px solid var(--attention); padding: var(--space-3); margin-top: var(--space-3); }
      .sample-practice .raw-answer { white-space: pre-wrap; overflow-wrap: anywhere; }
      .sample-practice .answer-history { padding-left: var(--space-6); }
      .sample-practice .answer-history li { padding: var(--space-4) 0; overflow-wrap: anywhere; }
      .sample-practice .table-scroll { margin: var(--space-6) 0; }
      .sample-practice .sample-answer button { margin-top: var(--space-4); }
      .sample-practice .panel, .sample-practice .scope-note { min-width: 0; }
    `}</style>
  </div>;
}
