'use client';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { classifyAnswerInput, type AnswerInputRejection } from '@/domain/learning/normalizeAnswer';
import type { SelectedQuestion, SessionSelection } from '@/domain/learning/selectSession';
import { abilityLabels, gradeSample, sampleAbilities, sampleKey, sampleStudyWords, type SampleAnswer } from './study-fixtures';

const rejectionMessages: Record<AnswerInputRejection, string> = {
  empty: 'Enter an answer before confirming. No answer was recorded.',
  wrong_input_type: 'Use Vietnamese for Meaning, not kana only. No answer was recorded.',
  invalid_kana: 'Use kana only and finish composing your reading. No answer was recorded.',
  invalid_choice: 'Select one of the displayed words before confirming. No answer was recorded.',
  too_long: 'Your answer exceeds the sample text limit (16,384 code units). No answer was recorded.',
};

function SamplePrompt({ question }: { question: SelectedQuestion }) {
  const word = sampleStudyWords.find(word => word.itemId === question.itemId)!;
  return question.ability === 'kanji'
    ? <><span lang="ja">{word.kana}</span> — <span lang="vi">{word.meaning}</span></>
    : <span lang="ja">{word.word} — {word.context}</span>;
}

function SampleResults({ selection, answers, onRestart }: {
  selection: SessionSelection; answers: readonly SampleAnswer[]; onRestart: () => void;
}) {
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { heading.current?.focus(); }, []);
  return <section className="panel" aria-labelledby="sample-result-title">
    <p className="eyebrow">SAMPLE / VISIT RESULTS</p>
    <h2 ref={heading} tabIndex={-1} id="sample-result-title">Your sample practice summary</h2>
    <p>{answers.length} of {selection.questions.length} questions answered. {selection.questions.length - answers.length} untested.</p>
    <p className="muted">These are actual answers from this visit. No XP, schedule or mastery changes. Reloading or leaving Practice clears these results.</p>
    <div className="table-scroll" role="region" aria-label="Sample results by ability" tabIndex={0}><table>
      <caption>By ability. Assisted overlaps the verdict counts; untested questions are outside the answered denominator.</caption>
      <thead><tr><th scope="col">Ability</th><th scope="col">Answered / planned</th><th scope="col">Matched</th><th scope="col">Incorrect</th><th scope="col">Pending</th><th scope="col">Assisted</th><th scope="col">Untested</th></tr></thead>
      <tbody>{sampleAbilities.map(ability => {
        const planned = selection.questions.filter(question => question.ability === ability).length;
        const actual = answers.filter(answer => selection.questions[answer.questionIndex].ability === ability);
        return <tr key={ability}><th scope="row">{abilityLabels[ability]}</th><td>{actual.length} / {planned}</td>
          <td>{actual.filter(answer => answer.verdict === 'matched').length}</td>
          <td>{actual.filter(answer => answer.verdict === 'incorrect').length}</td>
          <td>{actual.filter(answer => answer.verdict === 'pending').length}</td>
          <td>{actual.filter(answer => answer.assisted).length}</td><td>{planned - actual.length}</td></tr>;
      })}</tbody>
    </table></div>
    <h3>First accepted answers</h3>
    {answers.length === 0 ? <p>No answers recorded. Ending early is not an incorrect answer.</p> : <ol className="answer-history">{answers.map(answer => {
      const question = selection.questions[answer.questionIndex];
      const display = question.options?.find(option => option.optionId === answer.rawAnswer)?.label ?? answer.rawAnswer;
      return <li key={answer.questionIndex}><strong>{abilityLabels[question.ability]} · {answer.verdict}{answer.assisted ? ' · Assisted' : ''}</strong>
        <p className="history-prompt"><SamplePrompt question={question} /></p><p>First answer: <span className="raw-answer" lang={question.ability === 'meaning' ? 'vi' : 'ja'}>{display}</span></p>
        {question.inputKind === 'choice' && <p className="small">Recorded option: {answer.rawAnswer}</p>}</li>;
    })}</ol>}
    <button className="primary" onClick={onRestart}>Build another sample</button>
  </section>;
}

export function SampleRecallSession({ selection, onRestart }: { selection: SessionSelection; onRestart: () => void }) {
  const [index, setIndex] = useState(0);
  const [answers, setAnswers] = useState<SampleAnswer[]>([]);
  const [raw, setRaw] = useState('');
  const [assisted, setAssisted] = useState(false);
  const [error, setError] = useState('');
  const [finished, setFinished] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const choiceRef = useRef<HTMLInputElement>(null);
  const feedbackRef = useRef<HTMLDivElement>(null);
  const composing = useRef(false);
  const committed = useRef(false);
  const question = selection.questions[index];
  const answer = answers.find(answer => answer.questionIndex === index);
  useEffect(() => { inputRef.current?.focus(); choiceRef.current?.focus(); }, [index]);
  useEffect(() => { if (answer) feedbackRef.current?.focus(); }, [answer]);

  function submit(event: FormEvent) {
    event.preventDefault();
    if (composing.current || answer || committed.current) return;
    const checked = classifyAnswerInput(raw, question.ability, question.options?.map(option => option.optionId));
    if (!checked.accepted) {
      setError(rejectionMessages[checked.reason]);
      inputRef.current?.focus(); choiceRef.current?.focus();
      return;
    }
    setError('');
    committed.current = true;
    setAnswers(current => [...current, { questionIndex: index, rawAnswer: checked.rawAnswer,
      comparisonForm: checked.comparisonForm, verdict: gradeSample(question, checked.comparisonForm), assisted }]);
  }
  function next() {
    if (index + 1 === selection.questions.length) { setFinished(true); return; }
    setIndex(index + 1); setRaw(''); setError(''); setAssisted(false); composing.current = false; committed.current = false;
  }
  if (finished) return <SampleResults selection={selection} answers={answers} onRestart={onRestart} />;
  return <section className="panel recall-question" aria-labelledby="recall-title">
    <div className="section-heading"><span className="pill">SAMPLE PRACTICE · {index + 1} / {selection.questions.length}</span><span>{abilityLabels[question.ability]}</span></div>
    <h2 id="recall-title">{question.ability === 'meaning' ? 'What does this mean in Vietnamese?' : question.ability === 'kana' ? 'Write the reading in kana.' : 'Choose the written word.'}</h2>
    <p className="recall-prompt"><SamplePrompt question={question} /></p>
    <p id="sample-answer-hint" className="small">{question.inputKind === 'choice' ? 'Select a word, then confirm your answer.' : question.ability === 'kana' ? 'Kana only. Small kana, long vowels and dakuten matter.' : 'Write a Vietnamese meaning. Unrecognized paraphrases stay Pending.'}</p>
    <form onSubmit={submit} onKeyDown={event => {
      if (event.key === 'Enter' && (composing.current || event.nativeEvent.isComposing || event.nativeEvent.keyCode === 229)) event.preventDefault();
    }}>
      {question.inputKind === 'text' ? <><label className="field-label" htmlFor="sample-answer">{abilityLabels[question.ability]} answer</label>
        <input ref={inputRef} id="sample-answer" lang={question.ability === 'meaning' ? 'vi' : 'ja'} value={raw} disabled={Boolean(answer)} autoComplete="off" spellCheck={false}
          aria-invalid={Boolean(error)} aria-describedby={`sample-answer-hint${error ? ' sample-input-error' : ''}`}
          onChange={event => setRaw(event.target.value)} onCompositionStart={() => { composing.current = true; }} onCompositionEnd={() => { composing.current = false; }} /></>
        : <fieldset aria-describedby={`sample-answer-hint${error ? ' sample-input-error' : ''}`} aria-invalid={Boolean(error)} disabled={Boolean(answer)}>
          <legend>Kanji answer</legend>{question.options?.map((option, optionIndex) => <label className="sample-option" key={option.optionId}>
            <input ref={optionIndex === 0 ? choiceRef : undefined} type="radio" name="sample-kanji" value={option.optionId} checked={raw === option.optionId} onChange={() => setRaw(option.optionId)} /><span lang="ja">{option.label}</span>
          </label>)}
        </fieldset>}
      {error && <p id="sample-input-error" role="alert">{error}</p>}
      {!answer && <div className="sample-actions"><button className="primary" type="submit">Confirm answer</button><button type="button" onClick={() => setAssisted(true)} disabled={assisted}>Show sample help</button></div>}
    </form>
    {assisted && !answer && <div className="sample-answer" role="status"><strong>Assisted practice</strong><p>Sample answer: <span lang={question.ability === 'meaning' ? 'vi' : 'ja'}>{sampleKey(question)}</span></p><p className="small">Help before answering stays Assisted, whatever your answer.</p></div>}
    {answer && <div ref={feedbackRef} tabIndex={-1} className="sample-answer" role="status" aria-label="Answer feedback">
      <h3>{answer.verdict === 'matched' ? 'Matched the reviewed sample' : answer.verdict === 'incorrect' ? 'Incorrect for this sample' : 'Pending — meaning needs review'}{answer.assisted ? ' · Assisted' : ''}</h3>
      <p>{answer.verdict === 'pending' ? 'This phrasing is outside the curated sample answers. Semantic AI grading is unavailable; it has not been marked incorrect.' : 'Your first accepted answer is recorded for this visit.'}</p>
      <p>Sample answer: <span lang={question.ability === 'meaning' ? 'vi' : 'ja'}>{sampleKey(question)}</span></p>
      <p className="small">Viewing feedback after answering does not change the recorded assistance condition. Retry and undo are not available in this sample.</p>
      <button onClick={next}>{index + 1 === selection.questions.length ? 'Finish sample' : 'Next question →'}</button>
    </div>}
    <div className="card-footer"><p className="small">{answers.length} accepted answers · Invalid inputs are not attempts. No personal learning record.</p><button onClick={() => setFinished(true)}>Finish now</button></div>
  </section>;
}
