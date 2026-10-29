import assert from 'node:assert/strict';
import test from 'node:test';
import { createEmptyCard, fsrs, Rating, State } from 'ts-fsrs';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { motion } from 'motion/react';
import * as Dialog from '@radix-ui/react-dialog';

// Dependency contract probes only; these do not define product learning policy.
test('FSRS exposes four review outcomes without mutating the source card', () => {
  const now = new Date('2026-10-28T12:00:00Z');
  const card = createEmptyCard(now);
  const before = structuredClone(card);
  const outcomes = fsrs().repeat(card, now);
  for (const grade of [Rating.Again, Rating.Hard, Rating.Good, Rating.Easy]) {
    assert.ok(outcomes[grade].card.due instanceof Date);
    assert.ok(outcomes[grade].card.due.getTime() > now.getTime());
    assert.equal(outcomes[grade].log.rating, grade);
  }
  assert.deepEqual(card, before);
});

test('FSRS review accepts its previous outcome and increments repetitions', () => {
  const scheduler = fsrs();
  const now = new Date('2026-10-28T12:00:00Z');
  const first = scheduler.next(createEmptyCard(now), now, Rating.Good);
  const second = scheduler.next(first.card, first.card.due, Rating.Good);
  assert.equal(second.card.reps, first.card.reps + 1);
  assert.notEqual(second.card.state, State.New);
  assert.ok(Number.isFinite(second.card.stability));
});

test('React server rendering imports Motion and Radix with Japanese text', () => {
  const markup = renderToStaticMarkup(createElement(Dialog.Root, {},
    createElement(motion.div, { initial: false },
      createElement(Dialog.Trigger, {}, '日本語 compatibility'))));
  assert.match(markup, /日本語 compatibility/);
  assert.match(markup, /aria-haspopup="dialog"/);
});
