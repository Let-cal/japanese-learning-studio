import { createEmptyCard, fsrs, Rating, type Card, type RecordLogItem } from 'ts-fsrs';

// Compile the intended public API without fixing product policy here.
const probeTime = new Date('2026-10-28T12:00:00Z');
const probeCard: Card = createEmptyCard(probeTime);
const probeResult: RecordLogItem = fsrs().next(probeCard, probeTime, Rating.Good);
void probeResult;
