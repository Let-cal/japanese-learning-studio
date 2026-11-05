# Sample recall and pure learning rules

Verified locally on 2026-11-05, against uncommitted work based on `92ee26f8f57a64b9648d002becd296e27327d6e7`. This is not a hosted release or personal learning acceptance.

## What works

- Select exactly the original public sample words and Meaning, Kana or Kanji abilities; preview distinct words and ability questions separately. Source/shuffle ordering is explicit. Unavailable questions are excluded without padding from another scope.
- Submit text or a confirmed choice, preserve the first accepted answer, distinguish help used before answering, and finish early with unanswered questions counted as untested.
- Match curated Vietnamese meanings, compare reviewed kana and choice keys deterministically, and keep unrecognized meaning paraphrases Pending. No AI request is made.
- Retain the legacy sample Cards view. Recall answers exist only in the current React view; reload or leaving resets them.
- Reuse pure, immutable selection rules with revision/source snapshots and bounded input classification. Normalization is trim plus NFC only, preserving the original answer and meaningful script differences.

## Evidence

| Check | Result |
| --- | --- |
| Ordinary Vitest suite | 450 tests / 20 files passed |
| Focused domain suite | 74 tests passed, including three sparse-array RED-to-GREEN regressions |
| TypeScript, JavaScript/config lint, production build | Passed |
| OpenAPI syntax, references and generated freshness | Passed; operations remain planned |
| Full Chromium suite | 17 passed in 32.8 seconds |
| New recall scenarios | Subset/ability scope, NT1 validation, immutable first answer, assistance, Pending meanings, partial results, reset, IME Enter |
| Recall accessibility | Builder/question/results at 320, 768 and 1440 CSS px: axe WCAG A/AA tags, keyboard table scrolling, focus and language assertions |
| Existing shell regression | Five viewport widths, reduced motion, unavailable browser storage and public-provider isolation retained |

The initial full browser run had three failures: an ambiguous alert locator selected Next's route announcer, and two narrow results views exposed a keyboard-inaccessible scroll region. The locator now targets the owned validation error. The results region is named and focusable; ArrowRight scrolling is asserted. A focused six-test run passed, followed by the full 17-test result above. This was not a suppression of accessibility rules.

Independent read-only review approved the core and scoped UI corrections. The parent independently ran aggregate checks and inspected production-preview builder/question screenshots. Automated axe coverage is not complete WCAG conformance, real Safari testing or human UAT.

## Remaining work

Personal Auth, persistent approved items/answers/results, formal Test mode, per-ability scheduling, audio/pronunciation, OCR, sync and recovery are not implemented by this slice. Availability is not mastery. No XP or schedule is updated. This sample is not the full Task6 completion.

ADR0006 is a separate proposed Auth boundary; publishing its text does not approve credentials, SQL or cloud activation. Human diff, merge, security, UAT and release gates remain unchanged. No dependency, cloud configuration, hosted data or payment change is included.
