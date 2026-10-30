'use client';
export default function DemoError({ reset }: { reset: () => void }) { return <section role="alert" className="panel"><h1 tabIndex={-1}>The sample could not open.</h1><p>Your personal data is not connected to this workspace.</p><button onClick={reset}>Try opening the sample again</button></section>; }
