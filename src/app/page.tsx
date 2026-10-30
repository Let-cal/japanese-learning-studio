import Link from 'next/link';
export default function Welcome() {
  return <main className="welcome" id="main-content"><p className="eyebrow">JAPANESE LEARNING STUDIO · SAMPLE</p><h1>A calm space for Japanese.</h1><p>Explore a small, original sample wordbook and the study workspace taking shape around it.</p><div className="actions"><Link className="button primary" href="/demo">Explore sample workspace →</Link><Link className="button" href="/sign-in">Personal study status</Link></div><p className="muted">Public sample · No account needed · No private uploads</p></main>;
}
