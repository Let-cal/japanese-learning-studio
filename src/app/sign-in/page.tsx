import Link from 'next/link';
export const metadata = { title: 'Personal study status · Japanese Learning Studio' };
export default function SignIn() {
  return <main className="welcome" id="main-content"><p className="eyebrow">PERSONAL STUDY</p><h1>Your private workspace comes later.</h1><p>Owner authentication and private storage are not connected in this foundation. There is no sign-in or upload here yet.</p><Link className="button primary" href="/demo">Explore the isolated sample →</Link></main>;
}
