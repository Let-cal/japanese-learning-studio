'use client';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useEffect, useRef, type ReactNode } from 'react';
import { EffectsToggle } from '@/features/motion/MotionProvider';

const navigation = [{ href: '', name: 'Today', icon: '◷' }, { href: '/library', name: 'Library', icon: '▤' }, { href: '/practice', name: 'Practice', icon: 'あ' }, { href: '/progress', name: 'Progress', icon: '↗' }];
export function StudyShell({ children, mode }: { children: ReactNode; mode: 'personal' | 'demo' }) {
  const pathname = usePathname();
  const previousPath = useRef(pathname);
  const main = useRef<HTMLElement>(null);
  useEffect(() => {
    if (pathname !== previousPath.current) {
      main.current?.querySelector<HTMLElement>('h1')?.focus();
      previousPath.current = pathname;
    }
  }, [pathname]);
  if (mode === 'personal') return <main id="main-content" className="welcome"><h1>Personal workspace unavailable</h1><p>Owner access is not connected yet.</p><Link className="button" href="/demo">Open sample workspace</Link></main>;
  return <div className="study-shell">
    <a className="skip-link" href="#main-content">Skip to content</a>
    <aside className="rail">
      <Link href="/demo" className="brand" aria-label="Japanese Learning Studio sample home"><span className="brand-mark" aria-hidden="true">言</span><span>Japanese<br />Learning<span className="brand-sub">STUDIO · SAMPLE</span></span></Link>
      <p className="rail-caption">A LITTLE, EVERY DAY</p>
      <nav aria-label="Study">{navigation.map(item => <Link key={item.name} href={`/demo${item.href}`} aria-current={pathname === `/demo${item.href}` ? 'page' : undefined}><span className="nav-icon" aria-hidden="true">{item.icon}</span>{item.name}</Link>)}</nav>
      <div className="rail-footer"><span className="small muted">Your own pace.<br />Room to keep growing.</span><Link href="/demo/guide" aria-current={pathname === '/demo/guide' ? 'page' : undefined}>Demo guide</Link><Link href="/sign-in">Personal study status</Link></div>
    </aside>
    <div className="workspace">
      <header className="workspace-bar"><span className="mobile-name"><span aria-hidden="true">JLS</span><span className="sr-only">Japanese Learning Studio</span></span><span className="sample-label">Sample workspace</span><span className="header-note">Original examples · Nothing personal</span><EffectsToggle /></header>
      <main ref={main} id="main-content" tabIndex={-1}>{children}</main>
      <footer className="workspace-footer"><span>Sample only. No learning record is created.</span><Link href="/demo/guide">What’s available?</Link><Link className="mobile-guide" href="/demo/guide">Demo guide</Link></footer>
    </div>
  </div>;
}
