import type { ReactNode } from 'react';
import './globals.css';

export default function Layout({ children }: { children: ReactNode }) {
  return <html lang="ja"><body>{children}</body></html>;
}
