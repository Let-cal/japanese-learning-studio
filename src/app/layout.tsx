import type { Metadata } from 'next';
import type { ReactNode } from 'react';
import { MotionProvider } from '@/features/motion/MotionProvider';
import '@/styles/tokens.css';

export const metadata: Metadata = { title: 'Japanese Learning Studio · Sample', description: 'A public, fixture-only Japanese study workspace. No account or private material required.' };
export default function RootLayout({ children }: { children: ReactNode }) {
  return <html lang="en"><body><MotionProvider>{children}</MotionProvider></body></html>;
}
