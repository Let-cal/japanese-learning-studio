import type { ReactNode } from 'react';
import { StudyShell } from '@/features/shell/StudyShell';
export default function DemoLayout({ children }: { children: ReactNode }) { return <StudyShell mode="demo">{children}</StudyShell>; }
