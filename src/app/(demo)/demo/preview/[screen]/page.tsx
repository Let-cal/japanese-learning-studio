import Link from 'next/link';
import { notFound } from 'next/navigation';
import { PageHeading } from '@/components/ui/PageHeading';
import { screenFamilies } from '@/demo/fixtures';
export const metadata = { title: 'Available later · Japanese Learning Studio sample' };
export default async function PreviewPage({ params }: { params: Promise<{ screen: string }> }) {
  const { screen: id } = await params;
  const screen = screenFamilies.find(item => item.id === id && !item.href);
  if (!screen) notFound();
  return <><PageHeading eyebrow="WORKSPACE GUIDE / AVAILABLE LATER" title={screen.name}>{screen.description}</PageHeading><section className="panel"><h2>This screen is not connected yet</h2><p>The foundation provides an isolated sample shell. This part needs its own implementation and verification before it can accept data or create learning evidence.</p><Link className="button primary" href="/demo/guide">Return to the demo guide →</Link></section></>;
}
