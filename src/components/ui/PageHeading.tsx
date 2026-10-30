import type { ReactNode } from 'react';
export function PageHeading({ eyebrow, title, children }: { eyebrow: string; title: string; children?: ReactNode }) {
  return <div className="page-heading"><p className="eyebrow">{eyebrow}</p><h1 tabIndex={-1}>{title}</h1>{children && <p className="lede">{children}</p>}</div>;
}
