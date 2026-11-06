import type { Metadata } from 'next';
import { RootProvider } from 'fumadocs-ui/provider/next';
import './global.css';

export const metadata: Metadata = {
  title: {
    default: 'zkAPI — Anonymous prepaid API credits',
    template: '%s — zkAPI',
  },
  description:
    'Private prepaid API usage with note-bound Groth16 proofs, Schnorr-signed balances, short-lived OpenRouter keys, and native SOL settlement.',
};

export default function Layout({ children }: LayoutProps<'/'>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="flex flex-col min-h-screen font-sans">
        <RootProvider>{children}</RootProvider>
      </body>
    </html>
  );
}
