import Link from 'next/link';

export default function HomePage() {
  return (
    <main className="flex flex-1 flex-col items-center justify-center px-6 py-24 text-center">
      <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-fd-border bg-fd-card px-3 py-1 text-xs text-fd-muted-foreground">
        <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-500" />
        Anonymous prepaid API credits
      </div>
      <h1 className="max-w-3xl text-4xl font-semibold tracking-tight md:text-6xl">
        zkAPI
      </h1>
      <p className="mt-6 max-w-2xl text-balance text-lg text-fd-muted-foreground md:text-xl">
        Fund a private note with native SOL, prove authorization in your browser,
        and pay for API usage from a private balance. Each authorization consumes
        one state; settlement returns a fresh signed balance bound to your note.
      </p>
      <div className="mt-10 flex flex-wrap items-center justify-center gap-3">
        <Link
          href="/docs"
          className="inline-flex h-11 items-center rounded-md bg-fd-primary px-6 text-sm font-medium text-fd-primary-foreground hover:opacity-90"
        >
          Read the docs
        </Link>
        <Link
          href="/docs/protocol"
          className="inline-flex h-11 items-center rounded-md border border-fd-border bg-fd-card px-6 text-sm font-medium hover:bg-fd-accent"
        >
          Protocol overview
        </Link>
        <a
          href="https://github.com/inkwell-finance/dagon-zkAPI"
          className="inline-flex h-11 items-center rounded-md border border-fd-border bg-fd-card px-6 text-sm font-medium hover:bg-fd-accent"
        >
          GitHub
        </a>
      </div>
      <div className="mt-16 grid max-w-4xl gap-4 md:grid-cols-3">
        {[
          {
            title: 'Note-bound browser proofs',
            body: 'BN254 Groth16 proofs, Baby-JubJub signatures, and commitments bound to each private note.',
          },
          {
            title: 'Private API access',
            body: 'Short-lived OpenRouter keys keep prompts and responses between your app and OpenRouter.',
          },
          {
            title: 'Native SOL settlement',
            body: 'Only actual usage reduces your balance. Close the note to withdraw the unspent SOL.',
          },
        ].map((f) => (
          <div
            key={f.title}
            className="rounded-lg border border-fd-border bg-fd-card p-5 text-left"
          >
            <h3 className="text-sm font-semibold">{f.title}</h3>
            <p className="mt-2 text-sm text-fd-muted-foreground">{f.body}</p>
          </div>
        ))}
      </div>
    </main>
  );
}
