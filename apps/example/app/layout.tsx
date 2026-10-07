import type { Metadata } from "next";
import type { ReactNode } from "react";

export const metadata: Metadata = {
  title: "Tether Supabase example",
  description: "Bind a Supabase Auth session to a browser-held proof key.",
};

export default function RootLayout({ children }: { readonly children: ReactNode }) {
  return (
    <html lang="en">
      <body style={{ fontFamily: "system-ui, sans-serif", margin: "0 auto", maxWidth: 760, padding: 32 }}>
        {children}
      </body>
    </html>
  );
}
