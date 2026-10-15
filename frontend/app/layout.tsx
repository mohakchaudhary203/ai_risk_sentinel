import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AI RiskSentinel | Security Assessment",
  description: "Authorized-only hybrid security assessment dashboard",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body>{children}</body></html>;
}
