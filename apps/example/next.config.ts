import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  transpilePackages: ["@tether/core", "@tether/client", "@tether/next"],
};

export default nextConfig;
