/**
 * Fixed-window IP rate limiter. Mirrors impl/go/internal/server/ratelimit.go.
 *
 * @module
 */

import type { IncomingMessage } from "node:http";

interface Window {
  count: number;
  start: number;
}

export class IPRateLimiter {
  private readonly limit: number;
  private readonly windowMs: number;
  private readonly windows = new Map<string, Window>();

  constructor(limit: number, windowMs: number) {
    this.limit = limit;
    this.windowMs = windowMs;
  }

  /** True when `ip` is within the rate budget. */
  allow(ip: string): boolean {
    const now = Date.now();
    const w = this.windows.get(ip);
    if (w === undefined || now - w.start >= this.windowMs) {
      this.windows.set(ip, { count: 1, start: now });
      return true;
    }
    w.count++;
    return w.count <= this.limit;
  }

  /** Drop entries whose window has elapsed. */
  cleanup(): void {
    const now = Date.now();
    for (const [ip, w] of this.windows) {
      if (now - w.start >= this.windowMs) {
        this.windows.delete(ip);
      }
    }
  }
}

/** Extract the client IP from a request, preferring X-Forwarded-For. */
export function clientIP(req: IncomingMessage): string {
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff !== "") {
    const comma = xff.indexOf(",");
    return comma >= 0 ? xff.slice(0, comma).trim() : xff.trim();
  }
  if (Array.isArray(xff) && xff.length > 0) {
    return xff[0]?.split(",")[0]?.trim() ?? "";
  }
  return req.socket.remoteAddress ?? "";
}
