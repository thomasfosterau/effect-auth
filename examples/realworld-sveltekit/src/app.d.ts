import type { ConduitProfile } from "$lib/server/types";

declare global {
  namespace App {
    interface Locals {
      user: ConduitProfile | null;
      sessionId: string | null;
    }
  }
}

export {};
