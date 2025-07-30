// packages/core/src/config/VersionRegistry.ts
import { VersionDescriptor } from "../types/index.js";

export class VersionRegistry {
  private static readonly byId = new Map<number, VersionDescriptor>();

  /** register at app‑start (or dynamically for plug‑ins) */
  static register(v: VersionDescriptor): void {
    if (this.byId.has(v.id)) throw new Error(`Version ${v.id} already registered`);
    this.byId.set(v.id, v);
  }
  static get(id: number): VersionDescriptor {
    const v = this.byId.get(id);
    if (!v) throw new Error(`Unknown version: ${id}`);
    return v;
  }
  /** default (current) version – convenience */
  static get current(): VersionDescriptor { return this.get(0); }
}