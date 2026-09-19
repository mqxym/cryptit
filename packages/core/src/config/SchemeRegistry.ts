// packages/core/src/config/SchemeRegistry.ts
import { SchemeDescriptor } from "../types/index.js";
import { SchemeError } from "../errors/index.js";

export class SchemeRegistry {
  private static readonly byId = new Map<number, SchemeDescriptor>();

  static register(s: SchemeDescriptor): void {
    if (!Number.isInteger(s.id) || s.id < 0 || s.id > 7) {
      throw new SchemeError(`Scheme id must be an integer between 0 and 7: ${s.id}`);
    }
    if (this.byId.has(s.id)) throw new SchemeError(`Scheme ${s.id} already registered`);
    this.byId.set(s.id, s);
  }
  static get(id: number): SchemeDescriptor {
    const v = this.byId.get(id);
    if (!v) throw new SchemeError(`Unknown scheme: ${id}`);
    return v;
  }
  // default current scheme
  static get current(): SchemeDescriptor { return this.get(0); }
}