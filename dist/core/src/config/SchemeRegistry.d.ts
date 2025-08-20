import { SchemeDescriptor } from "../types/index.js";
export declare class SchemeRegistry {
    private static readonly byId;
    static register(s: SchemeDescriptor): void;
    static get(id: number): SchemeDescriptor;
    static get current(): SchemeDescriptor;
}
