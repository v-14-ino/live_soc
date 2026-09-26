// ============================================================
// LiveSOC - Monitoring module barrel export
//
// Re-exports all backend logic modules so they can be imported
// from a single entry point. Safe to import from both Next.js
// (node runtime) and the standalone socket.io mini-service.
//
// No Next.js-specific imports are present in any of these modules.
// ============================================================

export * from "./scanner";
export * from "./telemetry";
export * from "./detection";
export * from "./correlation";
export * from "./stats";
export * from "./audit";
export * from "./session";
export * from "./report";
