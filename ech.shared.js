// The names this package and magpie agree on.
//
// The plugin (ech.plugin.js) and the sidecar's keeper (sidecar.mjs) run
// in Bun, in magpie's plugin host; what they both use is written here.

// DEFAULT_PORT is the port the sidecar listens on.
export const DEFAULT_PORT = 8790

// portOf is the port the sidecar listens on, as the user set it: the one
// in the options, else the default. A port that is no port is no port.
export function portOf(options) {
  const port = options && Number(options.port)
  return Number.isInteger(port) && port > 0 && port < 65536 ? port : DEFAULT_PORT
}

// echOf says whether automatic ECH discovery was explicitly enabled.
export function echOf(options) {
  return options?.ech === true
}

// dohOf is the DoH endpoints the user set, as sidecarArgs hands them to
// -doh: comma separated. Nothing set leaves the sidecar's own default and
// lets it ask the built-in resolvers.
export function dohOf(options) {
  const doh = options && typeof options.doh === "string" ? options.doh.trim() : ""
  return doh
}
