// The provider side of this package: one provider of the user's own,
// signed in to with the address of an upstream and its key, whose
// traffic uses DoH and, when enabled and published, ECH.
//
// The plugin runs in Bun, in magpie's plugin host. It declares one
// provider, "ech". Signing in to it asks for the address of the
// upstream and its API key, the way the user's own providers are
// written. Every sign-in is one upstream, and one upstream may be
// signed in to more than once (two keys of the same vendor, say): the
// provider can be signed in to as many times as the user likes.
//
// The provider's loader sends the requests to the sidecar, which resolves
// the upstream over DoH and forwards them to the
// address the sign-in named. Its models are the ones the upstream lists,
// asked through the sidecar as well.
//
// It exports nothing else: magpie reads every function a plugin's entry
// exports as a plugin of its own, and a helper of ours would be asked to
// be one.
import { ensureSidecar, setUpstream } from "./sidecar.mjs"
import { KINDS, addressOf, kindOf, listedOf, slugOf, validateAddress } from "./ech.providers.js"
import { dohOf, portOf } from "./ech.shared.js"

// PROVIDER is the provider this package serves. Its models come from the
// upstream each account is signed in to, so none are declared here.
const PROVIDER = "ech"

// MODELS_WAIT is what magpie gives a provider's model list. The plugin
// answers within it even when the sidecar's binary is still being downloaded
// or the first DoH lookup is slow: the listing keeps the models it had
// instead of the host reporting that the plugin finished late.
const MODELS_WAIT = 18000

// START_WAIT leaves time for the listing when the sidecar takes a while.
const START_WAIT = 15000

// MIN_LIST_WAIT is the least a listing or its one retry gets.
const MIN_LIST_WAIT = 3000
const RETRY_WAIT = 500

// within answers the value when the promise has not settled in time. The
// promise goes on, so a sidecar that is still starting is kept.
function within(promise, ms, value) {
  let timer
  const late = new Promise((resolve) => {
    timer = setTimeout(() => resolve(value), ms)
  })
  return Promise.race([promise, late]).finally(() => clearTimeout(timer))
}

export const ech = async (input, options, internals = {}) => {
  const directory = typeof input?.directory === "string" ? input.directory : ""
  const port = portOf(options)
  const doh = dohOf(options)
  const ech = options?.ech === true
  let starting
  const sidecar = () => {
    starting ??= Promise.resolve(internals.ensureSidecar?.({ directory, port, doh, ech }) ?? ensureSidecar({ directory, port, doh, ech }))
      .then((ready) => {
        if (!ready) starting = undefined
        return ready
      })
      .catch(() => {
        starting = undefined
        return false
      })
    return starting
  }

  return {
    config: async (cfg) => {
      cfg.provider ??= {}
      cfg.provider[PROVIDER] ??= {
        name: "DoH",
        npm: "@ai-sdk/openai-compatible",
        api: `http://127.0.0.1:${port}`,
        models: {},
      }
    },

    auth: {
      provider: PROVIDER,
      methods: [
        {
          type: "api",
          label: "API key",
          editable: true,
          prompts: [
            {
              type: "text",
              key: "baseURL",
              message: "Base URL",
              placeholder: "https://api.example.com/v1",
              validate: validateAddress,
            },
            { type: "select", key: "kind", message: "API", options: KINDS },
            { type: "password", key: "key", message: "API key", placeholder: "sk-…" },
          ],
          // magpie keeps the answers of the select prompts only, and an
          // api method with an authorize of its own is asked no key: the
          // authorize signs in with what was answered, and the metadata
          // it gives back is the one kept — the address among it.
          async authorize(inputs) {
            const address = addressOf(inputs)
            if (!address) return { type: "failed", error: "an http(s) address of the upstream, like https://api.example.com/v1" }
            const key = typeof inputs.key === "string" ? inputs.key.trim() : ""
            if (!key) return { type: "failed", error: "an API key of the upstream" }
            return { type: "success", key, metadata: { baseURL: address, kind: kindOf(inputs) } }
          },
        },
      ],
      async loader(getAuth) {
        const auth = await getAuth()
        if (auth?.type !== "api") return {}
        const address = addressOf(auth.metadata)
        if (!address) {
          console.error("[ech] the sign-in names no address; sign in again with one")
          return {}
        }

        // The sidecar serves every upstream any account is signed in to:
        // this one is written down for it to read.
        const slug = slugOf(address)
        setUpstream(directory, slug, address)
        return { baseURL: `http://127.0.0.1:${port}/${slug}`, apiKey: auth.key }
      },
    },

    provider: {
      id: PROVIDER,
      async models(given, { auth }) {
        // magpie hands the provider as it has it now, the models it
        // already knows among its fields: what comes back is the models
        // themselves, so a fallback hands those back, not the provider,
        // or its own fields would be read in as models of theirs.
        const known = given?.models ?? {}
        if (auth?.type !== "api") return known
        const address = addressOf(auth.metadata)
        if (!address) return known

        // The listing is what brings the sidecar up, and a loader runs
        // for a request, not for a listing: the upstream is written down
        // here, the way the loader writes it for its requests.
        const began = internals.now?.() ?? Date.now()
        setUpstream(directory, slugOf(address), address)
        console.log("[ech] waiting for the sidecar before listing models")
        const up = await within(sidecar(), internals.startWait ?? START_WAIT, false)
        if (!up) {
          console.error("[ech] the sidecar was not ready within 15s; its startup continues in the background, so the models stay as they were")
          return known
        }
        console.log(`[ech] the sidecar is ready after ${(internals.now?.() ?? Date.now()) - began}ms`)
        let failure
        const totalWait = internals.modelsWait ?? MODELS_WAIT
        for (let attempt = 1; attempt <= 2; attempt++) {
          const left = totalWait - ((internals.now?.() ?? Date.now()) - began)
          if (left < MIN_LIST_WAIT) break
          failure = {}
          const said = await (internals.listedOf ?? listedOf)(
            kindOf(auth.metadata),
            address,
            typeof auth.key === "string" ? auth.key : "",
            port,
            left,
            failure,
          )
          if (said) {
            console.log(`[ech] the models of ${address} were listed after ${(internals.now?.() ?? Date.now()) - began}ms`)
            return said
          }
          console.error(`[ech] the models of ${address} could not be listed: ${failure.reason ?? "unknown error"}`)
          const remaining = totalWait - ((internals.now?.() ?? Date.now()) - began) - RETRY_WAIT
          if (attempt === 2 || !failure.retry || remaining < MIN_LIST_WAIT) break
          console.log(`[ech] trying the model listing again in ${RETRY_WAIT}ms`)
          await (internals.delay?.(RETRY_WAIT) ?? new Promise((resolve) => setTimeout(resolve, RETRY_WAIT)))
        }
        console.error(`[ech] the models of ${address} could not be listed after ${(internals.now?.() ?? Date.now()) - began}ms; the ones known stay`)
        return known
      },
    },
  }
}
