export const meta = {
  name: 'varve-docs-friction-audit',
  description: 'Ten personas try to USE varve from its embedded docs alone; find blockers, gaps and unhelpful errors',
  phases: [
    { title: 'Evaluate', detail: '10 personas run real commands from the docs' },
    { title: 'Synthesize', detail: 'rank blockers, doc gaps and friction' },
  ],
}

const BINARY = '/Volumes/Home/git/pulseengine/varve/target/debug/varve'

const COMMON = `
You are evaluating varve's EMBEDDED documentation by actually USING the tool, as a real
user would. varve is a toolchain layer manager (pinned, signed, dated tool bundles).

THE BINARY: ${BINARY}  (version 0.23.0)

GROUND RULES — these matter, do not shortcut them:
- Your ONLY sources of truth are \`varve docs\`, \`varve docs <topic>\`, \`varve docs --grep <q>\`
  and \`--help\`. You may read README.md at /Volumes/Home/git/pulseengine/varve/README.md.
  You may NOT read the Rust source to figure out how to do something — if you need the
  source to proceed, THAT IS A FINDING (the docs failed).
- ACTUALLY RUN COMMANDS. Do not theorise. Work in your own scratch dir under /tmp and set
  VARVE_ROOT to a scratch path so you never touch the real store at ~/.varve.
- NEVER modify the varve repo. Do not git commit, do not edit files in the repo. Read-only.
- Judge FRICTION honestly. The project's stated fear is that the tool causes friction.
  A command that works but whose docs made you guess is friction. An error that tells you
  what went wrong but not what to DO is friction.

FOR EVERY ERROR YOU HIT, capture: the exact command, the exact error text, and judge it:
does it say (a) what happened, (b) why, (c) what to do next? A varve design principle is
"an error carrying its fix, never a fallback" — hold it to that.

Be concrete and quote real output. Do not pad. If something worked well, say so briefly —
a false-negative audit is as useless as a false-positive one.
`

const SCHEMA = {
  type: 'object',
  properties: {
    persona: { type: 'string' },
    outcome: { type: 'string', enum: ['succeeded', 'succeeded_with_friction', 'blocked'] },
    summary: { type: 'string', description: '2-3 sentences: could you do the job from the docs?' },
    blockers: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          what: { type: 'string' },
          evidence: { type: 'string', description: 'exact command + output' },
          severity: { type: 'string', enum: ['blocked', 'major', 'minor'] },
        },
        required: ['what', 'evidence', 'severity'],
      },
    },
    missing_docs: {
      type: 'array',
      items: { type: 'string', description: 'a question the docs do not answer' },
    },
    bad_errors: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          command: { type: 'string' },
          error: { type: 'string' },
          why_bad: { type: 'string' },
          better: { type: 'string', description: 'concrete suggested wording' },
        },
        required: ['command', 'error', 'why_bad', 'better'],
      },
    },
    good: { type: 'array', items: { type: 'string' } },
    top_fix: { type: 'string', description: 'the single highest-value fix for this persona' },
  },
  required: ['persona', 'outcome', 'summary', 'blockers', 'missing_docs', 'bad_errors', 'top_fix'],
}

const PERSONAS = [
  {
    key: 'first-contact',
    task: `PERSONA: a developer who has never seen varve. You were told "use varve to get the
toolchain". Start from nothing. Goal: get to a working dispatched tool.
Try: \`varve docs\`, pick your way through. Create a project dir, write a varve.toml, try to
install something, try to run a tool. You have NO trust root and NO realms file initially —
find out from the docs how to get them. Judge: how many steps before you are stuck? Is the
"getting started" path discoverable from \`varve docs\` ALONE (not the README)?`,
  },
  {
    key: 'verify-and-trust',
    task: `PERSONA: a security engineer. Goal: understand precisely what \`varve verify\` proves
and what it does NOT. Read every trust-related topic (trust-roots, realms, verify, layers,
self-verify). Then try to answer, from docs only: What does verify check? Does it check
included layers? What happens if a tool binary is tampered with? What does the trust root
protect against, and what is out of scope (transparency log? revocation? key rotation?).
Actually run verify in failure modes you can construct. Judge whether the docs let a
security reviewer form an accurate mental model, or whether they overclaim.`,
  },
  {
    key: 'create-a-layer',
    task: `PERSONA: a release engineer who must PRODUCE a layer for the first time. Goal: deposit
a layer containing a tool you provide, sign it, and end up with something installable.
Use \`varve docs deposit\` and anything it points to. You need to work out: how to get a
signing key, the spec file format (or the flags), what annotations matter, what
issued-at/counter mean and what values to use. ACTUALLY DO IT end to end — produce a layer
and then install it into a scratch store. Judge: could a release engineer do this from the
docs without reading Rust source? What did you have to guess?`,
  },
  {
    key: 'deploy-and-distribute',
    task: `PERSONA: a platform engineer who has a layer and must get it to consumers. Goal: work
out the distribution story from the docs. How do you publish a layer (OCI registry? archive?
what exactly)? How do consumers point at it? What is a realms file, where does it live, what
goes in it, and who writes it? How does a consumer bootstrap trust the FIRST time?
Try to produce a realms file and an archive from the docs. Judge whether "deploy" is
documented at all, or whether the docs stop at the local/consumer side.`,
  },
  {
    key: 'own-realm-extend',
    task: `PERSONA: an organisation that wants its OWN trust universe — their own key, their own
tools, their own layers — not PulseEngine's. Goal: from the docs, work out how to stand up
your own realm end to end: generate a root key, define the realm, deposit under it, and have
a consumer pin it. This is the "extend / create your own set" path. Actually attempt it.
Judge: is this documented at all? Is it discoverable? What is missing to make an
organisation self-sufficient rather than a PulseEngine consumer?`,
  },
  {
    key: 'composition',
    task: `PERSONA: a consumer who needs tools from TWO sources — an org layer plus an upstream
layer (this is varve 0.23.0's new layer composition). Goal: from docs only, work out what
composition is, how to CREATE a composed layer, how to install one, and what verify does
with it. Try \`varve docs\` topics and --grep for "compose"/"include". Actually attempt to
build and install a composed layer. Judge whether a brand-new feature arrived with usable
documentation or only with a changelog entry.`,
  },
  {
    key: 'air-gapped',
    task: `PERSONA: an operator in an air-gapped facility. No internet, ever. Goal: from docs
only, work out the complete offline workflow: how to get a layer in, how to install without
network, how to verify offline, how to update, and what breaks. Read the air-gap topic and
archive topic. Actually simulate it: build an archive, then install from it with no network
source. Judge: air-gapped operation is varve's flagship claim — do the docs actually support
it end to end, or do they assume a registry somewhere?`,
  },
  {
    key: 'error-quality',
    task: `PERSONA: a hostile usability tester focused ONLY on error messages. Goal: deliberately
do wrong things and grade every error. Try at least 15 distinct failure modes across many
commands: missing pin, malformed varve.toml, wrong layer name, missing trust root, wrong
trust root, tool not in layer, uninstalled layer, bad digest, unknown subcommand, bad flag
values, missing files, wrong format strings, tampered store, nonexistent topic, unknown
payload kind, bad lockfile, etc.
For EACH: does the error say what happened, why, and what to do? varve claims "an error
carrying its fix, never a fallback" — grade against that claim and name every error that
fails it. This is the highest-value persona: quote the exact text and propose better wording.`,
  },
  {
    key: 'ci-integration',
    task: `PERSONA: a CI engineer wiring varve into a pipeline. Goal: from docs only, work out
every CI-side command and how they fit together: deposit, sign-status, attach-status,
sign-sums, sign-attestation, and how status/yank information reaches consumers. What secrets
does CI need? What is the ordering? What is idempotent? Try running the CI-side commands.
Judge whether someone could wire a real release pipeline from these docs.`,
  },
  {
    key: 'distribution-adapters',
    task: `PERSONA: a build engineer who wants varve to feed their build system. Goal: from docs
only, understand the export adapters and distribution-beyond-binaries story: export-cargo,
export-crates-vendor, export-bazel, export-bazel-distdir, sbom, verify --lockfile,
verify --export, payload kinds (crate/wit/sdk/wasm-component). Work out which to use when,
and what each produces. Actually run the ones you can. Judge whether the choice between four
export commands is clear, and whether the payload-kind story is comprehensible.`,
  },
]

phase('Evaluate')
const results = await parallel(
  PERSONAS.map((p) => () =>
    agent(`${COMMON}\n\n${p.task}\n\nReturn your findings in the required structure.`, {
      label: `eval:${p.key}`,
      phase: 'Evaluate',
      schema: SCHEMA,
    })
  )
)

const found = results.filter(Boolean)
log(`${found.length}/10 personas reported`)

phase('Synthesize')
const blocked = found.filter((r) => r.outcome === 'blocked').map((r) => r.persona)
const synthesis = await agent(
  `Ten personas tried to USE varve from its embedded documentation alone and reported
structured findings. Synthesize them into an actionable plan for the maintainer.

RAW FINDINGS:
${JSON.stringify(found, null, 1)}

Produce:
1. VERDICT: is the embedded documentation adequate in scope? One paragraph, blunt.
2. BLOCKED PATHS: which personas could NOT complete their job, and the single reason each.
   (Reported blocked: ${blocked.join(', ') || 'none'})
3. THE DOC GAPS THAT MATTER, ranked. For each: what question goes unanswered, who it
   blocks, and what topic should answer it. Distinguish MISSING TOPICS from THIN TOPICS.
4. WORST ERROR MESSAGES, ranked by friction caused. Quote the actual text and give the
   concrete better wording. Call out any error that violates varve's own stated principle
   ("an error carrying its fix, never a fallback").
5. THE PRODUCER/EXTENDER STORY specifically: can an organisation create its own layers and
   its own realm from these docs? This is the maintainer's main worry — answer it directly.
6. TOP 10 FIXES, ranked by (friction removed / effort). Be specific enough to act on:
   name the topic to add or the message to change.
Deduplicate aggressively — if six personas hit the same wall, say so once and note it is
six. Be blunt about what is genuinely fine, so the maintainer does not rewrite working docs.`,
  { label: 'synthesize', phase: 'Synthesize' }
)

return { personas: found.length, blocked, synthesis }
