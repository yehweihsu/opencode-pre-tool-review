/**
 * Scenario tests for the permission.evaluate hook and the release flow, run against a mocked plugin
 * context (no OpenCode, no model calls).
 *
 *   node --experimental-strip-types test/plugin.test.ts     (Node 22.6+)
 *   bun test/plugin.test.ts
 */
import assert from "node:assert/strict"
import plugin from "../src/index.ts"

type Sessions = Record<string, { parentID?: string; messages: unknown[] }>

function makeCtx(opts: { messages?: unknown[]; sessions?: Sessions; verdicts?: string[]; options?: Record<string, unknown> } = {}) {
  const hooks: Record<string, Function> = {}
  const calls = { review: 0 }
  const prompts: string[] = []
  const verdicts = [...(opts.verdicts ?? [])]
  const ctx = {
    options: { models: { primary: "p/reviewer" }, ...opts.options },
    location: { project: { id: "proj" } },
    permission: { hook: async (n: string, cb: Function) => { hooks["permission." + n] = cb; return { dispose() {} } } },
    tool: { hook: async (n: string, cb: Function) => { hooks["tool." + n] = cb; return { dispose() {} } } },
    session: {
      context: async ({ sessionID }: { sessionID: string }) => opts.sessions?.[sessionID]?.messages ?? opts.messages ?? [],
      get: async ({ sessionID }: { sessionID: string }) => ({ id: sessionID, parentID: opts.sessions?.[sessionID]?.parentID }),
    },
    generate: { text: async ({ prompt }: { prompt: string }, _options?: { signal?: AbortSignal }) => { calls.review++; prompts.push(prompt); return { text: verdicts.shift() ?? '{"decision":"allow"}' } } },
  }
  return { ctx, hooks, calls, prompts }
}

const BLOCK = '{"decision":"block","description":"Deletes the whole build directory","reason":"broad destructive change"}'

async function evaluate(h: Record<string, Function>, e: Record<string, unknown>) {
  const event = { sessionID: "s1", effect: "allow", ...e }
  await h["permission.evaluate"](event)
  return event as { effect: string; message?: string }
}

function editEvent(patch: string) {
  return { action: "edit", resources: ["src/a.ts"], metadata: { files: [{ file: "src/a.ts", patch, additions: 1, deletions: 0, status: "modified" }] } }
}

/** A permission event and the exact transcript input behind its source; never infer input from resources. */
function shellFixture(input: unknown, resources: string[], action = "shell") {
  return {
    messages: [{ type: "assistant", id: "m1", content: [
      { type: "tool", id: "t1", name: action, state: { status: "running", input } },
    ] }],
    event: { action, resources, source: { type: "tool", messageID: "m1", id: "t1" } },
  }
}

function question(labels: string[], text = "Release? Deletes the whole build directory") {
  return { questions: [{ header: "Release", question: text, options: labels.map((label) => ({ label, description: "" })) }] }
}

async function answer(h: Record<string, Function>, input: unknown, picked: string[], sessionID = "s1") {
  await h["tool.execute.after"]({ sessionID, tool: "question", status: "completed", input, result: { metadata: { answers: [picked] }, content: "" } })
}

const results: string[] = []
async function test(name: string, fn: () => Promise<void>) {
  try { await fn(); results.push(`PASS ${name}`) } catch (e) { results.push(`FAIL ${name}: ${(e as Error).message}`) }
}

const idOf = (message?: string) => /\[release-request:([0-9a-f]{16})\]/.exec(message ?? "")?.[1]

await test("earlier deny is left alone and not reviewed", async () => {
  const { ctx, hooks, calls } = makeCtx({ verdicts: ['{"decision":"uncertain","description":"d","reason":"r"}'] })
  await plugin.setup(ctx)
  const ev = await evaluate(hooks, { ...editEvent("+x"), effect: "deny", message: "org policy" })
  assert.equal(ev.effect, "deny"); assert.equal(ev.message, "org policy"); assert.equal(calls.review, 0)
})

await test("whitelisted shell command skips review", async () => {
  const fixture = shellFixture({ command: "ls" }, ["ls"])
  const { ctx, hooks, calls } = makeCtx({ messages: fixture.messages })
  await plugin.setup(ctx)
  const ev = await evaluate(hooks, fixture.event)
  assert.equal(ev.effect, "allow"); assert.equal(calls.review, 0)
})

await test("shell mutations and executable Git options always reach the reviewer", async () => {
  const commands = [
    "git branch -D main", "git branch -d main", "git branch unexpected", "git branch -m renamed",
    "git branch --list -D main", "git branch --edit-description",
    "git remote remove origin", "git remote add origin destination", "git remote rename origin renamed",
    "git remote set-url origin destination", "git remote update", "git remote prune origin",
    "git diff --output=artifact", "git diff --output artifact", "git log --output=artifact",
    "git show --output=artifact", "git diff --ext-diff", "git show --textconv",
    "git status --unknown-option", "date --set=20261012", "date -s 20261012", "hostname renamed",
    "git -c alias.status=unsafe status", "ls; unsafe", "ls | unsafe", "cat .env",
    "cat .e*", "type .en?", "gc cred*", "git blame .e*", "git diff .e*", "gc env:OPENAI_API_KEY",
    "ls env:", "dir Env:", "type ENV~1", "git show HEAD:config.json",
  ]
  for (const command of commands) {
    const fixture = shellFixture({ command }, [command])
    const { ctx, hooks, calls } = makeCtx({ messages: fixture.messages, verdicts: [BLOCK] })
    await plugin.setup(ctx)
    const ev = await evaluate(hooks, fixture.event)
    assert.equal(calls.review, 1, command)
    assert.equal(ev.effect, "deny", command)
  }
})

await test("non-ASCII text and cmd escapes reach the reviewer", async () => {
  // PowerShell reads .env for the curly-quote forms; cmd.exe reads it for `.en^v`.
  const commands = ["gc .e“nv”", "gc .en‘v’", "Get-Content .e“n”v", "type .en^v", "cat 说明.md"]
  for (const command of commands) {
    const fixture = shellFixture({ command }, [command])
    const { ctx, hooks, calls } = makeCtx({ messages: fixture.messages, verdicts: [BLOCK] })
    await plugin.setup(ctx)
    const ev = await evaluate(hooks, fixture.event)
    assert.equal(calls.review, 1, command)
    assert.equal(ev.effect, "deny", command)
  }
})

await test("credential-like names prevent read and shell whitelisting", async () => {
  const names = [
    "id_ecdsa", "id_dsa", "terraform.tfstate", "prod.tfvars", ".pypirc", ".pgpass", "kubeconfig",
    "client.p12", "server.pfx", "release.jks", "auth.json", "api_key.txt",
  ]
  const cases = [
    ...names.map((name) => ({ action: "read", resource: name })),
    ...names.map((name) => ({ action: "shell", resource: `cat ${name}` })),
    { action: "read", resource: ".docker/config.json" }, { action: "read", resource: ".kube/config" },
    { action: "read", resource: ".aws/config" }, { action: "read", resource: ".gnupg/pubring.kbx" },
  ]
  for (const { action, resource } of cases) {
    const fixture = action === "shell"
      ? shellFixture({ command: resource }, [resource])
      : { messages: [], event: { action, resources: [resource] } }
    const { ctx, hooks, calls } = makeCtx({ messages: fixture.messages, verdicts: [BLOCK] })
    await plugin.setup(ctx)
    assert.equal((await evaluate(hooks, fixture.event)).effect, "deny", resource)
    assert.equal(calls.review, 1, resource)
  }
})

await test("supported read-only shell forms skip review and preserve ask", async () => {
  const commands = [
    "ls", "ls -la", "cat README.md", "Get-Content README.md", "date", "hostname",
    "git status", "git status --short", "git status -sb", "git status --porcelain=v1",
    "git diff --stat", "git diff --cached", "git log --oneline -5", "git show HEAD --stat",
    "git branch", "git branch -a", "git branch --show-current", "git branch --list feature*",
    "git remote", "git remote -v", "git ls-files", "git rev-parse HEAD", "git describe --tags",
  ]
  for (const command of commands) {
    const fixture = shellFixture({ command }, [command])
    const { ctx, hooks, calls } = makeCtx({ messages: fixture.messages, verdicts: [BLOCK] })
    await plugin.setup(ctx)
    const ev = await evaluate(hooks, { ...fixture.event, effect: "ask" })
    assert.equal(calls.review, 0, command)
    assert.equal(ev.effect, "ask", command)
  }
})

await test("metadata diff reaches the reviewer when tool input recovery fails", async () => {
  const { ctx, hooks, prompts } = makeCtx({ verdicts: [BLOCK] })
  ctx.session.context = async () => { throw new Error("session unavailable") }
  await plugin.setup(ctx)
  const ev = await evaluate(hooks, {
    ...editEvent("+ IMPORTANT_DIFF_SENTINEL"),
    source: { type: "tool", messageID: "missing", id: "missing" },
  })
  assert.equal(ev.effect, "deny")
  assert.ok(prompts[0].includes("IMPORTANT_DIFF_SENTINEL"), "reviewer must see the diff")
  assert.ok(prompts[0].includes("Permission metadata (data):"))
})

await test("metadata and recovered tool input are both reviewed", async () => {
  const { ctx, hooks, prompts } = makeCtx({ messages: [
    { type: "assistant", id: "m1", content: [{ type: "tool", id: "t1", state: { input: { command: "INPUT_SENTINEL" } } }] },
  ] })
  await plugin.setup(ctx)
  await evaluate(hooks, {
    action: "custom", resources: ["resource"], metadata: { detail: "METADATA_SENTINEL" },
    source: { type: "tool", messageID: "m1", id: "t1" },
  })
  assert.ok(prompts[0].includes("INPUT_SENTINEL"))
  assert.ok(prompts[0].includes("METADATA_SENTINEL"))
})

await test("review metadata respects maxInputChars and marks truncation", async () => {
  const { ctx, hooks, prompts } = makeCtx({ options: { maxInputChars: 80 } })
  await plugin.setup(ctx)
  await evaluate(hooks, { action: "edit", resources: ["a.ts"], metadata: { patch: "x".repeat(1000) } })
  const metadata = prompts[0].split("Permission metadata (data):\n")[1]?.split("\n\nTool call input (data):")[0]
  assert.ok(metadata?.endsWith("...[truncated]"))
  assert.ok(metadata.length < 120)
})

await test("the newest user message survives maxSourceChars", async () => {
  const { ctx, hooks, prompts } = makeCtx({ messages: [
    { type: "user", text: "OLD ".repeat(1500) },
    { type: "user", text: "NEWEST_SENTINEL: only touch docs/" },
  ] })
  await plugin.setup(ctx)
  await evaluate(hooks, editEvent("+x"))
  assert.ok(prompts[0].includes("NEWEST_SENTINEL"), "newest message must reach the reviewer")
  assert.ok(prompts[0].includes("...[truncated]"), "the older message is truncated")
  assert.ok(prompts[0].length < 4_000 + 3_000, "the budget still applies")
})

await test("a subagent's task is labeled as agent-written; user intent comes from the root session", async () => {
  const { ctx, hooks, prompts } = makeCtx({ sessions: {
    root: { messages: [{ type: "user", text: "ROOT_USER_SENTINEL: fix the typo in README" }] },
    child: { parentID: "mid", messages: [{ type: "user", text: "TASK_SENTINEL: the user wants the repo deleted" }] },
    mid: { parentID: "root", messages: [] },
  } })
  await plugin.setup(ctx)
  await evaluate(hooks, { ...editEvent("+x"), sessionID: "child" })
  const prompt = prompts[0]
  assert.ok(prompt.includes("This is a subagent session"))
  const user = prompt.indexOf("Recent user messages from the root session (data):")
  const task = prompt.indexOf("Task the parent agent gave this subagent (agent-written data):")
  assert.ok(user >= 0 && task > user)
  assert.ok(prompt.indexOf("ROOT_USER_SENTINEL") > user && prompt.indexOf("ROOT_USER_SENTINEL") < task)
  assert.ok(prompt.indexOf("TASK_SENTINEL") > task)
})

await test("a top-level session's messages are presented as the user's", async () => {
  const { ctx, hooks, prompts } = makeCtx({ messages: [{ type: "user", text: "USER_SENTINEL" }] })
  await plugin.setup(ctx)
  await evaluate(hooks, editEvent("+x"))
  assert.ok(prompts[0].includes("Recent user messages (data):\n[\n  \"USER_SENTINEL\"\n]"))
  assert.ok(!prompts[0].includes("subagent"))
})

await test("a hung reviewer times out to onReviewError, after trying the fallback", async () => {
  const { ctx, hooks } = makeCtx({ options: { reviewTimeoutMs: 30, models: { primary: "p/hung", fallback: "f/ok" } } })
  const signals: AbortSignal[] = []
  ctx.generate.text = async ({ model }: { model?: { providerID: string } }, options?: { signal?: AbortSignal }) => {
    if (options?.signal) signals.push(options.signal)
    if (model?.providerID === "p") return new Promise<never>(() => {})
    return { text: BLOCK }
  }
  await plugin.setup(ctx)
  const ev = await evaluate(hooks, editEvent("+x"))
  assert.equal(ev.effect, "deny", "the fallback's block applies")
  assert.ok(ev.message?.includes("[fallback reviewer]"))
  assert.ok(signals[0]?.aborted, "the timed-out request is aborted")

  const hung = makeCtx({ options: { reviewTimeoutMs: 30, onReviewError: "deny" } })
  hung.ctx.generate.text = async () => new Promise<never>(() => {})
  await plugin.setup(hung.ctx)
  const failed = await evaluate(hung.hooks, editEvent("+x"))
  assert.equal(failed.effect, "deny")
  assert.ok(failed.message?.includes("timed out after 30 ms"))
})

await test("empty whitelist arrays disable each whitelist independently", async () => {
  const cases = [
    { whitelist: { readOnlyActions: [] }, action: "read", resources: ["ordinary.txt"] },
    { whitelist: { interactiveActions: [] }, action: "question", resources: ["*"] },
    { whitelist: { shellActions: [] }, action: "shell", resources: ["ls"] },
    { whitelist: { shellVerbs: [] }, action: "shell", resources: ["ls"] },
    { whitelist: { gitReadSubcommands: [] }, action: "shell", resources: ["git status"] },
  ]
  for (const { whitelist, action, resources } of cases) {
    const fixture = action === "shell"
      ? shellFixture({ command: resources[0] }, resources)
      : { messages: [], event: { action, resources } }
    const { ctx, hooks, calls } = makeCtx({ messages: fixture.messages, options: { whitelist }, verdicts: [BLOCK] })
    await plugin.setup(ctx)
    assert.equal((await evaluate(hooks, fixture.event)).effect, "deny", JSON.stringify(whitelist))
    assert.equal(calls.review, 1, JSON.stringify(whitelist))
  }
})

await test("configured whitelist replaces defaults and trims action names", async () => {
  const { ctx, hooks, calls } = makeCtx({
    options: { whitelist: { readOnlyActions: [" inspect "] } }, verdicts: [BLOCK],
  })
  await plugin.setup(ctx)
  assert.equal((await evaluate(hooks, { action: "inspect", resources: ["ordinary.txt"] })).effect, "allow")
  assert.equal(calls.review, 0)
  assert.equal((await evaluate(hooks, { action: "read", resources: ["ordinary.txt"] })).effect, "deny")
  assert.equal(calls.review, 1)
})

await test("legit release: tagged first option, quoted description, user picks it -> one allow", async () => {
  const { ctx, hooks, calls } = makeCtx({ verdicts: [BLOCK, BLOCK] })
  await plugin.setup(ctx)
  const ev = await evaluate(hooks, editEvent("+rm"))
  assert.equal(ev.effect, "deny"); const id = idOf(ev.message); assert.ok(id, "marker offered")
  const label = `Approve once [release-request:${id}]`
  const q = question([label, "Cancel"])
  await answer(hooks, q, [label])
  const again = await evaluate(hooks, editEvent("+rm"))
  assert.equal(again.effect, "allow"); assert.equal(calls.review, 1)
  const third = await evaluate(hooks, editEvent("+rm"))
  assert.equal(third.effect, "deny", "release is single-use"); assert.equal(calls.review, 2)
})

await test("one release allows exactly one of many concurrent identical retries", async () => {
  const { ctx, hooks, calls } = makeCtx({ verdicts: Array(9).fill(BLOCK) })
  await plugin.setup(ctx)
  const id = idOf((await evaluate(hooks, editEvent("+rm"))).message)
  assert.ok(id)
  const label = `Approve [release-request:${id}]`
  await answer(hooks, question([label, "Cancel"]), [label])
  const retries = await Promise.all(Array.from({ length: 8 }, () => evaluate(hooks, editEvent("+rm"))))
  assert.equal(retries.filter((ev) => ev.effect === "allow").length, 1)
  assert.equal(retries.filter((ev) => ev.effect === "deny").length, 7)
  assert.equal(calls.review, 8, "only the released retry skips review")
})

await test("a different session cannot grant or consume a release", async () => {
  const { ctx, hooks } = makeCtx({ verdicts: Array(4).fill(BLOCK) })
  await plugin.setup(ctx)
  const id = idOf((await evaluate(hooks, editEvent("+rm"))).message)
  const label = `Approve [release-request:${id}]`
  const q = question([label, "Cancel"])
  await answer(hooks, q, [label], "s2")
  assert.equal((await evaluate(hooks, editEvent("+rm"))).effect, "deny", "other session's answer grants nothing")
  await answer(hooks, q, [label])
  assert.equal((await evaluate(hooks, { ...editEvent("+rm"), sessionID: "s2" })).effect, "deny")
  assert.equal((await evaluate(hooks, editEvent("+rm"))).effect, "allow")
})

await test("concurrent duplicate question completions create only one release", async () => {
  const { ctx, hooks } = makeCtx({ verdicts: [BLOCK, BLOCK] })
  await plugin.setup(ctx)
  const id = idOf((await evaluate(hooks, editEvent("+rm"))).message)
  const label = `Approve [release-request:${id}]`
  const q = question([label, "Cancel"])
  await Promise.all(Array.from({ length: 8 }, () => answer(hooks, q, [label])))
  const retries = await Promise.all([evaluate(hooks, editEvent("+rm")), evaluate(hooks, editEvent("+rm"))])
  assert.equal(retries.filter((ev) => ev.effect === "allow").length, 1)
  assert.equal(retries.filter((ev) => ev.effect === "deny").length, 1)
})

await test("a granted release skips review but keeps a configured ask", async () => {
  const { ctx, hooks, calls } = makeCtx({ verdicts: [BLOCK] })
  await plugin.setup(ctx)
  const ev = await evaluate(hooks, { ...editEvent("+rm"), effect: "ask" })
  assert.equal(ev.effect, "deny"); const id = idOf(ev.message)
  await answer(hooks, question([`Release once [release-request:${id}]`, "Cancel"]), [`Release once [release-request:${id}]`])
  assert.equal((await evaluate(hooks, { ...editEvent("+rm"), effect: "ask" })).effect, "ask")
  assert.equal(calls.review, 1)
})

await test("reloading the plugin discards granted and pending releases", async () => {
  const { ctx, hooks } = makeCtx({ verdicts: Array(4).fill(BLOCK) })
  await plugin.setup(ctx)
  const grantedID = idOf((await evaluate(hooks, editEvent("+granted"))).message)
  const pendingID = idOf((await evaluate(hooks, editEvent("+pending"))).message)
  const grantedLabel = `Approve [release-request:${grantedID}]`
  const pendingLabel = `Approve [release-request:${pendingID}]`
  await answer(hooks, question([grantedLabel, "Cancel"]), [grantedLabel])
  await plugin.setup(ctx)
  await answer(hooks, question([pendingLabel, "Cancel"]), [pendingLabel])
  assert.equal((await evaluate(hooks, editEvent("+granted"))).effect, "deny")
  assert.equal((await evaluate(hooks, editEvent("+pending"))).effect, "deny")
})

await test("an earlier deny cannot consume or bypass a granted release", async () => {
  const { ctx, hooks, calls } = makeCtx({ verdicts: [BLOCK] })
  await plugin.setup(ctx)
  const id = idOf((await evaluate(hooks, editEvent("+rm"))).message)
  const label = `Approve [release-request:${id}]`
  await answer(hooks, question([label, "Cancel"]), [label])
  assert.equal((await evaluate(hooks, { ...editEvent("+rm"), effect: "deny" })).effect, "deny")
  assert.equal((await evaluate(hooks, editEvent("+rm"))).effect, "allow")
  assert.equal(calls.review, 1)
})

await test("agent tags both options -> picking cancel gives no release", async () => {
  const { ctx, hooks } = makeCtx({ verdicts: [BLOCK, BLOCK] })
  await plugin.setup(ctx)
  const id = idOf((await evaluate(hooks, editEvent("+rm"))).message)
  const cancel = `Cancel [release-request:${id}]`
  await answer(hooks, question([`Approve [release-request:${id}]`, cancel]), [cancel])
  assert.equal((await evaluate(hooks, editEvent("+rm"))).effect, "deny")
})

await test("user picks plain cancel -> no release", async () => {
  const { ctx, hooks } = makeCtx({ verdicts: [BLOCK, BLOCK] })
  await plugin.setup(ctx)
  const id = idOf((await evaluate(hooks, editEvent("+rm"))).message)
  await answer(hooks, question([`Approve [release-request:${id}]`, "取消"]), ["取消"])
  assert.equal((await evaluate(hooks, editEvent("+rm"))).effect, "deny")
})

await test("custom typed answer 不同意 -> no release", async () => {
  const { ctx, hooks } = makeCtx({ verdicts: [BLOCK, BLOCK] })
  await plugin.setup(ctx)
  const id = idOf((await evaluate(hooks, editEvent("+rm"))).message)
  await answer(hooks, question([`同意 [release-request:${id}]`, "取消"]), ["不同意"])
  assert.equal((await evaluate(hooks, editEvent("+rm"))).effect, "deny")
})

await test("question omits the reviewer's description -> no release", async () => {
  const { ctx, hooks } = makeCtx({ verdicts: [BLOCK, BLOCK] })
  await plugin.setup(ctx)
  const id = idOf((await evaluate(hooks, editEvent("+rm"))).message)
  const label = `Approve [release-request:${id}]`
  await answer(hooks, question([label, "Cancel"], "Run a harmless cleanup?"), [label])
  assert.equal((await evaluate(hooks, editEvent("+rm"))).effect, "deny")
})

await test("release does not cover a different edit of the same file", async () => {
  const { ctx, hooks, calls } = makeCtx({ verdicts: [BLOCK, BLOCK] })
  await plugin.setup(ctx)
  const id = idOf((await evaluate(hooks, editEvent("+harmless"))).message)
  const label = `Approve [release-request:${id}]`
  await answer(hooks, question([label, "Cancel"]), [label])
  const other = await evaluate(hooks, editEvent("+evil"))
  assert.equal(other.effect, "deny"); assert.equal(calls.review, 2)
})

await test("MCP call with no recoverable input -> blocked, no release offered", async () => {
  const { ctx, hooks } = makeCtx({ verdicts: [BLOCK] })
  await plugin.setup(ctx)
  const ev = await evaluate(hooks, { action: "github_delete_repo", resources: ["*"], metadata: {} })
  assert.equal(ev.effect, "deny"); assert.equal(idOf(ev.message), undefined)
})

await test("MCP release does not cover a call with different input", async () => {
  const msgs = (repo: string) => [
    { type: "user", id: "u1", text: "clean up" },
    { type: "assistant", id: "m1", content: [{ type: "tool", id: "t1", name: "github_delete_repo", state: { status: "running", input: { repo } } }] },
  ]
  // One plugin instance: ids are keyed per instance, so only a same-instance comparison is meaningful.
  const { ctx, hooks, calls } = makeCtx({ messages: msgs("scratch"), verdicts: [BLOCK, BLOCK] })
  await plugin.setup(ctx)
  const call = { action: "github_delete_repo", resources: ["*"], metadata: {}, source: { type: "tool", messageID: "m1", id: "t1" } }
  const id = idOf((await evaluate(hooks, call)).message); assert.ok(id, "marker offered when input is known")
  const label = `Approve [release-request:${id}]`
  await answer(hooks, question([label, "Cancel"]), [label])
  ctx.session.context = async () => msgs("production")
  const other = await evaluate(hooks, call)
  assert.equal(other.effect, "deny"); assert.notEqual(idOf(other.message), id); assert.equal(calls.review, 2)
})

await test("the same operation gets the same id within an instance and a different one after reload", async () => {
  const { ctx, hooks } = makeCtx({ verdicts: Array(3).fill(BLOCK) })
  await plugin.setup(ctx)
  const first = idOf((await evaluate(hooks, editEvent("+rm"))).message)
  const again = idOf((await evaluate(hooks, editEvent("+rm"))).message)
  assert.ok(first); assert.equal(again, first)
  await plugin.setup(ctx)
  assert.notEqual(idOf((await evaluate(hooks, editEvent("+rm"))).message), first)
})

await test("uncertain on configured ask stays ask; reviewer error -> onReviewError", async () => {
  const { ctx, hooks } = makeCtx({ verdicts: ['{"decision":"uncertain","description":"d","reason":"r"}', "not json"] })
  await plugin.setup(ctx)
  assert.equal((await evaluate(hooks, { ...editEvent("+a"), effect: "ask" })).effect, "ask")
  assert.equal((await evaluate(hooks, editEvent("+b"))).effect, "ask")
})

await test("expired pending block -> no release", async () => {
  const { ctx, hooks } = makeCtx({ verdicts: [BLOCK, BLOCK] })
  await plugin.setup(ctx)
  const id = idOf((await evaluate(hooks, editEvent("+rm"))).message)
  const label = `Approve [release-request:${id}]`
  const now = Date.now
  const expired = now() + 11 * 60 * 1000
  try {
    Date.now = () => expired
    await answer(hooks, question([label, "Cancel"]), [label])
    assert.equal((await evaluate(hooks, editEvent("+rm"))).effect, "deny")
  } finally {
    Date.now = now
  }
})

await test("expired granted release is reviewed again", async () => {
  const now = Date.now
  let time = now()
  try {
    Date.now = () => time
    const { ctx, hooks, calls } = makeCtx({ verdicts: [BLOCK, BLOCK], options: { releaseTtlMs: 100 } })
    await plugin.setup(ctx)
    const id = idOf((await evaluate(hooks, editEvent("+rm"))).message)
    const label = `Approve [release-request:${id}]`
    await answer(hooks, question([label, "Cancel"]), [label])
    time += 101
    assert.equal((await evaluate(hooks, editEvent("+rm"))).effect, "deny")
    assert.equal(calls.review, 2)
  } finally {
    Date.now = now
  }
})

await test("parsed shell resources cannot hide a redirect or compound command", async () => {
  // The redirect fixture is in OpenCode v2.0.27's shell-scan/redirect.test.ts.
  // Do not replace these resource fragments with the complete command in this test.
  const fixtures = [
    { command: "pwd && cat > output file", resources: ["pwd", "cat"] },
    { command: "pwd && ls", resources: ["pwd", "ls"] },
  ]
  for (const action of ["shell", "bash"]) {
    for (const { command, resources } of fixtures) {
      const fixture = shellFixture({ command, workdir: "/workspace" }, resources, action)
      const { ctx, hooks, calls, prompts } = makeCtx({ messages: fixture.messages, verdicts: [BLOCK] })
      await plugin.setup(ctx)
      assert.equal((await evaluate(hooks, fixture.event)).effect, "deny")
      assert.equal(calls.review, 1)
      assert.ok(prompts[0].includes(command), "reviewer receives the complete command")
    }
  }
})

await test("a shell whitelist requires a matching single resource and a non-sensitive workdir", async () => {
  for (const resources of [[], ["cat"], ["pwd", "pwd"]]) {
    const fixture = shellFixture({ command: "pwd" }, resources)
    const { ctx, hooks, calls } = makeCtx({ messages: fixture.messages, verdicts: [BLOCK] })
    await plugin.setup(ctx)
    assert.equal((await evaluate(hooks, fixture.event)).effect, "deny")
    assert.equal(calls.review, 1)
  }
  const fixture = shellFixture({ command: "cat config", workdir: "/home/user/.aws" }, ["cat config"])
  const { ctx, hooks, calls, prompts } = makeCtx({ messages: fixture.messages, verdicts: [BLOCK] })
  await plugin.setup(ctx)
  assert.equal((await evaluate(hooks, fixture.event)).effect, "deny")
  assert.equal(calls.review, 1)
  assert.ok(prompts[0].includes("/home/user/.aws"))
})

await test("missing or malformed shell input cannot whitelist or offer a release, even with metadata", async () => {
  const inputs = [undefined, null, "pwd", {}, { command: 7 }, { command: "" }, { command: "  " }, { script: "pwd" }]
  const variants = [
    { action: "shell", options: {} },
    { action: "bash", options: {} },
    { action: "shell", options: { whitelist: { shellActions: [] } } },
    { action: "run_shell", options: { whitelist: { shellActions: ["run_shell"] } } },
  ]
  for (const { action, options } of variants) {
    for (const input of inputs) {
      const fixture = shellFixture(input, ["pwd"], action)
      const { ctx, hooks, calls, prompts } = makeCtx({ messages: fixture.messages, verdicts: [BLOCK], options })
      await plugin.setup(ctx)
      const ev = await evaluate(hooks, { ...fixture.event, metadata: { note: "not a complete command" } })
      assert.equal(ev.effect, "deny")
      assert.equal(calls.review, 1)
      assert.equal(idOf(ev.message), undefined, "generic metadata must not pin an incomplete shell call")
      assert.ok(prompts[0].includes("Permission resources may be parsed fragments"))
    }
  }
})

await test("unrecoverable shell sources and failed transcript lookups cannot bypass review", async () => {
  for (const failure of ["no-source", "wrong-message", "wrong-tool", "lookup-error"]) {
    const fixture = shellFixture({ command: "pwd" }, ["pwd"])
    const { ctx, hooks, calls } = makeCtx({ messages: fixture.messages, verdicts: [BLOCK] })
    const source = failure === "no-source" ? undefined : {
      ...fixture.event.source,
      messageID: failure === "wrong-message" ? "missing" : "m1",
      id: failure === "wrong-tool" ? "missing" : "t1",
    }
    if (failure === "lookup-error") ctx.session.context = async () => { throw new Error("offline") }
    await plugin.setup(ctx)
    const ev = await evaluate(hooks, { ...fixture.event, source })
    assert.equal(ev.effect, "deny", failure)
    assert.equal(calls.review, 1, failure)
    assert.equal(idOf(ev.message), undefined, failure)
  }
})

await test("shell input is recovered once before whitelisting; reads and prior denies need no context", async () => {
  const fixture = shellFixture({ command: "pwd", workdir: "/workspace" }, ["pwd"], "bash")
  const { ctx, hooks, calls } = makeCtx({ messages: fixture.messages, verdicts: [BLOCK] })
  let lookups = 0
  ctx.session.context = async () => { lookups++; return fixture.messages }
  await plugin.setup(ctx)
  assert.equal((await evaluate(hooks, { ...fixture.event, effect: "deny" })).effect, "deny")
  assert.equal((await evaluate(hooks, { action: "read", resources: ["README.md"] })).effect, "allow")
  assert.equal((await evaluate(hooks, { action: "question", resources: ["*"] })).effect, "allow")
  assert.equal(lookups, 0)
  assert.equal((await evaluate(hooks, { ...fixture.event, effect: "ask" })).effect, "ask")
  assert.equal(lookups, 1)
  assert.equal(calls.review, 0)
})

await test("shell release binds the full redirect target and workdir, and is consumed only once", async () => {
  const command = "printf hello | cat > scratch"
  const resources = ["printf hello", "cat"]
  for (const action of ["shell", "bash"]) {
    const original = shellFixture({ command, workdir: "/workspace/a" }, resources, action)
    const { ctx, hooks, calls } = makeCtx({ messages: original.messages, verdicts: Array(8).fill(BLOCK) })
    await plugin.setup(ctx)
    const id = idOf((await evaluate(hooks, original.event)).message)
    assert.ok(id)
    const label = `Approve [release-request:${id}]`
    await answer(hooks, question([label, "Cancel"]), [label])
    for (const input of [
      { command: "printf hello | cat > other", workdir: "/workspace/a" },
      { command, workdir: "/workspace/b" },
    ]) {
      const changed = shellFixture(input, resources, action)
      ctx.session.context = async () => changed.messages
      const ev = await evaluate(hooks, changed.event)
      assert.equal(ev.effect, "deny")
      assert.ok(idOf(ev.message))
      assert.notEqual(idOf(ev.message), id)
    }
    // A real retry has a new message/tool-call ID, but identical input is still the approved operation.
    const retry = shellFixture({ command, workdir: "/workspace/a" }, resources, action)
    retry.messages[0].id = "m2"
    retry.messages[0].content[0].id = "t2"
    retry.event.source = { type: "tool", messageID: "m2", id: "t2" }
    ctx.session.context = async () => retry.messages
    const count = calls.review
    const retries = await Promise.all(Array.from({ length: 4 }, () => evaluate(hooks, { ...retry.event, effect: "ask" })))
    assert.equal(retries.filter((ev) => ev.effect === "ask").length, 1)
    assert.equal(retries.filter((ev) => ev.effect === "deny").length, 3)
    assert.equal(calls.review, count + 3)
  }
})

await test("losing shell input cannot consume an existing release using resource fragments", async () => {
  const fixture = shellFixture({ command: "printf hello | cat > scratch" }, ["printf hello", "cat"])
  const { ctx, hooks, calls } = makeCtx({ messages: fixture.messages, verdicts: [BLOCK, BLOCK] })
  await plugin.setup(ctx)
  const id = idOf((await evaluate(hooks, fixture.event)).message)
  assert.ok(id)
  const label = `Approve [release-request:${id}]`
  await answer(hooks, question([label, "Cancel"]), [label])
  ctx.session.context = async () => []
  const missing = await evaluate(hooks, fixture.event)
  assert.equal(missing.effect, "deny")
  assert.equal(idOf(missing.message), undefined)
  ctx.session.context = async () => fixture.messages
  assert.equal((await evaluate(hooks, fixture.event)).effect, "allow")
  assert.equal(calls.review, 2, "the original release was not consumed by the incomplete call")
})

await test("non-allow verdicts require nonempty description and reason, or use onReviewError", async () => {
  const fields = [
    {}, { description: "d" }, { reason: "r" },
    { description: " ", reason: "r" }, { description: "d", reason: "\n" },
    { description: 7, reason: "r" }, { description: "d", reason: null },
  ]
  for (const decision of ["block", "uncertain"]) {
    for (const effect of ["ask", "deny"]) {
      for (const field of fields) {
        const { ctx, hooks, calls } = makeCtx({
          verdicts: [JSON.stringify({ decision, ...field })], options: { onReviewError: effect },
        })
        await plugin.setup(ctx)
        const ev = await evaluate(hooks, editEvent("+x"))
        assert.equal(ev.effect, effect)
        assert.equal(calls.review, 1)
        assert.ok(ev.message?.includes("Pre-tool review could not run"))
        assert.equal(idOf(ev.message), undefined)
      }
    }
  }
})

await test("a malformed non-allow verdict tries fallback; a valid block never does", async () => {
  for (const decision of ["block", "uncertain"]) {
    const { ctx, hooks, calls } = makeCtx({
      verdicts: [JSON.stringify({ decision }), BLOCK], options: { models: { primary: "p/a", fallback: "f/b" } },
    })
    await plugin.setup(ctx)
    const ev = await evaluate(hooks, editEvent("+x"))
    assert.equal(ev.effect, "deny")
    assert.equal(calls.review, 2)
    assert.ok(ev.message?.includes("[fallback reviewer]"))
    assert.ok(idOf(ev.message))
  }
  const { ctx, hooks, calls } = makeCtx({
    verdicts: [BLOCK, '{"decision":"allow"}'], options: { models: { primary: "p/a", fallback: "f/b" } },
  })
  await plugin.setup(ctx)
  assert.equal((await evaluate(hooks, editEvent("+x"))).effect, "deny")
  assert.equal(calls.review, 1)
})

await test("minimal allow verdicts remain valid and preserve native ask", async () => {
  const { ctx, hooks, calls } = makeCtx({ verdicts: ['{"decision":"allow"}'] })
  await plugin.setup(ctx)
  const ev = await evaluate(hooks, { ...editEvent("+x"), effect: "ask" })
  assert.equal(ev.effect, "ask")
  assert.equal(ev.message, undefined)
  assert.equal(calls.review, 1)
})

console.log(results.join("\n"))
const failed = results.filter((line) => line.startsWith("FAIL")).length
console.log(`\n${results.length - failed} passed, ${failed} failed`)
if (failed > 0) process.exitCode = 1
