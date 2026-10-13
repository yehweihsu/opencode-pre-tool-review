# opencode-pre-tool-review

Model-assisted review for OpenCode V2 tool permissions. A reviewer model checks an action before it
runs; blocked or uncertain actions follow your configured deny/ask behavior through OpenCode's
native permission system.

**Experimental · OpenCode V2 only.** Development checks target `@opencode/plugin` 2.0.27. Use this
alongside OpenCode permission rules and appropriate OS isolation: model judgments and whitelist
matching can be wrong. V1 plugins use a different API and are not supported.

## First-time setup

No npm publication is needed. OpenCode V2 supports
[GitHub package specifications](https://opencode.ai/v2/docs/plugins).

Installation does **not** open a setup wizard or choose a reviewer automatically. You must configure
`options.models.primary`. The plugin does not inherit OpenCode's main agent model or sign you in to
a provider. Without a primary model, plugin initialization fails before the review hook is registered.

### 1. Connect a provider and find your model IDs

In OpenCode's terminal UI, run `/connect` to connect a provider you have access to, then `/models`
to find available models. You can also list model IDs from a terminal with `opencode models`.
See OpenCode's [provider setup](https://opencode.ai/v2/docs/providers) and
[model selection](https://opencode.ai/v2/docs/models) guides.

Choose a primary reviewer that can follow the JSON response format. A fallback is optional; it is
used when the primary request fails or returns an invalid response. The reviewer makes a separate
model request for each non-whitelisted permission check, so consider latency, cost and data handling.
It can use a different model from your main coding agent and does not need tool-calling support.

Use the exact `provider/model` ID, such as `opencode-go/deepseek-v4.1-flash`, rather than a display
name such as `DeepSeek V4.1 Flash`. Use the base ID without a `#variant` suffix. Keep API keys in
OpenCode's provider connection; the plugin options contain model IDs, not credentials.

### 2. Configure the plugin and reviewer together

Open or create one of these files:

- Global: `~/.config/opencode/opencode.jsonc` (Windows default:
  `%USERPROFILE%\.config\opencode\opencode.jsonc`). This applies to your projects.
- Project: `opencode.jsonc` in the project where you want review enabled.

Add the object-form entry below to its `plugins` array. The model pair shown was used in this
project's live integration checks on OpenCode 2.0.27. It requires an OpenCode Go connection with
access to both models; replace the IDs with models available to you, or omit `fallback` initially:

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [
    {
      "package": "github:yehweihsu/opencode-pre-tool-review",
      "options": {
        "models": {
          "primary": "opencode-go/deepseek-v4.1-flash",
          "fallback": "opencode-go/gpt-6-luna"
        },
        "language": "auto",
        "onBlock": "deny"
      }
    }
  ]
}
```

Use the V2 `plugins` key (plural). Keep your other configuration fields and plugin entries when
merging this example. Changing the root `model` field or selecting a model with `/models` does not
configure this plugin's reviewer; its model IDs belong inside `options.models`.

If you already ran `opencode plugin add github:yehweihsu/opencode-pre-tool-review`, replace the bare
string entry it created with the object above. Keep one entry for the package. A bare string has no
model options and is not a complete setup for this plugin.

Once the repository has a release tag, append it to the package specification, for example
`github:yehweihsu/opencode-pre-tool-review#v0.1.0`. Use a full commit hash for an immutable revision;
keep the same specification in the CLI command and configuration.

### 3. Reload and check provider access

Start OpenCode, or apply changes to an existing server:

```sh
opencode reload
opencode plugin list
```

Check startup diagnostics for load errors. To check that the primary model accepts requests, run
the following from the project where you enabled the plugin, substituting your chosen model ID:

```sh
opencode run --model opencode-go/deepseek-v4.1-flash "Reply with exactly REVIEWER_OK. Do not use tools."
```

This checks provider/model access for one run and does not change the main agent's configured model.
If you configured a fallback, check its ID in the same way. `plugin list` alone does not prove that
the review hook or model requests work.

### 4. Confirm a reviewed action works

In a disposable project, ask OpenCode to create a small scratch file. Check diagnostics for review
errors. Read-only commands such as `ls` or `git status` normally skip review, and an allowed review
does not add a dialog when OpenCode already permits the operation.

For a deliberate failure check, temporarily set `models.primary` to an unavailable model ID, omit
`fallback`, reload, then ask to create another scratch file. Expect a `Pre-tool review could not run`
message and your configured `onReviewError` behavior. Restore the real model ID and fallback, then
reload before using the plugin normally. See [Manual validation](#manual-validation) for more checks.

### Setup troubleshooting

| Symptom | Meaning and next step |
| --- | --- |
| Error mentions `options.models.primary` during loading | The plugin has no valid model reference and its review hook is not registered. Use the object-form entry with a primary model. |
| `Pre-tool review could not run` during an action | Model lookup, authentication, a request, or response parsing failed, or the request exceeded `reviewTimeoutMs`. Verify the exact ID and provider connection; the fallback is tried when configured. |
| No extra dialog for a command | It may be whitelisted or allowed. Use a non-whitelisted scratch-file operation or the deliberate failure check above. |
| Review errors still let a run continue | `onReviewError` defaults to `ask`, which is subject to auto-accept. Set it to `deny` if failures must stop execution. It only applies after successful plugin initialization. |
| A delete is allowed | Explicitly requested cleanup can be legitimate. The reviewer judges the action against user intent; it does not reject every deletion. |

The published package has no built-in provider/model defaults. Model pairs in this guide are
examples; any defaults added to a personal local deployment are specific to that installation.

### Local checkout

Clone this repository and set `package` to its directory in the same object-form entry:

```jsonc
{
  "package": "./path/to/opencode-pre-tool-review",
  "options": {
    "models": { "primary": "your-provider/your-reviewer-model" }
  }
}
```

Relative paths resolve from the configuration file. OpenCode loads the TypeScript source directly,
so no build step is needed. `npm ci` installs dependencies for local development and checks.

## How review works

The plugin hooks `permission.evaluate`. Checks already denied by OpenCode or an earlier plugin
stay denied. For other checks:

1. A whitelisted operation keeps its existing permission effect and skips the reviewer.
2. A valid, user-granted release in the same session is consumed synchronously and skips the
   reviewer for one call. The existing effect still applies, so a configured `ask` still shows
   OpenCode's dialog.
3. Otherwise, the reviewer receives recent user messages, the permission action and resources,
   permission metadata (including edit diffs), and tool input recovered from the session when
   available. Metadata is included even if input recovery fails. In a subagent session, the
   messages that started the subagent were written by the parent agent, so the reviewer gets them
   labeled as the parent agent's task and takes the user's intent from the root session.

| Reviewer result | Permission effect |
| --- | --- |
| `allow` | Preserve the existing effect, including an existing `ask`. |
| `block` | `onBlock`, default `deny`. |
| `uncertain` | `onUncertain`, default `ask`. |
| Request failure, timeout or invalid response | `onReviewError`, default `ask`. |

A deny raises OpenCode's blocked error with the reviewer's description and reason. An ask uses
OpenCode's native permission dialog and is subject to the client's auto-accept settings. For
blocking behavior on uncertainty or reviewer failures, set `onUncertain` and `onReviewError` to
`"deny"` as well.

A fallback reviewer is optional. It runs only when the primary request fails, times out or its
response is invalid; a valid primary `block` never retries against the fallback. `block` and
`uncertain` responses must include nonempty `description` and `reason` strings; missing fields
count as an invalid response, not as a releasable block. `{"decision":"allow"}` remains valid.

## Options

All options except `models.primary` are optional.

| Option | Type | Default | Meaning |
| --- | --- | --- | --- |
| `models.primary` | `"provider/model"` or `{ providerID, id }` | Required | Reviewer model. |
| `models.fallback` | Same as primary | None | Backup for request or response failures. |
| `language` | string | `"auto"` | Reviewer descriptions/reasons follow the latest available user message, or an explicit language such as `"English"`. |
| `onBlock` | `"deny"` or `"ask"` | `"deny"` | Effect when the reviewer blocks. |
| `onUncertain` | `"deny"` or `"ask"` | `"ask"` | Effect when the reviewer is unsure. |
| `onReviewError` | `"deny"` or `"ask"` | `"ask"` | Effect when review fails. |
| `allowRelease` | boolean | `true` | Enable user-confirmed, one-time releases for reviewer blocks. |
| `releaseTtlMs` | positive number | `600000` | Expiry for a pending request and, separately, its granted release. |
| `reviewTimeoutMs` | positive number | `60000` | Time limit for each reviewer request. A timeout counts as a failed request: the fallback runs if configured, then `onReviewError`. |
| `maxInputChars` | positive number | `12000` | Per-field character limit for resources, metadata and tool input. Truncation is marked. |
| `maxSourceChars` | positive number | `4000` | Character budget for recent user messages, filled from the newest message back. Older messages are truncated or omitted, and this is marked. A subagent's task gets its own budget. |
| `recentUserMessages` | positive number | `3` | Number of recent user messages included. |
| `whitelist.readOnlyActions` | string[] | `["read", "glob", "grep"]` | Read-only permission actions that skip review unless resources look sensitive. |
| `whitelist.interactiveActions` | string[] | `["question"]` | Interactive permission actions that skip review. |
| `whitelist.shellActions` | string[] | `["shell", "bash"]` | Actions eligible for shell whitelisting; requires a recovered full `command` matching a single permission resource. |
| `whitelist.shellVerbs` | string[] | See `DEFAULT_SHELL_VERBS` in [source](src/index.ts) | Permitted shell verbs, subject to syntax/argument checks. |
| `whitelist.gitReadSubcommands` | string[] | See `DEFAULT_GIT_READ_SUBCOMMANDS` in [source](src/index.ts) | Permitted Git subcommands, subject to argument checks. |

Whitelist arrays **replace** their defaults. `[]` disables that list; names are trimmed and empty
or non-string entries are discarded. Shell verb and Git subcommand names are normalized to
lowercase. Treat custom whitelist entries as explicit trust choices.

For example, review every read and shell operation while keeping the normal question-tool flow:

```jsonc
"whitelist": {
  "readOnlyActions": [],
  "shellVerbs": [],
  "gitReadSubcommands": []
}
```

Place this object inside the plugin's `options`.

## Whitelist behavior

Whitelisted operations skip model calls but still honor the existing OpenCode permission effect.
Shell matching is deliberately narrow:

- The full `command` must be recovered from the tool input before a shell call can skip review,
  and it must match one permission resource (ignoring surrounding whitespace). OpenCode can split
  commands into resources and omit operators or redirect targets: `pwd && cat > output file`, for
  example, can arrive as `["pwd", "cat"]`. Those fragments alone never justify skipping review.
  Missing or malformed tool input goes to review, even for an apparently read-only resource.
- A command must be a single, unquoted command, without chaining, pipes, redirection, substitution,
  comments or other recognized shell syntax, including cmd's `^` escape. Paths containing
  separators, `:` (drive letters, PowerShell provider paths such as `env:`), `..` or `~` go to
  review, and so do wildcards `*` and `?`, except in a `git branch --list` pattern.
- A command must be plain printable ASCII. Any other character goes to review: PowerShell treats
  curly quotes such as `“ ”` and `‘ ’` as quotes, so `gc .e“nv”` reads `.env`. Commands that name
  files with non-ASCII names are therefore reviewed too.
- Known Git subcommands accept only recognized read-only flags. Unknown flags go to review.
  `git branch` allows listing forms; a positional pattern requires `--list` or `-l`.
  `git remote` allows only listing, optionally with `-v` or `--verbose`.
- `date` and `hostname` skip review only without arguments. Custom shell verbs and custom Git
  subcommands skip review only without arguments.
- Credential-like resource names such as `.env`, `.ssh`, `id_rsa`, `id_ecdsa`, `.pem`, `.p12`,
  `.npmrc`, `.pypirc`, `kubeconfig`, `.tfstate`, `auth.json` and `token` prevent read/shell
  whitelisting. See `SENSITIVE` in the [source](src/index.ts) for the full list; it is a heuristic,
  so add OpenCode `read` rules for credential files it does not recognize. For `glob` and `grep`,
  only the resource pattern is checked; a broad search can still surface credential files.
  An explicitly supplied shell `workdir` with a sensitive name also prevents shell whitelisting.

Examples with the default lists, when the full tool input is recoverable:

| Command | Reviewed? |
| --- | --- |
| `ls -la`, `cat README.md`, `git status --short` | No |
| `git log --oneline -5`, `git diff --stat`, `git remote -v` | No |
| `git branch --list feature*` | No |
| `git branch feature`, `git branch -D main`, `git remote remove origin` | Yes |
| `git diff --output=artifact`, `git diff --ext-diff`, `git show --textconv` | Yes |
| `date --set=20261012`, `hostname renamed`, `cat .env` | Yes |
| `cat .e*`, `gc env:API_KEY`, `ls env:`, `git show HEAD:config.json` | Yes |
| `gc .e“nv”`, `type .en^v`, `cat id_ecdsa` | Yes |
| `pwd && cat > output file`, `pwd && ls` | Yes |

This matching does not inspect shell functions, executable replacements or Git configuration,
which can alter the behavior of an otherwise ordinary command. Disable the relevant lists when
you need those calls reviewed too.

## Releasing a blocked action

With `onBlock: "deny"` and `allowRelease: true`, a reviewer block can offer a one-time release.
The blocked error gives the agent a `[release-request:<id>]` marker and instructions:

1. Ask one single-choice question that quotes the reviewer's description, with an approving option
   ending in the marker and a plain cancel option.
2. The user must select exactly that marked option. The plugin checks the question and the
   question tool's structured answer; for clients without structured answers it can parse the
   tool's answer text. It never infers approval from keywords.
3. Retry the identical operation in the same session. The granted release permits exactly one
   permission check; simultaneous retries are reviewed separately after the release is consumed.

Exactly one option in the question call may contain a marker. Tagging both approve and cancel,
selecting cancel, typing a different answer, or omitting the reviewer's description grants nothing.

The operation ID includes the session, action, resources, metadata and recovered tool input.
Different edits or MCP inputs do not share a release. The ID is an HMAC-SHA-256 under a random key
held by the plugin instance, so the agent cannot compute IDs or search for a different operation
that shares an approved one. A call that cannot be identified beyond its resources is not offered
a release. Shell actions additionally require a recovered, nonempty `command`; parsed resources
or arbitrary permission metadata are not enough. The full recovered input is hashed without
truncation, including the command's redirect targets and any supplied `workdir`. Changing either
requires a new review. Disabling shell whitelisting does not relax this release requirement for
built-in `shell` and `bash` actions. Existing deny decisions cannot be bypassed by a release.

Pending requests and granted releases expire after `releaseTtlMs`. They live in memory in one
plugin instance and are discarded on plugin reload or server restart. A different session or
instance must obtain its own confirmation.

The agent supplies the question's option labels. The plugin verifies the description, marker and
selected label, but cannot verify that the label explains approval honestly. Read the question
before selecting it; set `allowRelease: false` to disable this flow.

## Privacy and limitations

- Review data is sent to your configured reviewer provider, including metadata/diffs and recovered
  tool input. A remote model receives that content; use a provider appropriate for your data.
- A normal reviewed check makes one model request. Fallback can add another, with extra cost and
  latency. Whitelisted checks make no model requests.
- Only operations that assert an OpenCode permission reach this hook.
- Missing context or truncated input can hide details. The prompt instructs the reviewer to return
  `uncertain` when it cannot determine the full effect, but that remains a model judgment.
- The reviewer is an additional check. It can misclassify actions or be influenced by untrusted data.
  Keep OpenCode permission rules and isolation appropriate to the tools you enable.
- Automated tests mock the OpenCode context and model responses. They verify plugin logic and
  concurrency behavior; they do not prove a live installation or the accuracy of a reviewer model.

## Development

Use Node.js 24 and npm for the development checks:

```sh
npm ci
npm test
npm run typecheck
npm pack --dry-run
```

The scenarios cover unsafe shell arguments (including Unicode quotes and cmd escapes), credential
names, read-only forms, empty whitelist configuration, metadata delivery/truncation, user-message
budgets, subagent sessions, reviewer timeouts, and release approval, concurrency, session
isolation, expiry and reload behavior. Shell regressions cover upstream resource fragments,
missing/malformed input, redirect-target and workdir identity, and recovery before whitelisting.
Verdict tests distinguish malformed non-allow responses from valid blocks and minimal allows.
The test suite can also run with `bun test/plugin.test.ts`.

[GitHub Actions](.github/workflows/ci.yml) is configured to run the Node.js checks on Linux and
Windows. The package ships the TypeScript source, README and MIT license; no generated build
artifacts are required.

### Manual validation

Before recommending a release, test it in a disposable project with your actual OpenCode V2 and
reviewer provider:

1. Configure a real reviewer model, reload, and check diagnostics for plugin load errors.
2. Confirm an ordinary read/whitelisted command still follows the existing permission rules.
3. Try a non-whitelisted operation on a disposable file and verify that it reaches the reviewer.
   Model decisions can vary; use the mocked tests for deterministic allow/block expectations.
4. Temporarily select an unavailable reviewer model with no fallback and verify the configured
   `onReviewError` behavior. While that unavailable model is selected, try the exact shell command
   `pwd && cat > output file` in a disposable directory containing a harmless file named `file`.
   Set `onReviewError: "deny"` for this check: review must be attempted, and `output` must not be
   created or overwritten. Restore the real reviewer and your normal options afterwards.
5. When a reviewer block offers a release, confirm that cancel leaves it blocked and approval permits
   a single identical retry in that session. Repeating a call after consumption must review again.

Report issues with the OpenCode version, reviewer provider/model, plugin options and a minimal
reproduction. Remove secrets and private content from prompts, diffs and logs before sharing them.

## License

[MIT](LICENSE)
