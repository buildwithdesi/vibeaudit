# Protection pilot

Run one reviewed Node.js skill against selected input in an offline Docker
container. A successful run produces the expected result and a host-written
receipt showing the enforced restrictions, exit status, and cleanup outcome.

This pilot covers executable skill scripts. It does not start an AI assistant,
send prompts to a model, inject provider credentials, or install agent hooks.
The [example skill](../examples/protection-pilot/skill/SKILL.md) turns a small
notes file into JSON without package installation or network access.

## What is protected

| Boundary | Pilot behavior |
|---|---|
| Skill and input | Review binds file paths and contents. A changed bundle needs a new review and approval. Execution uses the reviewed snapshot. |
| Filesystem | Only the staged skill and input are exposed at readonly `/skill` and `/input`. The workload can use disposable `/tmp` scratch space. |
| Network | The container has networking disabled. No destination allowlist or online mode is included. |
| Host credentials and policy | The host home directory, Docker socket, credentials, approval store, and receipt store are not mounted. |
| Process privileges | A trusted root PID 1 supervisor retains only the capabilities needed to drop identity and terminate the workload. The workload runs as UID/GID 65534 without capabilities. |
| Lifetime and resources | Container resource limits apply. The supervisor enforces the approved deadline independently of the host CLI; the default is 30 seconds. |
| Approval | A review digest acknowledges the exact bundle and execution policy. Approval expires after ten minutes and can be used once or revoked. |
| Output | Workload stdout is stored as untrusted data in JSON. It is not evaluated or rendered as instructions. |

The trusted computing base includes VibeGuard, its host account and store, the
selected official Node image, Docker and its Linux daemon/kernel, and the
supervisor. A hostile host administrator, compromised Docker daemon, or kernel
escape is outside this pilot's protection claim. Linux containers share the
daemon's kernel; this is not a separate microVM per skill.

Static findings help a person review a skill. A scan with no findings is not
proof that the skill is safe. Runtime restrictions must still hold for code the
scanner fails to recognize.

## Prepare Docker and the image

Use an existing, working local Docker installation running Linux containers.
Remote Docker daemons and Windows containers are outside the supported pilot.
The CLI does not start Docker, install runtimes, pull images, or fall back to
executing the skill on the host.

Choose an official Node image reference of the form
`node@sha256:<64 hexadecimal characters>`. Obtain and review the digest through
your image provisioning process. Pull that exact reference explicitly before
the pilot. A digest fixes the selected content; it does not independently prove
publisher authenticity or freedom from vulnerabilities.

Keep the skill directory and input directory separate. Supply only the input
needed for the task. Review records and receipts belong outside both directories;
the default store is `~/.vibeaudit/pilot`. An optional `--store <path>` selects an
external store and must be supplied consistently across commands.

Check readiness **before creating a review or spending its one-use approval**:

```text
node bin/vibeguard.js pilot doctor --image node@sha256:<reviewed-digest>
```

Doctor checks the Docker executable, the fixed local Linux engine, and the
already provisioned image. It prints `ready`, `unavailable`, or `blocked` with a
reason and a concrete next step. Add `--json` for a versioned result with stable
reason codes and individual checks. Exit 0 means ready; exit 4 means the check
did not establish readiness. Doctor never pulls an image, creates a container,
starts Docker, or reads or changes the approval store. It verifies removal of its
isolated temporary Docker client configuration before reporting readiness.

Readiness is a prerequisite check. It does not activate or verify isolation.
`pilot run` repeats the same runtime checks and inspects each container's policy
before starting it. A run attempt still consumes its one-use approval, including
when Docker or the image has become unavailable since doctor passed.

On Windows, the pilot addresses Docker Desktop's local Linux engine pipe. A
working remote context or Windows container engine does not satisfy this check.
On Linux, it uses the local `/var/run/docker.sock` endpoint. Inherited Docker
contexts, remote hosts, credentials, and proxy variables do not choose the
pilot's engine or client configuration.

## Run the example in PowerShell

Run these commands from the repository checkout. The prompt asks for the exact
image reference you selected; no mutable tag is accepted by the pilot.

```powershell
$pilotImage = Read-Host 'Approved official Node image reference (node@sha256:...)'
docker pull $pilotImage
if ($LASTEXITCODE -ne 0) { throw 'Image provisioning failed.' }

node bin/vibeguard.js pilot doctor --image $pilotImage
if ($LASTEXITCODE -ne 0) { throw 'Resolve the reported runtime issue before reviewing or approving a skill.' }

$pilotReviewText = node bin/vibeguard.js pilot review ./examples/protection-pilot/skill --input ./examples/protection-pilot/input --entry run.mjs --image $pilotImage --seconds 30 --json
if ($LASTEXITCODE -ne 0) { throw 'Pilot review failed. Read its error before continuing.' }
$pilotReview = $pilotReviewText | ConvertFrom-Json
$pilotReview | ConvertTo-Json -Depth 20
```

Read the source files, returned file manifest, findings, and policy. The next
command acknowledges that review. Do not automatically approve an unfamiliar
skill just because it received a digest.

```powershell
node bin/vibeguard.js pilot approve $pilotReview.id --accept $pilotReview.id --json
if ($LASTEXITCODE -ne 0) { throw 'Pilot approval failed.' }

node bin/vibeguard.js pilot run $pilotReview.id --json
if ($LASTEXITCODE -ne 0) { throw 'Pilot did not complete successfully. Inspect its receipt.' }
node bin/vibeguard.js pilot status --json
```

## Run the example in Bash

```bash
read -r -p 'Approved official Node image reference (node@sha256:...): ' pilot_image
docker pull "$pilot_image" || exit 1
node bin/vibeguard.js pilot doctor --image "$pilot_image" || exit 1

pilot_review=$(node bin/vibeguard.js pilot review ./examples/protection-pilot/skill --input ./examples/protection-pilot/input --entry run.mjs --image "$pilot_image" --seconds 30 --json) || exit 1
printf '%s\n' "$pilot_review"
pilot_id=$(printf '%s' "$pilot_review" | node --input-type=module -e 'let text=""; for await (const chunk of process.stdin) text += chunk; console.log(JSON.parse(text).id);')
```

Read the source, manifest, findings, and policy before acknowledging this review:

```bash
node bin/vibeguard.js pilot approve "$pilot_id" --accept "$pilot_id" --json || exit 1
node bin/vibeguard.js pilot run "$pilot_id" --json || exit 1
node bin/vibeguard.js pilot status --json
```

The example result contains three items, `lineCount: 3`, and `wordCount: 21`.
Read the generated receipt and the captured stdout. An exit code alone does not
prove that the task result is correct or that cleanup succeeded.

## Revoke and recover

Before execution, invalidate an approval with:

```text
node bin/vibeguard.js pilot revoke <review-id> --json
```

Revocation controls future use of the approval; it is not a substitute for
stopping an already running container. Approval is consumed when used, so a
second run needs a new review and approval.

If the host CLI is interrupted, the container's supervisor still enforces its
deadline. Use status to find the recorded run ID, then recover that specific run:

```text
node bin/vibeguard.js pilot status --json
node bin/vibeguard.js pilot recover <run-id> --json
```

Recovery reconciles the recorded container and cleanup state. It must not be
reported as successful while Docker is unavailable or the container cannot be
confirmed stopped and removed. A missing final receipt after a crash means the
run is unresolved until its state is reconciled.

## Verification and current limits

Follow the repository's [verification instructions](../CONTRIBUTING.md#verification)
for source checks. Runtime acceptance needs a real Docker daemon and the pinned
image; a mocked Docker command cannot establish isolation.

The CI image pin lives in `scripts/pilot-image.json`. To use that reviewed pin
locally in PowerShell:

```powershell
$env:VIBEGUARD_PILOT_IMAGE = (Get-Content scripts/pilot-image.json | ConvertFrom-Json).image
docker pull $env:VIBEGUARD_PILOT_IMAGE
if ($LASTEXITCODE -ne 0) { throw 'Image provisioning failed.' }
npm run test:pilot
```

The Docker suite is separate from `npm run verify` so source tests need no daemon.
It fails when prerequisites are missing. CI runs it on Linux and retains
`reports/pilot-runtime.json`, including failures. The suite executes only controlled
canary programs inside containers; ordinary scanner fixtures remain inert.

The acceptance evidence must include all of these outcomes:

- The example completes and its captured JSON matches the expected input summary.
- A hostile workload cannot read a fake host secret or change host approval policy.
- Attempts to send data over IPv4, IPv6, or DNS fail under the network policy.
- Changed skill content or input invalidates approval; approval cannot be replayed.
- A forced host-runner crash leaves the container subject to its deadline, followed
  by observable termination and recovery.
- Missing runtime, failed inspection, timeout, and failed cleanup remain explicit
  failures or unresolved states.

Use disposable fixtures and fake secrets for these tests. Read the receipts and
independently inspect container state. Record the OS, Docker version, image
digest, exercised cases, and remaining unverified boundaries with each run.

Keep Windows and Linux runtime evidence separate. A ready doctor result, source
tests, or Linux CI acceptance cannot establish Windows containment. Record the
actual Windows runtime acceptance results on a host with Docker Desktop running
Linux containers before claiming that boundary passed.

This pilot is an offline execution boundary, not a production security assurance
or an assessment of arbitrary AI assistants. It has no web interface, backend
service, database, remote worker queue, model-provider integration, or live
notification system. The path under test is the CLI, local review/approval store,
Docker workload, and host-written receipt.

## What to improve next

First measure intervention during the example: image setup, review clarity,
failed starts, output inspection, and crash recovery. Fix observed friction while
keeping the approval and containment boundaries intact.

Then select one real skill that can complete useful offline work. Test it against
a larger held-out set of malicious and benign inputs, recording misses and false
blocks. Connecting an AI provider or allowing network destinations requires a
separate design for credential handling, egress enforcement, and audit evidence.
Do not infer those guarantees from this offline pilot.
