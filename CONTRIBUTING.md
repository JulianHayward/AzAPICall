# Contributing to AzAPICall

Contributions to code, documentation, examples, and regression tests are welcome. Review [README.md](README.md) for usage before starting.

## Development setup

- Use a currently supported PowerShell 7 release and Git.
- Start from a clean checkout or review your existing changes before building: the build overwrites generated files and one development helper.
- Run the commands below from the **repository root**. The build uses paths relative to the working directory, not its own script directory.
- Live API testing requires `Az.Accounts`, an authenticated Azure context, appropriate permissions, and network access. Offline mocks and local packaging do not require an Azure login.
- The default build also requires `Find-Module` (provided by PowerShellGet) and access to the configured PowerShell repository containing the selected package. Use `-test` for local packaging without that lookup.

## Source layout: where to make changes

| Area | Purpose |
| --- | --- |
| [Development request function](pwsh/module/dev/AzAPICall/functions/AzAPICall.ps1) | Endpoint matching, requests, response processing, retries, and pagination. |
| [Development error rules](pwsh/module/dev/AzAPICall/functions/AzAPICallRuleSet.ps1) | Built-in API error handling. |
| [Token creation](pwsh/module/dev/AzAPICall/functions/createBearerToken.ps1) | Authentication and token renewal. |
| [Environment configuration](pwsh/module/dev/AzAPICall/functions/setAzureEnvironment.ps1) | Cloud-specific endpoint and audience configuration. |
| [Stable manifest](pwsh/module/dev/AzAPICall/AzAPICall.psd1) / [beta manifest](pwsh/module/dev/AzAPICall/AzAPICallBeta.psd1) | Package metadata, versions, and exported functions. |
| [Build script](pwsh/module/buildModule.ps1) | Packages the shared development functions into the selected distribution. |
| [Generated stable functions](pwsh/module/build/AzAPICall/functions/AzAPICallFunctions.ps1) / [generated beta functions](pwsh/module/build/AzAPICallBeta/functions/AzAPICallFunctions.ps1) | Combined distribution files; do not fix these directly. |

**Edit the individual development functions, not the combined build output.** Direct edits to generated functions are lost on the next build. Keep test scripts outside the development functions directory: every immediate `.ps1` file there is included in the package.

The [module loader](pwsh/module/dev/AzAPICall/AzAPICall.psm1) dot-sources the files in its `functions` directory. Development imports therefore load the individual files; built imports load the combined file. The manifest determines which functions are public. If adding a public function, review both package manifests.

## How the build works

This is a **packaging script**, not a compiler, test runner, or publisher. Stable and beta use the same development function sources, with separate manifests, loaders, and output directories.

For the selected package, the script performs these steps:

1. **Read the version.** Load `ModuleVersion` from the stable or beta development manifest.
2. **Check the Gallery version unless `-test` is supplied.** Call `Find-Module` for `AzAPICall` or `AzAPICallBeta`. If the returned version equals the development version, stop with a version-conflict error. This is an equality check, not a guarantee that the development version is newer or publishable.
3. **Remove the selected package's previous outputs.** Delete its existing ZIP, combined functions file, copied manifest, and copied loader when present. This does not clean the entire output directory or the other package's output.
4. **Regenerate the version helper in the source tree.** Overwrite [getAzAPICallVersion.ps1](pwsh/module/dev/AzAPICall/functions/getAzAPICallVersion.ps1) with a function returning the selected manifest version.
5. **Concatenate functions.** Enumerate immediate `.ps1` files in the shared development functions directory, read each file as text, and append it to the selected combined functions file. The script does not explicitly sort files or resolve dependencies; avoid introducing order-dependent top-level execution.
6. **Copy package metadata and loader.** Copy the selected development manifest and `.psm1` loader into the selected output directory.
7. **Create a ZIP.** Archive the selected output directory with `Compress-Archive`. The archive is named after the package and placed alongside its output directory.

The script uses `$ErrorActionPreference = 'Stop'`. A failure can leave partially regenerated output; it does not roll back earlier deletions or writes.

### Build modes

| Invocation | Package | Gallery lookup | Runs tests or publishes? |
| --- | --- | --- | --- |
| `./pwsh/module/buildModule.ps1 -test` | AzAPICall | No | No |
| `./pwsh/module/buildModule.ps1 -beta -test` | AzAPICallBeta | No | No |
| `./pwsh/module/buildModule.ps1` | AzAPICall | Yes | No |
| `./pwsh/module/buildModule.ps1 -beta` | AzAPICallBeta | Yes | No |

**`-test` only skips the Gallery lookup and version-conflict check.** It still deletes and recreates build outputs, rewrites the version helper, and creates the ZIP. It does not run regression tests or perform a dry run.

`AzAPICallBeta` is a separate package name, not simply an `-AllowPrerelease` variant of `AzAPICall`.

### Local stable build

From the repository root:

```powershell
./pwsh/module/buildModule.ps1 -test
```

Use a fresh PowerShell session to inspect the built module rather than an already loaded Gallery copy:

```powershell
Import-Module ./pwsh/module/build/AzAPICall/AzAPICall.psd1 -Force
Get-Command -Module AzAPICall
```

Importing the package is not an end-to-end API test. Authentication and calls to Azure are separate validation steps.

### Beta builds and version changes

For a beta package:

```powershell
./pwsh/module/buildModule.ps1 -beta -test
```

- Coordinate version bumps with the maintainer; a local test build does not require a version bump.
- Edit the selected development manifest, not the generated manifest or version helper.
- **Both builds overwrite the same development version helper.** After a beta build, it returns the beta manifest's version until regenerated by another build. Inspect that source change before submitting.
- Building stable does not update beta, and building beta does not update stable. Rebuild only the distribution(s) intended for the contribution.
- The script assumes the selected output directory and its `functions` directory already exist, as they do in the checkout. It does not create missing directories.
- Keep output directories free of unrelated files: the ZIP includes the whole selected package directory, not only the files regenerated in this run.
- Building does **not** publish to PowerShell Gallery, tag a release, stage files, or create a commit.

## Test and validate changes

### Test development code first

Import the development manifest in a fresh PowerShell session to test without rebuilding:

```powershell
Import-Module ./pwsh/module/dev/AzAPICall/AzAPICall.psd1 -Force
```

The [example script](pwsh/AzAPICallExample.ps1) also supports `-DevMode`. It is a live usage example, not an offline test suite; inspect its parameters and API calls before running it. The [forced error-handling script](pwsh/testForceErrorHandling.ps1) should likewise be reviewed before execution.

For regression tests, use isolated module scope and mock web requests, token creation, logging, and sleeps. Supply a fake `AzAPICallConfiguration` and dummy tokens. Never let an offline test fall through to real authentication or network calls. Cap mocked request counts so retry bugs cannot hang the test.

Test the behavior affected by the change, including where relevant:

- Success and failure responses, with `Stop`, `Continue`, and `ContinueQuiet`.
- Multi-page results, repeated continuation tokens, and `-noPaging`.
- Retry exhaustion and isolation between invocations.
- Output shapes for the affected `listenOn` modes.
- Stable and beta packaging, if both are part of the proposed change.

Existing regression scripts may target a proposed fix rather than current release behavior. Inspect each script's expectations and source-path parameters before treating it as a release gate. The build script does not discover or execute them.

### Validate the generated package

After an intended rebuild:

1. Check that the combined functions contain the source changes and the generated version matches the selected manifest.
2. Import the built manifest in a fresh session and inspect exports.
3. Run relevant regression checks against the built functions as well as development sources.
4. Review the Git diff for unintended source, metadata, or generated changes. Use `git diff --check` to detect whitespace problems.
5. Record what was tested, the PowerShell version, and whether tests were offline or live. Do not describe a successful build as a passing test suite.

## Submitting a contribution

- Keep changes focused and describe the problem, expected behavior, and compatibility impact.
- Include a reproducible example or regression check where practical. Remove credentials and sensitive tenant/resource information from examples and logs.
- Update documentation when parameters, endpoint support, output shapes, or failure behavior change.
- Generated distribution files are maintained in this repository. For contributions that include a rebuild, include the corresponding source and intended generated-file changes together; coordinate ZIP/release-artifact inclusion with the maintainer.
- Documentation-only or explicitly source-only contributions need not rebuild. State clearly if built distributions remain unchanged.
- Avoid unrelated stable/beta version changes or artifacts produced accidentally while testing.
- In the pull request, list the files or behavior changed, validation performed, known limitations, and whether the stable or beta package was rebuilt.