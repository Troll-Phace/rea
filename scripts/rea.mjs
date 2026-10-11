#!/usr/bin/env node

import { access } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// Route production MCP before importing Incur. Incur owns registration helpers
// such as `mcp add`, while only dist/main.js may serve the stdio tool catalog.
// A failed terminal owner remains callable to an importing host/preload. This
// single invocation is not a registry, and abrupt termination has no finally guarantee.
export let retainedCliCleanup;

const args = process.argv.slice(2);
const { default: packageJson } = await import("../package.json", {
  with: { type: "json" },
});
process.env.REA_PACKAGE_VERSION = packageJson.version;
const isMcpMode =
  args.length === 1 && (args[0] === "--mcp" || args[0] === "mcp");
const isMcpDoctorMode = args[0] === "mcp" && args[1] === "doctor";
const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const runtimeFiles = isMcpMode
  ? ["dist/main.js"]
  : isMcpDoctorMode
    ? ["dist/main.js", "dist/mcpDoctor.js"]
    : ["dist/cli.js", "dist/cliOutput.js", "dist/cli/streamedJsonOutput.js"];

if (!(await compiledRuntimeExists(runtimeFiles))) {
  process.stderr.write(
    `REA's compiled runtime is missing. Run \`npm ci && npm run build:cached\` in ${packageRoot} to install dependencies and build REA, then restart it. If this is an installed package, reinstall rea-agents.\n`,
  );
  process.exitCode = 1;
} else if (isMcpMode) {
  const { runEntrypoint } = await import("../dist/main.js");
  await runEntrypoint();
} else {
  await runOrdinaryCli();
}

async function runOrdinaryCli() {
  const { CliCleanupScope } =
    await import("../dist/composition/CliCleanupScope.js");
  const { closeProcessOwnershipInspection } =
    await import("../dist/process/ProcessOwnershipObservation.js");
  const scope = new CliCleanupScope();
  const inspectorFailures = [];
  const settlementFailures = [];
  let inspectorClosed = false;
  let primary;
  let primaryFailed = false;
  let receipt;
  let finalizationAttempt;
  const retained = {
    scope,
    receipt,
    primary,
    failures: [],
    settled: false,
    retry: finalize,
  };

  function finalize() {
    if (finalizationAttempt !== undefined) return finalizationAttempt;
    const attempt = (async () => {
      let scopeSettled = false;
      try {
        receipt = await scope.settle();
        scopeSettled = receipt.settled;
      } catch (cause) {
        // Unexpected settlement failure still retains the actual scope and retry.
        settlementFailures.push(cause);
      }
      if (scopeSettled && !inspectorClosed) {
        try {
          await closeProcessOwnershipInspection();
          inspectorClosed = true;
        } catch (cause) {
          inspectorFailures.push(cause);
        }
      }
      const failures = [
        ...(receipt?.failures ?? []),
        ...settlementFailures,
        ...inspectorFailures,
      ];
      const settled = scopeSettled && inspectorClosed;
      Object.assign(retained, { receipt, primary, failures, settled });
      if (!settled || failures.length > 0) {
        process.exitCode = 1;
        retainedCliCleanup = retained;
      }
      return { settled, receipt, failures };
    })();
    finalizationAttempt = attempt;
    const release = () => {
      if (finalizationAttempt === attempt) finalizationAttempt = undefined;
    };
    void attempt.then(release, release);
    return attempt;
  }

  try {
    await scope.run(async () => {
      if (isMcpDoctorMode) {
        const { runProductionMcpDoctorCli } =
          await import("../dist/mcpDoctor.js");
        const result = await runProductionMcpDoctorCli(args.slice(2), {
          dispatcherPath: fileURLToPath(import.meta.url),
          packageRoot,
        });
        process.stdout.write(result.output);
        process.exitCode = result.exitCode;
      } else {
        const { createCli } = await import("../dist/cli.js");
        const { createStreamedCliJsonOutput } =
          await import("../dist/cli/streamedJsonOutput.js");
        const {
          renderCliOutputArgumentError,
          renderEmptyFilteredCliOutput,
          validateCliOutputArguments,
        } = await import("../dist/cliOutput.js");
        const outputArguments = validateCliOutputArguments(args);
        if (!outputArguments.ok) {
          process.stdout.write(renderCliOutputArgumentError(outputArguments));
          process.exitCode = 1;
        } else {
          let wroteOutput = false;
          const resultOutput = createStreamedCliJsonOutput(
            args,
            process.stdout,
          );
          await createCli(process.env, resultOutput, scope).serve(args, {
            stdout: (output) => {
              if (resultOutput?.handled) {
                if (resultOutput.failed) process.stderr.write(output);
                return;
              }
              if (output.length > 0) wroteOutput = true;
              process.stdout.write(output);
            },
          });
          if (!wroteOutput && !resultOutput?.handled)
            process.stdout.write(renderEmptyFilteredCliOutput(args) ?? "");
        }
      }
    });
  } catch (cause) {
    primary = cause;
    primaryFailed = true;
  }
  const final = await finalize();
  if (!final.settled)
    process.stderr.write(
      "REA could not close cleanly. Owned cleanup remains available for retry; end this process before starting it again.\n",
    );
  else if (final.failures.length > 0)
    process.stderr.write(
      "REA cleanup encountered failures before settling. All owned cleanup is now settled; the failed exit status is preserved.\n",
    );
  if (primaryFailed) throw primary;
}

async function compiledRuntimeExists(paths) {
  for (const path of paths) {
    try {
      await access(resolve(packageRoot, path));
    } catch (cause) {
      if (isMissing(cause)) return false;
      throw cause;
    }
  }
  return true;
}

function isMissing(cause) {
  return (
    typeof cause === "object" &&
    cause !== null &&
    "code" in cause &&
    cause.code === "ENOENT"
  );
}
