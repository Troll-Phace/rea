import { randomUUID } from "node:crypto";
import { once } from "node:events";
import { watch } from "node:fs";
import {
  mkdir,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { createInterface } from "node:readline";
import { describe, expect, it, onTestFinished } from "vitest";
import { createAnalysisProfile } from "../../../../src/domain/analysisProfile.js";
import {
  createEvidence,
  type Evidence,
} from "../../../../src/domain/evidence.js";
import { cleanupOwnedProcessGroup } from "../../../../src/process/ProcessOwnership.js";
import {
  ProviderProcessSupervisor,
  spawnOwnedProviderProcess,
} from "../../../../src/process/ProviderProcess.js";
import {
  psxFixtureAgreement,
  psxFixtureCommitment,
  psxFixtureOriginalRecord,
  psxFixtureSha256,
  psxImportBytes,
} from "../../../fixtures/ghidraPsxImport.js";
import { createTestTempDirectory } from "../../../fixtures/temporaryDirectory.js";

type Event = {
  sequence: number;
  stage: string;
  kind: string;
  record_name?: string;
  runtime?: Allocation;
  [key: string]: unknown;
};
type FileRecord = {
  path: string;
  text: string;
  sha256: string;
  event_sequence?: number;
};
type Allocation = {
  root: string;
  run_id: string;
  ownership: {
    parent_pid: number;
    pid: number;
    run_id: string;
    [key: string]: unknown;
  };
  snapshot: { path: string; sha256?: string; byte_length?: number };
  records: Record<string, FileRecord>;
  capture_state: {
    status: "incomplete" | "complete";
    missing: string[];
    components: Record<string, { event_sequence: number }>;
  };
};
type Resource = {
  owner: string;
  identity: Record<string, unknown>;
  close(): Promise<void>;
};
type Context = {
  roots: Map<string, Allocation>;
  resources: Resource[];
  failures: { stage: string; message: string }[];
  unpersisted_events: Event[];
  fixtures: { path: string; before_sha256: string }[];
  primary?: Error;
  case(
    id: string,
    adapter: string,
    action: () => Promise<unknown>,
  ): Promise<unknown>;
};
type Outcome = {
  ok: boolean;
  failures: { stage: string; message: string }[];
  settlement: {
    remaining_roots: string[];
    unresolved_owners: {
      identity: Record<string, unknown>;
      retry(): Promise<void>;
    }[];
  };
};
type Binding = {
  operation: string;
  parameters: Record<string, unknown>;
  selectedProfile: unknown;
  sourceDigest: string;
};
type Filesystem = {
  readFile(path: string, encoding?: string): Promise<Buffer | string>;
  realpath: typeof realpath;
  readdir: typeof readdir;
  rm?: typeof rm;
};
const helper = (await import(
  new URL("../../../../scripts/lib/real-ghidra-psx-public.mjs", import.meta.url)
    .href
)) as {
  createPublicPsxContext(input: Record<string, unknown>): Context;
  observePublicPsxAllocations(
    context: Context,
    parentPid: number,
    caseId: string,
    adapter: string,
    sourceDigest: string,
  ): Promise<Allocation[]>;
  capturePublicPsxRuntime(context: Context, root: string): Promise<void>;
  assertPublicPsxRetainedCapture(
    allocation: Allocation,
    binding: { sourceDigest: string; profileDigest?: string },
  ): unknown;
  assertPublicPsxCliExecution(
    evidence: Evidence,
    binding: Binding,
    execution: unknown,
    allocations: Allocation[],
  ): unknown;
  invokePublicPsxCli(
    context: Context,
    argv: string[],
    options: Record<string, unknown>,
  ): Promise<{ evidence: Evidence; observation: unknown }>;
  settlePublicPsxContext(
    context: Context,
    postchecks?: (() => Promise<void>)[],
  ): Promise<Outcome>;
};

const nativeRunId = "00000000-0000-4000-8000-000000000005";
const exists = async (path: string) => {
  try {
    await stat(path);
    return true;
  } catch (cause) {
    if ((cause as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw cause;
  }
};
const failureMessages = (cause: unknown): string[] =>
  cause instanceof AggregateError
    ? cause.errors.flatMap(failureMessages)
    : cause instanceof Error
      ? [cause.message]
      : [String(cause)];

/** Filesystem notification barrier, with a check after installing the watcher. */
const reached = async (directory: string, name: string) => {
  if (await exists(join(directory, name))) return;
  await new Promise<void>((resolve, reject) => {
    const observer = watch(directory, () => {
      void check();
    });
    onTestFinished(() => observer.close());
    const check = async () => {
      try {
        if (await exists(join(directory, name))) {
          observer.close();
          resolve();
        }
      } catch (cause) {
        observer.close();
        reject(cause);
      }
    };
    observer.on("error", (cause) => {
      observer.close();
      reject(cause);
    });
    void check();
  });
};

const producerScript = `import {mkdir,readFile,writeFile,rm} from 'node:fs/promises';
import {watch} from 'node:fs';
import {join} from 'node:path';
import readline from 'node:readline';
const config=JSON.parse(await readFile(process.argv[2],'utf8'));
await mkdir(config.root,{recursive:true});
await writeFile(join(config.root,'ownership.json'),JSON.stringify({ownership_kind:'posix-process-group',parent_pid:process.ppid,pid:process.pid,process_group_id:process.pid,run_id:process.env.REA_PROCESS_RUN_ID,launcher:process.execPath,arguments:[process.execPath,process.argv[1],process.argv[2],'-import',config.snapshot]}));
await writeFile(join(config.control,'ready'),'ready');
if(config.protocol==='stdio') {
 for await (const line of readline.createInterface({input:process.stdin})) {
  const command=JSON.parse(line);
  if(command==='remove-snapshot') await rm(config.snapshot,{force:true});
  else if(command==='remove-root') await rm(config.root,{recursive:true,force:true});
  else if(command==='exit') process.exit(0);
  else if(command==='ping') {}
  else throw new Error('Unmodeled owned producer command '+command);
  process.stdout.write(JSON.stringify({ack:command})+'\\n');
 }
} else {
 const observer=watch(config.control,async()=>{
  try { await readFile(join(config.control,'release')); } catch(cause) { if(cause.code==='ENOENT') return; throw cause; }
  observer.close();
  if(config.retirement==='snapshot') await rm(config.snapshot);
  if(config.retirement==='root') await rm(config.root,{recursive:true});
  await writeFile(join(config.control,'retired'),'retired');
  const complete=async()=>{
   try { await readFile(join(config.control,'finish')); } catch(cause) { if(cause.code==='ENOENT') return; throw cause; }
   final.close();process.exit(0);
  };
  const final=watch(config.control,()=>{void complete();});void complete();
 });
}
`;

const captureRecords = (source: string, snapshot: string) => {
  const bytes = psxImportBytes();
  const sourceDigest = psxFixtureSha256(bytes);
  const provider = { id: "ghidra", name: "Ghidra", version: "12.1.4" };
  const profile = createAnalysisProfile(provider, {
    psx_import: { source_sha256: sourceDigest },
    startup_agreement: "psx-observed-import-and-provenance-v3",
    psx_source_provenance: "rea-psx-filebytes-rebind-v2",
    psx_preparation_transaction: "exclusive-top-level-v1",
    instruction_flow_evidence: "decoded-return-before-jump-and-delay-slots-v2",
  });
  const before = psxFixtureAgreement({
    commitment: psxFixtureCommitment(snapshot, bytes),
    runId: nativeRunId,
    profileDigest: profile.digest,
    selectedClasses: [
      {
        class_name: "psx.PsxLoader",
        role: "loader",
        code_source_url: "file:/generated/psx.jar",
        code_source_relative: "Ghidra/Extensions/renamed-psx/lib/psx.jar",
        code_source_sha256: "b".repeat(64),
        class_resource_url: "jar:file:/generated/psx.jar!/psx/PsxLoader.class",
        enabled: null,
      },
    ],
    languageAssets: [
      {
        relative_path: "Ghidra/Processors/PSX/data/languages/psx.ldefs",
        sha256: "c".repeat(64),
      },
    ],
  }).before;
  const original = psxFixtureOriginalRecord(
    before.commitment,
    before.provenance.metadata_preservation,
  );
  const records: Record<string, Buffer | string> = {
    snapshot: bytes,
    "psx-import-before.json": `${JSON.stringify(before)}\n`,
    "psx-provenance-original.json": `${JSON.stringify(original)}\n`,
  };
  const evidence = createEvidence(
    {
      path: source,
      sha256: sourceDigest,
      format: "ps-x-exe",
      architecture: "mips",
    },
    provider,
    {
      operation: "inspect_native_instruction",
      parameters: { address: "0x80010000" },
      analysisProfile: profile,
      result: {
        address: "0x80010000",
        status: "decoded",
        procedure: null,
        architecture: "mips",
        mode: "default",
        bytes: "00000000",
        length: 4,
        mnemonic: "nop",
        raw_disassembly: "nop",
        operands: [],
        flow: {
          kind: "fallthrough",
          conditional: false,
          computed: false,
          direct_destinations: [],
        },
        references: [],
        limitations: [],
      },
    },
  );
  const binding: Binding = {
    operation: evidence.operation,
    parameters: evidence.parameters,
    sourceDigest,
    selectedProfile: profile,
  };
  return { bytes, sourceDigest, profile, records, evidence, binding };
};

const fixture = async (
  options: {
    missing?: readonly string[];
    record?: (event: Event) => Promise<void>;
    filesystem?: Filesystem;
  } = {},
) => {
  const parent = await createTestTempDirectory("psx-capture-lifetime-");
  const workspace = join(parent, "workspace");
  const control = join(parent, "barriers");
  const root = join(workspace, "rea-ghidra-owned");
  await mkdir(root, { recursive: true });
  await mkdir(control);
  const source = join(workspace, "original source 雪.exe");
  const snapshot = join(root, "target");
  const { bytes, sourceDigest, profile, records, evidence, binding } =
    captureRecords(source, snapshot);
  await writeFile(source, bytes);
  const populate = async (names = Object.keys(records)) => {
    for (const name of names)
      await writeFile(
        name === "snapshot" ? snapshot : join(root, name),
        records[name]!,
      );
  };
  await populate(
    Object.keys(records).filter((name) => !options.missing?.includes(name)),
  );
  const script = join(parent, "owned producer.mjs");
  const config = join(parent, "producer.json");
  await writeFile(script, producerScript);
  await writeFile(
    config,
    JSON.stringify({ root, snapshot, control, protocol: "stdio" }),
  );
  const events: Event[] = [];
  const context = helper.createPublicPsxContext({
    executable: process.execPath,
    prefixArgs: [script, config],
    environment: {
      PATH: process.env.PATH ?? "",
      TMPDIR: workspace,
      HOME: parent,
    },
    workspace,
    ...(options.filesystem ? { captureFilesystem: options.filesystem } : {}),
    record: async (event: Event) => {
      events.push(event);
      await options.record?.(event);
    },
  });
  const scan = (parentPid = process.pid) =>
    helper.observePublicPsxAllocations(
      context,
      parentPid,
      "controlled-lifetime",
      "cli",
      sourceDigest,
    );
  context.fixtures.push({ path: source, before_sha256: sourceDigest });
  const start = async () => {
    const spawned = await spawnOwnedProviderProcess({
      command: process.execPath,
      arguments: [script, config],
      cwd: workspace,
      env: { REA_PROCESS_RUN_ID: nativeRunId },
      hostEnvironment: {},
      runId: nativeRunId,
      expectedCommand: null,
      stdin: "pipe",
    });
    let beforeCleanup: (() => Promise<void>) | undefined;
    const supervisor = new ProviderProcessSupervisor({
      ...spawned,
      ownsProcessLifetime: true,
      cleanup: async () => {
        if (beforeCleanup) {
          const action = beforeCleanup;
          beforeCleanup = undefined;
          await action();
        }
        return cleanupOwnedProcessGroup(spawned.ownership);
      },
    });
    const close = async () => {
      const result = await supervisor.stop();
      if (result.status === "incomplete") throw new Error(result.reason);
      supervisor.dispose();
    };
    context.resources.push({
      owner: `controlled-producer:${nativeRunId}`,
      identity: {
        kind: "controlled-producer",
        id: nativeRunId,
        ...spawned.ownership,
      },
      close,
    });
    onTestFinished(close);
    await reached(control, "ready");
    const replies = createInterface({ input: spawned.process.stdout! });
    onTestFinished(() => replies.close());
    const send = async (command: string) => {
      const reply = once(replies, "line");
      spawned.process.stdin!.write(`${JSON.stringify(command)}\n`);
      const [data] = await reply;
      expect(JSON.parse(String(data))).toEqual({ ack: command });
    };
    return {
      spawned,
      supervisor,
      close,
      send,
      beforeCleanup: (action: () => Promise<void>) => {
        beforeCleanup = action;
      },
    };
  };
  return {
    parent,
    workspace,
    control,
    root,
    source,
    snapshot,
    bytes,
    sourceDigest,
    profile,
    binding,
    evidence,
    records,
    config,
    script,
    context,
    events,
    populate,
    scan,
    start,
  };
};

const invocationFixture = async (
  retirement: "snapshot" | "root",
  missing: readonly string[] = [],
  record?: (event: Event) => Promise<void>,
) => {
  const f = await fixture({ missing, ...(record ? { record } : {}) });
  const launcher = join(f.parent, "controlled CLI.mjs");
  await writeFile(
    f.config,
    JSON.stringify({
      root: f.root,
      snapshot: f.snapshot,
      control: f.control,
      protocol: "barriers",
      retirement,
      producer: f.script,
      nativeRunId,
      evidence: f.evidence,
    }),
  );
  await writeFile(
    launcher,
    `import {spawn} from 'node:child_process';
import {readFile} from 'node:fs/promises';
const config=JSON.parse(await readFile(process.argv[2],'utf8'));
const child=spawn(process.execPath,[config.producer,process.argv[2]],{detached:true,stdio:['ignore','ignore','pipe'],env:{...process.env,REA_PROCESS_RUN_ID:config.nativeRunId}});
child.stderr.pipe(process.stderr);
child.on('error',error=>{throw error});
child.on('exit',(code,signal)=>{if(code!==0||signal) throw new Error('Controlled producer failed '+String(code)+' '+String(signal));process.stderr.write('controlled CLI diagnostics\\n');process.stdout.write(JSON.stringify(config.evidence));});
`,
  );
  const context = helper.createPublicPsxContext({
    executable: process.execPath,
    prefixArgs: [launcher, f.config],
    environment: {
      PATH: process.env.PATH ?? "",
      TMPDIR: f.workspace,
      HOME: f.parent,
    },
    workspace: f.workspace,
    record: async (event: Event) => {
      f.events.push(event);
      await record?.(event);
    },
  });
  onTestFinished(async () => {
    const settled = await helper.settlePublicPsxContext(context);
    for (const owner of settled.settlement.unresolved_owners)
      await owner.retry();
  });
  context.fixtures.push({ path: f.source, before_sha256: f.sourceDigest });
  const retire = async () => {
    await writeFile(join(f.control, "release"), "release");
    await reached(f.control, "retired");
  };
  const finish = () => writeFile(join(f.control, "finish"), "finish");
  const invoke = (options: Record<string, unknown> = {}) =>
    helper.invokePublicPsxCli(
      context,
      ["inspect-native-instruction", f.source, "0x80010000"],
      {
        caseId: "controlled-lifetime",
        sourceDigest: f.sourceDigest,
        binding: f.binding,
        execution: { mode: "native" },
        ...options,
      },
    );
  return { ...f, context, invoke, retire, finish };
};

describe("P5-R5 supervised CLI capture/finalization barriers (controlled Node producer)", () => {
  it.each(["snapshot", "root"] as const)(
    "accepts valid stdout after the owned %s disappears between polls",
    async (retirement) => {
      const f = await invocationFixture(retirement);
      const result = await f.invoke({
        afterAllocation: async (allocations: Allocation[]) => {
          expect(allocations[0]!.capture_state.status).toBe("complete");
          await f.retire();
          expect(await exists(f.snapshot)).toBe(false);
          await helper.observePublicPsxAllocations(
            f.context,
            allocations[0]!.ownership.parent_pid,
            "controlled-lifetime",
            "cli",
            f.sourceDigest,
          );
          await f.finish();
        },
      });
      expect(result.evidence).toEqual(f.evidence);
      expect(result.observation).toMatchObject({
        mode: "native",
        run_id: nativeRunId,
      });
      const raw = f.events.find(
        (event) =>
          event.kind === "raw_result" && typeof event.stdout === "string",
      );
      expect(raw).toMatchObject({
        stdout: JSON.stringify(f.evidence),
        stderr: "controlled CLI diagnostics\n",
        exit_code: 0,
      });
      expect(f.events.findIndex((event) => event === raw)).toBeLessThan(
        f.events.findIndex(
          (event) =>
            event.kind === "observation" && event.evidence !== undefined,
        ),
      );
      const settled = await helper.settlePublicPsxContext(f.context);
      for (const owner of settled.settlement.unresolved_owners)
        await owner.retry();
      expect(await exists(f.root)).toBe(false);
      expect(await readFile(f.source)).toEqual(f.bytes);
    },
  );
});

describe("P5-R5 incomplete CLI startup and observed cancellation", () => {
  it("valid stdout and exit zero cannot replace missing required startup bytes", async () => {
    const f = await invocationFixture("root", ["psx-import-before.json"]);
    await expect(
      f.invoke({
        afterAllocation: async (allocations: Allocation[]) => {
          expect(allocations[0]!.capture_state.status).toBe("incomplete");
          await f.retire();
          await f.finish();
        },
      }),
    ).rejects.toThrow("psx-import-before.json");
    expect(
      f.events.find((event) => typeof event.stdout === "string"),
    ).toMatchObject({ stdout: JSON.stringify(f.evidence), exit_code: 0 });
    const settled = await helper.settlePublicPsxContext(f.context);
    expect(settled.ok).toBe(false);
    expect(
      settled.failures.some(({ message }) =>
        message.includes("psx-import-before.json"),
      ),
    ).toBe(true);
    expect(await exists(f.root)).toBe(false);
  });

  it.each(["complete", "partial"] as const)(
    "cancels after %s capture and settles its owned child/root independently",
    async (mode) => {
      const f = await invocationFixture(
        "snapshot",
        mode === "partial" ? ["psx-import-before.json"] : [],
      );
      const abort = new AbortController();
      let caught: unknown;
      try {
        await f.invoke({
          signal: abort.signal,
          afterAllocation: async (allocations: Allocation[]) => {
            expect(allocations[0]!.capture_state.status).toBe(
              mode === "complete" ? "complete" : "incomplete",
            );
            await f.retire();
            abort.abort(new Error(`controlled ${mode} cancellation`));
          },
        });
      } catch (cause) {
        caught = cause;
      }
      expect(failureMessages(caught)).toContain(
        `controlled ${mode} cancellation`,
      );
      const raw = f.events.find((event) => typeof event.stdout === "string");
      expect(raw).toBeDefined();
      expect(f.events.some((event) => event.evidence !== undefined)).toBe(
        false,
      );
      const settled = await helper.settlePublicPsxContext(f.context);
      for (const owner of settled.settlement.unresolved_owners)
        await owner.retry();
      expect(await exists(f.root)).toBe(false);
      if (mode === "partial")
        expect(
          settled.failures.some(({ message }) =>
            message.includes("psx-import-before.json"),
          ),
        ).toBe(true);
      expect(await readFile(f.source)).toEqual(f.bytes);
    },
  );

  it("preserves primary cancellation and a separate durable raw-output failure", async () => {
    const f = await invocationFixture("snapshot", [], async (event) => {
      if (event.kind === "raw_result" && typeof event.stdout === "string")
        throw new Error("controlled raw capture failure");
    });
    const abort = new AbortController();
    let caught: unknown;
    try {
      await f.invoke({
        signal: abort.signal,
        afterAllocation: async () => {
          await f.retire();
          abort.abort(new Error("controlled primary cancellation"));
        },
      });
    } catch (cause) {
      caught = cause;
    }
    expect(caught).toBeInstanceOf(AggregateError);
    expect(failureMessages(caught)).toEqual(
      expect.arrayContaining([
        "controlled primary cancellation",
        "Durable public capture failed",
      ]),
    );
    expect(f.context.unpersisted_events).toHaveLength(1);
    const settled = await helper.settlePublicPsxContext(f.context);
    for (const owner of settled.settlement.unresolved_owners)
      await owner.retry();
    expect(settled.ok).toBe(false);
    expect(await exists(f.root)).toBe(false);
  });
});

describe("P5-R5 retained capture over real files and owned Node producers (no Ghidra claim)", () => {
  it.each(["remove-snapshot", "remove-root"])(
    "retains complete proof after %s without rereading retired source",
    async (command) => {
      const reads: string[] = [];
      const f = await fixture({
        filesystem: {
          readFile: async (path, encoding) => {
            reads.push(path);
            return encoding === "utf8"
              ? readFile(path, "utf8")
              : readFile(path);
          },
          realpath,
          readdir,
        },
      });
      const child = await f.start();
      const [allocation] = await f.scan();
      expect(allocation!.capture_state.status).toBe("complete");
      const count = reads.filter((path) => path === f.snapshot).length;
      await child.send(command);
      expect(await exists(f.snapshot)).toBe(false);
      expect(await f.scan()).toEqual([allocation]);
      expect(reads.filter((path) => path === f.snapshot)).toHaveLength(count);
      helper.assertPublicPsxRetainedCapture(allocation!, {
        sourceDigest: f.sourceDigest,
        profileDigest: f.profile.digest,
      });
      helper.assertPublicPsxCliExecution(
        f.evidence,
        f.binding,
        { mode: "native" },
        [allocation!],
      );
      await child.close();
      await rm(f.root, { recursive: true, force: true });
      const settled = await helper.settlePublicPsxContext(f.context);
      expect(settled.settlement.unresolved_owners).toEqual([]);
      expect(await readFile(f.source)).toEqual(f.bytes);
    },
  );

  it.each([
    "snapshot",
    "psx-import-before.json",
    "psx-provenance-original.json",
  ])(
    "retains incomplete %s and completes only after actual bytes become available",
    async (missing) => {
      const f = await fixture({ missing: [missing] });
      const child = await f.start();
      await f.scan();
      const allocation = f.context.roots.get(f.root)!;
      expect(allocation.capture_state.status).toBe("incomplete");
      expect(allocation.capture_state.missing).toContain(missing);
      expect(() =>
        helper.assertPublicPsxRetainedCapture(allocation, {
          sourceDigest: f.sourceDigest,
        }),
      ).toThrow();
      await f.populate([missing]);
      await f.scan();
      expect(allocation.capture_state.status).toBe("complete");
      expect(allocation.capture_state.missing).toEqual([]);
      const emitted = f.events.map(({ sequence }) => sequence);
      for (const component of Object.values(
        allocation.capture_state.components,
      ))
        expect(emitted).toContain(component.event_sequence);
      await child.close();
      await rm(f.root, { recursive: true });
      await helper.settlePublicPsxContext(f.context);
    },
  );
});

describe("P5-R5 durable component and completion capture", () => {
  it("a durable-write failure retains ownership and never commits the failed component", async () => {
    const f = await fixture({
      record: async (event) => {
        if (event.record_name === "psx-provenance-original.json")
          throw new Error("controlled durable failure");
      },
    });
    const child = await f.start();
    await expect(f.scan()).rejects.toThrow("Durable public capture failed");
    const allocation = f.context.roots.get(f.root)!;
    expect(allocation.capture_state.status).toBe("incomplete");
    expect(allocation.capture_state.missing).toContain(
      "psx-provenance-original.json",
    );
    expect(allocation.records).not.toHaveProperty(
      "psx-provenance-original.json",
    );
    expect(f.context.unpersisted_events).toHaveLength(1);
    f.context.primary = new Error("independent semantic failure");
    await child.close();
    await rm(f.root, { recursive: true });
    const settled = await helper.settlePublicPsxContext(f.context);
    expect(settled.ok).toBe(false);
    expect(
      settled.failures.some(
        ({ message }) => message === "independent semantic failure",
      ),
    ).toBe(true);
  });

  it("a failed durable completion event cannot declare capture complete", async () => {
    const f = await fixture({
      record: async (event) => {
        if (event.stage === "native-capture-complete")
          throw new Error("controlled completion capture failure");
      },
    });
    const child = await f.start();
    await expect(f.scan()).rejects.toThrow("Durable public capture failed");
    const allocation = f.context.roots.get(f.root)!;
    expect(allocation.capture_state.status).toBe("incomplete");
    expect(allocation.records).toHaveProperty("psx-import-before.json");
    expect(allocation.records).toHaveProperty("psx-provenance-original.json");
    expect(() =>
      helper.assertPublicPsxRetainedCapture(allocation, {
        sourceDigest: f.sourceDigest,
      }),
    ).toThrow("not complete");
    expect(f.context.unpersisted_events).toHaveLength(1);
    await child.close();
    await rm(f.root, { recursive: true });
    const settled = await helper.settlePublicPsxContext(f.context);
    expect(settled.ok).toBe(false);
  });
});

describe("P5-R5 source and fixed-record contradiction capture", () => {
  it.each([
    "source-digest",
    "record-json",
    "record-run",
    "record-profile",
    "record-source",
  ])(
    "rejects %s at initial capture while retaining the allocation owner",
    async (kind) => {
      const f = await fixture();
      if (kind === "source-digest") {
        const changed = Buffer.from(f.bytes);
        changed[0x900] = changed[0x900]! ^ 1;
        await writeFile(f.snapshot, changed);
      } else {
        const path = join(f.root, "psx-provenance-original.json");
        if (kind === "record-json") await writeFile(path, "{incomplete-json");
        else {
          const original = JSON.parse(await readFile(path, "utf8")) as {
            commitment: {
              run_id: string;
              source_sha256: string;
              profile_digest: string;
            };
          };
          if (kind === "record-run") original.commitment.run_id = randomUUID();
          if (kind === "record-profile")
            original.commitment.profile_digest = "9".repeat(64);
          if (kind === "record-source")
            original.commitment.source_sha256 = "9".repeat(64);
          await writeFile(path, JSON.stringify(original));
        }
      }
      const child = await f.start();
      await expect(f.scan()).rejects.toThrow();
      expect(f.context.roots.has(f.root)).toBe(true);
      expect(f.context.roots.get(f.root)!.capture_state.status).toBe(
        "incomplete",
      );
      expect(await exists(f.root)).toBe(true);
      await child.close();
      await rm(f.root, { recursive: true });
      await helper.settlePublicPsxContext(f.context);
    },
  );

  it.each(["run_id", "pid", "parent_pid"])(
    "refuses a replacement manifest %s at the same retained root",
    async (field) => {
      const f = await fixture();
      const child = await f.start();
      const [allocation] = await f.scan();
      const manifestPath = join(f.root, "ownership.json");
      const original = await readFile(manifestPath, "utf8");
      const changed = JSON.parse(original) as Record<string, unknown>;
      changed[field] =
        field === "run_id" ? randomUUID() : Number(changed[field]) + 1;
      await writeFile(manifestPath, JSON.stringify(changed));
      await expect(f.scan()).rejects.toThrow("ownership changed");
      expect(f.context.roots.get(f.root)).toBe(allocation);
      expect(await exists(f.root)).toBe(true);
      expect(child.spawned.process.exitCode).toBeNull();
      await child.send("ping");
      // Restore exact authored ownership before authorized test cleanup.
      await writeFile(manifestPath, original);
      await child.close();
      await rm(f.root, { recursive: true });
      await helper.settlePublicPsxContext(f.context);
    },
  );

  it("an available fixed record cannot mutate after its complete capture", async () => {
    const f = await fixture();
    const child = await f.start();
    const [allocation] = await f.scan();
    const raw = await readFile(
      join(f.root, "psx-provenance-original.json"),
      "utf8",
    );
    await writeFile(join(f.root, "psx-provenance-original.json"), `${raw} `);
    await expect(f.scan()).rejects.toThrow();
    expect(allocation!.records["psx-provenance-original.json"]!.text).toBe(raw);
    await child.close();
    await rm(f.root, { recursive: true });
    await helper.settlePublicPsxContext(f.context);
  });
});

describe("P5-R5 permission and unknown-owner refusal", () => {
  it("permission failure is an evidence failure rather than an absent component", async () => {
    let refusedPath = "";
    const f = await fixture({
      filesystem: {
        readFile: async (path, encoding) => {
          if (path === refusedPath)
            throw Object.assign(
              new Error("controlled capture permission denial"),
              { code: "EACCES" },
            );
          return encoding === "utf8" ? readFile(path, "utf8") : readFile(path);
        },
        realpath,
        readdir,
      },
    });
    refusedPath = f.snapshot;
    const child = await f.start();
    await expect(f.scan()).rejects.toMatchObject({ code: "EACCES" });
    expect(f.context.roots.has(f.root)).toBe(true);
    expect(f.context.roots.get(f.root)!.capture_state.status).toBe(
      "incomplete",
    );
    expect(await readFile(f.snapshot)).toEqual(f.bytes);
    await child.close();
    await rm(f.root, { recursive: true });
    await helper.settlePublicPsxContext(f.context);
  });

  it("a real filesystem I/O contradiction does not become an ENOENT lifetime observation", async () => {
    const f = await fixture({ missing: ["snapshot"] });
    await mkdir(f.snapshot);
    const child = await f.start();
    await expect(f.scan()).rejects.toMatchObject({ code: "EISDIR" });
    expect(f.context.roots.has(f.root)).toBe(true);
    await child.close();
    await rm(f.root, { recursive: true });
    await helper.settlePublicPsxContext(f.context);
  });

  it("unknown runtime roots remain unresolved without inferred deletion authority", async () => {
    const f = await fixture();
    expect(await f.scan()).toEqual([]);
    const settled = await helper.settlePublicPsxContext(f.context);
    expect(settled.ok).toBe(false);
    expect(settled.settlement.remaining_roots).toContain(f.root);
    const owner = settled.settlement.unresolved_owners.find(
      ({ identity }) => identity.kind === "unobserved-native-root",
    )!;
    await expect(owner.retry()).rejects.toThrow("cleanup authority");
    expect(await exists(f.root)).toBe(true);
  });
});

describe("P5-R5 retained native cleanup and failed-close retry", () => {
  it("complete capture lets the exact cleanup handle settle after source deletion during process close", async () => {
    const f = await fixture();
    const child = await f.start();
    const [allocation] = await f.scan();
    expect(await exists(f.snapshot)).toBe(true);
    let retired = false;
    child.beforeCleanup(async () => {
      await child.send("remove-snapshot");
      expect(await exists(f.snapshot)).toBe(false);
      expect(child.spawned.process.exitCode).toBeNull();
      retired = true;
    });
    await child.close();
    expect(retired).toBe(true);
    expect(child.spawned.process.signalCode).toBe("SIGKILL");
    expect(await exists(f.snapshot)).toBe(false);
    const native = f.context.resources.find(
      ({ identity }) => identity.kind === "native-runtime",
    )!;
    await native.close();
    expect(await exists(f.root)).toBe(false);
    const settled = await helper.settlePublicPsxContext(f.context);
    const owner = settled.settlement.unresolved_owners.find(
      ({ identity }) => identity.kind === "native-runtime",
    );
    if (owner) await owner.retry();
    expect(await exists(f.root)).toBe(false);
    helper.assertPublicPsxRetainedCapture(allocation!, {
      sourceDigest: f.sourceDigest,
      profileDigest: f.profile.digest,
    });
    expect(await readFile(f.source)).toEqual(f.bytes);
  });

  it("failed close retains its exact handle; retry settles without erasing the failure", async () => {
    let enabled = false;
    const f = await fixture({
      filesystem: {
        readFile: (path, encoding) =>
          encoding === "utf8" ? readFile(path, "utf8") : readFile(path),
        realpath,
        readdir,
        rm: async (path, options) => {
          if (!enabled)
            throw Object.assign(
              new Error("controlled native root removal failure"),
              { code: "EACCES" },
            );
          await rm(path, options);
        },
      },
    });
    await f.start();
    await f.scan();
    const settled = await helper.settlePublicPsxContext(f.context);
    expect(settled.ok).toBe(false);
    const failure = settled.failures.find(
      ({ message }) => message === "controlled native root removal failure",
    );
    expect(failure).toBeDefined();
    const owner = settled.settlement.unresolved_owners.find(
      ({ identity }) => identity.kind === "native-runtime",
    )!;
    expect(owner.identity.id).toBe(nativeRunId);
    expect(await exists(f.root)).toBe(true);
    enabled = true;
    await owner.retry();
    expect(await exists(f.root)).toBe(false);
    expect(settled.failures).toContain(failure);
    expect(settled.ok).toBe(false);
  });

  it("incomplete capture followed by successful cleanup remains failed native acceptance", async () => {
    const f = await fixture({ missing: ["psx-import-before.json"] });
    const child = await f.start();
    const [allocation] = await f.scan();
    expect(allocation!.capture_state.missing).toContain(
      "psx-import-before.json",
    );
    expect(() =>
      helper.assertPublicPsxCliExecution(
        f.evidence,
        f.binding,
        { mode: "native" },
        [allocation!],
      ),
    ).toThrow();
    await child.send("remove-root");
    await child.close();
    const settled = await helper.settlePublicPsxContext(f.context);
    expect(settled.ok).toBe(false);
    expect(
      settled.failures.some(({ message }) =>
        message.includes("psx-import-before.json"),
      ),
    ).toBe(true);
    expect(await exists(f.root)).toBe(false);
  });
});
