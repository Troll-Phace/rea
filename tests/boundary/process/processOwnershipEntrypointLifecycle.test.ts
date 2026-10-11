import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { access, chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import { expect, it, onTestFinished } from "vitest";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

// Controlled compiler/provider boundaries. These tests do not exercise Swift,
// Darwin kernel identity observations, or any installed reverse-engineering provider.
const itDarwin = process.platform === "darwin" ? it : it.skip;
const repository = resolve(import.meta.dirname, "../../..");
const dispatcher = join(repository, "scripts/rea.mjs");
const runtime = (path: string) =>
  pathToFileURL(join(repository, "dist", path)).href;
const hookedPaths = [
  "process/DarwinProcessRunTokenReader.js",
  "application/process/ProcessCli.js",
  "composition/binary.js",
] as const;
type Mode =
  | "owned-success"
  | "owned-failure"
  | "owned-cancel"
  | "pty-failure"
  | "mcp"
  | "startup-failure"
  | "compiler-cancel"
  | "inspector-failure";

const json = JSON.stringify;
const digest = async (path: string) =>
  createHash("sha256")
    .update(await readFile(path))
    .digest("hex");
const exists = async (path: string) =>
  access(path).then(
    () => true,
    () => false,
  );
const readEvents = async (path: string): Promise<Record<string, unknown>[]> =>
  (await readFile(path, "utf8").catch(() => ""))
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
const waitEvent = async (
  path: string,
  type: string,
  diagnostic?: () => Promise<string>,
) => {
  let found: Record<string, unknown> | undefined;
  try {
    await expect
      .poll(
        async () => {
          found = (await readEvents(path)).find((event) => event.type === type);
          return found !== undefined;
        },
        { timeout: 12_000, interval: 20 },
      )
      .toBe(true);
  } catch (cause: unknown) {
    if (diagnostic === undefined) throw cause;
    throw new Error(`No ${type} boundary: ${await diagnostic()}`, { cause });
  }
  if (found === undefined) throw new Error(`No ${type} boundary`);
  return found;
};

const writeBoundaryPreload = async (input: {
  mode: Mode;
  events: string;
  release: string;
  compiler: string;
  workload: string;
  cwd: string;
  preload: string;
}) => {
  const { mode, events, release, compiler, workload, cwd, preload } = input;
  const paths = Object.fromEntries(
    hookedPaths.map((path) => [path, runtime(path)]),
  );
  // The load hook changes precisely named factories in memory. No source/dist
  // bytes, global environment switches, dispatcher branches or SDK internals change.
  await writeFile(
    preload,
    `import {registerHooks} from 'node:module';
import * as fs from 'node:fs/promises';import {appendFileSync,existsSync} from 'node:fs';
const record=value=>appendFileSync(${json(events)},JSON.stringify(value)+'\\n');
const describe=value=>value instanceof Error?{name:value.name,message:value.message,...value}:value;
const mode=${json(mode)},release=${json(release)};
const waitRelease=async()=>{while(!existsSync(release))await new Promise(resolve=>setTimeout(resolve,20))};
const urls=${json(paths)};
globalThis.controlledBoundary={record,mode,release,fs,existsSync};
const injections={
 [urls['process/DarwinProcessRunTokenReader.js']]:['createDarwinProcessRunTokenReader',\
 \`export const createDarwinProcessRunTokenReader=(options={})=>{
 record({type:'reader-factory'});
 const reader=original_createDarwinProcessRunTokenReader({...options,xcrun:${json(compiler)},temporaryFiles:{...fs,rm:async(path,options)=>{
 record({type:'inspector-removal',path});
 if(mode==='inspector-failure'&&!existsSync(release))throw new Error('controlled compiler root removal denied');
 await fs.rm(path,options);record({type:'inspector-root-absent',path});
 }}});
 return {...reader,close:async()=>{record({type:'inspector-close'});await reader.close();record({type:'inspector-closed'})}};
 };\`],
 [urls['application/process/ProcessCli.js']]:['captureProcessScenarioFile',\
 \`export const captureProcessScenarioFile=async(path,environment=process.env,signal)=>{
 const {runOwnedCommand}=await import(${json(runtime("process/OwnedCommand.js"))});
 const {spawnOwnedProviderProcess}=await import(${json(runtime("process/ProviderProcess.js"))});
 const ownership=await import(${json(runtime("process/ProcessOwnership.js"))});
 if(mode==='pty-failure'){
 const {captureProcessScenario}=await import(${json(runtime("process/capture/ProcessHarness.js"))});
 const {processScenarioSchema}=await import(${json(runtime("domain/process/processScenario.js"))});
 const scenario=processScenarioSchema.parse(JSON.parse(await fs.readFile(path,'utf8')));
 const outcome=await captureProcessScenario(scenario,signal,process.platform,environment,undefined,{
 platform:process.platform,
 cleanupProcessGroup:async(...args)=>existsSync(release)?ownership.cleanupOwnedProcessGroup(...args):{cleaned:false,reason:'controlled PTY cleanup denied'},
 verifyTokenOwnedProcesses:async(...args)=>existsSync(release)?ownership.verifyNoTokenOwnedProcesses(...args):{cleaned:false,reason:'controlled PTY cleanup denied'},
 removeTemporaryRoot:async(path)=>{await fs.rm(path,{recursive:true,force:true});record({type:'capture-root-absent',path})}
 });
 record({type:'producer-result',ok:outcome.ok});
 if(!outcome.ok){const {projectAnalysisError}=await import(${json(runtime("domain/analysisErrorProjection.js"))});return {error:'Process command failed',...projectAnalysisError(outcome.error)}}
 return outcome.value;
 }
 try{
 const snapshot=await runOwnedCommand({command:process.execPath,arguments:[${json(workload)}],runId:'controlled-public-command',expectedCommand:null,cwd:${json(cwd)}},{timeoutMs:8000,diagnosticBytes:4096},{signal,launcher:async(input)=>{
 const acquired=await spawnOwnedProviderProcess(input);
 record({type:'command-acquired',pid:acquired.process.pid});
 return {...acquired,cleanup:async()=>{
 record({type:'producer-close'});
 if(mode!=='owned-success'&&mode!=='inspector-failure'&&!existsSync(release))return {cleaned:false,reason:'controlled command cleanup denied'};
 const result=await ownership.cleanupOwnedProcessGroup(acquired.ownership);
 record({type:'producer-cleaned',cleaned:result.cleaned});return result;
 }};
 }});
 return {controlled_snapshot:snapshot};
 }catch(cause){record({type:'producer-result',reason:cause.reason,cleanupFailure:cause.cleanupFailure});return {error:'Process command failed',category:cause.reason,message:cause.message,cleanup_failure:cause.cleanupFailure,snapshot:cause.snapshot}}
 };\`],
 [urls['composition/binary.js']]:['createBinarySession',\
 \`export const createBinarySession=(...args)=>{
 record({type:'session-factory'});
 const provider={identity:()=>({id:'controlled',name:'Controlled local provider',version:'1'}),capabilities:()=>[],createClient:()=>({
 execute:async()=>{throw new Error('No analysis operation supplied by controlled boundary')},
 open:async()=>{},close:async()=>{record({type:'provider-close'});return {ok:true,value:null}}
 })};
 // The actual BinarySession/router own this controlled provider, including open/close queues.
 const router=globalThis.controlledRouter(provider);
 return globalThis.controlledSession(router);
 };\`]
};
const hits={};
registerHooks({load(url,context,nextLoad){
 const result=nextLoad(url,context);const change=injections[url];if(!change)return result;
 const [name,wrapper]=change;const source=typeof result.source==='string'?result.source:Buffer.from(result.source).toString('utf8');const declaration='export const '+name+' =';
 if(source.split(declaration).length!==2)throw new Error('Expected exactly one named factory '+url);
 hits[url]=(hits[url]??0)+1;record({type:'hook',url,count:hits[url]});
 return {...result,source:source.replace(declaration,'const original_'+name+' =')+'\\nconst {record,mode,release,fs,existsSync}=globalThis.controlledBoundary;\\n'+wrapper};
}});
// These imports retain the actual singleton and actual session construction.
const {BinarySession}=await import(${json(runtime("application/binary/BinarySession.js"))});
const {SessionProviderRouter}=await import(${json(runtime("application/binary/SessionProviderRouter.js"))});
const {AnalysisProviderRegistry}=await import(${json(runtime("application/binary/AnalysisProviderRegistry.js"))});
const {createAnalysisExecution}=await import(${json(runtime("application/AnalysisProvider.js"))});
const {systemProcessOwnershipHost}=await import(${json(runtime("process/ProcessOwnershipObservation.js"))});
globalThis.controlledRouter=provider=>{
 provider.createClient=()=>{
  return {execute:async(operation)=>{if(operation!=='health')throw new Error('No analysis operation supplied');return {ok:true,value:createAnalysisExecution(null,provider.identity())}},close:async()=>{record({type:'provider-close'});return {ok:true,value:null}}};
 };
 return SessionProviderRouter.selectable(new AnalysisProviderRegistry([]),[provider]);
};
globalThis.controlledSession=router=>{
 const session=new BinarySession(router);
 const original=session.open.bind(session);
 session.open=async(...args)=>{await systemProcessOwnershipHost.prepare();record({type:'provider-open'});if(mode==='startup-failure')throw new Error('controlled startup rejection');return original(...args)};
 return session;
};
process.on('exit',code=>record({type:'exit',code}));
const module=await import(${json(pathToFileURL(dispatcher).href)});
record({type:'dispatcher-returned'});
if(module.retainedCliCleanup){
 const owner=module.retainedCliCleanup;
 record({type:'retained',settled:owner.settled,processes:owner.receipt?.processes.unresolved.map(item=>item.identity),failures:owner.failures.map(describe)});
 await waitRelease();
 const first=owner.retry(),second=owner.retry();
 record({type:'retry-coalesced',same:first===second,ownerSame:module.retainedCliCleanup===owner});
 const result=await first;
 record({type:'retried',settled:result.settled,processes:result.receipt?.processes.unresolved.map(item=>item.identity),failures:result.failures.map(describe),ownerSame:module.retainedCliCleanup===owner});
}
`,
  );
};

const makeBoundary = async (mode: Mode) => {
  const root = await createTestTempDirectory("rea-public-cleanup-");
  const cwd = join(root, "unrelated 日本語 cwd");
  const ambient = join(root, "ambient TMPDIR 日本語");
  await Promise.all([mkdir(cwd), mkdir(ambient), mkdir(join(root, "tokens"))]);
  const sentinel = join(ambient, "keep.txt");
  await writeFile(sentinel, "caller-owned sentinel");
  const events = join(root, "events.jsonl");
  const release = join(root, "release-cleanup");
  const target = join(root, "controlled.hop");
  await writeFile(target, "controlled local provider document");
  const helper = `#!${process.execPath}\nconst fs=require('node:fs');
const identities=process.argv[2]==='--identities';
const pids=process.argv.slice(identities?3:2).map(Number);
process.stdout.write(JSON.stringify({results:pids.map(pid=>{
 if(identities)return {pid,state:'readable',identity:'controlled-start:'+pid};
 const path=${json(join(root, "tokens"))}+'/'+pid;
 return fs.existsSync(path)?{pid,state:'readable',run_id:fs.readFileSync(path,'utf8')}:{pid,state:'readable'};
})}));\n`;
  const compiler = join(root, "controlled-xcrun");
  await writeFile(
    compiler,
    `#!${process.execPath}\nconst fs=require('node:fs');const path=require('node:path');
const output=process.argv[process.argv.indexOf('-o')+1];
const record=value=>fs.appendFileSync(${json(events)},JSON.stringify(value)+'\\n');
process.on('SIGINT',()=>{record({type:'compiler-interrupt',signal:'SIGINT'});process.exit(130)});
record({type:'compiler',root:path.dirname(output),temporary:process.env.TMPDIR,cwd:process.cwd(),arguments:process.argv.slice(2),pid:process.pid});
if(${json(mode)}==='compiler-cancel'){setInterval(()=>{},1000)}else{fs.writeFileSync(output,${json(helper)});fs.chmodSync(output,0o755)}\n`,
  );
  await chmod(compiler, 0o755);
  const workload = join(root, "workload.cjs");
  await writeFile(
    workload,
    `const fs=require('node:fs');
fs.writeFileSync(${json(join(root, "tokens"))}+'/'+process.pid,process.env.REA_PROCESS_RUN_ID);
fs.appendFileSync(${json(events)},JSON.stringify({type:'workload',pid:process.pid,runId:process.env.REA_PROCESS_RUN_ID})+'\\n');
process.stdout.write('controlled workload stdout\\n');process.stderr.write('controlled workload stderr\\n');
if(${json(mode)}==='owned-cancel'){setInterval(()=>{},1000)}else{process.exitCode=${mode === "owned-failure" ? 7 : 0}}\n`,
  );
  const scenario = join(root, "scenario.json");
  await writeFile(
    scenario,
    json({
      executable: process.execPath,
      arguments: [workload],
      working_directory: cwd,
      settle_ms: 0,
      timeout_ms: 8_000,
      idle_timeout_ms: 8_000,
    }),
  );
  const preload = join(root, "boundary-preload.mjs");
  await writeBoundaryPreload({
    mode,
    events,
    release,
    compiler,
    workload,
    cwd,
    preload,
  });
  const before = await Promise.all(
    hookedPaths.map((path) => digest(join(repository, "dist", path))),
  );
  return {
    root,
    cwd,
    ambient,
    sentinel,
    events,
    release,
    preload,
    scenario,
    target,
    before,
  };
};

type Boundary = Awaited<ReturnType<typeof makeBoundary>>;
const startCli = (boundary: Boundary) => {
  const child = spawn(
    process.execPath,
    [
      "--import",
      boundary.preload,
      dispatcher,
      "capture-process",
      boundary.scenario,
      "--format",
      "json",
    ],
    {
      cwd: boundary.cwd,
      env: {
        PATH: process.env.PATH,
        HOME: boundary.root,
        TMPDIR: boundary.ambient,
        REA_LOG_LEVEL: "silent",
      },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  let stdout = "",
    stderr = "";
  child.stdout.on("data", (chunk: Buffer) => {
    stdout += chunk.toString();
  });
  child.stderr.on("data", (chunk: Buffer) => {
    stderr += chunk.toString();
  });
  const closed = new Promise<{
    code: number | null;
    signal: NodeJS.Signals | null;
  }>((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => resolve({ code, signal }));
  });
  onTestFinished(async () => {
    await writeFile(boundary.release, "release").catch(() => undefined);
    if (child.exitCode === null && child.signalCode === null) {
      await Promise.race([
        closed,
        new Promise<void>((resolve) => {
          const timeout = setTimeout(resolve, 5_000);
          void closed.finally(() => clearTimeout(timeout));
        }),
      ]);
    }
    if (child.exitCode === null && child.signalCode === null) {
      child.kill("SIGTERM");
      await Promise.race([
        closed,
        new Promise<void>((resolve) => {
          const timeout = setTimeout(resolve, 1_000);
          void closed.finally(() => clearTimeout(timeout));
        }),
      ]);
    }
    if (child.exitCode === null && child.signalCode === null)
      child.kill("SIGKILL");
    await closed;
  });
  return { child, closed, stdout: () => stdout, stderr: () => stderr };
};

const assertInspectorClosed = async (boundary: Boundary) => {
  expect(
    await Promise.all(
      hookedPaths.map((path) => digest(join(repository, "dist", path))),
    ),
  ).toEqual(boundary.before);
  expect(await readFile(boundary.sentinel, "utf8")).toBe(
    "caller-owned sentinel",
  );
  const events = await readEvents(boundary.events);
  expect(events.filter(({ type }) => type === "reader-factory")).toHaveLength(
    1,
  );
  expect(events.filter(({ type }) => type === "inspector-closed")).toHaveLength(
    1,
  );
  const compilation = events.find(({ type }) => type === "compiler");
  if (compilation === undefined || typeof compilation.root !== "string")
    throw new Error("No compiler owner was observed");
  expect(compilation.cwd).toBe(boundary.cwd);
  expect(compilation.temporary).toBe(join(compilation.root, "tmp"));
  expect(compilation.root).not.toContain(boundary.ambient);
  expect(await exists(compilation.root)).toBe(false);
  for (const event of events.filter(({ type }) => type === "hook"))
    expect(event.count).toBe(1);
  const exit = events.find(({ type }) => type === "exit");
  expect(exit).toBeDefined();
  return events;
};

itDarwin(
  "closes the actual singleton after an ordinary public CLI command and complete child output",
  async () => {
    const boundary = await makeBoundary("owned-success");
    const cli = startCli(boundary);
    expect(await cli.closed).toEqual({ code: 0, signal: null });
    expect(cli.stderr()).toBe("");
    expect(JSON.parse(cli.stdout())).toMatchObject({
      controlled_snapshot: {
        stdout: { text: "controlled workload stdout\n" },
        stderr: { text: "controlled workload stderr\n" },
        exitCode: 0,
      },
    });
    const events = await assertInspectorClosed(boundary);
    expect(
      events.findIndex(({ type }) => type === "producer-cleaned"),
    ).toBeLessThan(events.findIndex(({ type }) => type === "inspector-close"));
  },
  20_000,
);

itDarwin.each(["owned-failure", "pty-failure", "inspector-failure"] as const)(
  "retains the actual %s owner across public projection and same-process terminal retry",
  async (mode) => {
    const boundary = await makeBoundary(mode);
    const cli = startCli(boundary);
    const retained = await waitEvent(
      boundary.events,
      "retained",
      mode === "pty-failure"
        ? async () =>
            json({
              stdout: cli.stdout(),
              stderr: cli.stderr(),
              events: await readEvents(boundary.events),
            })
        : undefined,
    );
    expect(retained.settled).toBe(false);
    const eventsBefore = await readEvents(boundary.events);
    if (mode !== "inspector-failure") {
      expect(retained.processes).toHaveLength(1);
      expect(eventsBefore.some(({ type }) => type === "inspector-close")).toBe(
        false,
      );
    }
    const compilation = eventsBefore.find(({ type }) => type === "compiler");
    expect(await exists(String(compilation?.root))).toBe(true);
    await writeFile(boundary.release, "release");
    expect(await cli.closed).toEqual({ code: 1, signal: null });
    const retried = await waitEvent(boundary.events, "retried");
    expect(
      retried,
      json({
        stdout: cli.stdout(),
        stderr: cli.stderr(),
        events: await readEvents(boundary.events),
        retried,
      }),
    ).toMatchObject({
      settled: true,
      processes: [],
      ownerSame: true,
    });
    expect(retried.failures).not.toEqual([]);
    expect(await waitEvent(boundary.events, "retry-coalesced")).toMatchObject({
      same: true,
      ownerSame: true,
    });
    const output = JSON.parse(cli.stdout());
    if (mode === "owned-failure")
      expect(output).toMatchObject({
        error: "Process command failed",
        category: "process",
        snapshot: {
          exitCode: 7,
          stdout: { text: "controlled workload stdout\n" },
          stderr: { text: "controlled workload stderr\n" },
        },
        cleanup_failure: expect.stringContaining(
          "controlled command cleanup denied",
        ),
      });
    if (mode === "pty-failure")
      expect(output).toMatchObject({
        code: "cleanup_incomplete",
        details: {
          cleanup: "incomplete",
          resources: ["owned_process_group", "temporary_root"],
        },
      });
    expect(cli.stderr()).toContain("Owned cleanup remains available for retry");
    const events = await assertInspectorClosed(boundary);
    if (mode === "pty-failure")
      expect(events.some(({ type }) => type === "capture-root-absent")).toBe(
        true,
      );
  },
  25_000,
);

itDarwin.each(["SIGINT", "SIGTERM"] as const)(
  "preserves public cancellation and denied child cleanup until terminal retry after %s",
  async (signal) => {
    const boundary = await makeBoundary("owned-cancel");
    const cli = startCli(boundary);
    const workload = await waitEvent(boundary.events, "workload");
    expect(typeof workload.pid).toBe("number");
    cli.child.kill(signal);
    const retained = await waitEvent(boundary.events, "retained");
    expect(retained).toMatchObject({ settled: false });
    expect(retained.processes).toHaveLength(1);
    expect(
      (await readEvents(boundary.events)).some(
        ({ type }) => type === "inspector-close",
      ),
    ).toBe(false);
    await writeFile(boundary.release, "release");
    expect(await cli.closed).toEqual({ code: 1, signal: null });
    expect(JSON.parse(cli.stdout())).toMatchObject({
      category: "cancelled",
      cleanup_failure: expect.stringContaining(
        "controlled command cleanup denied",
      ),
    });
    expect(await waitEvent(boundary.events, "retried")).toMatchObject({
      settled: true,
      ownerSame: true,
    });
    await assertInspectorClosed(boundary);
  },
  25_000,
);

itDarwin.each(["SIGINT", "SIGTERM"] as const)(
  "interrupts an actual controlled compiler with SIGINT before public %s completion",
  async (signal) => {
    const boundary = await makeBoundary("compiler-cancel");
    const cli = startCli(boundary);
    await waitEvent(boundary.events, "compiler");
    cli.child.kill(signal);
    expect(await cli.closed).toEqual({
      code: signal === "SIGINT" ? 130 : 143,
      signal: null,
    });
    expect(
      await waitEvent(boundary.events, "compiler-interrupt"),
    ).toMatchObject({ signal: "SIGINT" });
    expect(
      (await readEvents(boundary.events)).some(
        ({ type }) => type === "workload",
      ),
    ).toBe(false);
    await assertInspectorClosed(boundary);
  },
  20_000,
);

itDarwin.each(["client-close", "transport-disconnect"] as const)(
  "keeps the lazy MCP singleton usable through two target cycles and closes it after SDK %s",
  async (ending) => {
    const boundary = await makeBoundary("mcp");
    const transport = new StdioClientTransport({
      command: process.execPath,
      args: ["--import", boundary.preload, dispatcher, "mcp"],
      cwd: boundary.cwd,
      env: {
        PATH: process.env.PATH ?? "",
        HOME: boundary.root,
        TMPDIR: boundary.ambient,
        REA_LOG_LEVEL: "silent",
      },
      stderr: "pipe",
    });
    const client = new Client({ name: "rea-cleanup-boundary", version: "1" });
    let stderr = "";
    transport.stderr?.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });
    onTestFinished(async () => {
      await client.close();
      await transport.close();
    });
    await client.connect(transport);
    await waitEvent(boundary.events, "dispatcher-returned");
    expect(
      (await readEvents(boundary.events)).some(
        ({ type }) => type === "inspector-close",
      ),
    ).toBe(false);
    for (let cycle = 0; cycle < 2; cycle += 1) {
      const opened = await client.callTool({
        name: "open_binary",
        arguments: { path: boundary.target },
      });
      expect(opened.isError, json(opened)).not.toBe(true);
      const closed = await client.callTool({
        name: "close_binary",
        arguments: {},
      });
      expect(closed.isError, json(closed)).not.toBe(true);
      expect(
        (await readEvents(boundary.events)).some(
          ({ type }) => type === "inspector-close",
        ),
      ).toBe(false);
    }
    if (ending === "client-close") await client.close();
    else await transport.close();
    expect(await waitEvent(boundary.events, "exit")).toMatchObject({ code: 0 });
    expect(stderr).toBe("");
    const events = await assertInspectorClosed(boundary);
    expect(events.filter(({ type }) => type === "provider-open")).toHaveLength(
      2,
    );
    expect(events.filter(({ type }) => type === "provider-close")).toHaveLength(
      2,
    );
  },
  25_000,
);

itDarwin(
  "settles the actual allocated inspector after a public MCP startup rejection",
  async () => {
    const boundary = await makeBoundary("startup-failure");
    const child = spawn(
      process.execPath,
      ["--import", boundary.preload, dispatcher, "mcp"],
      {
        cwd: boundary.cwd,
        env: {
          PATH: process.env.PATH,
          HOME: boundary.root,
          TMPDIR: boundary.ambient,
          REA_LOG_LEVEL: "silent",
          HOPPER_TARGET_PATH: boundary.target,
        },
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    let stdout = "",
      stderr = "";
    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });
    const closed = new Promise((resolve, reject) => {
      child.once("error", reject);
      child.once("close", (code, signal) => resolve({ code, signal }));
    });
    onTestFinished(async () => {
      child.stdin.end();
      if (child.exitCode === null && child.signalCode === null)
        child.kill("SIGKILL");
      await closed;
    });
    expect(await closed).toEqual({ code: 1, signal: null });
    expect(stdout).toBe("");
    expect(stderr).toContain("REA could not start.");
    await assertInspectorClosed(boundary);
  },
  20_000,
);
