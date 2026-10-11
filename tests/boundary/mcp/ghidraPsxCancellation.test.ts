import { createRequire } from "node:module";
import { watch } from "node:fs";
import {
  access,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { describe, expect, it, onTestFinished } from "vitest";
import { inspectGhidraPsxLoader } from "../../../src/ghidra/GhidraPsxLoader.js";
import {
  createPsxInstallationFixture,
  psxAppliedLoadImageObservation,
  psxFixtureAgreement,
  psxFixtureCommitment,
  psxFixtureOriginalRecord,
  psxFixtureSha256,
  psxImportBytes,
} from "../../fixtures/ghidraPsxImport.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";

type Owner = {
  root: string;
  run_id: string;
  source_digest: string;
  ownership: { parent_pid: number; pid: number; run_id: string };
  snapshot: { path: string; sha256?: string };
  capture_state: { status: string; missing: string[] };
};
type Context = {
  roots: Map<string, Owner>;
  resources: { owner: string }[];
  case(id: string, adapter: string, action: () => Promise<void>): Promise<void>;
  fixtures: { path: string; before_sha256: string }[];
  failures: { message: string }[];
  unpersisted_events: unknown[];
};
type Session = {
  pid: number;
  call(
    name: string,
    params?: Record<string, unknown>,
    options?: Record<string, unknown>,
  ): Promise<Record<string, any>>;
  disconnect(): Promise<void>;
  close(): Promise<void>;
};
type Cancellation = {
  status: string;
  allocated: Owner[];
  outcome: { value?: unknown; cause?: Error };
};
const helper = (await import(
  new URL("../../../scripts/lib/real-ghidra-psx-public.mjs", import.meta.url)
    .href
)) as {
  createPublicPsxContext(input: Record<string, unknown>): Context;
  connectPublicPsxMcp(context: Context, caseId?: string): Promise<Session>;
  verifyPublicPsxCancellationRecovery(
    context: Context,
    session: Session,
    input: Record<string, unknown>,
  ): Promise<void>;
  cancelPublicPsxNativeRequest(
    context: Context,
    session: Session,
    input: Record<string, unknown>,
  ): Promise<{
    cancellation: Cancellation;
    admission: Record<string, any>;
    binding: Record<string, any>;
    run_id: string;
  }>;
  coordinatePublicPsxCancellation(
    input: Record<string, unknown>,
  ): Promise<Cancellation>;
  observePublicPsxAllocations(
    context: Context,
    pid: number,
    id: string,
    adapter: string,
    digest: string,
  ): Promise<Owner[]>;
  settlePublicPsxContext(context: Context): Promise<{
    ok: boolean;
    failures: { message: string }[];
    settlement: {
      unresolved_owners: { retry(): Promise<void> }[];
      remaining_roots: string[];
      verified_empty_lineage: boolean;
    };
  }>;
};
const require = createRequire(import.meta.url);
const moduleUrl = (path: string) =>
  new URL(`../../../dist/${path}.js`, import.meta.url).href;
const sdkStdio = pathToFileURL(
  require.resolve("@modelcontextprotocol/server/stdio"),
).href;
const exists = async (path: string) => {
  try {
    await access(path);
    return true;
  } catch (cause) {
    if ((cause as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw cause;
  }
};
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
    observer.on("error", reject);
    void check();
  });
};

/** Controlled producer only: real socket/child lifetime, synthetic startup and image observations. */
const producer = `
import {watch} from 'node:fs';
import {readFile,writeFile} from 'node:fs/promises';
import {createServer} from 'node:net';
const input=JSON.parse(await readFile(process.argv[2],'utf8'));
const gate=input.gate;
await new Promise((resolve,reject)=>{
 const observer=watch(input.control,()=>void check());
 const check=async()=>{try{await readFile(gate);observer.close();resolve();}catch(error){if(error.code!=='ENOENT'){observer.close();reject(error);}}};
 void check();
});
await writeFile(input.beforePath,input.before);
await writeFile(input.originalPath,input.original);
process.stdout.write(input.report+'\\n'+input.marker+'\\n');
process.stderr.write('controlled producer retained diagnostics '+input.runId+'\\n');
const server=createServer(socket=>{
 socket.setEncoding('utf8'); let pending='';
 socket.on('data',chunk=>{pending+=chunk;for(;;){const at=pending.indexOf('\\n');if(at<0)break;const request=JSON.parse(pending.slice(0,at));pending=pending.slice(at+1);
 if(request.token!==input.token)throw new Error('Authentication mismatch');
 const result=request.method==='ping'?input.info:request.method==='inspect_native_load_image'?input.image:request.method==='shutdown'?{shutdown:true,project_ephemeral:true}:null;
 if(result===null)throw new Error('Unmodeled operation '+request.method);
 socket.write(JSON.stringify({id:request.id,ok:true,result})+'\\n');
 if(request.method==='shutdown'){socket.end();server.close(()=>process.exit(0));}
 }});
});
server.listen(input.endpoint);
`;

const controlledServer = (dataPath: string, producerPath: string) => `
import {readFile,writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';
import {createHash} from 'node:crypto';
import {serveStdio} from ${JSON.stringify(sdkStdio)};
import {composeBinarySession} from ${JSON.stringify(moduleUrl("application/binary/BinarySessionComposition"))};
import {AnalysisProviderRegistry} from ${JSON.stringify(moduleUrl("application/binary/AnalysisProviderRegistry"))};
import {GhidraProvider} from ${JSON.stringify(moduleUrl("ghidra/GhidraProvider"))};
import {GhidraClient} from ${JSON.stringify(moduleUrl("ghidra/GhidraClient"))};
import {spawnOwnedProviderProcess} from ${JSON.stringify(moduleUrl("process/ProviderProcess"))};
import {cleanupOwnedProcessGroup} from ${JSON.stringify(moduleUrl("process/ProcessOwnership"))};
import {parseConfig} from ${JSON.stringify(moduleUrl("config/parseConfig"))};
import {silentLogger} from ${JSON.stringify(moduleUrl("logger"))};
import {startMcpTransport} from ${JSON.stringify(moduleUrl("main/transport"))};
import {createShutdown} from ${JSON.stringify(moduleUrl("main/shutdown"))};
import {createToolResultDelivery} from ${JSON.stringify(moduleUrl("server/toolResult"))};
import {GHIDRA_SESSION_CAPABILITIES} from ${JSON.stringify(moduleUrl("ghidra/GhidraSessionValues"))};
const data=JSON.parse(await readFile(${JSON.stringify(dataPath)},'utf8'));
const hash=text=>createHash('sha256').update(text).digest('hex');
const host={platform:'linux',architecture:'x64',readText:path=>path.endsWith('application.properties')?'application.version=12.1.4\\n':'',executable:()=>true,probeJava:()=>({version:'21.0.11',major:21,home:'/synthetic/jdk',bits:64,runtime:'jdk'})};
const config=parseConfig({GHIDRA_INSTALL_DIR:data.installationRoot});if(!config.ok)throw config.error;
const provider=new GhidraProvider(config.value,silentLogger,process.env,host,options=>new GhidraClient({...options,startupTimeoutMs:5000,launcher:{launch:async(session,{signal}={})=>{
 if(data.mode==='reject')throw new Error('controlled unrelated launcher rejection');
 const agreement=structuredClone(data.agreement);
 for(const stage of [agreement.before,agreement.after]){
  stage.commitment={run_id:session.runId,profile_digest:session.profileDigest,source_sha256:session.targetSha256};
  stage.observed.source.snapshot_path=session.targetPath;
  stage.observed.program.executable_path=session.targetPath;
  stage.observed.asset_inventory_digest=options.psxImport.commitment.asset_inventory_digest;
 }
 const original={...structuredClone(data.original),commitment:agreement.before.commitment};
 const originalText=JSON.stringify(original)+'\\n';
 for(const stage of [agreement.before,agreement.after])stage.provenance.metadata_preservation.original_record_sha256=hash(originalText);
 const before=JSON.stringify(agreement.before)+'\\n';agreement.before_record_sha256=hash(before);
 const image=structuredClone(data.image);image.psx.provenance=agreement.after.provenance;
 const info={name:'REA Ghidra bridge',run_id:session.runId,profile_digest:session.profileDigest,provider:{id:'ghidra',version:session.providerVersion},read_only:false,analysis_complete:true,analysis_timed_out:false,capabilities:[...GHIDRA_SESSION_CAPABILITIES],psx_import:agreement,target:{name:'synthetic PSX',language_id:'PSX:LE:32:default',compiler_spec_id:'default',image_base:'0x80000000',default_address_space:'ram',sha256:session.targetSha256}};
 const inputPath=join(data.control,session.runId+'.producer.json');
 await writeFile(inputPath,JSON.stringify({control:data.control,gate:join(data.control,session.runId+'.release'),beforePath:join(session.runtimeRoot,'psx-import-before.json'),originalPath:join(session.runtimeRoot,'psx-provenance-original.json'),before,original:originalText,info,image,endpoint:session.endpointPath,token:session.token,runId:session.runId,report:'REPORT: Analysis succeeded for file: '+pathToFileURL(session.targetPath).href,marker:'REA_PSX_IMPORT_BEFORE_COMPLETE '+session.runId+' '+agreement.before_record_sha256}));
 const spawned=await spawnOwnedProviderProcess({command:process.execPath,arguments:[${JSON.stringify(producerPath)},inputPath],runId:session.runId,env:{},hostEnvironment:{},platform:'linux'});
 await writeFile(join(session.runtimeRoot,'descriptor.json'),JSON.stringify({run_id:session.runId,target_sha256:session.targetSha256,profile_digest:session.profileDigest,target_path:session.targetPath,token:session.token}));
 if(data.mode!=='no-manifest')await writeFile(join(session.runtimeRoot,'ownership.json'),JSON.stringify({run_id:session.runId,pid:spawned.ownership.leaderPid,process_group_id:spawned.ownership.processGroupId,parent_pid:data.mode==='wrong-parent'?process.pid+1:process.pid,ownership_kind:'posix-process-group',launcher:process.execPath,arguments:[process.execPath,${JSON.stringify(producerPath)},inputPath,'-import',session.targetPath]}));
 signal?.addEventListener('abort',()=>{void writeFile(join(data.control,session.runId+'.aborted'),String(signal.reason));},{once:true});
 await writeFile(join(data.control,session.runId+'.allocated'),JSON.stringify({root:session.runtimeRoot,pid:spawned.process.pid,parent_pid:process.pid,run_id:session.runId,source:session.targetSha256,profile:session.profileDigest}));
 return {ok:true,value:{process:spawned.process,ownership:spawned.ownership,ownsProcessLifetime:true,cleanup:async()=>{
  try{await readFile(join(data.control,'deny-cleanup'));return {cleaned:false,reason:'controlled cleanup denial'};}catch(error){if(error.code!=='ENOENT')throw error;}
  return cleanupOwnedProcessGroup(spawned.ownership);
 },projectRoot:join(session.runtimeRoot,'project'),ghidraLogPath:join(session.runtimeRoot,'ghidra.log'),scriptLogPath:join(session.runtimeRoot,'script.log')}};
}}}));
const session=composeBinarySession(new AnalysisProviderRegistry([provider]));
const deps={env:process.env,serve:serveStdio,writeStderr:text=>process.stderr.write(text),setExitCode:code=>{process.exitCode=code;},registerShutdown:handler=>{process.once('SIGINT',handler);process.once('SIGTERM',handler);process.stdin.once('end',handler);process.stdin.once('close',handler);return ()=>{process.off('SIGINT',handler);process.off('SIGTERM',handler);process.stdin.off('end',handler);process.stdin.off('close',handler);};}};
const transport=await startMcpTransport(deps,session,{environment:process.env,logger:silentLogger,serverLogger:silentLogger,delivery:createToolResultDelivery(),loadOptionalProviders:async()=>({})});
if(!transport.ok)throw new Error('controlled MCP transport failed');
createShutdown({handle:transport.handle,closeAndroid:transport.closeAndroid,session,dependencies:deps,serverLogger:silentLogger});
`;

const harness = async (
  mode: "held" | "wrong-parent" | "no-manifest" | "reject" = "held",
) => {
  const fixture = await createPsxInstallationFixture();
  const parent = await createTestTempDirectory("psx-sdk-startup-");
  const workspace = join(parent, "workspace");
  const control = join(parent, "control");
  await mkdir(workspace);
  await mkdir(control);
  const inspected = await inspectGhidraPsxLoader(
    fixture.installationRoot,
    "12.1.4",
  );
  if (inspected.status !== "available") throw new Error(inspected.reason);
  const candidate = inspected.candidate;
  const selectedClasses = [
    ...candidate.analyzer_classes.map((className) => ({
      className,
      role: "analyzer" as const,
    })),
    { className: "psx.PsxLoader", role: "loader" as const },
  ]
    .map(({ className, role }) => {
      const relative =
        className === "ghidra.app.plugin.core.analysis.MipsPreAnalyzer"
          ? "Ghidra/Processors/MIPS/lib/MIPS.jar"
          : candidate.loader.code_source_relative;
      const asset = candidate.assets.find(
        (value) => value.relative_path === relative,
      )!;
      const url = pathToFileURL(
        join(candidate.installation_root, relative),
      ).href;
      return {
        class_name: className,
        role,
        code_source_url: url,
        code_source_relative: relative,
        code_source_sha256: asset.sha256,
        class_resource_url: `jar:${url}!/${className.replaceAll(".", "/")}.class`,
        enabled: role === "loader" ? null : true,
      };
    })
    .sort((a, b) => a.class_name.localeCompare(b.class_name));
  const agreement = psxFixtureAgreement({
    commitment: psxFixtureCommitment(fixture.source),
    runId: "00000000-0000-4000-8000-000000000007",
    profileDigest: "a".repeat(64),
    selectedClasses,
    languageAssets: [...candidate.language_assets],
  });
  const dataPath = join(control, "data.json");
  const producerPath = join(control, "producer.mjs");
  const serverPath = join(control, "server.mjs");
  await writeFile(
    dataPath,
    JSON.stringify({
      installationRoot: fixture.installationRoot,
      mode,
      control,
      agreement,
      original: psxFixtureOriginalRecord(
        agreement.before.commitment,
        agreement.before.provenance.metadata_preservation,
      ),
      image: psxAppliedLoadImageObservation(),
    }),
  );
  await writeFile(producerPath, producer);
  await writeFile(serverPath, controlledServer(dataPath, producerPath));
  const flags = { capture: false, deletion: false };
  const events: Record<string, any>[] = [];
  const context = helper.createPublicPsxContext({
    executable: process.execPath,
    prefixArgs: [serverPath],
    workspace,
    environment: {
      PATH: process.env.PATH ?? "",
      HOME: parent,
      TMPDIR: workspace,
      REA_LOG_LEVEL: "silent",
    },
    captureFilesystem: {
      rm: async (path: string, options: Parameters<typeof rm>[1]) => {
        if (flags.deletion && path.includes("rea-ghidra-"))
          throw new Error("controlled exact native removal failure");
        await rm(path, options);
      },
    },
    record: async (event: Record<string, any>) => {
      if (flags.capture && event.stage === "snapshot-capture")
        throw new Error("controlled durable capture failure");
      events.push(event);
      await writeFile(
        join(parent, "events.jsonl"),
        JSON.stringify(event) + "\n",
        { flag: "a" },
      );
    },
  });
  const digest = psxFixtureSha256(psxImportBytes());
  context.fixtures.push({ path: fixture.source, before_sha256: digest });
  onTestFinished(async () => {
    flags.capture = false;
    flags.deletion = false;
    await rm(join(control, "deny-cleanup"), { force: true });
    const result = await helper.settlePublicPsxContext(context);
    expect(result.settlement.unresolved_owners).toEqual([]);
    expect(result.settlement.remaining_roots).toEqual([]);
    expect(await readFile(fixture.source)).toEqual(psxImportBytes());
  });
  return {
    fixture,
    parent,
    workspace,
    control,
    events,
    context,
    digest,
    flags,
  };
};
const release = async (f: Awaited<ReturnType<typeof harness>>, runId: string) =>
  writeFile(join(f.control, runId + ".release"), "release controlled producer");
const probe = async (
  f: Awaited<ReturnType<typeof harness>>,
  session: Session,
  id: string,
) => {
  const opened = await session.call(
    "open_binary",
    { path: f.fixture.source, provider_id: "ghidra" },
    { caseId: id + "-open" },
  );
  expect(opened.value).toMatchObject({
    path: f.fixture.source,
    sha256: f.digest,
    format: "ps-x-exe",
    architecture: "mips",
  });
  const state = (await session.call("binary_session")).value;
  expect(state).toMatchObject({
    open: true,
    path: f.fixture.source,
    sha256: f.digest,
  });
  const pending = helper.verifyPublicPsxCancellationRecovery(
    f.context,
    session,
    { source: f.fixture.source, sourceDigest: f.digest, caseId: id },
  );
  const result = pending.then(
    () => ({ ok: true }),
    (cause) => ({ cause }),
  );
  await reached(f.control, state.analysis_run.run_id + ".allocated");
  await release(f, state.analysis_run.run_id);
  const completed = await result;
  if ("cause" in completed) throw completed.cause;
  await session.call("close_binary");
  return state.analysis_run.run_id as string;
};

describe.skipIf(process.platform === "win32")(
  "P5-R7 actual stdio SDK and production pending startup cancellation",
  () => {
    it.each(["abort", "disconnect"] as const)(
      "cancels the pending image through %s after bound partial startup and recovers on new startup",
      async (mode) => {
        const f = await harness();
        await f.context.case(
          `controlled-${mode}-startup-recovery`,
          "mcp",
          async () => {
            const sdk = await helper.connectPublicPsxMcp(
              f.context,
              "controlled-" + mode,
            );
            const result = await helper.cancelPublicPsxNativeRequest(
              f.context,
              sdk,
              {
                source: f.fixture.source,
                sourceDigest: f.digest,
                caseId: mode + "-image",
                mode,
                deadlineMs: 5000,
              },
            );
            expect(result.cancellation.status).toBe("passed");
            expect(result.cancellation.allocated).toHaveLength(1);
            const owner = result.cancellation.allocated[0]!;
            expect(
              f.context.resources.filter(
                (resource) =>
                  resource.owner === `native-runtime:${owner.run_id}`,
              ),
            ).toHaveLength(1);
            expect(owner).toMatchObject({
              run_id: result.run_id,
              source_digest: f.digest,
              ownership: { parent_pid: sdk.pid, run_id: result.run_id },
              snapshot: { sha256: f.digest },
              capture_state: {
                status: "incomplete",
                missing: [
                  "psx-import-before.json",
                  "psx-provenance-original.json",
                ],
              },
            });
            expect(result.binding).toMatchObject({
              operation: "inspect_native_load_image",
              parameters: {},
              sourceDigest: f.digest,
            });
            await reached(f.control, result.run_id + ".aborted");
            const allocated = JSON.parse(
              await readFile(
                join(f.control, result.run_id + ".allocated"),
                "utf8",
              ),
            );
            expect(allocated).toMatchObject({
              root: owner.root,
              parent_pid: sdk.pid,
              run_id: result.run_id,
              source: f.digest,
              profile: result.binding.selectedProfile.digest,
            });
            await expect(access(owner.root)).rejects.toMatchObject({
              code: "ENOENT",
            });
            const requests = f.events
              .filter(
                (event) =>
                  event.kind === "invocation" && event.stage === "operation",
              )
              .map((event) => [event.operation, event.parameters]);
            expect(requests.slice(0, 4)).toEqual([
              ["close_binary", {}],
              [
                "open_binary",
                { path: f.fixture.source, provider_id: "ghidra" },
              ],
              ["binary_session", {}],
              ["inspect_native_load_image", {}],
            ]);
            const allocationSequence = f.events.find(
              (event) => event.stage === "native-allocation",
            )!.sequence;
            const imageRequest = f.events.find(
              (event) =>
                event.kind === "invocation" &&
                event.case_id === mode + "-image",
            )!;
            expect(imageRequest.sequence).toBeLessThan(allocationSequence);
            expect(
              f.events.filter(
                (event) =>
                  event.stage === "cancellation" && event.action !== undefined,
              ),
            ).toHaveLength(1);
            const connection =
              mode === "disconnect"
                ? await helper.connectPublicPsxMcp(
                    f.context,
                    "fresh-after-disconnect",
                  )
                : sdk;
            if (mode === "abort") {
              const state = (await sdk.call("binary_session")).value;
              expect(state.open).toBe(true);
              const recovery = helper.verifyPublicPsxCancellationRecovery(
                f.context,
                sdk,
                {
                  source: f.fixture.source,
                  sourceDigest: f.digest,
                  caseId: "same-target-recovery",
                },
              );
              const captured = recovery.then(
                () => ({ ok: true }),
                (cause) => ({ cause }),
              );
              await release(f, result.run_id);
              const completed = await captured;
              if ("cause" in completed) throw completed.cause;
              await sdk.call("close_binary");
            }
            const recoveryRun = await probe(f, connection, "fresh-recovery");
            expect(recoveryRun).not.toBe(result.run_id);
            await connection.close();
            if (mode === "abort")
              expect(f.context.roots.size).toBeGreaterThanOrEqual(1);
          },
        );
        const settled = await helper.settlePublicPsxContext(f.context);
        expect(settled.ok, JSON.stringify(settled.failures)).toBe(true);
        expect(settled.settlement).toMatchObject({
          verified_empty_lineage: true,
          remaining_roots: [],
          unresolved_owners: [],
        });
        expect(await readFile(f.fixture.source)).toEqual(psxImportBytes());
        const durable = (await readFile(join(f.parent, "events.jsonl"), "utf8"))
          .trim()
          .split("\n")
          .map((line) => JSON.parse(line));
        expect(durable).toEqual(f.events);
      },
    );
  },
);

describe.skipIf(process.platform === "win32")(
  "P5-R7 actual SDK startup refusal and retained cleanup",
  () => {
    it("retains the source-bound partial owner when capture fails and settles the pending process", async () => {
      const f = await harness();
      const sdk = await helper.connectPublicPsxMcp(
        f.context,
        "capture-failure",
      );
      f.flags.capture = true;
      await expect(
        helper.cancelPublicPsxNativeRequest(f.context, sdk, {
          source: f.fixture.source,
          sourceDigest: f.digest,
          caseId: "capture-image",
          mode: "abort",
          deadlineMs: 5000,
        }),
      ).rejects.toThrow();
      const settled = await helper.settlePublicPsxContext(f.context);
      expect(settled.ok).toBe(false);
      expect(f.context.unpersisted_events.length).toBeGreaterThan(0);
      expect(
        settled.settlement.unresolved_owners,
        JSON.stringify(settled.failures),
      ).toEqual([]);
      expect(settled.settlement.remaining_roots).toEqual([]);
      expect(await readFile(f.fixture.source)).toEqual(psxImportBytes());
    });
  },
);

describe("P5-R7 coordinator cannot infer cancellation from unrelated outcomes", () => {
  it("fails its explicit deadline when no exact allocation becomes available", async () => {
    let triggered = false;
    let finish: (value: unknown) => void = () => undefined;
    const pending = new Promise((resolve) => {
      finish = resolve;
    });
    try {
      await expect(
        helper.coordinatePublicPsxCancellation({
          pending,
          observe: async () => [],
          cancel: async () => {
            triggered = true;
          },
          deadlineMs: 1,
        }),
      ).rejects.toThrow();
      expect(triggered).toBe(false);
    } finally {
      finish({ not_cancelled: true });
    }
  });
});

describe.skipIf(process.platform === "win32")(
  "P5-R7 exact allocation and actual public refusal controls",
  () => {
    it.each(["wrong-parent", "no-manifest"] as const)(
      "does not trigger on %s allocation and interrupts its real pending request at the deadline",
      async (mode) => {
        const f = await harness(mode);
        const sdk = await helper.connectPublicPsxMcp(f.context, mode);
        await expect(
          helper.cancelPublicPsxNativeRequest(f.context, sdk, {
            source: f.fixture.source,
            sourceDigest: f.digest,
            caseId: mode + "-image",
            mode: "abort",
            deadlineMs: 100,
          }),
        ).rejects.toThrow();
        expect(
          f.events.filter(
            (event) => event.stage === "cancellation" && event.action,
          ),
        ).toEqual([]);
        expect(
          f.events.find(
            (event) =>
              event.case_id === mode + "-image" &&
              event.transport_status === "failed",
          ),
        ).toMatchObject({
          kind: "raw_result",
          failure: {
            message: "Error: Owned SDK cancellation coordination failed",
          },
        });
        await sdk.close();
        const settled = await helper.settlePublicPsxContext(f.context);
        expect(settled.settlement).toMatchObject({
          remaining_roots: [],
          unresolved_owners: [],
          verified_empty_lineage: true,
        });
        expect(
          (await readdir(f.workspace)).filter((name) =>
            name.startsWith("rea-ghidra-"),
          ),
        ).toEqual([]);
      },
    );
    it("preserves an actual unrelated launcher refusal and never calls it cancellation", async () => {
      const f = await harness("reject");
      const sdk = await helper.connectPublicPsxMcp(
        f.context,
        "unrelated-launch",
      );
      await expect(
        helper.cancelPublicPsxNativeRequest(f.context, sdk, {
          source: f.fixture.source,
          sourceDigest: f.digest,
          caseId: "unrelated-image",
          mode: "abort",
          deadlineMs: 5000,
        }),
      ).rejects.toThrow("completed before cancellation");
      expect(
        f.events.filter(
          (event) => event.stage === "cancellation" && event.action,
        ),
      ).toEqual([]);
      const raw = f.events.find(
        (event) =>
          event.case_id === "unrelated-image" &&
          event.kind === "raw_result" &&
          event.reply,
      );
      expect(raw).toBeDefined();
      expect(JSON.stringify(raw)).toContain(
        "controlled unrelated launcher rejection",
      );
      expect(f.context.roots.size).toBe(0);
      await sdk.close();
    });
    it("keeps actual completed image Evidence inconclusive for cancellation and excludes its historical allocation from a later request", async () => {
      const f = await harness();
      const sdk = await helper.connectPublicPsxMcp(
        f.context,
        "completed-before-trigger",
      );
      const completedRun = await probe(f, sdk, "completed-image");
      const historical = [...f.context.roots.values()].find(
        (owner) => owner.run_id === completedRun,
      )!;
      const evidenceEvent = f.events.find(
        (event) =>
          event.case_id === "completed-image" &&
          event.kind === "observation" &&
          event.evidence,
      )!;
      expect(evidenceEvent).toBeDefined();
      let triggered = false;
      const result = await helper.coordinatePublicPsxCancellation({
        pending: Promise.resolve({ evidence: evidenceEvent.evidence }),
        observe: async () => {
          await Promise.resolve();
          return [historical];
        },
        cancel: async () => {
          triggered = true;
        },
      });
      expect(result.status).toBe("inconclusive");
      expect(result.allocated).toEqual([]);
      expect(triggered).toBe(false);
      const actual = await helper.cancelPublicPsxNativeRequest(f.context, sdk, {
        source: f.fixture.source,
        sourceDigest: f.digest,
        caseId: "after-historical-image",
        mode: "abort",
        deadlineMs: 5000,
      });
      expect(actual.cancellation.allocated).toHaveLength(1);
      expect(actual.cancellation.allocated[0]!.root).not.toBe(historical.root);
      expect(actual.run_id).not.toBe(completedRun);
      await sdk.close();
    });
  },
);

describe.skipIf(process.platform === "win32")(
  "P5-R7 exact canceled owner removal and awaited retry",
  () => {
    it("retains failed cleanup ownership and the original cancellation outcome until exact native removal retry succeeds", async () => {
      const f = await harness();
      const sdk = await helper.connectPublicPsxMcp(f.context, "cleanup-retry");
      f.flags.deletion = true;
      await writeFile(
        join(f.control, "deny-cleanup"),
        "retain actual process owner",
      );
      await expect(
        helper.cancelPublicPsxNativeRequest(f.context, sdk, {
          source: f.fixture.source,
          sourceDigest: f.digest,
          caseId: "cleanup-image",
          mode: "abort",
          deadlineMs: 5000,
        }),
      ).rejects.toThrow("controlled exact native removal failure");
      expect(
        f.events.some(
          (event) =>
            event.stage === "cancellation" &&
            event.criterion === "observed-in-flight-cancellation",
        ),
      ).toBe(true);
      const failed = await helper.settlePublicPsxContext(f.context);
      expect(failed.ok).toBe(false);
      expect(failed.settlement.unresolved_owners.length).toBeGreaterThan(0);
      const originalFailures = structuredClone(failed.failures);
      f.flags.deletion = false;
      await rm(join(f.control, "deny-cleanup"));
      for (const owner of failed.settlement.unresolved_owners)
        await owner.retry();
      const settled = await helper.settlePublicPsxContext(f.context);
      expect(settled.settlement.unresolved_owners).toEqual([]);
      expect(settled.settlement.remaining_roots).toEqual([]);
      expect(settled.ok).toBe(false);
      expect(settled.failures).toEqual(
        expect.arrayContaining(originalFailures),
      );
      expect(await readFile(f.fixture.source)).toEqual(psxImportBytes());
    });
  },
);
