import { describe, expect, it } from "vitest";

import { artifactInventoryResultSchema } from "./artifactGraph.js";

describe("artifact graph path and provenance fields", () => {
  it.each(["directory", "ps-x-exe"] as const)(
    "preserves %s storage identity with paths and provenance inline",
    (format) => {
      const path = `${"deep/".repeat(1_000)}resource.bin`;
      const arguments_ = Array.from({ length: 1_025 }, (_, index) =>
        index === 0 ? `/${"long/".repeat(1_000)}archive.ipa` : `arg-${index}`,
      );
      const artifactId = `art_${"a".repeat(64)}`;
      const parsed = artifactInventoryResultSchema.parse({
        manifest: {
          manifest_id: `agm_${"b".repeat(64)}`,
          root_artifact_id: artifactId,
          root_sha256: "c".repeat(64),
          root_format: format,
          graph_sha256: "d".repeat(64),
          node_count: 1,
          occurrence_count: 1,
          edge_count: 0,
        },
        nodes: [
          {
            artifact_id: artifactId,
            format,
            sha256: "c".repeat(64),
            size: 0,
            media_type: null,
            architecture: null,
            content_state: "materialized",
            limitations: [],
          },
        ],
        occurrences: [
          {
            occurrence_id: `occ_${"e".repeat(64)}`,
            artifact_id: artifactId,
            parent_occurrence_id: null,
            logical_path: path,
            entry_kind: "file",
            artifact_kind: format === "ps-x-exe" ? "executable" : "resource",
            artifact_format: format === "ps-x-exe" ? format : "file",
            declared_size: 0,
            compressed_size: 0,
            executable: false,
            encrypted: false,
            hash_status: "verified",
            source_location: null,
            limitations: [],
          },
        ],
        edges: [],
        provenance: [
          {
            tool: "archive-reader",
            arguments: arguments_,
            tool_version: null,
            executable_sha256: null,
            exit_code: 0,
            effects: ["read"],
          },
        ],
        integrity_contradictions: [],
        limitations: [],
      });

      expect(parsed.nodes[0]?.format).toBe(format);
      expect(parsed.manifest.root_format).toBe(format);
      expect(parsed.occurrences[0]?.artifact_format).toBe(
        format === "ps-x-exe" ? format : "file",
      );
      expect(parsed.occurrences[0]?.logical_path).toBe(path);
      expect(parsed.provenance[0]?.arguments).toHaveLength(1_025);
      expect(parsed.provenance[0]?.arguments[0]).toBe(arguments_[0]);
    },
  );
});
