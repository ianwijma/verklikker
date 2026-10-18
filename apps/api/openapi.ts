import { z } from "zod";
import { runSpec } from "../../packages/contracts/index.js";
const json = (schema: unknown) => ({ "application/json": { schema } });
const ok = { description: "Successful response" };
const id = {
  name: "id",
  in: "path",
  required: true,
  schema: { type: "string", format: "uuid" },
};
const operation = (summary: string, body?: unknown) => ({
  summary,
  responses: {
    200: ok,
    400: { description: "Invalid request" },
    401: { description: "Authentication required" },
    403: { description: "Insufficient scope" },
    404: { description: "Resource unavailable in this tenant" },
    409: { description: "Quota or state conflict" },
  },
  ...(body ? { requestBody: { required: true, content: json(body) } } : {}),
});
export const openapi = {
  openapi: "3.1.0",
  info: { title: "Verklikker API", version: "0.1.0" },
  security: [{ bearer: [] }],
  components: {
    securitySchemes: {
      bearer: {
        type: "http",
        scheme: "bearer",
        description: "OIDC access token or scoped vk_ API key",
      },
    },
    schemas: { RunSpec: z.toJSONSchema(runSpec, { io: "input" }) },
  },
  paths: {
    "/v1/me": { get: operation("Current account and quotas") },
    "/v1/runs": {
      get: operation("Latest 200 runs"),
      post: operation("Submit a run", {
        type: "object",
        required: ["spec"],
        properties: {
          spec: { $ref: "#/components/schemas/RunSpec" },
          idempotencyKey: { type: "string", maxLength: 128 },
        },
      }),
    },
    "/v1/runs/{id}": {
      parameters: [id],
      get: operation("Run details and manifest"),
      delete: operation(
        "Delete a terminal run; object deletion is delayed past signed URL expiry",
      ),
    },
    "/v1/runs/{id}/cancel": {
      parameters: [id],
      post: operation("Cancel queued or executing run", {}),
    },
    "/v1/runs/{id}/stream": {
      parameters: [id],
      get: {
        ...operation("Server-sent run state updates"),
        responses: {
          200: {
            description: "SSE stream",
            content: { "text/event-stream": { schema: { type: "string" } } },
          },
        },
      },
    },
    "/v1/runs/{id}/events": {
      parameters: [
        id,
        { name: "after", in: "query", schema: { type: "integer", minimum: 0 } },
        {
          name: "limit",
          in: "query",
          schema: { type: "integer", minimum: 1, maximum: 500 },
        },
        { name: "kind", in: "query", schema: { type: "string" } },
      ],
      get: operation("Query normalized events in sequence order"),
    },
    "/v1/runs/{id}/artifacts": {
      parameters: [id],
      get: operation("Committed evidence metadata"),
    },
    "/v1/artifacts/{id}/download": {
      parameters: [id],
      get: operation("Short-lived artifact download URL"),
    },
    "/v1/inputs": {
      post: operation("Upload up to 64 MiB of input", {
        type: "object",
        required: ["name", "data"],
        properties: {
          name: { type: "string" },
          data: { type: "string", contentEncoding: "base64" },
        },
      }),
    },
    "/v1/inputs/{id}": {
      parameters: [id],
      delete: operation("Delete an input not referenced by unfinished runs"),
    },
    "/v1/batches": {
      post: {
        ...operation("Submit up to 1000 jobs; inspect each result", {
          type: "object",
          required: ["jobs"],
          properties: {
            jobs: {
              type: "array",
              maxItems: 1000,
              items: {
                type: "object",
                required: ["spec"],
                properties: {
                  spec: { $ref: "#/components/schemas/RunSpec" },
                  idempotencyKey: { type: "string" },
                },
              },
            },
          },
        }),
        responses: {
          207: { description: "Per-job accepted or rejected results" },
        },
      },
    },
    "/v1/keys": {
      get: operation("List API keys; requires owner session"),
      post: operation("Create scoped API key; returned once", {
        type: "object",
        required: ["name", "scopes"],
        properties: {
          name: { type: "string" },
          scopes: {
            type: "array",
            items: { enum: ["runs:read", "runs:write", "artifacts:read"] },
          },
        },
      }),
    },
    "/v1/keys/{id}": {
      parameters: [id],
      delete: operation("Revoke API key immediately"),
    },
  },
};
