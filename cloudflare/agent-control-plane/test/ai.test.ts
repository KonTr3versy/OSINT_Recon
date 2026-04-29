import { describe, expect, it, vi } from "vitest";
import { runReconModel } from "../src/ai";
import type { Env } from "../src/types";

describe("AI routing", () => {
  it("uses Workers AI when no gateway URL is configured", async () => {
    const env = {
      AI_MODEL: "@cf/test/model",
      AI: { run: vi.fn(async () => ({ response: "workers-ai response" })) },
    } as unknown as Env;

    const result = await runReconModel(env, [{ role: "user", content: "hi" }]);

    expect(result.provider).toBe("workers-ai");
    expect(result.gatewayUsed).toBe(false);
    expect(result.content).toBe("workers-ai response");
  });

  it("uses AI Gateway when a gateway URL is configured", async () => {
    const originalFetch = globalThis.fetch;
    const fetchMock = vi.fn(async () => Response.json({ response: "gateway response" }));
    globalThis.fetch = fetchMock as typeof fetch;
    const env = {
      AI_MODEL: "@cf/test/model",
      AI_GATEWAY_URL: "https://gateway.example.test/v1/account/gateway/workers-ai/@cf/test/model",
      AI_GATEWAY_TOKEN: "token",
    } as unknown as Env;

    try {
      const result = await runReconModel(env, [{ role: "user", content: "hi" }], { action: "test" });

      expect(result.provider).toBe("ai-gateway");
      expect(result.gatewayUsed).toBe(true);
      expect(result.content).toBe("gateway response");
      expect(fetchMock).toHaveBeenCalledWith(
        env.AI_GATEWAY_URL,
        expect.objectContaining({
          method: "POST",
          headers: expect.objectContaining({
            authorization: "Bearer token",
            "cf-aig-metadata": JSON.stringify({ model: "@cf/test/model", action: "test" }),
          }),
        }),
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
