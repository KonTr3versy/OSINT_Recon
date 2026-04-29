import { describe, expect, it } from "vitest";
import { authenticateRequest } from "../src/auth";

function jwtWithPayload(payload: Record<string, unknown>) {
  const encoded = btoa(JSON.stringify(payload)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  return `header.${encoded}.signature`;
}

describe("Cloudflare Access auth", () => {
  it("allows dev mode when Access is disabled", () => {
    const result = authenticateRequest(new Request("https://example.com/api/assets"), {
      ACCESS_REQUIRED: "false",
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.identity.type).toBe("dev");
    }
  });

  it("rejects protected requests without Access headers", () => {
    const result = authenticateRequest(new Request("https://example.com/api/assets"), {
      ACCESS_REQUIRED: "true",
    });

    expect(result.ok).toBe(false);
  });

  it("accepts Access headers with matching audience", () => {
    const request = new Request("https://example.com/api/assets", {
      headers: {
        "Cf-Access-Authenticated-User-Email": "analyst@example.com",
        "Cf-Access-Jwt-Assertion": jwtWithPayload({ aud: ["aud-123"] }),
      },
    });

    const result = authenticateRequest(request, {
      ACCESS_REQUIRED: "true",
      CF_ACCESS_AUD: "aud-123",
    });

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.identity.email).toBe("analyst@example.com");
      expect(result.identity.jwtPresent).toBe(true);
    }
  });

  it("requires callback bearer token when configured", () => {
    const request = new Request("https://example.com/api/jobs/1/result", {
      headers: { authorization: "Bearer secret" },
    });

    const result = authenticateRequest(
      request,
      { ACCESS_REQUIRED: "true", CONTROL_PLANE_TOKEN: "secret" },
      { serviceCallback: true },
    );

    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.identity.type).toBe("service-token");
    }
  });
});
