import type { Env } from "./types";

export interface ModelResult {
  content: string;
  provider: "workers-ai" | "ai-gateway";
  model: string;
  gatewayUsed: boolean;
}

export async function runReconModel(
  env: Env,
  messages: Array<{ role: string; content: string }>,
  metadata: Record<string, string> = {},
): Promise<ModelResult> {
  const model = env.AI_MODEL || "@cf/meta/llama-3.1-8b-instruct";
  if (env.AI_GATEWAY_URL) {
    const response = await fetch(env.AI_GATEWAY_URL, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        ...(env.AI_GATEWAY_TOKEN ? { authorization: `Bearer ${env.AI_GATEWAY_TOKEN}` } : {}),
        "cf-aig-metadata": JSON.stringify({ model, ...metadata }),
      },
      body: JSON.stringify({ model, messages }),
    });
    if (!response.ok) {
      throw new Error(`AI Gateway request failed: ${response.status} ${await response.text()}`);
    }
    const payload = await response.json<Record<string, unknown>>();
    return {
      content: extractGatewayContent(payload),
      provider: "ai-gateway",
      model,
      gatewayUsed: true,
    };
  }

  const result = await env.AI.run(model, { messages });
  return {
    content: String((result as { response?: string }).response ?? ""),
    provider: "workers-ai",
    model,
    gatewayUsed: false,
  };
}

function extractGatewayContent(payload: Record<string, unknown>): string {
  if (typeof payload.response === "string") {
    return payload.response;
  }
  const choices = payload.choices;
  if (Array.isArray(choices)) {
    const first = choices[0] as { message?: { content?: unknown }; text?: unknown } | undefined;
    if (typeof first?.message?.content === "string") {
      return first.message.content;
    }
    if (typeof first?.text === "string") {
      return first.text;
    }
  }
  if (typeof payload.output === "string") {
    return payload.output;
  }
  return JSON.stringify(payload);
}
