export interface AccessIdentity {
  type: "access-user" | "service-token" | "dev";
  email?: string;
  jwtPresent: boolean;
}

export type AuthResult =
  | { ok: true; identity: AccessIdentity }
  | { ok: false; response: Response };

export interface AuthEnv {
  ACCESS_REQUIRED?: string;
  CF_ACCESS_AUD?: string;
  CONTROL_PLANE_TOKEN?: string;
}

export function authenticateRequest(
  request: Request,
  env: AuthEnv,
  options: { allowAnonymous?: boolean; serviceCallback?: boolean } = {},
): AuthResult {
  if (options.allowAnonymous) {
    return { ok: true, identity: { type: "dev", jwtPresent: false } };
  }

  if (options.serviceCallback && env.CONTROL_PLANE_TOKEN) {
    const token = bearerToken(request);
    if (token === env.CONTROL_PLANE_TOKEN) {
      return { ok: true, identity: { type: "service-token", jwtPresent: false } };
    }
    return unauthorized("invalid_control_plane_token");
  }

  const accessRequired = env.ACCESS_REQUIRED !== "false";
  if (!accessRequired) {
    return { ok: true, identity: { type: "dev", jwtPresent: false } };
  }

  const jwt = request.headers.get("Cf-Access-Jwt-Assertion");
  const email = request.headers.get("Cf-Access-Authenticated-User-Email");
  if (!jwt || !email) {
    return unauthorized("cloudflare_access_required");
  }

  if (env.CF_ACCESS_AUD) {
    const payload = parseJwtPayload(jwt);
    const aud = payload?.aud;
    const audiences = Array.isArray(aud) ? aud : aud ? [aud] : [];
    if (!audiences.includes(env.CF_ACCESS_AUD)) {
      return unauthorized("cloudflare_access_audience_mismatch");
    }
  }

  return { ok: true, identity: { type: "access-user", email, jwtPresent: true } };
}

export function identityAuditPayload(identity: AccessIdentity): Record<string, string | boolean> {
  return {
    actorType: identity.type,
    actorEmail: identity.email ?? "",
    accessJwtPresent: identity.jwtPresent,
  };
}

function unauthorized(error: string): AuthResult {
  return {
    ok: false,
    response: Response.json({ error }, { status: 401 }),
  };
}

function bearerToken(request: Request): string | null {
  const header = request.headers.get("authorization");
  if (!header) {
    return null;
  }
  const [scheme, token] = header.split(/\s+/, 2);
  return scheme?.toLowerCase() === "bearer" ? token ?? null : null;
}

function parseJwtPayload(jwt: string): Record<string, unknown> | null {
  const parts = jwt.split(".");
  if (parts.length < 2) {
    return null;
  }
  try {
    const normalized = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    return JSON.parse(atob(padded)) as Record<string, unknown>;
  } catch {
    return null;
  }
}
