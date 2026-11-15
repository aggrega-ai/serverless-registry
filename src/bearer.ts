import type { Env } from "..";
import type { Authenticator, RegistryAuthProtocolTokenPayload, RegistryTokenCapability } from "./auth";
import { base64, base64url } from "rfc4648";
import { RegistryTokens } from "./token";

/**
 * Registry tokens for the Docker token authentication flow.
 *
 * Docker decides from the version check (`GET /v2/`) how to authenticate. A `Basic`
 * challenge there makes a logged-in client send its credentials, but an anonymous client
 * then gives up instead of pulling. A `Bearer` challenge serves both: the client asks the
 * token endpoint (`GET /v2/token`) for a token, anonymously or with its credentials, and
 * presents that token on every following request.
 *
 * Tokens are issued and verified by this Worker alone, so they are signed with HMAC-SHA256
 * under a key derived from the configured username/password credentials. No additional
 * secret is needed, and changing any configured password invalidates every token issued
 * under the old one.
 */

export const TOKEN_PATH = "/v2/token";

// TOKEN_LIFETIME_SECONDS is how long an issued token stays valid. Clients fetch a new one
// when it expires.
const TOKEN_LIFETIME_SECONDS = 3600;

// KEY_DERIVATION_LABEL separates the token signing key from any other use of the
// configured credentials.
const KEY_DERIVATION_LABEL = "serverless-registry bearer token signing key v1";

type IssuedTokenPayload = {
  sub: string;
  cap: RegistryTokenCapability[];
  aud: string;
  iat: number;
  exp: number;
};

const encoder = new TextEncoder();

function base64UrlFromBytes(bytes: ArrayBuffer | Uint8Array): string {
  return base64url.stringify(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes), { pad: false });
}

function bytesFromBase64Url(s: string): Uint8Array | null {
  try {
    return base64url.parse(s, { loose: true });
  } catch {
    return null;
  }
}

/**
 * Returns the secret material the token signing key is derived from: every configured
 * username/password pair. Returns undefined when no password is configured, for example
 * when the registry authenticates with JWT_REGISTRY_TOKENS_PUBLIC_KEY alone.
 */
function signingMaterial(env: Env): string | undefined {
  const parts: string[] = [];
  if (env.USERNAME && env.PASSWORD) {
    parts.push(env.USERNAME, env.PASSWORD);
  }
  if (env.READONLY_USERNAME && env.READONLY_PASSWORD) {
    parts.push(env.READONLY_USERNAME, env.READONLY_PASSWORD);
  }
  if (parts.length === 0) {
    return undefined;
  }
  // Length-prefix every part so that no two different configurations produce the same bytes.
  return parts.map((p) => `${p.length}:${p}`).join("");
}

/**
 * Whether this registry answers with the token flow: anonymous pull is enabled and the
 * registry authenticates with configured username/password credentials, which is what the
 * signing key is derived from. Otherwise the registry keeps its Basic-only behaviour.
 */
export function bearerFlowEnabled(env: Env): boolean {
  return env.READONLY_ANONYMOUS === "true" && !env.JWT_REGISTRY_TOKENS_PUBLIC_KEY && signingMaterial(env) !== undefined;
}

export class BearerTokens {
  private constructor(private key: CryptoKey) {}

  static async fromEnv(env: Env): Promise<BearerTokens | undefined> {
    const material = signingMaterial(env);
    if (material === undefined) {
      return undefined;
    }
    // Derive the signing key as HMAC(material, label) rather than using the passwords
    // directly, so the key never equals a credential.
    const materialKey = await crypto.subtle.importKey(
      "raw",
      encoder.encode(material),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const derived = await crypto.subtle.sign("HMAC", materialKey, encoder.encode(KEY_DERIVATION_LABEL));
    const key = await crypto.subtle.importKey("raw", derived, { name: "HMAC", hash: "SHA-256" }, false, [
      "sign",
      "verify",
    ]);
    return new BearerTokens(key);
  }

  /**
   * Issues a token for the given principal, bound to the host of the request it answers.
   */
  async issue(request: Request, subject: string, capabilities: RegistryTokenCapability[]): Promise<Response> {
    const now = Math.floor(Date.now() / 1000);
    const payload: IssuedTokenPayload = {
      sub: subject,
      cap: capabilities,
      aud: new URL(request.url).host.toLowerCase(),
      iat: now,
      exp: now + TOKEN_LIFETIME_SECONDS,
    };
    const body = base64UrlFromBytes(encoder.encode(JSON.stringify(payload)));
    const signature = await crypto.subtle.sign("HMAC", this.key, encoder.encode(body));
    const token = `${body}.${base64UrlFromBytes(signature)}`;
    return new Response(
      JSON.stringify({
        token,
        access_token: token,
        expires_in: TOKEN_LIFETIME_SECONDS,
        issued_at: new Date(now * 1000).toISOString(),
      }),
      {
        status: 200,
        headers: { "content-type": "application/json", "cache-control": "no-store" },
      },
    );
  }

  /**
   * Verifies a presented token: its signature, the host it was issued for, and its expiry.
   * Returns the principal it carries, or null when the token is not one this registry issued
   * for this host or it has expired.
   */
  async verify(request: Request, token: string): Promise<RegistryAuthProtocolTokenPayload | null> {
    const [body, signature, ...rest] = token.split(".");
    if (!body || !signature || rest.length > 0) {
      return null;
    }
    const signatureBytes = bytesFromBase64Url(signature);
    const bodyBytes = bytesFromBase64Url(body);
    if (signatureBytes === null || bodyBytes === null) {
      return null;
    }
    // crypto.subtle.verify compares the signature in constant time.
    if (!(await crypto.subtle.verify("HMAC", this.key, signatureBytes, encoder.encode(body)))) {
      console.warn("verifyBearerToken: signature does not verify");
      return null;
    }

    let payload: IssuedTokenPayload;
    try {
      payload = JSON.parse(new TextDecoder().decode(bodyBytes)) as IssuedTokenPayload;
    } catch {
      return null;
    }
    if (payload.aud !== new URL(request.url).host.toLowerCase()) {
      console.warn("verifyBearerToken: token was issued for another registry host");
      return null;
    }
    if (typeof payload.exp !== "number" || Math.floor(Date.now() / 1000) >= payload.exp) {
      console.warn("verifyBearerToken: token has expired");
      return null;
    }
    if (!Array.isArray(payload.cap)) {
      return null;
    }

    return {
      username: payload.sub,
      capabilities: payload.cap,
      exp: payload.exp,
      iat: payload.iat,
      aud: payload.aud,
    };
  }

  /**
   * Checks a request carrying `Authorization: Bearer <token>` against the capabilities its
   * method needs.
   */
  async checkBearer(
    request: Request,
  ): Promise<{ verified: boolean; payload: RegistryAuthProtocolTokenPayload | null }> {
    const authorization = request.headers.get("Authorization") ?? "";
    const [scheme, token] = authorization.split(" ");
    if (scheme !== "Bearer" || !token) {
      return { verified: false, payload: null };
    }
    const payload = await this.verify(request, token);
    if (payload === null) {
      return { verified: false, payload: null };
    }
    return RegistryTokens.verifyPayload(request, payload);
  }
}

export function isBearerAuthorization(request: Request): boolean {
  return (request.headers.get("Authorization") ?? "").startsWith("Bearer ");
}

/**
 * Returns the `WWW-Authenticate` value pointing a client at this registry's token endpoint.
 * The realm uses the scheme and host the request arrived on. A request that names a
 * repository also carries the scope the client should ask for.
 */
export function bearerChallenge(request: Request): string {
  const url = new URL(request.url);
  let challenge = `Bearer realm="${url.origin}${TOKEN_PATH}",service="${url.host}"`;
  const scope = requestScope(request);
  if (scope) {
    challenge += `,scope="${scope}"`;
  }
  return challenge;
}

function requestScope(request: Request): string | undefined {
  const pathname = new URL(request.url).pathname;
  if (pathname === "/v2/_catalog") {
    return "registry:catalog:*";
  }
  const match = /^\/v2\/(.+?)\/(manifests|blobs|tags|referrers)\//.exec(pathname);
  if (!match) {
    return undefined;
  }
  const actions = request.method === "GET" || request.method === "HEAD" ? "pull" : "pull,push";
  return `repository:${match[1]}:${actions}`;
}

/**
 * Answers the token endpoint.
 *
 * - No credentials: a token holding only the `pull` capability.
 * - `Authorization: Basic`: the credentials are checked by the configured authenticator,
 *   and the token holds that user's capabilities. Invalid credentials are rejected.
 * - `POST` with an OAuth2 password grant: the same check, for clients that ask that way.
 */
export async function serveToken(
  request: Request,
  authenticator: Authenticator,
  tokens: BearerTokens,
  unauthorized: (r: Request) => Response,
): Promise<Response> {
  let authorization: string | null;
  if (request.method === "GET" || request.method === "HEAD") {
    authorization = request.headers.get("Authorization");
  } else if (request.method === "POST") {
    authorization = await passwordGrantAuthorization(request);
    if (authorization === null) {
      return unauthorized(request);
    }
  } else {
    return new Response("Method Not Allowed.", { status: 405, headers: { Allow: "GET, HEAD, POST" } });
  }

  if (!authorization) {
    return tokens.issue(request, "anonymous", ["pull"]);
  }
  if (!authorization.startsWith("Basic ")) {
    return unauthorized(request);
  }

  // The authenticator checks capabilities against the request method and path, so it is
  // handed a read of the token endpoint: a read-only user still receives a pull token.
  const check = new Request(request.url, { method: "GET", headers: { Authorization: authorization } });
  const credentials = await authenticator.checkCredentials(check);
  if (!credentials.verified || credentials.payload === null) {
    return unauthorized(request);
  }
  return tokens.issue(request, credentials.payload.username, credentials.payload.capabilities);
}

// passwordGrantAuthorization reads an OAuth2 password grant from a form body and returns it
// as a Basic Authorization value, or null when the body is not such a grant.
async function passwordGrantAuthorization(request: Request): Promise<string | null> {
  let form: FormData;
  try {
    form = await request.formData();
  } catch {
    return null;
  }
  const username = form.get("username");
  const password = form.get("password");
  if (form.get("grant_type") !== "password" || typeof username !== "string" || typeof password !== "string") {
    return null;
  }
  return `Basic ${base64.stringify(encoder.encode(`${username}:${password}`))}`;
}
