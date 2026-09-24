import { base64Decode, base64UrlDecode, errorString } from "./utils";

export type RegistryTokenCapability = "push" | "pull";
export type RegistryAuthProtocolTokenPayload = {
  username: string;
  account_id?: string;
  capabilities: RegistryTokenCapability[];
  exp: number;
  aud: string;
  iat?: number;
};

export type AuthenticatorCheckCredentialsResponse = {
  verified: boolean;
  payload: RegistryAuthProtocolTokenPayload | null;
};

export interface Authenticator {
  authmode: string;
  checkCredentials(r: Request): Promise<AuthenticatorCheckCredentialsResponse>;
}

export function stripUsernamePasswordFromHeader(r: Request): [string, string] | { verified: false; payload: null } {
  // first check if we have an Authorization header, this is the basis for all auth stuff in our registry
  const authorization = r.headers.get("Authorization") ?? "";
  if (!authorization) {
    // missing authorization header
    // do not log this. the /v2/ sends this request without any credentials to do version checking
    // we do not want to remove /v2/ from the auth middleware as well
    return { verified: false, payload: null };
  }

  // now check the Authorization scheme used in the request
  const [scheme, encoded] = authorization.split(" ");

  // we strictly assume that auth scheme can only be Basic
  if (!encoded || scheme !== "Basic") {
    console.warn("failed checkCredentials: Authorization doesn't include Basic scheme");
    return { verified: false, payload: null };
  }

  try {
    // Decodes the base64 value and performs unicode normalization.
    const decoded = decodeBasicCredentials(encoded);

    // The username & password are split by the first colon.
    //=> example: "username:password"
    const index = decoded.indexOf(":");

    // The user & password are split by the first colon and MUST NOT contain control characters.
    // @see https://tools.ietf.org/html/rfc5234#appendix-B.1 (=> "CTL = %x00-1F / %x7F")
    // eslint-disable-next-line no-control-regex
    if (index === -1 || /[\0-\x1F\x7F]/.test(decoded)) {
      return { verified: false, payload: null };
    }

    const username = decoded.substring(0, index);
    const password = decoded.substring(index + 1);
    return [username, password];
  } catch (err) {
    console.error(`Failure getting data from Authorization header: ${errorString(err)}`);
    return { verified: false, payload: null };
  }
}

// RFC 7617 encodes Basic credentials with the standard base64 alphabet, so a credential whose encoding contains
// "+" or "/" must be decoded with it. The URL-safe alphabet is still accepted so clients that send it keep
// working. The two alphabets differ only in "+/" versus "-_": a value valid in both decodes to the same bytes
// either way, and a value mixing them is rejected by both.
function decodeBasicCredentials(encoded: string): string {
  try {
    return base64Decode(encoded);
  } catch {
    return base64UrlDecode(encoded);
  }
}
