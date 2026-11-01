import { Env } from "..";
import { errorString } from "./utils";
import { isValidDigest } from "./user";

// Pull counting with Workers Analytics Engine. When the optional PULL_ANALYTICS binding is
// configured, every manifest GET the registry answers successfully writes one data point:
//
//   index1 — the repository name, cut to the 96-byte index limit (the sampling key)
//   blob1  — the repository name
//   blob2  — the reference exactly as requested: a tag or a digest
//   blob3  — the status class of the response sent: "2xx", or "3xx" for a 304 Not Modified
//   blob4  — the kind of reference: "digest" when blob2 is a digest, otherwise "tag"
//
// Nothing else is written: no client address, user agent, credential, token, account or
// location. Without the binding nothing is written and the registry behaves the same.

// Workers Analytics Engine rejects an index longer than 96 bytes.
const maxIndexBytes = 96;

// recordManifestPull writes the data point for a successful manifest GET and returns the
// response unchanged. Writing never affects the response: writeDataPoint is not awaited (it
// returns immediately and the runtime writes in the background), and an error it throws is
// logged and dropped.
export function recordManifestPull(env: Env, name: string, reference: string, response: Response): Response {
  const dataset = env.PULL_ANALYTICS;
  if (!dataset) {
    return response;
  }

  try {
    dataset.writeDataPoint({
      indexes: [samplingIndex(name)],
      blobs: [name, reference, statusClass(response.status), referenceKind(reference)],
    });
  } catch (err) {
    console.warn("Could not record the manifest pull:", errorString(err));
  }

  return response;
}

// referenceKind tells a digest reference from a tag with the same digest check the manifest
// response uses to choose its Cache-Control.
function referenceKind(reference: string): string {
  return isValidDigest(reference) ? "digest" : "tag";
}

// statusClass maps a status code to its class, for example 200 to "2xx".
function statusClass(status: number): string {
  return `${Math.floor(status / 100)}xx`;
}

// samplingIndex returns the longest prefix of the name, cut at a character boundary, that fits
// the index limit. The index only keys sampling; blob1 carries the full name.
function samplingIndex(name: string): string {
  const encoder = new TextEncoder();
  let index = "";
  let size = 0;
  for (const character of name) {
    size += encoder.encode(character).length;
    if (size > maxIndexBytes) {
      break;
    }
    index += character;
  }

  return index;
}
