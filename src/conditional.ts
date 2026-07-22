import { getSHA256 } from "./user";

// Helpers for HTTP conditional GET (RFC 9110) on the read routes: strong entity-tags
// and If-None-Match evaluation. Manifest and blob responses are content-addressed, so
// their entity-tag is derived from the content digest. The tags-list and referrers
// routes are computed JSON with no single backing object, so their entity-tag is a
// stable hash of the serialized response body.

// strongETag wraps a validator value as a strong entity-tag (a quoted string).
export function strongETag(validator: string): string {
  return `"${validator}"`;
}

// listingETag computes a strong entity-tag for a computed listing body (tags list,
// referrers index) that has no single backing object. The tag is a hash of the
// serialized body, so an unchanged listing always yields the same validator and a
// changed listing yields a different one.
export async function listingETag(body: string): Promise<string> {
  return strongETag(await getSHA256(body));
}

// matchesIfNoneMatch reports whether the request's If-None-Match precondition matches
// the given entity-tag. Per RFC 9110 §13.1.2 the comparison is weak (the W/ prefix is
// ignored), the "*" wildcard matches any current representation, and a comma-separated
// list matches if any member matches.
export function matchesIfNoneMatch(request: Request, etag: string): boolean {
  const header = request.headers.get("If-None-Match");
  if (header === null) {
    return false;
  }
  if (header.trim() === "*") {
    return true;
  }

  const target = stripWeakPrefix(etag);
  return header.split(",").some((candidate) => stripWeakPrefix(candidate.trim()) === target);
}

function stripWeakPrefix(etag: string): string {
  return etag.startsWith("W/") ? etag.slice(2) : etag;
}
