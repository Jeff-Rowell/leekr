export const DefaultFalsePositives: Set<string> = new Set([
  "example", "xxxxxx", "aaaaaa", "abcde", "00000", "sample", "*****"
]);

export const falsePositiveSecretPattern = /^[a-f0-9]{40}$/;

export function isLikelyUUID(str: string): boolean {
  const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
  return uuidPattern.test(str);
}

export function isKnownFalsePositive(
  match: string, 
  falsePositives: Set<string> = DefaultFalsePositives, 
  performWordCheck: boolean = true
): [boolean, string] {
  try {
    if (match !== decodeURIComponent(encodeURIComponent(match))) {
      return [true, "invalid utf8"];
    }
  } catch {
    return [true, "invalid utf8"];
  }
  
  const lower = match.toLowerCase();
  
  if (falsePositives.has(lower)) {
    return [true, `matches term: ${lower}`];
  }
  
  for (const fp of falsePositives) {
    if (lower.includes(fp)) {
      return [true, `contains term: ${fp}`];
    }
  }

  if (falsePositiveSecretPattern.test(match)) {
    return [true, "matches hash pattern"];
  }

  if (isLikelyUUID(match)) {
    return [true, "matches UUID pattern"];
  }
  
  return [false, ""];
}
