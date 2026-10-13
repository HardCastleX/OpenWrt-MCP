export interface PeerHandshakeSummary {
  peerCount: number;
  hasRecentHandshake: boolean;
}

export function parsePeerHandshakes(output: string, nowSeconds = Date.now() / 1000): PeerHandshakeSummary {
  const rows = output.split(/\r?\n/).filter(Boolean).map((line) => line.trim().split(/\s+/));
  const validRows = rows.filter((fields) => fields.length >= 2 && /^[A-Za-z0-9+/]{43}=$/.test(fields[0]!));
  const timestamps = validRows.map((fields) => Number(fields[1])).filter(Number.isFinite);
  return {
    peerCount: validRows.length,
    hasRecentHandshake: timestamps.some((timestamp) => timestamp > 0 && nowSeconds - timestamp < 180),
  };
}
