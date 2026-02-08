
// Cloudflare Workers Ed25519 signer example.
// Deploy: wrangler deploy; bind `PRIVATE_KEY_PEM` as a secret (PKCS#8 Ed25519)
export interface Env {
  PRIVATE_KEY_PEM: string;
  AUTH_BEARER?: string; // optional
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    if (env.AUTH_BEARER) {
      const hdr = request.headers.get("Authorization") || "";
      if (hdr !== `Bearer ${env.AUTH_BEARER}`) {
        return new Response("unauthorized", { status: 401 });
      }
    }
    if (request.method !== "POST") return new Response("method not allowed", { status: 405 });
    const { sha256_hex, kid } = await request.json();
    if (!sha256_hex || typeof sha256_hex !== "string") {
      return new Response("bad request", { status: 400 });
    }
    // Import Ed25519 PKCS#8 PEM
    const pkcs8 = env.PRIVATE_KEY_PEM
      .replace("-----BEGIN PRIVATE KEY-----", "")
      .replace("-----END PRIVATE KEY-----", "")
      .replace(/\s+/g, "");
    const keyData = Uint8Array.from(atob(pkcs8), c => c.charCodeAt(0));
    const key = await crypto.subtle.importKey(
      "pkcs8",
      keyData,
      { name: "Ed25519" },
      false,
      ["sign"]
    );
    // Sign the raw 32-byte digest
    const digest = hexToBytes(sha256_hex);
    const sig = await crypto.subtle.sign({ name: "Ed25519" }, key, digest);
    const sig_b64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
    return new Response(JSON.stringify({ sig_b64, kid }), {
      headers: { "content-type": "application/json" }
    });
  }
};

function hexToBytes(h: string): Uint8Array {
  if (h.length !== 64) { throw new Error("sha256 must be 32 bytes hex"); }
  const out = new Uint8Array(32);
  for (let i=0;i<32;i++) out[i] = parseInt(h.slice(i*2, i*2+2), 16);
  return out;
}
