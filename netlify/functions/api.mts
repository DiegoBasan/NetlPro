import { getStore } from "@netlify/blobs";
import type { Config } from "@netlify/functions";
import { createHmac, randomBytes, scryptSync, timingSafeEqual, randomUUID } from "node:crypto";

/*
  Fotos Puente API
  - Login con usuario/contraseña -> token firmado (1 año)
  - Archivos guardados por partes de 4 MB (permite videos grandes)
  - /api/raw soporta Range para reproducir video
*/

const CHUNK = 4_000_000;
const TOKEN_DAYS = 365;
const store = () => getStore({ name: "media", consistency: "strong" });
const istore = () => getStore({ name: "instr", consistency: "strong" });

/* ---------- instrucciones ---------- */
type Block = { id: string; type: "text" | "image"; text?: string; kind?: "step" | "note"; img?: string; w?: number; h?: number; caption?: string };
type Doc = { id: string; title: string; desc: string; blocks: Block[]; createdAt: number; updatedAt: number };
const imgIds = (d: Doc | null) => new Set((d?.blocks || []).filter((b) => b.type === "image" && b.img).map((b) => b.img!));
function sanitizeDoc(raw: any, prev: Doc | null): Doc {
  const str = (v: unknown, max: number) => String(v ?? "").slice(0, max);
  const blocks: Block[] = (Array.isArray(raw.blocks) ? raw.blocks : []).slice(0, 500).map((b: any) => {
    const id = /^[a-z0-9-]{4,60}$/i.test(b?.id) ? b.id : randomUUID().slice(0, 12);
    if (b?.type === "image") {
      return { id, type: "image", img: /^[a-z0-9-]{8,60}$/i.test(b.img) ? b.img : undefined, w: Number(b.w) || undefined, h: Number(b.h) || undefined, caption: str(b.caption, 500) };
    }
    return { id, type: "text", kind: b?.kind === "note" ? "note" : "step", text: str(b?.text, 8000) };
  });
  return { id: raw.id, title: str(raw.title, 160).trim() || "Sin título", desc: str(raw.desc, 4000), blocks, createdAt: prev?.createdAt || Date.now(), updatedAt: Date.now() };
}
async function deleteImages(ids: Iterable<string>) {
  const s = istore();
  await Promise.all([...ids].flatMap((i) => [s.delete(`img/${i}`), s.delete(`thumb/${i}`)]));
}

const json = (data: unknown, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });

const clean = (s: unknown, fallback: string) =>
  String(s ?? "")
    .normalize("NFC")
    .replace(/[\\/:*?"<>|\u0000-\u001f]/g, "-")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 120) || fallback;

const b64url = (b: Buffer | string) => Buffer.from(b).toString("base64url");
const secret = () => Netlify.env.get("APP_SECRET") || "";
const sign = (payload: string) => createHmac("sha256", secret()).update(payload).digest("base64url");
const safeEq = (a: string, b: string) => {
  const A = Buffer.from(a), B = Buffer.from(b);
  return A.length === B.length && timingSafeEqual(A, B);
};

/* ---------- credentials ---------- */
type Creds = { user: string; salt?: string; hash?: string; gen: number; fromEnv?: boolean };
let credCache: { at: number; v: Creds } | null = null;

async function getCreds(): Promise<Creds> {
  if (credCache && Date.now() - credCache.at < 20_000) return credCache.v;
  const saved = (await store().get("auth/credentials", { type: "json" })) as Creds | null;
  const v: Creds = saved || { user: Netlify.env.get("APP_USER") || "", gen: 0, fromEnv: true };
  credCache = { at: Date.now(), v };
  return v;
}
async function checkPassword(user: string, pass: string) {
  const c = await getCreds();
  if (!c.user || user.trim().toLowerCase() !== c.user.toLowerCase()) return false;
  if (c.fromEnv) return safeEq(pass, Netlify.env.get("APP_PASS") || "\u0000");
  const h = scryptSync(pass, Buffer.from(c.salt!, "base64"), 32).toString("base64");
  return safeEq(h, c.hash!);
}
async function issueToken(days = TOKEN_DAYS) {
  const c = await getCreds();
  const payload = b64url(JSON.stringify({ g: c.gen, exp: Date.now() + days * 864e5 }));
  return `${payload}.${sign(payload)}`;
}
async function validToken(tok: string) {
  const [payload, sig] = (tok || "").split(".");
  if (!payload || !sig || !safeEq(sign(payload), sig)) return false;
  try {
    const p = JSON.parse(Buffer.from(payload, "base64url").toString());
    const c = await getCreds();
    return p.exp > Date.now() && p.g === c.gen;
  } catch { return false; }
}

/* ---------- items ---------- */
type Item = {
  id: string; name: string; folder: string; kind: "image" | "video" | "file" | "text"; type: string; ext: string; preview?: string;
  size: number; chunks: number; uploadedAt: number; complete: boolean;
  hasThumb?: boolean; hasMed?: boolean; duration?: number; width?: number; height?: number;
};
const itemKey = (id: string) => `items/${id}`;
const getItem = async (id: string) => (await store().get(itemKey(id), { type: "json" })) as Item | null;
const validId = (id: string | null) => !!id && /^[a-z0-9-]{8,60}$/i.test(id);
const KINDS = ["image", "video", "file", "text"] as const;
const kindFromExt = (ext: string) =>
  /^(jpe?g|png|heic|heif|gif|webp|bmp|tiff?)$/.test(ext) ? "image" : /^(mov|mp4|m4v|webm|3gp|avi|mkv)$/.test(ext) ? "video" : ext === "txt" ? "text" : "file";
const MIME: Record<string, string> = { jpg: "image/jpeg", jpeg: "image/jpeg", png: "image/png", heic: "image/heic", heif: "image/heif", gif: "image/gif", webp: "image/webp",
  mov: "video/quicktime", mp4: "video/mp4", m4v: "video/x-m4v", webm: "video/webm", pdf: "application/pdf", txt: "text/plain;charset=utf-8", csv: "text/csv" };
const textPreview = (t: string) => t.replace(/\s+$/g, "").slice(0, 300);

// guarda un archivo completo (ya en memoria) partido en partes, y lo deja listo en la galería
async function storeWhole(data: Uint8Array, meta: Partial<Item> & { name: string; folder: string; kind: Item["kind"]; type: string; ext: string }) {
  const s = store();
  const it: Item = {
    id: `${Date.now().toString(36)}-${randomUUID().slice(0, 8)}`, ...meta,
    size: data.byteLength, chunks: Math.max(1, Math.ceil(data.byteLength / CHUNK)), uploadedAt: Date.now(), complete: false,
  } as Item;
  for (let n = 0; n < it.chunks; n++) await s.set(`data/${it.id}/${n}`, data.slice(n * CHUNK, (n + 1) * CHUNK));
  it.complete = true;
  await s.setJSON(itemKey(it.id), it);
  return it;
}

async function removeItem(it: Item) {
  const s = store();
  await Promise.all([
    ...Array.from({ length: it.chunks }, (_, n) => s.delete(`data/${it.id}/${n}`)),
    s.delete(`thumb/${it.id}`), s.delete(`med/${it.id}`),
  ]);
  await s.delete(itemKey(it.id));
}

const binary = (data: ArrayBuffer, type: string, cache = "private, max-age=31536000, immutable") =>
  new Response(data, { headers: { "content-type": type, "cache-control": cache } });

export default async (req: Request) => {
  const url = new URL(req.url);
  const route = url.pathname.replace(/^\/api\/?/, "").replace(/\/$/, "");
  const q = (k: string) => url.searchParams.get(k);

  if (!secret() || !Netlify.env.get("APP_USER")) return json({ error: "Faltan variables APP_USER / APP_PASS / APP_SECRET en Netlify" }, 500);

  try {
    /* ----- public: login ----- */
    if (route === "login" && req.method === "POST") {
      const { user, pass } = (await req.json().catch(() => ({}))) as any;
      if (!(await checkPassword(String(user || ""), String(pass || "")))) {
        await new Promise((r) => setTimeout(r, 900)); // frena intentos repetidos
        return json({ error: "Usuario o contraseña incorrectos" }, 401);
      }
      return json({ token: await issueToken(), user: (await getCreds()).user });
    }

    /* ----- everything else needs a token ----- */
    const auth = req.headers.get("authorization")?.replace(/^Bearer\s+/i, "") || q("t") || "";
    if (!(await validToken(auth))) return json({ error: "Sesión expirada" }, 401);
    const s = store();

    if (route === "me") return json({ user: (await getCreds()).user });

    // clave de larga duración para el atajo de iPhone (se invalida si cambias la contraseña)
    if (route === "apptoken" && req.method === "POST") return json({ token: await issueToken(3650) });

    // subida rápida en una sola petición (atajo de iPhone): texto en JSON o archivo crudo (máx. ~4 MB)
    if (route === "quick" && req.method === "POST") {
      const ctype = req.headers.get("content-type") || "";
      const folder = clean(q("folder"), "Atajo");
      if (/json/i.test(ctype)) {
        const b = (await req.json().catch(() => ({}))) as any;
        const text = String(b.text ?? b.texto ?? "").slice(0, 2_000_000);
        if (!text.trim()) return json({ error: "Texto vacío" }, 400);
        const t = text.trim(), firstLine = t.split("\n")[0].slice(0, 60);
        let auto = clean(firstLine, "Texto");
        if (/^https?:\/\/\S+$/i.test(t)) { try { auto = "Link " + new URL(t).hostname.replace(/^www\./, ""); } catch {} }
        const it = await storeWhole(new TextEncoder().encode(text), {
          name: clean(b.name || q("name"), auto), folder: clean(b.folder, folder),
          kind: "text", type: MIME.txt, ext: "txt", preview: textPreview(text),
        });
        return json({ ok: true, id: it.id, name: it.name });
      }
      const data = new Uint8Array(await req.arrayBuffer());
      if (!data.byteLength) return json({ error: "Archivo vacío" }, 400);
      let ext = clean(q("ext"), "").toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 6);
      let name = clean(q("name"), "");
      const m = name.match(/^(.*)\.([a-z0-9]{1,6})$/i);
      if (m && !ext) { name = m[1]; ext = m[2].toLowerCase(); } else if (m && m[2].toLowerCase() === ext) name = m[1];
      if (!ext) ext = (Object.entries(MIME).find(([, v]) => ctype.startsWith(v.split(";")[0]))?.[0]) || "bin";
      const kind = kindFromExt(ext);
      const type = MIME[ext] || (ctype && !/form|octet/i.test(ctype) ? ctype.slice(0, 80) : "application/octet-stream");
      const meta: any = { name: name || (kind === "image" ? "Foto" : kind === "video" ? "Video" : "Archivo"), folder, kind, type, ext };
      if (kind === "text") { const t = new TextDecoder().decode(data); meta.preview = textPreview(t); }
      const it = await storeWhole(data, meta);
      return json({ ok: true, id: it.id, name: it.name });
    }

    // cambiar usuario/contraseña (invalida sesiones viejas)
    if (route === "password" && req.method === "POST") {
      const { current, user, pass } = (await req.json()) as any;
      const c = await getCreds();
      if (!(await checkPassword(c.user, String(current || "")))) return json({ error: "La contraseña actual no coincide" }, 400);
      const newUser = clean(user, c.user).toLowerCase();
      if (!pass || String(pass).length < 6) return json({ error: "La contraseña nueva debe tener al menos 6 caracteres" }, 400);
      const salt = randomBytes(16);
      const next: Creds = { user: newUser, salt: salt.toString("base64"), hash: scryptSync(String(pass), salt, 32).toString("base64"), gen: c.gen + 1 };
      await s.setJSON("auth/credentials", next);
      credCache = { at: Date.now(), v: next };
      return json({ token: await issueToken(), user: newUser });
    }

    // lista
    if (route === "list" && req.method === "GET") {
      const { blobs } = await s.list({ prefix: "items/" });
      const all = (await Promise.all(blobs.map((b) => s.get(b.key, { type: "json" })))) as (Item | null)[];
      const items: Item[] = [];
      for (const it of all) {
        if (!it) continue;
        if (it.complete) items.push(it);
        else if (Date.now() - it.uploadedAt > 6 * 3600e3) removeItem(it).catch(() => {}); // subidas abandonadas
      }
      items.sort((a, b) => b.uploadedAt - a.uploadedAt);
      return json({ items, chunkSize: CHUNK });
    }

    // crear item (antes de subir partes)
    if (route === "items" && req.method === "POST") {
      const b = (await req.json()) as any;
      const size = Number(b.size) || 0;
      if (size <= 0) return json({ error: "Archivo vacío" }, 400);
      const it: Item = {
        id: `${Date.now().toString(36)}-${randomUUID().slice(0, 8)}`,
        name: clean(b.name, "archivo"), folder: clean(b.folder, "Sin carpeta"),
        kind: (KINDS as readonly string[]).includes(b.kind) ? b.kind : "image",
        preview: b.kind === "text" ? textPreview(String(b.preview || "")) : undefined,
        type: String(b.type || "application/octet-stream").slice(0, 80),
        ext: clean(b.ext, "bin").toLowerCase().replace(/[^a-z0-9]/g, "").slice(0, 6) || "bin",
        size, chunks: Math.ceil(size / CHUNK), uploadedAt: Date.now(), complete: false,
        duration: Number(b.duration) || undefined, width: Number(b.width) || undefined, height: Number(b.height) || undefined,
      };
      await s.setJSON(itemKey(it.id), it);
      return json({ id: it.id, chunkSize: CHUNK, chunks: it.chunks });
    }

    // subir una parte / miniatura / versión media
    if (["chunk", "thumb", "med"].includes(route) && req.method === "PUT") {
      const id = q("id");
      if (!validId(id)) return json({ error: "id inválido" }, 400);
      const it = await getItem(id!);
      if (!it) return json({ error: "No existe" }, 404);
      const body = await req.arrayBuffer();
      if (!body.byteLength || body.byteLength > CHUNK) return json({ error: "Tamaño de parte inválido" }, 400);
      if (route === "chunk") {
        const n = Number(q("n"));
        if (!Number.isInteger(n) || n < 0 || n >= it.chunks) return json({ error: "Parte inválida" }, 400);
        await s.set(`data/${id}/${n}`, body);
      } else {
        await s.set(`${route}/${id}`, body);
      }
      return json({ ok: true });
    }

    // marcar como completo
    if (route === "complete" && req.method === "POST") {
      const { id, hasThumb, hasMed } = (await req.json()) as any;
      const it = validId(id) ? await getItem(id) : null;
      if (!it) return json({ error: "No existe" }, 404);
      const { blobs } = await s.list({ prefix: `data/${id}/` });
      if (blobs.length !== it.chunks) return json({ error: `Faltan partes (${blobs.length}/${it.chunks})` }, 409);
      Object.assign(it, { complete: true, hasThumb: !!hasThumb, hasMed: !!hasMed });
      await s.setJSON(itemKey(id), it);
      return json({ ok: true, item: it });
    }

    // renombrar / mover de carpeta
    if (route === "item" && req.method === "PATCH") {
      const { id, name, folder, hasThumb, hasMed, width, height, duration } = (await req.json()) as any;
      const it = validId(id) ? await getItem(id) : null;
      if (!it) return json({ error: "No existe" }, 404);
      if (name !== undefined) it.name = clean(name, it.name);
      if (folder !== undefined) it.folder = clean(folder, "Sin carpeta");
      if (hasThumb === true && await s.getMetadata(`thumb/${id}`)) it.hasThumb = true;
      if (hasMed === true && await s.getMetadata(`med/${id}`)) it.hasMed = true;
      if (Number(width) > 0 && !it.width) { it.width = Number(width); it.height = Number(height) || undefined; }
      if (Number(duration) > 0 && !it.duration) it.duration = Number(duration);
      await s.setJSON(itemKey(id), it);
      return json({ ok: true, item: it });
    }

    // borrar varios
    if (route === "delete" && req.method === "POST") {
      const { ids } = (await req.json()) as { ids: string[] };
      let n = 0;
      for (const id of (ids || []).filter(validId)) {
        const it = await getItem(id);
        if (it) { await removeItem(it); n++; }
      }
      return json({ ok: true, deleted: n });
    }

    // leer miniatura / versión media
    if ((route === "thumb" || route === "med") && req.method === "GET") {
      const id = q("id");
      if (!validId(id)) return json({ error: "id inválido" }, 400);
      const data = await s.get(`${route}/${id}`, { type: "arrayBuffer" });
      if (!data) return json({ error: "No encontrado" }, 404);
      return binary(data, "image/jpeg");
    }

    // leer una parte (para armar el ZIP)
    if (route === "chunk" && req.method === "GET") {
      const id = q("id"), n = Number(q("n"));
      if (!validId(id)) return json({ error: "id inválido" }, 400);
      const data = await s.get(`data/${id}/${n}`, { type: "arrayBuffer" });
      if (!data) return json({ error: "No encontrado" }, 404);
      return binary(data, "application/octet-stream");
    }

    // archivo original con soporte de Range (videos)
    if (route === "raw" && req.method === "GET") {
      const id = q("id");
      const it = validId(id) ? await getItem(id!) : null;
      if (!it || !it.complete) return json({ error: "No encontrado" }, 404);
      const range = req.headers.get("range");
      // solo se muestran en el navegador tipos seguros; lo demás se descarga (evita que un .html corra dentro de la app)
      const inline = /^(image\/(jpeg|png|gif|webp|heic|heif)|video\/|audio\/|application\/pdf$|text\/plain(;|$))/i.test(it.type);
      const fname = encodeURIComponent(`${it.name}.${it.ext}`);
      const common = {
        "content-type": inline ? it.type : "application/octet-stream", "accept-ranges": "bytes", "cache-control": "private, max-age=86400",
        "x-content-type-options": "nosniff",
        "content-disposition": `${inline ? "inline" : "attachment"}; filename*=UTF-8''${fname}`,
      };

      if (range) {
        const m = /bytes=(\d*)-(\d*)/.exec(range);
        let start = m && m[1] ? Number(m[1]) : 0;
        let end = m && m[2] ? Number(m[2]) : it.size - 1;
        if (m && !m[1] && m[2]) { start = Math.max(0, it.size - Number(m[2])); end = it.size - 1; }
        if (start >= it.size) return new Response(null, { status: 416, headers: { "content-range": `bytes */${it.size}` } });
        const n = Math.floor(start / CHUNK);
        end = Math.min(end, it.size - 1, (n + 1) * CHUNK - 1); // una parte por respuesta
        const data = await s.get(`data/${id}/${n}`, { type: "arrayBuffer" });
        if (!data) return json({ error: "Parte faltante" }, 404);
        const slice = data.slice(start - n * CHUNK, end - n * CHUNK + 1);
        return new Response(slice, {
          status: 206,
          headers: { ...common, "content-range": `bytes ${start}-${end}/${it.size}`, "content-length": String(slice.byteLength) },
        });
      }

      const stream = new ReadableStream({
        async start(controller) {
          for (let n = 0; n < it.chunks; n++) {
            const d = await s.get(`data/${id}/${n}`, { type: "arrayBuffer" });
            if (d) controller.enqueue(new Uint8Array(d));
          }
          controller.close();
        },
      });
      return new Response(stream, { headers: { ...common, "content-length": String(it.size) } });
    }

    /* ----- instrucciones ----- */
    const is = istore();
    if (route === "docs" && req.method === "GET") {
      const { blobs } = await is.list({ prefix: "docs/" });
      const docs = (await Promise.all(blobs.map((b) => is.get(b.key, { type: "json" })))) as (Doc | null)[];
      const list = docs.filter(Boolean).map((d) => ({
        id: d!.id, title: d!.title, updatedAt: d!.updatedAt,
        steps: d!.blocks.filter((b) => b.type === "text" && b.kind !== "note" && b.text?.trim()).length,
        photos: d!.blocks.filter((b) => b.type === "image" && b.img).length,
        cover: d!.blocks.find((b) => b.type === "image" && b.img)?.img || null,
      }));
      list.sort((a, b) => b.updatedAt - a.updatedAt);
      return json({ docs: list });
    }
    if (route === "doc") {
      const id = q("id");
      if (!validId(id)) return json({ error: "id inválido" }, 400);
      const key = `docs/${id}`;
      if (req.method === "GET") {
        const d = await is.get(key, { type: "json" });
        return d ? json({ doc: d }) : json({ error: "No existe" }, 404);
      }
      if (req.method === "PUT") {
        const prev = (await is.get(key, { type: "json" })) as Doc | null;
        const doc = sanitizeDoc({ ...(await req.json()), id }, prev);
        await is.setJSON(key, doc);
        const keep = imgIds(doc), gone = [...imgIds(prev)].filter((i) => !keep.has(i));
        if (gone.length) await deleteImages(gone);
        return json({ ok: true, updatedAt: doc.updatedAt });
      }
      if (req.method === "DELETE") {
        const prev = (await is.get(key, { type: "json" })) as Doc | null;
        if (prev) await deleteImages(imgIds(prev));
        await is.delete(key);
        return json({ ok: true });
      }
    }
    if (route === "img") {
      const id = q("id"), v = q("v") === "thumb" ? "thumb" : "img";
      if (!validId(id)) return json({ error: "id inválido" }, 400);
      if (req.method === "PUT") {
        const body = await req.arrayBuffer();
        if (!body.byteLength || body.byteLength > CHUNK) return json({ error: "Imagen demasiado grande" }, 400);
        await is.set(`${v}/${id}`, body);
        return json({ ok: true });
      }
      if (req.method === "GET") {
        const data = await is.get(`${v}/${id}`, { type: "arrayBuffer" });
        if (!data) return json({ error: "No encontrado" }, 404);
        return binary(data, "image/jpeg");
      }
    }

    return json({ error: "Ruta no encontrada" }, 404);
  } catch (err: any) {
    console.error(err);
    return json({ error: err?.message || "Error del servidor" }, 500);
  }
};

export const config: Config = { path: "/api/*" };
