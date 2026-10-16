import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';
import { readFile, readdir, writeFile } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const base = 'https://jasonk33.github.io/trips/';
const marker = /(<script id="encrypted-library" type="application\/json">)([^<]+)(<\/script>)/;
const filename = /^[a-z0-9][a-z0-9-]*\.html$/;

function decrypt(payload, key) {
  if (payload.version !== 1 || payload.algorithm !== 'AES-GCM') throw new Error('Unsupported encryption format.');
  const ciphertext = Buffer.from(payload.ciphertext, 'base64');
  const cipher = createDecipheriv('aes-256-gcm', key, Buffer.from(payload.iv, 'base64'));
  cipher.setAuthTag(ciphertext.subarray(-16));
  return Buffer.concat([cipher.update(ciphertext.subarray(0,-16)), cipher.final()]);
}

function linkKey(link, expected) {
  const url = new URL(link);
  const key = new URLSearchParams(url.hash.slice(1)).get('key');
  if (url.origin + url.pathname !== expected || url.search || !/^[A-Za-z0-9_-]{43}$/.test(key || '')) throw new Error('Invalid complete sharing link.');
  return Buffer.from(key, 'base64url');
}

function reportPayload(html) {
  for (const id of ['encrypted-report','encrypted-trip-data']) {
    const match = html.match(new RegExp(`<script id="${id}" type="application/json">([^<]+)</script>`));
    if (match) return {id,payload:JSON.parse(match[1])};
  }
  if (html.includes('AES-GCM')) throw new Error('Unrecognized encrypted report format; add validation before publishing.');
  return null;
}

export function updateLibrary({html,pages,libraryLink,password,entry,checkOnly = false}) {
  const match = html.match(marker);
  if (!match) throw new Error('Encrypted library payload is missing.');
  const payload = JSON.parse(match[2]);
  let key;
  if (libraryLink) {
    key = linkKey(libraryLink, base);
  } else if (typeof password === 'string' && password.length) {
    const access = payload.password;
    if (access?.version !== 1 || access.kdf !== 'PBKDF2' || access.hash !== 'SHA-256' || access.iterations !== 600000) throw new Error('Unsupported password access format.');
    const derived = pbkdf2Sync(password, Buffer.from(access.salt, 'base64'), access.iterations, 32, 'sha256');
    key = decrypt({...access,algorithm:'AES-GCM'}, derived);
  } else {
    throw new Error('A library credential is required: use --library-link-file or --password-stdin.');
  }
  if (key.length !== 32) throw new Error('Invalid library credential.');
  const catalog = JSON.parse(decrypt(payload,key));
  if (catalog.version !== 1 || !Array.isArray(catalog.reports)) throw new Error('Unsupported library catalog.');
  const original = JSON.stringify(catalog);
  const records = new Map();
  for (const report of catalog.reports) {
    if (!filename.test(report.path) || report.path === 'index.html' || records.has(report.path)) throw new Error('Invalid or duplicate catalog path.');
    records.set(report.path,report);
  }
  if (entry) {
    if (checkOnly) throw new Error('Check mode cannot edit the catalog.');
    if (!filename.test(entry.path) || entry.path === 'index.html') throw new Error('Invalid report path.');
    const previous = records.get(entry.path);
    if (previous?.protected && entry.publicPage) throw new Error('Do not downgrade an existing private report to public access.');
    const report = {...previous,path:entry.path};
    for (const field of ['title','description','collection']) {
      if (entry[field] !== undefined) report[field] = entry[field];
    }
    if (entry.reportLink) {
      linkKey(entry.reportLink,base + entry.path);
      report.href = entry.path + new URL(entry.reportLink).hash;
      report.protected = true;
    } else if (entry.publicPage) {
      report.href = entry.path;
      report.protected = false;
    } else if (!previous) {
      throw new Error('Choose explicit public access or supply a complete private report link.');
    }
    records.set(entry.path,report);
  }
  const paths = [...records.keys()].sort();
  if (JSON.stringify(paths) !== JSON.stringify([...pages.keys()].sort())) throw new Error('Library inventory mismatch: every root HTML report must have exactly one catalog entry. Add metadata for new pages; do not silently drop missing pages.');
  const secrets = [key.toString('base64url')];
  if (password) secrets.push(password);
  for (const report of records.values()) {
    if (['title','description','collection','href'].some(field => typeof report[field] !== 'string' || !report[field].trim()) || typeof report.protected !== 'boolean') throw new Error('Incomplete report metadata.');
    const source = pages.get(report.path);
    const encrypted = reportPayload(source);
    const url = new URL(report.href,base);
    if (url.origin + url.pathname !== base + report.path || url.search) throw new Error('Invalid report link.');
    if (report.protected) {
      if (!encrypted) throw new Error('Private report must contain an encrypted wrapper, not plaintext.');
      const reportKey = linkKey(url.href,base + report.path);
      const plaintext = decrypt(encrypted.payload,reportKey).toString('utf8');
      if (encrypted.id === 'encrypted-report') {
        if (!plaintext.startsWith('<!doctype html>')) throw new Error('Invalid decrypted private report.');
      } else {
        const trip = JSON.parse(plaintext);
        if (trip.id !== 'hawaii-nye-2026' || trip.sharing !== 'shared') throw new Error('Invalid decrypted private report.');
      }
      secrets.push(reportKey.toString('base64url'));
    } else if (encrypted || url.hash) {
      throw new Error('An encrypted report needs its complete private sharing link.');
    }
  }
  for (const source of [html,...pages.values()]) {
    if (secrets.some(secret => source.includes(secret))) throw new Error('A secret key or password appears in public source; do not publish.');
  }
  catalog.reports = [...records.values()];
  if (checkOnly || JSON.stringify(catalog) === original) return html;
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm',key,iv);
  const ciphertext = Buffer.concat([cipher.update(JSON.stringify(catalog),'utf8'),cipher.final(),cipher.getAuthTag()]);
  const updated = {...payload,iv:iv.toString('base64'),ciphertext:ciphertext.toString('base64')};
  return html.replace(marker,(_,start,data,end) => start + JSON.stringify(updated) + end);
}

async function main() {
  const {values} = parseArgs({options:{
    'library-link-file':{type:'string'}, 'password-stdin':{type:'boolean'},
    page:{type:'string'}, title:{type:'string'}, description:{type:'string'}, collection:{type:'string'},
    public:{type:'boolean'}, 'report-link-file':{type:'string'}, check:{type:'boolean'}
  }});
  if (values['library-link-file'] && values['password-stdin']) throw new Error('Use one library credential source.');
  if (!values.check && !values.page) throw new Error('Use --check or provide --page with metadata for a new report.');
  if (values.public && values['report-link-file']) throw new Error('Choose public access or a private report link, not both.');
  const root = fileURLToPath(new URL('../',import.meta.url));
  const names = (await readdir(root)).filter(name => /\.html$/i.test(name) && name !== 'index.html');
  const pages = new Map(await Promise.all(names.map(async name => [name,await readFile(path.join(root,name),'utf8')])));
  const libraryLink = values['library-link-file'] ? (await readFile(values['library-link-file'],'utf8')).trim() : undefined;
  const password = values['password-stdin'] ? readFileSync(0,'utf8').replace(/\r?\n$/,'') : undefined;
  const reportLink = values['report-link-file'] ? (await readFile(values['report-link-file'],'utf8')).trim() : undefined;
  const index = path.join(root,'index.html');
  const html = await readFile(index,'utf8');
  const result = updateLibrary({
    html,pages,libraryLink,password,checkOnly:values.check,
    entry:values.page ? {path:values.page,title:values.title,description:values.description,collection:values.collection,publicPage:values.public,reportLink} : undefined
  });
  if (result !== html) await writeFile(index,result);
  console.log(`${result === html ? 'Validated' : 'Updated'} encrypted library: ${pages.size} reports; existing password access and sharing keys preserved.`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    console.error(`Library update failed: ${error.message}`);
    process.exitCode = 1;
  });
}
