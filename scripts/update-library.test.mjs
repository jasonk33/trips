import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from 'node:crypto';
import { updateLibrary } from './update-library.mjs';

const base = 'https://jasonk33.github.io/trips/';
function encrypt(value, key) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(value), cipher.final(), cipher.getAuthTag()]);
  return { version:1, algorithm:'AES-GCM', iv:iv.toString('base64'), ciphertext:ciphertext.toString('base64') };
}
function decrypt(payload, key) {
  const ciphertext = Buffer.from(payload.ciphertext, 'base64');
  const cipher = createDecipheriv('aes-256-gcm', key, Buffer.from(payload.iv, 'base64'));
  cipher.setAuthTag(ciphertext.subarray(-16));
  return Buffer.concat([cipher.update(ciphertext.subarray(0,-16)), cipher.final()]);
}
function payload(html) {
  return JSON.parse(html.match(/id="encrypted-library" type="application\/json">([^<]+)</)[1]);
}
function fixture(password = 'synthetic-test-password') {
  const key = randomBytes(32);
  const reportKey = randomBytes(32);
  const salt = randomBytes(16);
  const wrapped = encrypt(key, pbkdf2Sync(password, salt, 600000, 32, 'sha256'));
  const access = { version:1, kdf:'PBKDF2', hash:'SHA-256', iterations:600000, salt:salt.toString('base64'), iv:wrapped.iv, ciphertext:wrapped.ciphertext };
  const privateHref = 'private.html#key=' + reportKey.toString('base64url');
  const reports = [
    {path:'public.html',title:'Public',description:'Public report',collection:'Travel',href:'public.html',protected:false},
    {path:'private.html',title:'Private',description:'Private report',collection:'Planning',href:privateHref,protected:true}
  ];
  const sealed = {...encrypt(JSON.stringify({version:1,reports}), key), password:access};
  return {
    key, reportKey, password,
    libraryLink:base + '#key=' + key.toString('base64url'),
    html:`<!doctype html><script id="encrypted-library" type="application/json">${JSON.stringify(sealed)}</script>`,
    pages:new Map([
      ['public.html','<!doctype html><h1>Public report</h1>'],
      ['private.html',`<!doctype html><script id="encrypted-report" type="application/json">${JSON.stringify(encrypt('<!doctype html><h1>Private report</h1>',reportKey))}</script>`]
    ]),
    reports
  };
}
const added = {path:'new.html',title:'New page',description:'A new report',collection:'Travel',publicPage:true};

test('check and unchanged updates preserve the exact index', () => {
  const f = fixture();
  assert.equal(updateLibrary({...f,checkOnly:true}), f.html);
  assert.equal(updateLibrary({...f,entry:{path:'private.html'}}), f.html);
});

test('adding a public page preserves password access, private links and bookmark key', () => {
  const f = fixture();
  f.pages.set('new.html','<!doctype html><h1>New report</h1>');
  const result = updateLibrary({...f,entry:added});
  const sealed = payload(result);
  assert.deepEqual(sealed.password, payload(f.html).password);
  const catalog = JSON.parse(decrypt(sealed, f.key));
  assert.deepEqual(catalog.reports.slice(0,2), f.reports);
  assert.deepEqual(catalog.reports[2], {path:'new.html',title:'New page',description:'A new report',collection:'Travel',href:'new.html',protected:false});
  for (const secret of [f.password,f.key.toString('base64url'),f.reportKey.toString('base64url')]) assert(!result.includes(secret));
  assert.equal(updateLibrary({...f,html:result,checkOnly:true}), result);
});

test('password input unlocks the same catalog without storing or rotating it', () => {
  const f = fixture();
  assert.equal(updateLibrary({...f,libraryLink:undefined,password:f.password,checkOnly:true}), f.html);
  assert.throws(() => updateLibrary({...f,libraryLink:undefined,password:'wrong',checkOnly:true}));
  assert.throws(() => updateLibrary({...f,libraryLink:base + '#key=' + randomBytes(32).toString('base64url'),checkOnly:true}));
  assert.throws(() => updateLibrary({...f,libraryLink:undefined,password:undefined,checkOnly:true}), /credential/i);
  const g = fixture(' password with spaces ');
  assert.equal(updateLibrary({...g,libraryLink:undefined,password:g.password,checkOnly:true}),g.html);
});

test('a new private report requires a valid complete encrypted sharing link', () => {
  const f = fixture();
  const key = randomBytes(32);
  f.pages.set('new.html',`<!doctype html><script id="encrypted-report" type="application/json">${JSON.stringify(encrypt('<!doctype html><h1>Secret</h1>',key))}</script>`);
  const entry = {...added,publicPage:false,reportLink:base + 'new.html#key=' + key.toString('base64url')};
  const result = updateLibrary({...f,entry});
  const report = JSON.parse(decrypt(payload(result),f.key)).reports.at(-1);
  assert.equal(report.protected,true);
  assert.equal(report.href,'new.html#key=' + key.toString('base64url'));
  assert.throws(() => updateLibrary({...f,entry:{...entry,reportLink:undefined}}), /access|link/i);
  assert.throws(() => updateLibrary({...f,entry:added}), /encrypted|private/i);
  assert.throws(() => updateLibrary({...f,entry:{...entry,reportLink:entry.reportLink.replace('jasonk33.github.io','example.com')}}), /link/i);
  assert.throws(() => updateLibrary({...f,entry:{...entry,reportLink:base + 'new.html#key=' + randomBytes(32).toString('base64url')}}));
});

test('new public pages require explicit approval and metadata', () => {
  const f = fixture();
  f.pages.set('new.html','<!doctype html><h1>New report</h1>');
  assert.throws(() => updateLibrary({...f,entry:{...added,publicPage:false}}), /access|public/i);
  for (const field of ['title','description','collection']) {
    assert.throws(() => updateLibrary({...f,entry:{...added,[field]:''}}), /metadata/i);
  }
  assert.throws(() => updateLibrary({...f,entry:{...added,path:'../new.html'}}), /path/i);
});

test('checks reject unlisted, missing, duplicate and invalid report paths', () => {
  const f = fixture();
  f.pages.set('orphan.html','<!doctype html>');
  assert.throws(() => updateLibrary({...f,checkOnly:true}), /inventory/i);
  f.pages.delete('orphan.html');
  f.pages.delete('public.html');
  assert.throws(() => updateLibrary({...f,checkOnly:true}), /inventory|missing/i);
  const g = fixture();
  const catalog = {version:1,reports:[...g.reports,g.reports[0]]};
  const html = g.html.replace(/(<script[^>]+>)[^<]+/,(_,start) => start + JSON.stringify(encrypt(JSON.stringify(catalog),g.key)));
  assert.throws(() => updateLibrary({...g,html,checkOnly:true}), /duplicate|path/i);
});

test('routine edits keep privacy and reject leaked keys or lost encrypted content', () => {
  const f = fixture();
  const result = updateLibrary({...f,entry:{path:'private.html',title:'Updated title'}});
  const report = JSON.parse(decrypt(payload(result),f.key)).reports[1];
  assert.equal(report.title,'Updated title');
  assert.equal(report.href,f.reports[1].href);
  assert.throws(() => updateLibrary({...f,entry:{path:'private.html',publicPage:true}}), /private|downgrade/i);
  f.pages.set('public.html','<!doctype html>' + f.reportKey.toString('base64url'));
  assert.throws(() => updateLibrary({...f,checkOnly:true}), /key|secret/i);
  f.pages.set('public.html','<!doctype html>');
  f.pages.set('private.html','<!doctype html><h1>Accidentally unencrypted</h1>');
  assert.throws(() => updateLibrary({...f,checkOnly:true}), /encrypted|private/i);
});

test('private report validation matches the browser wrapper contracts', () => {
  const f = fixture();
  f.pages.set('private.html',`<!doctype html><script id="encrypted-report" type="application/json">${JSON.stringify(encrypt('<!DOCTYPE html><h1>Not accepted by the report wrapper</h1>',f.reportKey))}</script>`);
  assert.throws(() => updateLibrary({...f,checkOnly:true}), /private report/i);
  for (const id of ['wrong-trip','hawaii-nye-2026']) {
    const data = JSON.stringify({id,sharing:'shared'});
    f.pages.set('private.html',`<!doctype html><script id="encrypted-trip-data" type="application/json">${JSON.stringify(encrypt(data,f.reportKey))}</script>`);
    if (id === 'wrong-trip') assert.throws(() => updateLibrary({...f,checkOnly:true}), /private report/i);
    else assert.equal(updateLibrary({...f,checkOnly:true}),f.html);
  }
});

test('password-authenticated checks reject plaintext password matches', () => {
  for (const password of ['synthetic-test-password','a']) {
    const f = fixture(password);
    f.pages.set('public.html','<!doctype html><p>Accidentally included password: ' + password + '</p>');
    assert.throws(() => updateLibrary({...f,libraryLink:undefined,password,checkOnly:true}), /password|secret/i);
  }
});
