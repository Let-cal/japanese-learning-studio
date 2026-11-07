import { test, expect, type BrowserContext } from '@playwright/test';
import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, readFile, rm } from 'node:fs/promises';
import { createServer, type Server } from 'node:https';
import type { IncomingMessage, ServerResponse } from 'node:http';
import type { Duplex } from 'node:stream';
import { dirname, join, relative, resolve } from 'node:path';
import { BrowserBindingSecretSchema, parseAuthLoginForm } from '../../src/contracts/auth';

function opensslExecutable(): string {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore', windowsHide: true, timeout: 5000 });
    return 'openssl';
  } catch (error) {
    if (process.platform !== 'win32') throw error;
  }
  const gitPaths = execFileSync('where.exe', ['git'], { encoding: 'utf8', windowsHide: true, timeout: 5000 }).trim().split(/\r?\n/);
  for (const gitPath of gitPaths) {
    const directory = dirname(gitPath);
    for (const root of [directory, resolve(directory, '..'), resolve(directory, '../..')]) {
      for (const candidate of [join(root, 'usr/bin/openssl.exe'), join(root, 'mingw64/bin/openssl.exe')]) {
        if (existsSync(candidate)) return candidate;
      }
    }
  }
  throw new Error('The isolated TLS transport fixture requires OpenSSL from Git for Windows.');
}

interface CapturedRequest {
  method: string; origin: string; contentType: string; cookie: string; proofHeader: string;
  body: string; bytes: number;
}

// Fixture only: two owned loopback HTTPS servers, no app Auth route or real provider.
test('native login form sends body proof and HttpOnly binding before a top-level external 303', async ({ browser }, testInfo) => {
  const outputRoot = resolve(testInfo.outputDir);
  const tlsDirectory = resolve(testInfo.outputPath('tls-fixture'));
  if (relative(outputRoot, tlsDirectory) !== 'tls-fixture') throw new Error('TLS fixture directory must be an owned output child.');
  const servers: Server[] = [];
  const sockets = new Set<Duplex>();
  let context: BrowserContext | undefined;
  let testFailure: unknown;
  const failures: string[] = [];
  const fail = (message: string) => { if (failures.length < 16) failures.push(message); };
  const loginRequests: CapturedRequest[] = [];
  const authorizeRequests: CapturedRequest[] = [];
  const proof = `jls-csrf-v1.${'A'.repeat(43)}`;
  const binding = `jls-browser-v1.${'A'.repeat(43)}`;
  expect(BrowserBindingSecretSchema.safeParse(binding).success).toBe(true);

  function capture(request: IncomingMessage, response: ServerResponse, target: CapturedRequest[], respond: () => void) {
    const chunks: Buffer[] = [];
    let bytes = 0;
    request.on('error', () => fail('Owned fixture request failed.'));
    response.on('error', () => fail('Owned fixture response failed.'));
    request.on('data', (chunk: Buffer) => {
      bytes += chunk.byteLength;
      if (bytes <= 256) chunks.push(chunk);
      else fail('Owned fixture request exceeded 256 bytes.');
    });
    request.on('end', () => {
      const header = (name: string) => String(request.headers[name] ?? '').slice(0, 1024);
      if (target.length < 8) target.push({
        method: (request.method ?? '').slice(0, 16), origin: header('origin'), contentType: header('content-type'),
        cookie: header('cookie'), proofHeader: header('x-csrf-token'), body: Buffer.concat(chunks).toString('utf8'), bytes,
      });
      else fail('Too many owned fixture requests.');
      respond();
    });
  }

  async function listen(server: Server): Promise<number> {
    servers.push(server);
    server.maxHeadersCount = 32;
    server.requestTimeout = 5000;
    server.headersTimeout = 5000;
    server.on('connection', socket => {
      sockets.add(socket);
      socket.once('close', () => sockets.delete(socket));
    });
    server.on('error', () => fail('Owned HTTPS fixture server failed.'));
    await new Promise<void>((done, reject) => {
      const timer = setTimeout(() => reject(new Error('Owned HTTPS fixture startup timed out.')), 5000);
      const onError = (error: Error) => { clearTimeout(timer); reject(error); };
      server.once('error', onError);
      server.listen(0, '127.0.0.1', () => { clearTimeout(timer); server.removeListener('error', onError); done(); });
    });
    const address = server.address();
    if (!address || typeof address === 'string') throw new Error('Owned HTTPS fixture did not bind a TCP port.');
    return address.port;
  }

  try {
    await mkdir(tlsDirectory, { recursive: true });
    const keyPath = join(tlsDirectory, 'key.pem');
    const certificatePath = join(tlsDirectory, 'certificate.pem');
    execFileSync(opensslExecutable(), [
      'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1', '-subj', '/CN=localhost',
      '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1', '-keyout', keyPath, '-out', certificatePath,
    ], { stdio: 'ignore', windowsHide: true, timeout: 15000 });
    const tls = { key: await readFile(keyPath), cert: await readFile(certificatePath) };
    const authorizePort = await listen(createServer(tls, (request, response) => {
      if (request.url === '/favicon.ico') { response.writeHead(204).end(); return; }
      if (request.url !== '/authorize') { fail('Unexpected authorization-fixture path.'); response.writeHead(404).end(); return; }
      capture(request, response, authorizeRequests, () => {
        response.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' });
        response.end('<!doctype html><html><body><h1>Mock authorization destination</h1></body></html>');
      });
    }));
    const authorizeUrl = `https://127.0.0.1:${authorizePort}/authorize`;
    const appPort = await listen(createServer(tls, (request, response) => {
      if (request.url === '/favicon.ico') { response.writeHead(204).end(); return; }
      if (request.url === '/signin' && request.method === 'GET') {
        response.writeHead(200, { 'Content-Type': 'text/html', 'Cache-Control': 'no-store' });
        response.end(`<!doctype html><html><body>
          <form method="post" enctype="application/x-www-form-urlencoded" action="/api/v1/auth/login">
            <input type="hidden" name="csrfToken" value="${proof}">
            <button type="submit">Sign in</button>
          </form>
        </body></html>`);
        return;
      }
      if (request.url === '/api/v1/auth/login') {
        capture(request, response, loginRequests, () => {
          response.writeHead(303, { Location: authorizeUrl, 'Cache-Control': 'no-store' });
          response.end();
        });
        return;
      }
      fail('Unexpected app-fixture path.');
      response.writeHead(404).end();
    }));
    const appOrigin = `https://localhost:${appPort}`;
    context = await browser.newContext({ ignoreHTTPSErrors: true, serviceWorkers: 'block' });
    await context.addCookies([{
      url: `${appOrigin}/`, name: '__Host-jls-browser', value: binding,
      secure: true, httpOnly: true, sameSite: 'Lax',
    }]);
    const page = await context.newPage();
    const allowedUrls = new Set([
      `${appOrigin}/signin`, `${appOrigin}/api/v1/auth/login`, `${appOrigin}/favicon.ico`,
      authorizeUrl, `https://127.0.0.1:${authorizePort}/favicon.ico`,
    ]);
    const navigations: { url: string; method: string; mainFrame: boolean; navigation: boolean }[] = [];
    context.on('request', request => {
      if (!allowedUrls.has(request.url())) fail('Unexpected browser network URL.');
      if ((request.url() === `${appOrigin}/api/v1/auth/login` || request.url() === authorizeUrl) && navigations.length < 8) {
        navigations.push({ url: request.url(), method: request.method(), mainFrame: request.frame() === page.mainFrame(), navigation: request.isNavigationRequest() });
      }
    });
    // Guard new requests; the actual redirect goes to the second owned server, not a route.fulfill chain.
    await context.route('**/*', route => allowedUrls.has(route.request().url()) ? route.continue() : route.abort('blockedbyclient'));
    await page.goto(`${appOrigin}/signin`);
    expect(await page.evaluate(() => document.cookie)).not.toContain('__Host-jls-browser');
    const [loginResponse] = await Promise.all([
      page.waitForResponse(response => response.url() === `${appOrigin}/api/v1/auth/login`),
      page.waitForURL(authorizeUrl),
      page.getByRole('button', { name: 'Sign in', exact: true }).click(),
    ]);
    await expect(page.getByRole('heading', { name: 'Mock authorization destination' })).toBeVisible();
    expect(loginResponse.status()).toBe(303);
    expect(loginResponse.headers().location).toBe(authorizeUrl);
    expect(page.mainFrame().url()).toBe(authorizeUrl);
    expect(navigations).toEqual([
      { url: `${appOrigin}/api/v1/auth/login`, method: 'POST', mainFrame: true, navigation: true },
      { url: authorizeUrl, method: 'GET', mainFrame: true, navigation: true },
    ]);
    expect(loginRequests).toHaveLength(1);
    expect(loginRequests[0]).toMatchObject({ method: 'POST', origin: appOrigin, contentType: 'application/x-www-form-urlencoded', proofHeader: '' });
    expect(loginRequests[0].cookie).toBe(`__Host-jls-browser=${binding}`);
    expect(loginRequests[0].bytes).toBeLessThanOrEqual(256);
    expect(parseAuthLoginForm(new URLSearchParams(loginRequests[0].body))).toEqual({ ok: true, value: { csrfToken: proof } });
    expect(authorizeRequests).toHaveLength(1);
    expect(authorizeRequests[0]).toMatchObject({ method: 'GET', cookie: '', proofHeader: '', body: '', bytes: 0 });
    expect(failures).toEqual([]);
  } catch (error) {
    testFailure = error;
    throw error;
  } finally {
    for (const socket of sockets) socket.destroy();
    const cleanup = await Promise.allSettled([
      new Promise<void>((done, reject) => {
        const timer = setTimeout(() => reject(new Error('Owned browser context cleanup timed out.')), 5000);
        Promise.resolve(context?.close()).then(() => { clearTimeout(timer); done(); }, error => { clearTimeout(timer); reject(error); });
      }),
      ...servers.map(server => new Promise<void>((done, reject) => {
        const timer = setTimeout(() => reject(new Error('Owned HTTPS fixture cleanup timed out.')), 5000);
        server.close(error => {
          clearTimeout(timer);
          if (error && (error as NodeJS.ErrnoException).code !== 'ERR_SERVER_NOT_RUNNING') reject(error);
          else done();
        });
        server.closeAllConnections();
      })),
      (async () => {
        // Recheck the resolved child boundary before recursive deletion, including on Windows.
        if (relative(outputRoot, resolve(tlsDirectory)) !== 'tls-fixture') throw new Error('Refusing TLS fixture cleanup outside its owned output child.');
        await rm(tlsDirectory, { recursive: true, force: true });
      })(),
    ]);
    const cleanupErrors = cleanup.filter(result => result.status === 'rejected');
    if (cleanupErrors.length) throw new AggregateError([
      ...(testFailure === undefined ? [] : [testFailure]), ...cleanupErrors.map(result => result.reason),
    ], 'Owned transport fixture cleanup failed.', { cause: testFailure });
  }
});
