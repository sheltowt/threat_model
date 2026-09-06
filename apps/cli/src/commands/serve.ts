import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { createReadStream, existsSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { extname, join, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { modelSchema } from 'tmac-core';
import { findModel } from '../context.js';
import { bold, dim, green, red, yellow } from '../ui.js';

/**
 * Serve the editor against a local model file.
 *
 * This is deliberately not a general web server. It binds to the loopback
 * interface, serves one directory of static assets, and reads and writes exactly one
 * file: the model named on the command line. Threat Dragon's server keeps refresh
 * tokens in a module-level array and its own code calls that a code smell; there is
 * no reason for a local editing server to hold any state at all.
 */

const HERE = fileURLToPath(new URL('.', import.meta.url));

const MIME: Readonly<Record<string, string>> = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.yaml': 'text/yaml; charset=utf-8',
  '.yml': 'text/yaml; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.map': 'application/json; charset=utf-8',
  '.wasm': 'application/wasm',
  '.woff2': 'font/woff2',
  '.ico': 'image/x-icon',
};

/** Locate the built editor, whether running from source or from an install. */
function findWebRoot(): string | undefined {
  const candidates = [
    join(HERE, '..', '..', 'web'),
    join(HERE, '..', '..', '..', 'web', 'dist'),
    join(HERE, '..', '..', '..', '..', 'apps', 'web', 'dist'),
    resolve(process.cwd(), 'apps/web/dist'),
  ];
  return candidates.find((dir) => existsSync(join(dir, 'index.html')));
}

function send(
  res: ServerResponse,
  status: number,
  body: string,
  type = 'text/plain; charset=utf-8',
): void {
  res.writeHead(status, {
    'content-type': type,
    'content-length': Buffer.byteLength(body),
    // Nothing here should be cached by anything, and nothing should frame it.
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    'x-frame-options': 'SAMEORIGIN',
  });
  res.end(body);
}

async function readBody(req: IncomingMessage, limitBytes: number): Promise<string> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > limitBytes) throw new Error(`request body exceeded ${limitBytes} bytes`);
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
}

export interface ServeOptions {
  port: string;
  host: string;
  /** Allow the editor to write back to the model file. */
  write?: boolean;
  open?: boolean;
}

export async function serve(file: string | undefined, options: ServeOptions): Promise<number> {
  const modelPath = findModel(file);
  if (!existsSync(modelPath)) {
    process.stderr.write(
      red(`no model at ${modelPath}\n`) + dim('  run "tmac init" to create one\n'),
    );
    return 1;
  }

  const webRoot = findWebRoot();
  if (!webRoot) {
    process.stderr.write(
      red('the editor has not been built\n') +
        dim('  run "npm run build --workspace tmac-web" and try again\n'),
    );
    return 1;
  }

  const port = Number(options.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    process.stderr.write(red(`--port must be a number between 1 and 65535\n`));
    return 2;
  }

  const server = createServer((req, res) => {
    void handle(req, res, { modelPath, webRoot, allowWrite: options.write === true });
  });

  return new Promise<number>((resolveOuter) => {
    server.on('error', (err) => {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'EADDRINUSE') {
        process.stderr.write(
          red(`port ${port} is already in use\n`) + dim('  pass --port to choose another\n'),
        );
      } else {
        process.stderr.write(red(`${err.message}\n`));
      }
      resolveOuter(1);
    });

    // Loopback by default. This server reads and writes a file on this machine and
    // has no authentication, so it has no business listening on a network.
    server.listen(port, options.host, () => {
      const url = `http://${options.host}:${port}/?model=/api/model`;
      process.stdout.write(
        `${green('tmac')} editing ${bold(modelPath)}\n` +
          `  ${url}\n` +
          (options.write
            ? dim('  saving from the editor is enabled\n')
            : dim('  read only; pass --write to let the editor save\n')) +
          dim('  press ctrl+c to stop\n'),
      );
    });

    const stop = () => {
      server.close(() => resolveOuter(0));
      // Give in-flight requests a moment, then stop regardless.
      setTimeout(() => resolveOuter(0), 500).unref();
    };
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
  });
}

interface Context {
  modelPath: string;
  webRoot: string;
  allowWrite: boolean;
}

async function handle(
  req: IncomingMessage,
  res: ServerResponse,
  ctx: Context,
): Promise<void> {
  const url = new URL(req.url ?? '/', 'http://localhost');
  const path = decodeURIComponent(url.pathname);

  if (path === '/api/model') {
    if (req.method === 'GET') {
      try {
        send(res, 200, readFileSync(ctx.modelPath, 'utf8'), MIME['.yaml']!);
      } catch (err) {
        send(res, 500, `cannot read the model: ${(err as Error).message}`);
      }
      return;
    }
    if (req.method === 'PUT') {
      if (!ctx.allowWrite) {
        send(res, 403, 'this server was started read only; restart it with --write');
        return;
      }
      try {
        const body = await readBody(req, 8 * 1024 * 1024);
        // Never write something that would not load. A corrupted model file is a
        // much worse outcome than a rejected save.
        const parsed = modelSchema.safeParse(
          (await import('yaml')).parse(body, { merge: true }),
        );
        if (!parsed.success) {
          send(
            res,
            422,
            JSON.stringify({
              error: 'the model is not valid, so it was not written',
              issues: parsed.error.issues.map((i) => ({
                path: i.path.join('.'),
                message: i.message,
              })),
            }),
            MIME['.json']!,
          );
          return;
        }
        writeFileSync(ctx.modelPath, body, 'utf8');
        process.stdout.write(`${green('saved')} ${ctx.modelPath}\n`);
        send(res, 200, JSON.stringify({ ok: true }), MIME['.json']!);
      } catch (err) {
        send(res, 400, `${(err as Error).message}`);
      }
      return;
    }
    send(res, 405, 'GET or PUT only');
    return;
  }

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    send(res, 405, 'GET only');
    return;
  }

  // Static assets, confined to the editor's own directory.
  const relative = path === '/' ? 'index.html' : path.replace(/^\/+/, '');
  const target = resolve(ctx.webRoot, relative);
  if (target !== ctx.webRoot && !target.startsWith(ctx.webRoot + sep)) {
    send(res, 403, 'forbidden');
    return;
  }

  const finalPath =
    existsSync(target) && statSync(target).isFile() ? target : join(ctx.webRoot, 'index.html');

  const type = MIME[extname(finalPath)] ?? 'application/octet-stream';
  res.writeHead(200, {
    'content-type': type,
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
  });
  if (req.method === 'HEAD') {
    res.end();
    return;
  }
  createReadStream(finalPath).pipe(res);
}
