import net from 'node:net';

export interface ReplayGuard {
  consume(jti: string, expiresAtSeconds: number, nowSeconds?: number): boolean | Promise<boolean>;
}

function encodeRespCommand(args: string[]): string {
  let out = `*${args.length}\r\n`;
  for (const arg of args) {
    const byteLen = Buffer.byteLength(arg, 'utf8');
    out += `$${byteLen}\r\n${arg}\r\n`;
  }
  return out;
}

/**
 * Zero-dependency Redis / Valkey RESP2 client for atomic distributed JTI replay
 * prevention (`SET vectoll:jti:<jti> 1 NX EX <ttl>`) across multi-replica Gate clusters.
 */
export class RedisReplayStore implements ReplayGuard {
  private readonly host: string;
  private readonly port: number;
  private readonly password?: string;
  private readonly keyPrefix: string;
  private readonly timeoutMs: number;

  constructor(
    redisUrl = process.env.VECTOLL_REDIS_URL ?? 'redis://127.0.0.1:6379',
    options: { keyPrefix?: string; timeoutMs?: number } = {},
  ) {
    const parsed = new URL(redisUrl);
    this.host = parsed.hostname || '127.0.0.1';
    this.port = Number(parsed.port || 6379);
    this.password = parsed.password ? decodeURIComponent(parsed.password) : undefined;
    this.keyPrefix = options.keyPrefix ?? 'vectoll:jti:';
    this.timeoutMs = options.timeoutMs ?? 1500;
  }

  private execCommands(commands: string[][]): Promise<string[]> {
    return new Promise((resolve, reject) => {
      const socket = net.createConnection({ host: this.host, port: this.port });
      socket.setTimeout(this.timeoutMs);

      let rawBuf = '';
      const expectedResponses = commands.length;
      const payload = commands.map(encodeRespCommand).join('');

      const cleanup = () => {
        socket.removeAllListeners();
        socket.destroy();
      };

      socket.once('connect', () => {
        socket.write(payload, 'utf8');
      });

      socket.on('data', (chunk) => {
        rawBuf += chunk.toString('utf8');
        const replies = parseTopLevelRespReplies(rawBuf);
        if (replies.length >= expectedResponses) {
          cleanup();
          const errReply = replies.find((r) => r.startsWith('-'));
          if (errReply) {
            reject(new Error(`ERR_REDIS_REPLY: ${errReply.slice(1).trim()}`));
          } else {
            resolve(replies);
          }
        }
      });

      socket.once('timeout', () => {
        cleanup();
        reject(new Error('ERR_REDIS_TIMEOUT'));
      });

      socket.once('error', (err) => {
        cleanup();
        reject(err);
      });
    });
  }

  async consume(
    jti: string,
    expiresAtSeconds: number,
    nowSeconds = Math.floor(Date.now() / 1000),
  ): Promise<boolean> {
    const ttl = Math.max(expiresAtSeconds - nowSeconds + 60, 60);
    const cmds: string[][] = [];
    if (this.password) {
      cmds.push(['AUTH', this.password]);
    }
    cmds.push(['SET', `${this.keyPrefix}${jti}`, '1', 'NX', 'EX', String(ttl)]);
    const replies = await this.execCommands(cmds);
    const setReply = replies[replies.length - 1] ?? '';
    return setReply.startsWith('+OK');
  }
}

function parseTopLevelRespReplies(buf: string): string[] {
  const out: string[] = [];
  let idx = 0;
  while (idx < buf.length) {
    const prefix = buf[idx];
    const lineEnd = buf.indexOf('\r\n', idx);
    if (lineEnd === -1) break;

    if (prefix === '+' || prefix === '-' || prefix === ':') {
      out.push(buf.slice(idx, lineEnd));
      idx = lineEnd + 2;
      continue;
    }

    if (prefix === '$') {
      const len = Number(buf.slice(idx + 1, lineEnd));
      if (len === -1) {
        out.push('$-1');
        idx = lineEnd + 2;
        continue;
      }
      const valStart = lineEnd + 2;
      const valEnd = valStart + len;
      if (buf.length < valEnd + 2) break;
      out.push(`$${buf.slice(valStart, valEnd)}`);
      idx = valEnd + 2;
      continue;
    }

    break;
  }
  return out;
}
