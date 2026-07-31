import http from 'node:http';
import net from 'node:net';

const listenPort = Number(process.env.PREVIEW_PORT || 18501);
const webTargetPort = Number(process.env.WEB_TARGET_PORT || 8501);
const apiTargetPort = Number(process.env.API_TARGET_PORT || 8000);
const targetFor = (url = '/') => url === '/health' || url.startsWith('/sub/') || url.startsWith('/ruleset/')
  ? { host: '127.0.0.1', port: apiTargetPort }
  : { host: '127.0.0.1', port: webTargetPort };
const headersFor = (headers, target) => ({
  ...headers,
  host: `${target.host}:${target.port}`,
  'x-forwarded-host': `127.0.0.1:${listenPort}`,
  'x-forwarded-proto': 'http',
});

const server = http.createServer((request, response) => {
  const target = targetFor(request.url);
  const upstream = http.request(
    { ...target, method: request.method, path: request.url, headers: headersFor(request.headers, target) },
    (upstreamResponse) => {
      response.writeHead(upstreamResponse.statusCode ?? 502, upstreamResponse.headers);
      upstreamResponse.pipe(response);
    },
  );
  upstream.on('error', (error) => {
    response.writeHead(502, { 'content-type': 'text/plain; charset=utf-8' });
    response.end(`Preview upstream unavailable: ${error.message}`);
  });
  request.pipe(upstream);
});

server.on('upgrade', (request, socket, head) => {
  const target = targetFor(request.url);
  const upstream = net.connect(target.port, target.host, () => {
    upstream.write([
      `${request.method} ${request.url} HTTP/${request.httpVersion}`,
      ...Object.entries(headersFor(request.headers, target)).map(([key, value]) => `${key}: ${value}`),
      '',
      '',
    ].join('\r\n'));
    if (head.length) upstream.write(head);
    socket.pipe(upstream).pipe(socket);
  });
  upstream.on('error', () => socket.destroy());
});

server.listen(listenPort, '127.0.0.1');
