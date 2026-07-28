import http from 'node:http'

const image = 'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII='
const port = Number(process.env.MOCK_PORT || 8790)

http.createServer((request, response) => {
  request.resume()
  request.on('end', () => {
    if (!['/v1/images/generations', '/v1/images/edits'].includes(request.url || '')) {
      response.writeHead(404).end()
      return
    }
    response.writeHead(200, { 'content-type': 'application/json' })
    response.end(JSON.stringify({
      data: Array.from({ length: 4 }, () => ({ b64_json: image })),
      usage: { input_tokens: 1, output_tokens: 1, total_tokens: 2 },
    }))
  })
}).listen(port, '127.0.0.1')
