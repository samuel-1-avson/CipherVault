@echo off
title CipherVault Landing Page Preview
echo =======================================================
echo   Launching CipherVault Marketing Landing Page
echo =======================================================
node -e "const http = require('http'), fs = require('fs'), path = require('path'); const mime = {'.html':'text/html','.css':'text/css','.js':'application/javascript','.svg':'image/svg+xml'}; http.createServer((req,res)=>{ let f = path.join('apps/landing', req.url === '/' ? 'index.html' : req.url.split('?')[0].replace(/\.\./g,'')); fs.readFile(f, (err,data)=>{ if(err){res.writeHead(404);res.end('Not Found');} else { res.writeHead(200, {'Content-Type': mime[path.extname(f)]||'text/plain'}); res.end(data);} }); }).listen(3000, ()=>{ console.log('Serving landing page at: http://localhost:3000'); require('child_process').exec('start http://localhost:3000'); });"
