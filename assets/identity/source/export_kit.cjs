#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const cp = require('child_process');
const sharp = require(process.env.CODEX_PRIMARY_RUNTIME_NODE_MODULES ? path.join(process.env.CODEX_PRIMARY_RUNTIME_NODE_MODULES, 'sharp') : 'sharp');
const root = path.resolve(__dirname, '..');
const jobs = [];
function render(source, dest, width, height) {
  jobs.push(async () => {
    let pipeline = sharp(path.join(root, source), { density: 144 }).resize(width, height, { fit: 'contain', background: '#00000000' });
    await pipeline.png().toFile(path.join(root, dest));
  });
}
const sizes = [16,20,24,32,48,64,96,128,192,256,512,1024];
for (const tone of ['dark','light']) {
  for (const size of sizes) render(`icons/planarian-app-${tone}${size<=32?'-micro':''}.svg`, `icons/${tone}/planarian-${size}.png`, size, size);
  render(`social/planarian-avatar-${tone}.svg`, `social/planarian-avatar-${tone}.png`, 1024, 1024);
  render(`social/planarian-card-${tone}.svg`, `social/planarian-card-${tone}.png`, 1280, 640);
  render(`previews/boot-${tone}.svg`, `previews/boot-${tone}.png`, 1920, 1080);
  for (const size of [192,512]) render(`web/planarian-maskable-${tone}.svg`, `web/planarian-maskable-${tone}-${size}.png`, size, size);
  for (const layout of ['horizontal','stacked']) render(`wordmarks/planarian-${layout}-${tone}.svg`, `wordmarks/planarian-${layout}-${tone}.png`, layout==='horizontal'?1800:1024, undefined);
}
for(const tone of ['black','white']) for(const size of [128,256,512,1024]) render(`marks/planarian-mark-${tone}.svg`, `marks/planarian-mark-${tone}-${size}.png`, size, size);
for(const size of [16,24,32,48,64]) render(`icons/planarian-app-dark${size<=32?'-micro':''}.svg`, `web/favicon-${size}.png`, size, size);
render('web/planarian-maskable-dark.svg', 'web/apple-touch-icon.png', 180, 180);
render('previews/software-applications.svg', 'previews/software-applications.png', 1600, 1000);
async function run() {
  // Limit concurrent SVG rasterization to keep memory predictable.
  let cursor=0;
  await Promise.all(Array.from({length:4}, async()=>{while(cursor<jobs.length){const job=jobs[cursor++];await job();}}));
  cp.execFileSync('convert', [16,24,32,48,64].map(s=>path.join(root, `web/favicon-${s}.png`)).concat(path.join(root,'web/favicon.ico')));
  const files = fs.readdirSync(path.join(root,'web'));
  const manifest = {
    name:'planarian', short_name:'planarian', start_url:'.', display:'standalone', background_color:'#151719', theme_color:'#151719',
    icons:[192,512].map(size=>({src:`planarian-maskable-dark-${size}.png`,sizes:`${size}x${size}`,type:'image/png',purpose:'any maskable'}))
  };
  fs.writeFileSync(path.join(root,'web/site.webmanifest'),JSON.stringify(manifest,null,2)+'\n');
  console.log(JSON.stringify({png_exports:jobs.length, favicon_frames:5, web_files:files.length},null,2));
}
run().catch(err=>{console.error(err);process.exit(1);});
