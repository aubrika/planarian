#!/usr/bin/env node
/* Organic vector-motion prototypes derived from the existing planarian mark. */
const fs=require('fs'), path=require('path'), cp=require('child_process');
const sharp=require(process.env.CODEX_PRIMARY_RUNTIME_NODE_MODULES ? path.join(process.env.CODEX_PRIMARY_RUNTIME_NODE_MODULES,'sharp') : 'sharp');
const ROOT=path.resolve(__dirname,'..');
const OUT=path.join(ROOT,'animations');
fs.mkdirSync(OUT,{recursive:true});
const trace=JSON.parse(fs.readFileSync(path.join(ROOT,'source/trace-data.json'),'utf8'));
const [x0,y0,x1,y1]=trace.bounds;
const scale=800/Math.max(x1-x0,y1-y0);
const dx=(1024-(x1-x0)*scale)/2-x0*scale;
const dy=(1024-(y1-y0)*scale)/2-y0*scale;
const CONTOURS=trace.contours.map(c=>c.segments.map(([tag,points])=>[tag,points.map(([x,y])=>[x*scale+dx,y*scale+dy])]));
const centers=CONTOURS.slice(1).map(c=>{
 const pts=c.flatMap(s=>s[1]);
 return [(Math.min(...pts.map(p=>p[0]))+Math.max(...pts.map(p=>p[0])))/2,(Math.min(...pts.map(p=>p[1]))+Math.max(...pts.map(p=>p[1])))/2];
});
const HX=(centers[0][0]+centers[1][0])/2, HY=(centers[0][1]+centers[1][1])/2;
const CX=512,CY=560;
const STATIC_PATH=fs.readFileSync(path.join(ROOT,'marks/planarian-mark-black.svg'),'utf8').match(/<path d="([^"]+)"/)[1];
const DURATIONS={loading:3.6,working:2.4};

function transformPoint(x,y,mode,phase){
 const vx=x-CX,vy=y-CY;
 const head=Math.exp(-(((x-HX)/150)**2+((y-HY)/145)**2));
 const body=1-.94*head;
 const tail=Math.exp(-(((x-(HX+148))/88)**2+((y-(HY+18))/88)**2));
 let nx=x,ny=y;
 if(mode==='loading'){
   const breath=Math.sin(phase);
   nx+=vx*.066*breath*body + tail*12*breath + head*1.2*breath;
   ny+=vy*.090*breath*body + tail*8*breath + head*1.8*breath;
 }else if(mode==='working'){
   const r=Math.max(1,Math.hypot(vx,vy));
   const theta=Math.atan2(vy,vx);
   const travelPhase=-phase;
   const wave=Math.exp(5*(Math.cos(theta-(travelPhase-Math.PI/3))-1));
   const newR=r-(r-300)*.34*wave*body;
   nx=CX+vx*newR/r + tail*12*Math.sin(travelPhase) + head*.8*Math.sin(travelPhase);
   ny=CY+vy*newR/r + tail*8*Math.sin(travelPhase) + head*1.4*Math.sin(travelPhase);
 }
 return [nx,ny];
}

function motionPath(mode,progress){
 const phase=2*Math.PI*((progress%1+1)%1);
 function point(p){
   const [x,y]=transformPoint(p[0],p[1],mode,phase);
   if(!Number.isFinite(x)||!Number.isFinite(y))throw new Error('Non-finite motion coordinate');
   return x.toFixed(3)+','+y.toFixed(3);
 }
 return CONTOURS.map(curve=>{
   const out=['M'+point(curve[curve.length-1][1][2])];
   for(const [tag,pts] of curve)out.push(tag===1?'C'+pts.map(point).join(' '):'L'+point(pts[1])+' '+point(pts[2]));
   return out.join(' ')+' Z';
 }).join(' ');
}

function glyph(d,fill='currentColor',transform=''){
 const mark=`<path d="${d}" fill="${fill}" fill-rule="evenodd"/>`;
 return transform?`<g transform="${transform}">${mark}</g>`:mark;
}
function svg(body,w=1024,h=1024,label='planarian'){
 return `<svg xmlns="http://www.w3.org/2000/svg" width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" role="img" aria-label="${label}"><title>${label}</title>${body}</svg>`;
}
function text(x,y,value,size=24,fill='#151719',more=''){
 return `<text x="${x}" y="${y}" font-family="Arial,Helvetica,sans-serif" font-size="${size}" fill="${fill}" ${more}>${value}</text>`;
}
function embed(name,x,y,maxw,maxh){
 const file=fs.readFileSync(path.join(ROOT,name),'utf8');
 const box=file.match(/viewBox="([^"]+)"/)[1].split(/\s+/).map(Number);
 const factor=Math.min(maxw/box[2],maxh/box[3]);
 const body=file.replace(/^<svg[^>]*>/,'').replace(/<\/svg>\s*$/,'');
 return `<g transform="translate(${x+(maxw-box[2]*factor)/2} ${y+(maxh-box[3]*factor)/2}) scale(${factor})">${body}</g>`;
}

const COMMON=`const CONTOURS=${JSON.stringify(CONTOURS)};\nconst HX=${HX},HY=${HY},CX=${CX},CY=${CY};\nconst STATIC_PATH=${JSON.stringify(STATIC_PATH)};\nconst DURATIONS=${JSON.stringify(DURATIONS)};\n${transformPoint.toString()}\n${motionPath.toString()}\n`;
fs.writeFileSync(path.join(OUT,'planarian-motion.js'),COMMON+'export { motionPath, STATIC_PATH as staticPath, DURATIONS as durations };\n');
const keyframes={format:'planarian-svg-path-keyframes-v1',viewBox:[0,0,1024,1024],staticPath:STATIC_PATH,animations:[]};
for(const mode of ['loading','working']){
 const n=48;
 const values=Array.from({length:n+1},(_,i)=>motionPath(mode,i===n?0:i/n));
 keyframes.animations.push({name:mode,durationMs:DURATIONS[mode]*1000,keyframes:values.map((d,i)=>({offset:i/n,d}))});
 for(const [tone,ink] of [['black','#000000'],['white','#ffffff']]){
   const style='<style>.p-still{display:none}@media(prefers-reduced-motion:reduce){.p-motion{display:none}.p-still{display:inline}}</style>';
   const animated=`<g class="p-motion"><path d="${STATIC_PATH}" fill="${ink}" fill-rule="evenodd"><animate attributeName="d" dur="${DURATIONS[mode]}s" repeatCount="indefinite" calcMode="linear" values="${values.join(';')}"/></path></g>`;
   const still=`<g class="p-still">${glyph(STATIC_PATH,ink)}</g>`;
   fs.writeFileSync(path.join(OUT,`${mode}-${tone}.svg`),svg(style+animated+still,1024,1024,`planarian ${mode} motion prototype`));
 }
}
fs.writeFileSync(path.join(OUT,'keyframes.json'),JSON.stringify(keyframes)+'\n');

const prototype=`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>planarian motion prototypes</title>
<style>*{box-sizing:border-box}body{--bg:#151719;--fg:#fff;--panel:#202326;--muted:#a7afb2;--line:#3b4145;background:var(--bg);color:var(--fg);margin:0;font:16px/1.5 Arial,Helvetica,sans-serif}body.light{--bg:#f6f5f0;--fg:#111;--panel:#fff;--muted:#697175;--line:#d6d9d5}main{max-width:1040px;margin:auto;padding:48px 26px}header{display:flex;align-items:baseline;justify-content:space-between;gap:20px;flex-wrap:wrap}h1{font-size:48px;font-weight:400;letter-spacing:-.045em;margin:0}header p{color:var(--muted);margin:0}.controls{display:flex;gap:14px;align-items:center;flex-wrap:wrap;margin:30px 0}button{border:1px solid var(--line);border-radius:9px;color:var(--fg);background:var(--panel);font:inherit;padding:10px 18px;min-height:44px;cursor:pointer}button:focus-visible,input:focus-visible{outline:2px solid var(--fg);outline-offset:4px}label{display:flex;align-items:center;gap:10px}.controls output{width:3em;color:var(--muted)}input{accent-color:var(--fg);max-width:140px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:20px}.card{border:1px solid var(--line);border-radius:20px;background:var(--panel);padding:28px;text-align:center}.card svg{width:min(100%,310px);height:auto;display:block;margin:0 auto 18px}h2{font-size:25px;font-weight:400;margin:0}p{color:var(--muted)}.card p{font-size:15px;margin:8px 0}.note{margin:22px 0;color:var(--muted);font-size:14px}#status{min-height:22px;font-size:14px;color:var(--muted)}@media(max-width:620px){main{padding:28px 18px}.grid{grid-template-columns:1fr}.card svg{width:240px}h1{font-size:40px}}</style>
<main><header><h1>planarian</h1><p>organic motion studies</p></header><div class="controls"><button id="play" type="button">pause</button><button id="theme" type="button">light background</button><label for="speed">speed <input id="speed" type="range" min="0.5" max="1.5" step="0.1" value="1"><output id="speed-value">1.0×</output></label><button id="reset" type="button">reset</button></div><div class="grid"><section class="card"><svg viewBox="0 0 1024 1024" role="img" aria-label="planarian loading, slow breathing"><path data-motion="loading" d="${STATIC_PATH}" fill="currentColor" fill-rule="evenodd"/></svg><h2>loading</h2><p>deeper breathing · gentle tail flex</p><p>3.6 seconds per cycle</p></section><section class="card"><svg viewBox="0 0 1024 1024" role="img" aria-label="planarian working, a traveling contraction"><path data-motion="working" d="${STATIC_PATH}" fill="currentColor" fill-rule="evenodd"/></svg><h2>working</h2><p>counterclockwise wave · head almost still</p><p>2.4 seconds per cycle</p></section></div><p id="status" role="status" aria-live="polite"></p><p class="note">The head orientation and two eye cutouts stay consistent. These are indeterminate activity prototypes; completion and error states should have their own text or status indicator.</p></main>
<script>${COMMON}
const reduced=matchMedia('(prefers-reduced-motion: reduce)');
let paused=reduced.matches,elapsed=0,speed=1,last=0,raf=0;
const marks=[...document.querySelectorAll('[data-motion]')];
const play=document.querySelector('#play'),status=document.querySelector('#status');
function render(){for(const p of marks)p.setAttribute('d',motionPath(p.dataset.motion,elapsed/DURATIONS[p.dataset.motion]));}
function state(){play.textContent=paused?'play':'pause';play.setAttribute('aria-pressed',String(!paused));status.textContent=paused?(reduced.matches?'paused · reduced-motion preference respected; play to opt in':'paused'):'playing';}
function tick(now){const dt=last?Math.min((now-last)/1000,.1):0;last=now;elapsed+=dt*speed;render();if(!paused)raf=requestAnimationFrame(tick);}
function start(){if(raf)cancelAnimationFrame(raf);last=0;state();if(!paused)raf=requestAnimationFrame(tick);}
play.onclick=()=>{paused=!paused;start();};
document.querySelector('#theme').onclick=()=>{const light=document.body.classList.toggle('light');document.querySelector('#theme').textContent=light?'dark background':'light background';};
document.querySelector('#speed').oninput=e=>{speed=Number(e.target.value);document.querySelector('#speed-value').textContent=speed.toFixed(1)+'×';};
document.querySelector('#reset').onclick=()=>{elapsed=0;last=0;render();};
reduced.addEventListener('change',()=>{if(reduced.matches){paused=true;for(const p of marks)p.setAttribute('d',STATIC_PATH);start();}});
state();if(!paused)start();
</script></html>`;
fs.writeFileSync(path.join(OUT,'prototype.html'),prototype);

function individualFrame(mode,time,tone){
 const dark=tone==='dark',bg=dark?'#151719':'#ffffff',ink=dark?'#ffffff':'#000000';
 return svg(`<rect width="1024" height="1024" fill="${bg}"/>`+glyph(motionPath(mode,time/DURATIONS[mode]),ink));
}
function comparisonFrame(time){
 let out='<rect width="960" height="620" fill="#151719"/>';
 out+=text(480,78,'planarian',46,'#fff','text-anchor="middle"');
 for(const [mode,x] of [['loading',48],['working',504]]){
  out+=`<rect x="${x}" y="126" width="408" height="368" rx="24" fill="#202326"/>`;
  out+=glyph(motionPath(mode,time/DURATIONS[mode]),'#ffffff',`translate(${x+40} 146) scale(.32)`);
  out+=text(x+204,546,mode,32,'#ffffff','text-anchor="middle"');
  out+=text(x+204,579,mode==='loading'?'deeper breathing':'counterclockwise wave',20,'#b6bdc0','text-anchor="middle"');
 }
 return svg(out,960,620,'planarian loading and working motion comparison');
}

// Replace the old generated concept board with an exact, lowercase vector board.
let board='<rect width="1600" height="1120" fill="#f7f6f2"/>';
board+=text(48,86,'planarian',52,'#151719')+text(50,122,'identity kit 1.2',17,'#788084');
board+='<path d="M32 158H1568 M32 610H1568 M544 158V1080 M1056 158V1080" stroke="#dedfd9"/>';
for(const [x,y,label] of [[52,198,'01 / primary mark'],[566,198,'02 / lowercase wordmark'],[1078,198,'03 / app icons'],[52,650,'04 / documentation'],[566,650,'05 / motion studies'],[1078,650,'06 / boot artwork']])board+=text(x,y,label,17,'#7a8285');
board+=glyph(STATIC_PATH,'#000000','translate(55 230) scale(.32)');
board+='<rect x="374" y="350" width="128" height="128" rx="24" fill="#151719"/>';
board+=glyph(STATIC_PATH,'#ffffff','translate(377 353) scale(.119)');
board+=embed('wordmarks/planarian-horizontal-light.svg',570,238,450,160);
board+=embed('wordmarks/planarian-stacked-light.svg',720,390,160,190);
board+=embed('icons/planarian-app-dark.svg',1086,300,190,190);
board+='<rect x="1310" y="300" width="190" height="190" rx="38" fill="#fff" stroke="#dedfd9"/>';
board+=embed('icons/planarian-app-light.svg',1310,300,190,190);
board+=embed('previews/software-applications.svg',52,702,465,320);
board+=glyph(motionPath('loading',.25),'#000000','translate(574 705) scale(.20)');
board+=glyph(motionPath('working',.36),'#000000','translate(814 705) scale(.20)');
board+=text(677,964,'loading',23,'#151719','text-anchor="middle"')+text(917,964,'working',23,'#151719','text-anchor="middle"');
board+=text(792,1024,'animated SVGs · GIF previews · interactive prototype',16,'#788084','text-anchor="middle"');
board+=embed('previews/boot-dark.svg',1082,716,438,286);
fs.writeFileSync(path.join(ROOT,'previews/identity-board.svg'),svg(board,1600,1120,'planarian lowercase identity overview'));

async function main(){
 const temp=fs.mkdtempSync(path.join(ROOT,'..','.planarian-motion-'));
 const specs=[];
 for(const mode of ['loading','working'])for(const tone of ['light','dark'])specs.push({name:`${mode}-${tone}`,frames:Math.round(DURATIONS[mode]*20),width:512,height:512,frame:i=>individualFrame(mode,i/20,tone)});
 specs.push({name:'comparison',frames:144,width:960,height:620,frame:i=>comparisonFrame(i/20)});
 const jobs=[];
 for(const spec of specs){
  const dir=path.join(temp,spec.name);fs.mkdirSync(dir);
  for(let i=0;i<spec.frames;i++)jobs.push(async()=>sharp(Buffer.from(spec.frame(i))).resize(spec.width,spec.height).png().toFile(path.join(dir,String(i).padStart(4,'0')+'.png')));
 }
 let cursor=0;
 await Promise.all(Array.from({length:6},async()=>{while(cursor<jobs.length)await jobs[cursor++]();}));
 await sharp(Buffer.from(comparisonFrame(0))).png().toFile(path.join(OUT,'poster.png'));
 await sharp(path.join(ROOT,'previews/identity-board.svg')).png().toFile(path.join(ROOT,'previews/identity-board.png'));
 await sharp(path.join(ROOT,'wordmarks/planarian-horizontal-light.svg')).flatten({background:'#ffffff'}).png().toFile(path.join(ROOT,'previews/wordmark-on-white.png'));
 const result=cp.spawnSync('python3',['-c',`
from pathlib import Path
from PIL import Image
import sys
root=Path(sys.argv[1]); dest=Path(sys.argv[2])
for folder in sorted(root.iterdir()):
    frames=[]
    for p in sorted(folder.glob('*.png')):
        with Image.open(p) as im:
            frames.append(im.convert('RGB').quantize(colors=128))
    target=dest/('planarian-motion-preview.gif' if folder.name=='comparison' else folder.name+'.gif')
    frames[0].save(target,save_all=True,append_images=frames[1:],duration=50,loop=0,disposal=2,optimize=True)
    print(target.name, len(frames), target.stat().st_size)
`,temp,OUT],{encoding:'utf8'});
 if(result.status!==0)throw new Error(result.stderr);
 process.stdout.write(result.stdout);
 fs.rmSync(temp,{recursive:true,force:true});
 for(const mode of ['loading','working']){
   if(motionPath(mode,0)!==motionPath(mode,1))throw new Error('Loop seam mismatch');
 }
 console.log(JSON.stringify({animated_svg_files:4,cycles:DURATIONS,vector_keyframes_per_state:49,prototype:'animations/prototype.html',lowercase_board:'previews/identity-board.png'},null,2));
}
main().catch(e=>{console.error(e);process.exit(1);});
