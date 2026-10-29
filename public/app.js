document.querySelectorAll('form.confirm').forEach(f=>f.addEventListener('submit',e=>{const b=f.querySelector('button');if(b.dataset.armed)return;e.preventDefault();b.dataset.armed=1;b.dataset.t=b.textContent;b.textContent='Sure?';b.classList.add('arm');setTimeout(()=>{delete b.dataset.armed;b.textContent=b.dataset.t;b.classList.remove('arm')},3000)}));
document.querySelectorAll('.toast').forEach(t=>t.addEventListener('click',()=>t.remove()));
document.querySelectorAll('.print-btn').forEach(b=>b.addEventListener('click',()=>window.print()));
(function(){const box=document.getElementById('util');if(!box)return;const out=document.getElementById('util-out');
let seed=[];try{seed=JSON.parse(box.dataset.seed||'[]')}catch(e){}if(!seed.length)seed=[{n:'Card 1',b:0,l:0}];
const cls=p=>p<10?'good':p<30?'mid':'high';
function row(c){const d=document.createElement('div');d.className='urow';d.innerHTML='<input class="n" placeholder="Card name"><input class="b" type="number" min="0" step="0.01" placeholder="Balance"><input class="l" type="number" min="0" step="0.01" placeholder="Limit"><span class="p"></span><button type="button" class="ghost sm">✕</button>';
d.querySelector('.n').value=c.n||'';d.querySelector('.b').value=c.b||'';d.querySelector('.l').value=c.l||'';d.querySelector('button').onclick=()=>{d.remove();calc()};d.oninput=calc;box.appendChild(d)}
function calc(){let B=0,L=0;box.querySelectorAll('.urow').forEach(r=>{const b=+r.querySelector('.b').value||0,l=+r.querySelector('.l').value||0;B+=b;L+=l;const p=l?b/l*100:0;const s=r.querySelector('.p');s.textContent=l?p.toFixed(1)+'%':'—';s.className='p '+(l?cls(p):'')});
const p=L?B/L*100:0;const pay30=Math.max(0,B-L*.3),pay10=Math.max(0,B-L*.1);
out.innerHTML=L?'<div class="big-num '+cls(p)+'">'+p.toFixed(1)+'%</div><div class="bar"><i style="width:'+Math.min(100,p)+'%"></i></div><p>Total $'+B.toFixed(2)+' of $'+L.toFixed(2)+'. '+(pay30>0?'Pay down <b>$'+pay30.toFixed(2)+'</b> to reach 30%; ':'Under 30% ✓ ')+(pay10>0?'<b>$'+pay10.toFixed(2)+'</b> to reach 10%.':'Under 10% ✓')+'</p>':'<p class="muted">Enter balances and limits.</p>'}
seed.forEach(row);document.getElementById('addcard').onclick=()=>{row({});calc()};calc()})();
