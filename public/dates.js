// Shared date logic: offset-free provider timestamps (NVD) are UTC.
(function(root){
function timestamp(value){
 if(typeof value!=='string'||!value.trim())return NaN;
 let s=value.trim();
 if(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/.test(s)&&!/(Z|[+-]\d{2}:?\d{2})$/i.test(s))s+='Z';
 return Date.parse(s);
}
function boundary(day){
 if(!/^\d{4}-\d{2}-\d{2}$/.test(day))return NaN;
 const ms=Date.parse(day+'T00:00:00+07:00');
 return Number.isFinite(ms)&&new Date(ms+7*3600000).toISOString().slice(0,10)===day?ms:NaN;
}
function select(items,{field,order='newest',from='',to='',score=false}){
 const lo=from?boundary(from):-Infinity,hi=to?boundary(to)+86400000:Infinity;
 if(Number.isNaN(lo)||Number.isNaN(hi)||lo>=hi)return [];
 return items.map((item,index)=>({item,index,time:timestamp(item[field])}))
 .filter(x=>(!from&&!to)||(Number.isFinite(x.time)&&x.time>=lo&&x.time<hi))
 .sort((a,b)=>{
  if(score)return ((b.item.score??-1)-(a.item.score??-1))||a.index-b.index;
  const av=Number.isFinite(a.time),bv=Number.isFinite(b.time);
  if(av!==bv)return av?-1:1;
  return (av?((order==='oldest'?1:-1)*(a.time-b.time)):0)||a.index-b.index;
 }).map(x=>x.item);
}
root.CyberDates={timestamp,boundary,select};
})(globalThis);
