var debug    = require("./debug.js").debug
  , defaults = require("./defaultConfig.js")


// delete any defunct hashnames!
function hnReap(self)
{
  var hn;
  function del(why)
  {
    if(hn.lineOut) delete self.lines[hn.lineOut];
    delete self.all[hn.hashname];
    debug("reaping ", hn.hashname, why);
  }
  Object.keys(self.all).forEach(function(h){
    hn = self.all[h];
    debug("reap check",hn.hashname,Date.now()-hn.sentAt,Date.now()-hn.recvAt,Object.keys(hn.chans).length);
    if(hn.isSeed) return;
    if(Object.keys(hn.chans).length > 0) return; // let channels clean themselves up
    if(Date.now() - hn.at < hn.timeout()) return; // always leave n00bs around for a while
    if(!hn.sentAt) return del("never sent anything, gc");
    if(!hn.recvAt) return del("sent open, never received");
    if(Date.now() - hn.sentAt > hn.timeout()) return del("we stopped sending to them");
    if(Date.now() - hn.recvAt > hn.timeout()) return del("they stopped responding to us");
  });
}

// every link that needs to be maintained, ping them
function linkMaint(self)
{
  // process every bucket
  Object.keys(self.buckets).forEach(function(bucket){
    // sort by age and send maintenance to only k links
    var sorted = self.buckets[bucket].sort(function(a,b){ return a.age - b.age });

    if(sorted.length)
      debug("link maintenance on bucket",bucket,sorted.length);

    sorted.slice(0,defaults.link_k).forEach(function(hn){
      if(!hn.linked || !pathValid(hn.to))
        return;
      if((Date.now() - hn.linked.sentAt) < Math.ceil(defaults.link_timer/2))
        return; // we sent to them recently

      hn.linked.send({js:{seed:self.seed}});
    });
  });
}


// do the maintenance work for links
function linkLoop(self)
{
  self.bridgeCache = {}; // reset cache for any bridging
//  hnReap(self); // remove any dead ones, temporarily disabled due to node crypto compiled cleanup bug
  linkMaint(self); // ping all of them
  setTimeout(function(){linkLoop(self)}, defaults.link_timer);
}

module.exports = {
    loop       : linkLoop
  , maintainer : linkMaint
}
