var etc = require("./etc.js")
  , pathValid = etc.pathValid
  , dhash = require("./dhash.js")
  , debugs = require("./debug.js")
  , debug = debugs.debug

// seek the dht for this hashname
function seek(hn, callback)
{
  var self = this;
  if(typeof hn == "string")
    hn = self.whois(hn);
  if(!callback)
    callback = function(){};
  if(!hn)
    return callback("invalid hashname");

  var did = {};
  var doing = {};
  var queue = [];
  var wise = {};
  var closest = 255;

  // load all seeds and sort to get the top 3
  var seeds = []
  Object.keys(self.buckets).forEach(function(bucket){
    self.buckets[bucket].forEach(function(link){
      if(link.hashname == hn)
        return; // ignore the one we're (re)seeking
      if(link.seed && pathValid(link.to))
        seeds.push(link);
    });
  });
  seeds.sort(function(a,b){
    return dhash(hn.hashname,a.hashname) - dhash(hn.hashname,b.hashname)
  }).slice(0,3)
  .forEach(function(seed){
    wise[seed.hashname] = true;
    queue.push(seed.hashname);
  });

  debug("seek starting with",queue,seeds.length);

  // always process potentials in order
  function sort()
  {
    queue = queue.sort(function(a,b){
      return dhash(hn.hashname,a) - dhash(hn.hashname,b)
    });
  }

  // track when we finish
  function done(err)
  {
    // get all the hashnames we used/found and do final sort to return
    Object.keys(did)
    .forEach(function(k){
      if(queue.indexOf(k) == -1)
        queue.push(k);
    });

    Object.keys(doing)
    .forEach(function(k){
      if(queue.indexOf(k) == -1)
        queue.push(k);
    });

    sort();
    while(cb = hn.seeking.shift())
      cb(err, queue.slice());
  }

  // track callback(s);
  if(!hn.seeking)
    hn.seeking = [];
  hn.seeking.push(callback);
  if(hn.seeking.length > 1)
    return;

  // main loop, multiples of these running at the same time
  function loop(onetime){
    if(!hn.seeking.length)
      return; // already returned
    debug("SEEK LOOP",queue);
    // if nothing left to do and nobody's doing anything, failed :(
    if(Object.keys(doing).length == 0 && queue.length == 0)
      return done("failed to find the hashname");

    // get the next one to ask
    var mine = onetime||queue.shift();
    if(!mine)
      return; // another loop() is still running

    // if we found it, yay! :)
    if(mine == hn.hashname)
      return done();
    // skip dups
    if(did[mine] || doing[mine])
      return onetime||loop();
    var distance = dhash(hn.hashname, mine);
    if(distance > closest)
      return onetime||loop(); // don't "back up" further away
    if(wise[mine])
      closest = distance; // update distance if trusted
    doing[mine] = true;
    var to = self.whois(mine);
    to.seek(hn.hashname, function(err, sees){
      sees.forEach(function(address){
        var see = to.sees(address);
        if(!see)
          return;
        // if this is the first entry and from a wise one, give them wisdom too
        if(wise[to.hashname] && sees.indexOf(address) == 0)
          wise[see.hashname] = true;
        queue.push(see.hashname);
      });
      sort();
      did[mine] = true;
      delete doing[mine];
      onetime||loop();
    });
  }

  // start three of them
  loop();loop();loop();

  // also force query any locals
  self.locals.forEach(function(local){loop(local.hashname)});
}

module.exports = seek
