var defaults = require("./defaultConfig.js")
  , pathShareOrder = defaults.pathShareOrder
  , etc            = require("./etc.js")
  , pathValid      = etc.pathValid
  , pathMatch      = etc.pathMatch
  , debug          = require("./debug.js").debug
  , warn           = require("./debug.js").warn
  , Packet         = require("./Packet.js")
  , pdecode        = Packet.decode
  , pencode        = Packet.pencode

function inMaintenance(err, packet, chan)
{
  // ignore if this isn't the main link
  if(!packet.from || !packet.from.linked || packet.from.linked != chan)
    return;
  var self = packet.from.self;
  if(err)
  {
    debug("LINKDOWN",packet.from.hashname,err);
    delete packet.from.linked;
    var index = self.buckets[packet.from.bucket].indexOf(packet.from);
    if(index > -1)
      self.buckets[packet.from.bucket].splice(index,1);
    // if this channel was ever active, try to re-start it
    if(chan.recvAt)
      packet.from.link();
    return;
  }

  // update seed status
  packet.from.seed = packet.js.seed;

  // only send a response if we've not sent one in a while
  if((Date.now() - chan.sentAt) > Math.ceil(defaults.link_timer/2))
    chan.send({js:{seed:self.seed}});
}

function relay(self, from, to, packet)
{
  if(from.ended && !to.ended)
    return to.send({js:{err:"disconnected"}});
  if(to.ended && !from.ended)
    return from.send({js:{err:"disconnected"}});

  // check to see if we should set the bridge flag for line packets
  var js = {};
  if(self.isBridge(from.hashname) || self.isBridge(to.hashname))
  {
    var bp = pdecode(packet.body);
    var id = bp && bp.body && bp.body.length > 16 && bp.body.slice(0,16).toString("hex");
    // only create bridge once from valid line packet
    if(id && bp.head.length == 0 && !to.bridged && to.last && !self.lines[id])
    {
      to.bridged = true;
      debug("auto-bridging",to.hashname,id,JSON.stringify(to.last.json))
      self.bridgeLine[id] = JSON.parse(JSON.stringify(to.last.json));
    }
  }

  // have to seen both directions to bridge
  if(from.bridged && to.bridged)
    js = {"bridge":true};

  // throttle
  if(!from.relayed || Date.now() - from.relayed > 1000)
  {
    from.relayed = Date.now();
    from.relays = 0;
  }
  from.relays++;
  if(from.relays > 5)
  {
    debug("relay too fast, warning",from.relays);
    js.warn = "toofast";
    // TODO start dropping these again in production
//    from.send({js:js});
//    return;
  }

  from.relayed = Date.now();
  to.send({js:js, body:packet.body});
}

function inRelay(chan, packet)
{
  var to = chan.relayTo;
  var self = packet.from.self;

  // if the active relay is failing, try to create one via a bridge
  if((packet.js.err || packet.js.warn) && !chan.migrating && to.relayChan == chan && !to.to)
  {
    debug("relay failing, trying to migrate",to.hashname);
    chan.migrating = true;
    // try to find all bridges w/ a matching path type
    var bridges = [];
    to.paths.forEach(function(path){
      if(!self.bridges[path.type])
        return;
      Object.keys(self.bridges[path.type]).forEach(function(id){
        if(bridges.indexOf(id) == -1)
          bridges.push(id);
      });
    });
    // TODO, some way to sort them, retry?
    var done;
    bridges.forEach(function(id){
      if(done) return;
      if(id == to.hashname || id == packet.from.hashname) return; // lolz
      var hn = self.whois(id);
      if(!pathValid(hn.to))
        return;
      // send peer request through the bridge
      done = hn.peer(to.hashname,to.csid);
    });
  }

  if(packet.js.err || packet.js.end)
  {
    debug("ending relay from",chan.hashname,"to",to.hashname,packet.js.err||packet.js.end);
    if(to.relayChan == chan) to.relayChan = false;
    return;
  }

  // clear any older default paths
  if(to.to && to.to.recvAt < chan.startAt) to.to = false;

  // most recent is always the current default back
  to.relayChan = chan;

  // if the sender has created a bridge, clone their path as the packet's origin!
  var path = (packet.js.bridge) ? JSON.parse(JSON.stringify(packet.sender.json)) : false;
  if(packet.body && packet.body.length) self.receive(packet.body, path);

  // always try a path sync to upgrade the relay
  to.pathSync();
}

// someone's trying to connect to us, send an open to them
function inConnect(err, packet, chan)
{
  // if this channel is acting as a relay
  if(chan.relayTo)
    return inRelay(chan, packet);

  var to = chan.relayTo = packet.from.self.whokey(packet.js.from,packet.body);
  if(!chan.relayTo)
    return warn("invalid connect request from",packet.from.hashname,packet.js);

  // up the timeout to the nat default
  chan.timeout(defaults.nat_timeout);

  // try the suggested paths
  if(Array.isArray(packet.js.paths)) {
    packet.js.paths.forEach(function(path){
      if(typeof path.type != "string")
        return debug("bad path",JSON.stringify(path));
      packet.from.self.send(path,to.open(),to);
    });
  }
  // send back an open through the connect too
  chan.send({body:to.open()});

  // we know they see them too
  packet.from.sees(to.hashname);
}

// be the middleman to help NAT hole punch
function inPeer(err, packet, chan)
{
  if(err)
    return;
  var self = packet.from.self;
  if(chan.relay)
    return relay(self, chan, chan.relay, packet);

  if(!isHEX(packet.js.peer, 64))
    return;
  var peer = self.whois(packet.js.peer);
  if(!peer)
    return;

  // only accept peer if active network or support bridging for either party
  if(!(pathValid(peer.to) || self.isBridge(packet.from.hashname) || self.isBridge(peer.hashname)))
    return debug("disconnected peer request");

  // sanity on incoming paths array
  if(!Array.isArray(packet.js.paths))
    packet.js.paths = [];

  // insert our known usable/safe sender paths
  packet.from.paths.forEach(function(path){
    if(!path.recvAt) return;
    if(pathShareOrder.indexOf(path.type) == -1)
      return;
    if(isLocalPath(path) && !peer.isLocal)
      return;
    packet.js.paths.push(path.json);
  });

  // load/cleanse all paths
  var js = {from:packet.from.parts,paths:[]};
  packet.js.paths.forEach(function(path){
    if(typeof path.type != "string")
      return;
    if(pathMatch(path,js.paths))
      return; // duplicate
    js.paths.push(path);
  });

  // start relay via connect, must bundle the senders key so the recipient can open them
  chan.timeout(defaults.nat_timeout);
  chan.relay = peer.raw("connect",{js:js, body:packet.body},function(err, packet, chan2){
    if(err)
      return;
    relay(self, chan2, chan, packet);
  });
}

// return a see to anyone closer
function inSeek(err, packet, chan)
{
  if(err) return;
  if(!isHEX(packet.js.seek)) return warn("invalid seek of ", packet.js.seek, "from:", packet.from.hashname);
  var self = packet.from.self;
  var seek = packet.js.seek;

  var see = [];
  var seen = {};

  // see if we have any seeds to add
  var bucket = dhash(self.hashname, packet.js.seek);
  var links = self.buckets[bucket] ? self.buckets[bucket] : [];

  // first, sort by age and add the most wise one
  links.sort(function(a,b){ return a.age - b.age}).forEach(function(seed){
    if(see.length) return;
    if(!seed.seed) return;
    see.push(seed.address(packet.from));
    seen[seed.hashname] = true;
  });

  // sort by distance for more
  links
  .sort(function(a,b){
    return dhash(seek,a.hashname) - dhash(seek,b.hashname)
  })
  .forEach(function(link){
    if(seen[link.hashname])
      return;
    if(link.seed || link.hashname.substr(0,seek.length) == seek)
    {
      see.push(link.address(packet.from));
      seen[link.hashname] = true;
    }
  });

  var answer = {end:true, see:see.filter(function(x){return x}).slice(0,8)};
  chan.send({js:answer});
}

// accept a dht link
function inLink(err, packet, chan)
{
  if(err)
    return;
  var self = packet.from.self;
  chan.timeout(defaults.nat_timeout*2); // two NAT windows to be safe

  // add in this link
  debug("LINKUP",packet.from.hashname);
  if(!packet.from.age)
    packet.from.age = Date.now();
  packet.from.linked = chan;
  packet.from.seed = packet.js.seed;
  if(self.buckets[packet.from.bucket].indexOf(packet.from) == -1)
    self.buckets[packet.from.bucket].push(packet.from);

  // if it was a local seed, add them to list to always-query
  if(packet.from.seed && packet.from.isLocal && self.locals.indexOf(packet.from) == -1)
    self.locals.push(packet.from);

  // send a response if this is a new incoming
  if(!chan.sentAt)
    packet.from.link();

  // look for any see and check to see if we should create a link
  if(Array.isArray(packet.js.see))
    packet.js.see.forEach(function(address){
    var hn = packet.from.sees(address);
    if(!hn || hn.linked)
      return;
    if(self.buckets[hn.bucket].length < defaults.link_k)
      hn.link();
  });

  // check for bridges
  if(Array.isArray(packet.js.bridges)) {
    packet.js.bridges
    .forEach(function(type){
      if(!self.bridges[type])
        self.bridges[type] = {};
      self.bridges[type][packet.from.hashname] = Date.now();
    });
  }

  // let mainteanance handle
  chan.callback = inMaintenance;
}


// update/respond to network state
function inPath(err, packet, chan)
{
  if(err)
    return;
  var self = packet.from.self;

  // add any/all suggested paths
  if(Array.isArray(packet.js.paths))
    packet.js.paths.forEach(function(path){
      packet.from.pathGet(path)
    });

  // send back on all paths
  packet.from.paths.forEach(function(path){
    var js = {};
    if(pathShareOrder.indexOf(path.type) >= 0)
      js.path = path.json;
    chan.send({js:js, to:path});
  });
}



module.exports = {
  peer      : inPeer
  , connect : inConnect
  , seek    : inSeek
  , path    : inPath
  , link    : inLink
}
