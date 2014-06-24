
// return random bytes, in hex
function randomHEX(len)
{
  return crypto.randomBytes(len).toString("hex");
}

// validate if a network path is acceptable to stop at
function pathValid(path)
{
  if(!path || path.gone)
    return false;
  if(!path.recvAt)
    return false; // all else must receive to be valid
  if(Date.now() - path.recvAt < defaults.nat_timeout)
    return true; // received anything recently is good
  return false;
}

function partsMatch(parts1, parts2)
{
  if(typeof parts1 != "object" || typeof parts2 != "object")
    return false;
  var ids = Object.keys(parts1).sort();
  var csid;
  while(csid = ids.pop())
    if(parts2[csid])
      return csid;
  return false;
}

function openize(self, to)
{
  if(!to.csid)
  {
    console.log("can't open w/ no key");
    return undefined;
  }
  if(!to.lineOut)
    to.lineOut = randomHEX(16);
  if(!to.lineAt)
    to.lineAt = Date.now();
  var inner = {}
  inner.at = to.lineAt; // always the same for the generated line id/key
  inner.to = to.hashname;
  inner.from = self.parts;
  inner.line = to.lineOut;
  return self.CSets[to.csid].openize(self, to, inner);
}

function deopenize(self, open)
{
//  console.log("DEOPEN",open.body.length);
  var ret;
  var csid = open.head.charCodeAt().toString(16);
  if(!self.CSets[csid]) return {err:"unknown CSID of "+csid};
  try{ret = self.CSets[csid].deopenize(self, open);}catch(E){return {err:E};}
  ret.csid = csid;
  return ret;
}


function isLocalPath(path)
{
  if(!path || !path.type)
    return false;
  if(path.type == "bluetooth")
    return true;
  if(path.type == "http" && typeof path.http == "string")
    return isLocalIP(require("url").parse(path.http).hostname);
  if(["ipv4","ipv6"].indexOf(path.type) >= 0)
    return isLocalIP(path.ip);
  // http?
  return false;
}


function parts2hn(parts)
{
  var rollup = new Buffer(0);
  Object.keys(parts).sort().forEach(function(id){
    rollup = crypto.createHash("sha256").update(Buffer.concat([rollup,new Buffer(id)])).digest();
    rollup = crypto.createHash("sha256").update(Buffer.concat([rollup,new Buffer(parts[id])])).digest();
  });
  return rollup.toString("hex");
}


function loadkeys(self)
{
  self.cs = {};
  self.keys = {};
  self.parts = {};
  var err = false;
  Object.keys(self.id).forEach(function(csid){
    if(csid.length != 2) return; // only csid keys
    self.cs[csid] = {};
    if(!self.CSets[csid]) err = csid+" not supported";
    err = err||self.CSets[csid].loadkey(self.cs[csid], self.id[csid], self.id[csid+"_secret"]);
    self.keys[csid] = self.id[csid];
    self.parts[csid] = crypto.createHash("sha256").update(self.cs[csid].key).digest("hex");
  });
  return err;
}

function loadkey(self, id, csid, key)
{
  id.csid = csid;
  return self.CSets[csid].loadkey(id, key);
}

function keysgen(cbDone,cbStep)
{
  var self = this;
  var ret = {};
  var todo = Object.keys(self.CSets);
  if(todo.length == 0) return cbDone("no sets supported");
  function pop(err)
  {
    if(err) return cbDone(err);
    var csid = todo.pop();
    if(!csid){
      self.load(ret);
      return cbDone(null, ret);
    }
    self.CSets[csid].genkey(ret,pop,cbStep);
  }
  pop();
}

// someone's looking for a local seed
function inPing(self, packet)
{
  if(packet.js.trace == self.tracer) return; // ignore ourselves
  if(self.locals.length > 1) return; // more than one locally is announcing already
  if(self.lanSkip && self.lanSkip == packet.js.trace) return; // often immediate duplicates, skip them
  debug("PING-PONG",packet.js,packet.sender);
  self.lanSkip = packet.js.trace;
  // announce ourself as the seed back
  var csid = partsMatch(self.parts,packet.js);
  if(!csid) return;
  var js = {type:"pong",from:self.parts,trace:packet.js.trace};
  self.send(packet.sender, pencode(js, getkey(self,csid)));
}

// answers from any LAN broadcast notice we sent
function inPong(self, packet)
{
  debug("PONG",JSON.stringify(packet.js),JSON.stringify(packet.sender));
  if(packet.js.trace != self.tracer) return;
  if(self.locals.length >= 5) return warn("locals full");
  if(!packet.body || packet.body.length == 0) return;
  var to = self.whokey(packet.js.from,packet.body);
  if(!to) return warn("invalid lan request from",packet.js.from,packet.sender);
  to.local = true;
  debug("local seed open",to.hashname,JSON.stringify(packet.sender));
  self.send(packet.sender,to.open(),to);
  to.link();
}


// convert hex string to nibble array
function hex2nib(hex)
{
  var ret = [];
  for (var i = 0; i < hex.length / 2; i ++) {
      var bite = parseInt(hex.substr(i * 2, 2), 16);
      if (isNaN(bite)) return [];
      ret[ret.length] = bite >> 4;
      ret[ret.length] = bite & 0xf;
  }
  return ret;
}

function pathMatch(path1, paths)
{
  var match;
  if(!path1 || !Array.isArray(paths)) return match;
  paths.forEach(function(path2){
    if(!path2 || path2.type != path1.type) return;
    switch(path1.type)
    {
    case "ipv4":
    case "ipv6":
      if(path1.ip == path2.ip && path1.port == path2.port) match = path2;
      break;
    case "http":
      if(path1.http == path2.http) match = path2;
      break;
    default:
      // all other paths match based on id, local, webrtc, etc
      if(path1.id === path2.id) match = path2;
    }
  });
  return match;
}

module.exports = {
  isLocalPath  : isLocalPath
  , isLocalIP  : isLocalIP
  , partsMatch : partsMatch
  , openize    : openize
  , deopenize  : deopenize
  , pathValid  : pathValid
  , pathMatch  : pathMatch
  , randomHEX  : randomHEX
  , parts2hn   : parts2hn
  , loadkey    : loadkey
  , loadkeys   : loadkeys
  , keysgen    : keysgen
  , inPing     : inPing
  , inPong     : inPong
  , hex2nib    : hex2nib
}
