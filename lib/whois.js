var dhash   = require("./dhash.js")
  , Channel = require("./Channel.js")
  , Path    = require("./Path.js")
  , Debug   = require("./debug.js")
  , inRelay = require("./inRelay.js")
  , PacketFn= require("./Packet.js")
  , inLink  = require("./ins.js").link
  , info    = Debug.info
  , warn    = Debug.warn
  , debug   = Debug.debug
  , defaults = require("./defaultConfig.js")
  , pathShareOrder = defaults.pathShareOrder
  , etc = require("./etc.js")
  , isLocalIP   = etc.isLocalIP
  , isLocalPath = etc.isLocalPath
  , partsMatch  = etc.partsMatch
  , pathValid   = etc.pathValid
  , openize     = etc.openize
  , isHEX       = etc.isHEX

// this creates a hashname identity object (or returns existing), optional from creates a via relationship
function whois(hashname)
{
  var self, hn;

  self = this;

  // validations
  if(!hashname)
  {
    warn("whois called without a hashname", hashname, new Error().stack);
    return false;
  }

  if(typeof hashname != "string")
  {
    warn("wrong type, should be string", typeof hashname,hashname);
    return false;
  }

  if(!isHEX(hashname, 64))
  {
    warn("whois called without a valid hashname", hashname);
    return false;
  }

  // never return ourselves
  if(hashname === self.hashname)
  {
    debug("whois called for self");
    return false;
  }

  hn = self.all[hashname];
  if(hn)
    return hn;

  // make a new one.
  // TODO: create a hashname class in seperate file so this becomes:
  // Hashname = require("./Hashname.js")
  // hn = new Hashname(self, hashname)
  hn = self.all[hashname] = {
    hashname   : hashname
    , chans    : {}
    , self     : self
    , paths    : []
    , isAlive  : 0
    , sendwait : []
    , at       : Date.now()
    , bucket   : dhash(self.hashname, hashname)
    , chanOut  : (function(){
      var res = (([self.hashname , hashname].sort()) == self.hashname) ? 2 : 1;
      return res;
    })()
    , start    : Channel.reliable
    , raw      : Channel.raw
    , pathGet  : function(path)
    {
      if(typeof path != "object" || typeof path.type != "string")
        return false;

      var match = Path.match(path, hn.paths);
      if(match)
        return match;

      // clone and also preserve original (hackey)
      path = JSON.parse(JSON.stringify(path));
      if(!path.json)
        path.json = JSON.parse(JSON.stringify(path));

      debug("adding new path",hn.paths.length,JSON.stringify(path.json));
      info(hn.hashname,path.type , JSON.stringify(path.json));

      hn.paths.push(path);

      // track overall if they have a public IP network
      if(!isLocalPath(path))
        hn.isPublic = true;

      // if possibly behind the same NAT (same public ip), set flag to allow/ask to share local paths
      if(path.type == "ipv4")
        self.paths.forEach(function(path2){
          if(path2.type == "ipv4" && path2.ip == path.ip) hn.isLocal = true;
        })

      return path;
    }
    , pathOut  : function(path) {
      path = hn.pathGet(path);
      if(!path)
        return false;

      // send a NAT hole punching empty packet the first time
      if(!path.sentAt && path.type == "ipv4")
        self.send(path,PacketFn.encode());

      path.sentAt = Date.now();
      if(!pathValid(hn.to) && pathValid(path))
        hn.to = path;

      return path;
    }
    , pathEnd : function(path) {
      if(path.seed)
        return false; // never remove a seed-path
      if(hn.to == path)
        hn.to = false;
      path.gone = true;
      var index = hn.paths.indexOf(path);
      if(index >= 0)
        hn.paths.splice(index,1);

      debug("PATH END",JSON.stringify(path.json));
      return false;
    }
    , pathIn : function(path)
    {
      path = hn.pathGet(path);
      if(!path)
        return false;

      // first time we've seen em
      if(!path.recvAt && !path.sentAt)
      {
        debug("PATH IN: NEW",isLocalPath(path)?"local":"public",JSON.stringify(path.json),hn.paths.map(function(p){return JSON.stringify(p.json)}));

        // update public ipv4 info
        if(path.type == "ipv4" && !isLocalIP(path.ip))
        {
          hn.ip = path.ip;
          hn.port = path.port;
        }

        // cull any invalid paths of the same type : invald || depricated || http
        hn.paths.forEach(function(other){
          if((other == path) || (other.type != path.type))
            return;
          if((!pathValid(other)) || (path.ip && other.ip == path.ip) || (path.type == "http"))
            return hn.pathEnd(other);
        });

        // any custom non-public paths, we must bridge for
        if(pathShareOrder.indexOf(path.type) == -1)
          hn.bridging = true;

        // track overall if we trust them as local
        if(isLocalPath(path) && !hn.isLocal)
        {
          hn.isLocal = true;
          hn.pathSync();
        }
      }

      // always update default to newest
      path.recvAt = Date.now();
      hn.to = path;

      return path;
    }
    , active : function()
    {
      self.recvAt = Date.now();

      // if we've not been active, (re)sync paths
      if(!hn.recvAt || (Date.now() - hn.recvAt) > defaults.nat_timeout)
        setTimeout(function(){
          hn.pathSync()
        }, 10 );

      hn.recvAt = Date.now();

      // resend any waiting packets (if they're still valid)
      hn.sendwait.forEach(function(packet){
        if(!hn.chans[packet.js.c])
          return;
        hn.send(packet);
      });
      hn.sendwait = [];
    }
    , send : function(packet)
    {
      if (Buffer.isBuffer(packet))
        console.log("lined packet?!", hn.hashname, typeof hn.sendwait.length, new Error().stack);

      // if there's a line, try sending it via a valid network path!
      if(hn.lineIn)
      {
        debug("line sending",hn.hashname,hn.lineIn);
        var lined = self.CSets[hn.csid].lineize(hn, packet);
        hn.sentAt = Date.now();

        // directed packets, just dump and done
        if(packet.to)
          return self.send(packet.to, lined, hn);

        // if there's a valid path to them, just use it
        if(pathValid(hn.to))
          return self.send(hn.to, lined, hn);

        // if relay, always send it there
        if(hn.relayChan)
          return hn.relayChan.send({body:lined});

        // everything else falls through
      }

      // we've fallen through, either no line, or no valid paths
      hn.openAt = false;

      // add to queue to send on line
      if(hn.sendwait.indexOf(packet) == -1) hn.sendwait.push(packet);

      // TODO should we rate-limit the flow into this section?
      debug("alive failthrough",hn.sendSeek,Object.keys(hn.vias||{}));

      // always send to open all known paths to increase restart-resiliency
      if(hn.open()) hn.paths.forEach(function(path){
        debug("hn.open() ", hn.open())
        self.send(path, hn.open(), hn);
      });

      // todo change all .see processing to add via info, and change inConnect
      function vias()
      {
        if(!hn.vias)
          return;
        var todo = hn.vias;
        delete hn.vias; // never use more than once so we re-seek
        // send a peer request to all of them
        Object.keys(todo).forEach(function(via){
          self.whois(via).peer(hn.hashname,todo[via]);
        });
      }

      // if there's via information, just try that
      if(hn.vias)
        return vias();

      // never too fast, worst case is to try to seek again
      if(!hn.sendSeek || (Date.now() - hn.sendSeek) > 5000)
      {
        hn.sendSeek = Date.now();
        self.seek(hn, function(err){
          if(!hn.sendwait.length)
            return; // already connected
          vias(); // process any new vias
        });
      }
    }
    , receive : function(packet)
    {
      //    if((Math.floor(Math.random()*10) == 4)) return warn("testing dropping randomly!");
      if(!packet.js || typeof packet.js.c != "number")
        return warn("dropping invalid channel packet", packet.js);

      // normalize/track sender network path
      packet.sender = hn.pathIn(packet.sender);
      packet.from = hn;

      // find any existing channel
      var chan = hn.chans[packet.js.c];
      debug("LINEIN",chan&&chan.type,JSON.stringify(packet.js),packet.body&&packet.body.length);

      if(chan === false)
        return; // drop packet for a closed channel

      if(chan)
        return chan.receive(packet);

      // start a channel if one doesn't exist, check either reliable or unreliable types
      var listening = {};

      if(typeof packet.js.seq == "undefined")
        listening = self.raws;

      if(packet.js.seq === 0)
        listening = self.rels;

      // ignore/drop unknowns
      if(!listening[packet.js.type])
        return;

      // verify incoming new chan id
      if(packet.js.c % 2 == hn.chanOut % 2)
        return warn("channel id incorrect",packet.js.c,hn.chanOut)

      // make the correct kind of channel;
      var kind = (listening == self.raws) ? "raw" : "start";
      var chan = hn[kind](packet.js.type, {bare:true,id:packet.js.c}, listening[packet.js.type]);

      chan.receive(packet);
    }
    , chanEnded : function(id)
    {
      if(!hn.chans[id])
        return;
      debug("channel ended",id,hn.chans[id].type,hn.hashname);
      hn.chans[id] = false;
    }
    , sees : function(address)
    {
      if(typeof address != "string")
        warn("invalid see address",address,hn.hashname);
      if(typeof address != "string")
        return false;
      var parts = address.split(",");
      if(!self.isHashname(parts[0]) || parts[0] == self.hashname)
        return false;
      var see = self.whois(parts[0]);
      if(!see)
        return false;
      // save suggested path if given/valid
      if(parts.length >= 4 && parts[2].split(".").length == 4 && parseInt(parts[3]) > 0)
        see.pathGet({type:"ipv4",ip:parts[2],port:parseInt(parts[3])});
      if(!see.vias)
        see.vias = {};
      // save suggested csid if we don't know one yet
      see.vias[hn.hashname] = see.cisd || parts[1];
      return see;
    }
    , seek : function(hashname, callback)
    {
      var bucket = dhash(hn.hashname, hashname);
      var prefix = hashname.substr(0, Math.ceil((255-bucket)/4)+2);
      hn.raw("seek", {timeout:defaults.seek_timeout, retry:3, js:{"seek":prefix}}, function(err, packet, chan){
        callback(packet.js.err,Array.isArray(packet.js.see)?packet.js.see:[]);
      });
    }
    , address : function(to)
    {
      if(!to)
        return "";
      var csid = partsMatch(hn.parts,to.parts);
      if(!csid)
        return "";
      if(!hn.ip)
        return [hn.hashname,csid].join(",");

      return [hn.hashname,csid,hn.ip,hn.port].join(",");
    }
    , link : function(callback)
    {
      if(!callback)
        callback = function(){}

      debug("LINKTRY",hn.hashname);
      var js = {seed:self.seed};

      js.see = self.buckets[hn.bucket].sort(function(a,b){
        return a.age - b.age;
      }).filter(function(a){
        return a.seed;
      }).map(function(seed){
        return seed.address(hn)
      }).slice(0,8);

      // add some distant ones if none
      if(js.see.length < 8)
        Object.keys(self.buckets).forEach(function(bucket){
          if(js.see.length >= 8)
            return;
          self.buckets[bucket].sort(function(a,b){
            return a.age - b.age;
          }).forEach(function(seed){
            if(js.see.length >= 8 || !seed.seed || js.see.indexOf(seed.address(hn)) != -1)
              return;
            js.see.push(seed.address(hn));
          });
        });

      if(self.isBridge(hn))
        js.bridges = self.paths.filter(function(path){
          return !isLocalPath(path);
        }).map(function(path){
          return path.type;
        });

      //debug("hn.linke", hn, hn.linked)

      if(hn.linked)
      {
        hn.linked.send({js:js});
        return callback();
      }

      hn.linked = hn.raw("link", {retry:3, js:js, timeout:defaults.idle_timeout}, function(err, packet, chan){
        inLink(err, packet, chan);
        callback(packet.js.err);
      });
    }
    , peer : function(hashname, csid)
    {
      if(!csid || !self.parts[csid])
        return;
      var js = {"peer":hashname};
      js.paths = hn.pathsOut();
      hn.raw("peer",{timeout:defaults.nat_timeout, js:js, body:getkey(self,csid)}, function(err, packet, chan){
        if(!chan.relayTo)
          chan.relayTo = self.whois(hashname);
        inRelay(chan, packet);
      });
    }
    , open : function()
    {
      if(!hn.parts)
        return false; // can't open if no key
      if(!hn.opened)
        hn.opened = openize(self,hn);
      return hn.opened;
    }
    , pathsOut : function()
    {
      var paths = [];
      self.paths.forEach(function(path){
        if(isLocalPath(path) && !hn.isLocal)
          return;
        paths.push(path);
      });
      return paths;
    }
    , pathSync : function()
    {
      if(hn.pathSyncing)
        return;
      hn.pathSyncing = true;
      debug("pathSync",hn.hashname);
      var js = {};
      var paths = hn.pathsOut();
      if(paths.length > 0)
        js.paths = paths;
      var alive = [];
      hn.raw("path",{js:js, timeout:10*1000}, function(err, packet){
        if(err)
        {
          hn.pathSyncing = false;
          return;
        }

        // if path answer is from a seed, update our public ip/port in case we're behind a NAT
        if(packet.from.isSeed && typeof packet.js.path == "object" && packet.js.path.type == "ipv4" && !isLocalIP(packet.js.path.ip))
        {
          debug("updating public ipv4",JSON.stringify(self.pub4),JSON.stringify(packet.js.path));
          self.pathSet(self.pub4,true);
          self.pub4 = {type:"ipv4", ip:packet.js.path.ip, port:parseInt(packet.js.path.port)};
          self.pathSet(self.pub4);
        }

        if(!packet.sender)
          return; // no sender path is bad

        // add to all answers and update best default from active ones
        alive.push(packet.sender);
        var best = packet.sender;
        alive.forEach(function(path){
          if(pathShareOrder.indexOf(best.type) < pathShareOrder.indexOf(path.type))
            return;
          if(isLocalPath(best))
            return; // always prefer (the first) local paths
          best = path;
        });
        debug("pathSync best",hn.hashname,JSON.stringify(best.json));
        hn.to = best;
      });
    }
    , ticket : function(packet)
    {
      if(self.pencode(packet).length > 1024)
        return false;
      return ticketize(self, hn, packet);
    }
    , ticketed : function(ticket)
    {
      packet = pdecode(ticket);
      if(!packet)
        return false;
      return deticketize(self, hn, packet);
    }

  };

  if(!self.buckets[hn.bucket])
    self.buckets[hn.bucket] = [];

  return hn;
}

module.exports = whois;
