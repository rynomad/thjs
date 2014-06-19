var debug  = require("./debug.js").debug
  , warn   = require("./debug.js").warn
  , Packet = require("./Packet.js")
  , linkLoop = require("./linkLoop.js")
  , Path   = require("./Path.js")
  , Seed   = require("./Seed.js")
  , whois  = require("./whois.js")
  , info   = function(){}
  , Switch = function Switch()
{
  var self = {
      seeds   : []
    , locals  : []
    , lines   : {}
    , bridges : {}
    , bridgeLine : {}
    , all        : {}
    , buckets  : []
    , capacity : []
    , rels  : {}
    , raws  : {}
    , paths : []
    , bridgeCache : {}
    , networks    : {}
    , CSets    : {}
    , seed     : true         //TODO: load defaults/customs from config.js/export a 'loadConfig' function
    , pcounter : 1
    , load  : function(id)
      { var err;
        if (typeof id != "object")
          return "bad keys";
        self.id = id;

        err = loadkeys(self);

        if (err)
          return err;
        if (Object.keys(self.cs).length == 0)
          return "missing cipher sets";

        self.hashname = parts2hn(self.parts);
        return false;
      }

    , make  : function (cbDone,cbStep)
      { var self, ret, todo;

        self = this;
        ret = {};
        todo = Object.keys(self.CSets);

        if (todo.length == 0)
          return cbDone("no sets supported");

        function pop(err)
        { var csid;
          if(err)
            return cbDone(err);

          csid = todo.pop();
          if (!csid) {
            self.load(ret);
            return cbDone(null, ret);
          }
          self.CSets[csid].genkey(ret,pop,cbStep);
        }
        pop();
      }

    , receive : function receive(msg, path)
      { var open, csid, from, age, openAck, chan, lineID, err
          , self = this
          , packet = packet.decode(msg);

        if (!packet)
          return warn("failed to decode a packet from", path, (new Buffer(msg)).toString("hex"));

        if(packet.length == 2)
          return; // empty packets are NAT pings

        packet.sender = path;
        packet.id = self.pcounter++;
        packet.at = Date.now();

        debug(">>>>",Date(),msg.length, packet.head.length, path&&[path.type,path.ip,path.port,path.id].join(","));

        // handle any discovery requests
        if(packet.js.type == "ping")
          return inPing(self, packet);
        if(packet.js.type == "pong")
          return inPong(self, packet);

        // either it's an open
        if (packet.head.length == 1)  // open
          return packetFn.open(self, packet, path)
        else if (packet.head.length == 0)
          return packetFn.line(self, packet, path)
        else
          warn("dropping incoming packet of unknown type", packet.js, packet.sender);
      }

    , deliver : function (type, callback)
      {
        self.networks[type] = callback;
      }

    , send : function (path, msg, to)
      {
        if(!msg)
          return debug("send called w/ no packet, dropping",new Error().stack) && false;
        if(!path)
          return debug("send called w/ no path, dropping", new Error().stack) && false;
        if(!self.networks[path.type])
          return false;
        if(to)
          path = to.pathOut(path);

        debug("<<<<",Date(),msg.length,path&&[path.type,path.ip,path.port,path.id].join(","),to&&to.hashname);

        return self.networks[path.type](path,msg,to);
      }

    , pathSet   : Path.set
    , pathMatch : Path.match
    , addSeed   : Seed.add
    , whois     : whois
  };

  // map a hashname to an object, whois(hashname)
  self.whois = whois;
  self.whokey = whokey;
  self.start = function(hashname,type,arg,cb)
  {
    var hn = self.whois(hashname);
    if(!hn) return cb("invalid hashname");
    return hn.start(type,arg,cb);
  }

  // connect to the network, online(callback(err))
  self.online = online;

  // handle new reliable channels coming in from anyone
  self.listen = function(type, callback){
    if(typeof type != "string" || typeof callback != "function") return warn("invalid arguments to listen");
    if(type.substr(0,1) !== "_") type = "_"+type;
    self.rels[type] = callback;
  };
  // advanced usage only
  self.raw = function(type, callback){
    if(typeof type != "string" || typeof callback != "function") return warn("invalid arguments to raw");
    self.raws[type] = callback;
  };

  // internal listening unreliable channels
  self.raws["peer"] = inPeer;
  self.raws["connect"] = inConnect;
  self.raws["seek"] = inSeek;
  self.raws["path"] = inPath;
  self.raws["link"] = inLink;

  // primarily internal, to seek/connect to a hashname
  self.seek = seek;

  // for modules
  self.pencode = pencode;
  self.pdecode = packet.decode;
  self.isLocalIP = isLocalIP;
  self.randomHEX = randomHEX;
  self.uriparse = uriparse;
  self.pathMatch = pathMatch;
  self.isHashname = function(hex){return isHEX(hex, 64)};
  self.isBridge = isBridge;
  self.wraps = channelWraps;
  self.waits = [];
  self.waiting = false
  self.wait = function(bool){
    if(bool) return self.waits.push(true);
    self.waits.pop();
    if(self.waiting && self.waits.length == 0) self.waiting();
  }
  self.ping = function(){
    if(!self.tracer) self.tracer = randomHEX(16);
    var js = {type:"ping",trace:self.tracer};
    Object.keys(self.parts).forEach(function(csid){js[csid] = true;});
    return js;
  }

  linkLoop.loop(self);
  return self;
}

module.exports = Switch
