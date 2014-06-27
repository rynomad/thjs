var debug = require("./debug.js").debug
var defaults = require("./defaultConfig.js")

function pathValid(path)
{
  if(!path || path.gone) return false;
  if(!path.recvAt) return false; // all else must receive to be valid
  if(Date.now() - path.recvAt < defaults.nat_timeout) return true; // received anything recently is good
  return false;
}


module.exports = function inRelay(chan, packet)
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
      if(done)
        return;
      if(id == to.hashname || id == packet.from.hashname)
        return; // lolz
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
    if(to.relayChan == chan)
      to.relayChan = false;
    return;
  }

  // clear any older default paths
  if(to.to && to.to.recvAt < chan.startAt)
    to.to = false;

  // most recent is always the current default back
  to.relayChan = chan;

  // if the sender has created a bridge, clone their path as the packet's origin!
  var path = (packet.js.bridge) ? JSON.parse(JSON.stringify(packet.sender.json)) : false;
  if(packet.body && packet.body.length)
    self.receive(packet.body, path);

  // always try a path sync to upgrade the relay
  to.pathSync();
}

