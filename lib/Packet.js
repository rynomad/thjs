var debug = require("./debug.js").debug
  , warn  = require("./debug.js").warn
  , isHEX = require("./etc.js").isHEX
  , defaults = require("./defaultConfig.js")
  , Packet;

function deopenize(self, open)
{ var ret, csid;

  //  console.log("DEOPEN",open.body.length);

  csid = open.head.charCodeAt().toString(16);
  if (!self.CSets[csid])
    return {err : "unknown CSID of " + csid};

  try{
    ret = self.CSets[csid].deopenize(self, open);
  } catch(E){
    return {err:E};
  }


  ret.csid = csid;
  return ret;
}

function partsMatch(parts1, parts2)
{ var ids, csid;

  if ( (typeof parts1 != "object") || (typeof parts2 != "object") )
    return false;

  ids = Object.keys(parts1).sort();
  csid;
  while(csid = ids.pop())
    if(parts2[csid])
      return csid;

  return false;
}

module.exports = Packet = {

    encode : function pencode(js, body)
    { var head, len;

      // be flexible, take {js:{},body:...} as first arg
      if(!body && js && js.js)
      {
        body = js.body;
        js = js.js;
      }
      head = (typeof js == "number") ? new Buffer(String.fromCharCode(js))
             : new Buffer(js ? JSON.stringify(js)
                            : ""
                          , "utf8");

      if (typeof body == "string")
        body = new Buffer(body, "binary");
      else
        body = new Buffer(0);

      len = new Buffer(2);
      len.writeInt16BE(head.length, 0);
      return Buffer.concat([len, head, body]);
    }

  , decode : function pdecode(packet)
    { var buf, len, head, body, js;

     if ((!packet) || (packet.length < 2))
       return undefined;

     buf = (typeof packet == "string")
     ? new Buffer(packet, "binary")
     : packet;

     // read and validate the json length
     len = buf.readUInt16BE(0);
     if (len > (buf.length - 2))
       return undefined;

     head = buf.slice(2, len+2);
     body = buf.slice(len + 2);

     // parse out the json
     js = {};

     if(len > 1)
     {
       try {
         js = JSON.parse(head.toString("utf8"));
       } catch(E) {
         console.log( "couldn't parse JS" , buf.toString("hex") , E);
         return undefined;
       }
     }
     return {
       js     : js
       , length : buf.length
       , head   : head.toString("binary")
       , body   : body
     };
    }

  , open: function (self, packet, path)
  { var open, csid, from, age, openAck;

    open = deopenize(self, packet);

    if (!open || !open.verify)
      return warn("couldn't decode open (possibly using the wrong public key?)" , open && open.err);
    if (!isHEX(open.js.line, 32))
      return warn("invalid line id enclosed" , open.js.line);
    if (open.js.to !== self.hashname)
      return warn("open for wrong hashname" , open.js.to);

    csid = partsMatch(self.parts,open.js.from);

    if(csid != open.csid)
      return warn( "open with mismatch CSID" , csid , open.csid );

    from = self.whokey(open.js.from,open.key);
    if (!from)
      return warn("invalid hashname", open.js.from);

    from.csid = open.csid;

    // make sure this open is legit
    if (typeof open.js.at != "number")
      return warn("invalid at", open.js.at);

    // older open, ignore it
    if (from.openAt && open.js.at < from.openAt)
      return debug("dropping older open");

    from.openAt = open.js.at;

    debug("inOpen verified", from.hashname , path && JSON.stringify(path.json));

    // ignore incoming opens if too fast or recent duplicates
    if(open.js.line == from.lineIn)
    {
      age = Date.now() - ( from.openAcked || 0 );
      if ((age < defaults.seek_timeout) || (age < defaults.nat_timeout && from.openDup >= 3))
        return;
      from.openDup++;
    }else{
      from.openDup = 0;
    }

    // always minimally flag activity and send an open ack back via network or relay
    openAck = from.open(); // inits line crypto
    from.active();
    from.openAcked = Date.now();
    path = from.pathIn(path);
    if (path)
      self.send(path , openAck , from);
    else if(from.relayChan)
      from.relayChan.send({body : openAck});

    // only do new line setup once
    if(open.js.line != from.lineIn)
    {
      from.lineIn = open.js.line;
      debug("new line",from.lineIn,from.lineOut);
      self.CSets[open.csid].openline(from, open);
      self.lines[from.lineOut] = from;

      // force reset old channels
      Object.keys(from.chans).forEach(function(id){
        var chan = from.chans[id];
        if(chan)
        {
          // SPECIAL CASE: skip channels that haven't received a packet, they're new waiting outgoing-opening ones!
          if(!chan.recvAt)
            return;
          // fail all other active channels
          from.receive( {js:{c:chan.id,err:"reset"}});
        }
        // actually remove so new ones w/ same id can come in
        delete from.chans[id];
      });
    }

    return;
  }

  , line: function (self, packet, path)
  { var lineID, from, id, err;

    lineID = packet.body.slice(0,16).toString("hex");
    from = self.lines[lineID];

    // a matching line is required to decode the packet
    if (!from) {
      if (!self.bridgeLine[lineID])
        return debug("unknown line received", lineID, packet.sender);

      debug("BRIDGE",JSON.stringify(self.bridgeLine[lineID]),lineID);

      id = crypto.createHash("sha256").update(packet.body).digest("hex")

      // drop duplicates
      if (self.bridgeCache[id])
        return;

      self.bridgeCache[id] = true;

      // flat out raw retransmit any bridge packets
      return self.send( self.bridgeLine[lineID] , Packet.encode(false,packet.body) );
    }

    // decrypt and process
    if (err = self.CSets[from.csid].delineize(from, packet))
      return debug("couldn't decrypt line" , err , packet.sender);

    from.linedAt = from.openAt;
    from.active();
    from.receive(packet);
    return;
  }
};
