// create a reliable channel with a friendlier interface
function channel(type, arg, callback)
{
  var hn = this;
  var chan = {inq:[], outq:[], outSeq:0, inDone:-1, outConfirmed:-1, lastAck:-1, callback:callback};
  chan.id = arg.id;
  chan.startAt = Date.now();
  if(!chan.id)
  {
    chan.id = hn.chanOut;
    hn.chanOut += 2;
  }
  chan.isOut = (chan.id % 2 == hn.chanOut % 2);
  hn.chans[chan.id] = chan;
  // app originating if not bare, be friendly w/ the type, don't double-underscore if they did already
  if(!arg.bare && type.substr(0,1) !== "_") type = "_"+type;
  chan.type = type; // save for debug
  if(chan.type.substr(0,1) != "_") chan.safe = true; // means don't _ escape the json
  chan.hashname = hn.hashname; // for convenience

  debug("new channel",hn.hashname,chan.type,chan.id);

  // configure default timeout, for resend
  chan.timeout = function(timeout)
  {
    arg.timeout = timeout;
  }
  chan.timeout(arg.timeout || defaults.chan_timeout);

  // used by app to change how it interfaces with the channel
  chan.wrap = function(wrap)
  {
    if(!channelWraps[wrap]) return false;
    return channelWraps[wrap](chan);
  }

  // called to do eventual cleanup
  function cleanup()
  {
    if(chan.timer) clearTimeout(chan.timer);
    chan.timer = setTimeout(function(){
      chan.ended = chan.ended || true;
      hn.chanEnded(chan.id);
    }, arg.timeout);
  }

  // process packets at a raw level, handle all miss/ack tracking and ordering
  chan.receive = function(packet)
  {
    // if it's an incoming error, bail hard/fast
    if(packet.js.err)
    {
      chan.inq = [];
      chan.ended = packet.js.err;
      chan.callback(packet.js.err, packet, chan, function(){});
      cleanup();
      return;
    }

    chan.recvAt = Date.now();
    chan.opened = true;
    chan.last = packet.sender;

    // process any valid newer incoming ack/miss
    var ack = parseInt(packet.js.ack);
    if(ack > chan.outSeq) return warn("bad ack, dropping entirely",chan.outSeq,ack);
    var miss = Array.isArray(packet.js.miss) ? packet.js.miss : [];
    if(miss.length > 100) {
      warn("too many misses", miss.length, chan.id, packet.from.hashname);
      miss = miss.slice(0,100);
    }
    if(miss.length > 0 || ack > chan.lastAck)
    {
      debug("miss processing",ack,chan.lastAck,miss,chan.outq.length);
      chan.lastAck = ack;
      // rebuild outq, only keeping newer packets, resending any misses
      var outq = chan.outq;
      chan.outq = [];
      outq.forEach(function(pold){
        // packet acknowleged!
        if(pold.js.seq <= ack) {
          if(pold.callback) pold.callback();
          if(pold.js.end) cleanup();
          return;
        }
        chan.outq.push(pold);
        if(miss.indexOf(pold.js.seq) == -1) return;
        // resend misses but not too frequently
        if(Date.now() - pold.resentAt < 1000) return;
        pold.resentAt = Date.now();
        chan.ack(pold);
      });
    }

    // don't process packets w/o a seq, no batteries included
    var seq = packet.js.seq;
    if(!(seq >= 0)) return;

    // auto trigger an ack in case none were sent
    if(!chan.acker) chan.acker = setTimeout(function(){ delete chan.acker; chan.ack();}, defaults.chan_autoack);

    // drop duplicate packets, always force an ack
    if(seq <= chan.inDone || chan.inq[seq-(chan.inDone+1)]) return chan.forceAck = true;

    // drop if too far ahead, must ack
    if(seq-chan.inDone > defaults.chan_inbuf)
    {
      warn("chan too far behind, dropping", seq, chan.inDone, chan.id, packet.from.hashname);
      return chan.forceAck = true;
    }

    // stash this seq and process any in sequence, adjust for yacht-based array indicies
    chan.inq[seq-(chan.inDone+1)] = packet;
    debug("INQ",Object.keys(chan.inq),chan.inDone,chan.handling);
    chan.handler();
  }

  // wrapper to deliver packets in series
  chan.handler = function()
  {
    if(chan.handling) return;
    var packet = chan.inq[0];
    // always force an ack when there's misses yet
    if(!packet && chan.inq.length > 0) chan.forceAck = true;
    if(!packet) return;
    chan.handling = true;
    chan.ended = chan.ended || packet.js.end;
    if(!chan.safe) packet.js = packet.js._ || {}; // unescape all content json
    chan.callback(chan.ended, packet, chan, function(ack){
      // catch whenever it was ended to do cleanup
      chan.inq.shift();
      chan.inDone++;
      chan.handling = false;
      if(ack) chan.ack(); // auto-ack functionality
      // cleanup eventually
      if(chan.ended) cleanup();
      chan.handler();
    });
  }

  // resend the last sent packet if it wasn't acked
  chan.resend = function()
  {
    if(chan.ended) return;
    if(!chan.outq.length) return;
    var lastpacket = chan.outq[chan.outq.length-1];
    // timeout force-end the channel
    if(Date.now() - lastpacket.sentAt > arg.timeout)
    {
      hn.receive({js:{err:"timeout",c:chan.id}});
      return;
    }
    debug("channel resending");
    chan.ack(lastpacket);
    setTimeout(function(){chan.resend()}, defaults.chan_resend); // recurse until chan_timeout
  }

  // add/create ack/miss values and send
  chan.ack = function(packet)
  {
    if(!packet) debug("ACK CHECK",chan.id,chan.outConfirmed,chan.inDone);

    // these are just empty "ack" requests
    if(!packet)
    {
      // drop if no reason to ack so calling .ack() harmless when already ack'd
      if(!chan.forceAck && chan.outConfirmed == chan.inDone) return;
      packet = {js:{}};
    }
    chan.forceAck = false;

    // confirm only what's been processed
    if(chan.inDone >= 0) chan.outConfirmed = packet.js.ack = chan.inDone;

    // calculate misses, if any
    delete packet.js.miss; // when resending packets, make sure no old info slips through
    if(chan.inq.length > 0)
    {
      packet.js.miss = [];
      for(var i = 0; i < chan.inq.length; i++)
      {
        if(!chan.inq[i]) packet.js.miss.push(chan.inDone+i+1);
      }
    }

    // now validate and send the packet
    packet.js.c = chan.id;
    debug("SEND",chan.type,JSON.stringify(packet.js));
    cleanup();
    hn.send(packet);
  }

  // send content reliably
  chan.send = function(arg)
  {
    // create a new packet from the arg
    if(!arg) arg = {};
    // immediate fail errors
    if(arg.err)
    {
      if(chan.ended) return;
      chan.ended = arg.err;
      hn.send({js:{err:arg.err,c:chan.id}});
      return cleanup();
    }
    var packet = {};
    packet.js = chan.safe ? arg.js : {_:arg.js};
    if(arg.type) packet.js.type = arg.type;
    if(arg.end) packet.js.end = arg.end;
    packet.body = arg.body;
    packet.callback = arg.callback;

    // do durable stuff
    packet.js.seq = chan.outSeq++;

    // reset/update tracking stats
    packet.sentAt = Date.now();
    chan.outq.push(packet);

    // add optional ack/miss and send
    chan.ack(packet);

    // to auto-resend if it isn't acked
    if(chan.resender) clearTimeout(chan.resender);
    chan.resender = setTimeout(function(){chan.resend()}, defaults.chan_resend);
    return chan;
  }

  // convenience
  chan.end = function()
  {
    if(chan.ended) return chan.ack();
    chan.send({js:{end:true}});
  }

  // send error immediately, flexible arguments
  chan.fail = function(arg)
  {
    var err = "failed";
    if(typeof arg == "string") err = arg;
    if(typeof arg == "object" && arg.js && arg.js.err) err = arg.js.err;
    chan.send({err:err});
  }

  // send optional initial packet with type set
  if(arg.js)
  {
    arg.type = type;
    chan.send(arg);
  }

  return chan;
}

// create an unreliable channel
function raw(type, arg, callback)
{
  var hn = this;
  var chan = {type:type, callback:callback};
  chan.id = arg.id;
  chan.startAt = Date.now();
  if(!chan.id)
  {
    chan.id = hn.chanOut;
    hn.chanOut += 2;
  }
  chan.isOut = (chan.id % 2 == hn.chanOut % 2);
  hn.chans[chan.id] = chan;

  // raw channels always timeout/expire after the last received packet
  function timer()
  {
    if(chan.timer) clearTimeout(chan.timer);
    chan.timer = setTimeout(function(){
      // signal incoming error if still open, restarts timer
      if(!chan.ended) return hn.receive({js:{err:"timeout",c:chan.id}});
      // clean up references if ended
      hn.chanEnded(chan.id);
    }, arg.timeout);
  }
  chan.timeout = function(timeout)
  {
    arg.timeout = timeout;
    timer();
  }
  chan.timeout(arg.timeout || defaults.chan_timeout);

  chan.hashname = hn.hashname; // for convenience

  debug("new unreliable channel",hn.hashname,chan.type,chan.id);

  // process packets at a raw level, very little to do
  chan.receive = function(packet)
  {
    if(!hn.chans[chan.id]) return debug("dropping receive packet to dead channel",chan.id,packet.js)
    chan.opened = true;
    chan.ended = chan.ended || packet.js.err || packet.js.end;
    chan.recvAt = Date.now();
    chan.last = packet.sender;
    chan.callback(chan.ended, packet, chan);
    timer();
  }

  // minimal wrapper to send raw packets
  chan.send = function(packet)
  {
    if(!hn.chans[chan.id]) return debug("dropping send packet to dead channel",chan.id,packet.js);
    if(!packet.js) packet.js = {};
    packet.js.c = chan.id;
    chan.ended = chan.ended || packet.js.err || packet.js.end;
    chan.sentAt = Date.now();
    debug("SEND",chan.type,JSON.stringify(packet.js),packet.body&&packet.body.length);
    hn.send(packet);
  }

  // convenience
  chan.end = function()
  {
    if(chan.ended) return;
    chan.send({js:{end:true}});
  }

  chan.fail = function(err)
  {
    if(chan.ended) return;
    chan.ended = err || "failed";
    hn.send({js:{err:chan.ended,c:chan.id}});
  }


  // send optional initial packet with type set
  if(arg.js)
  {
    arg.js.type = type;
    chan.send(arg);
    // retry if asked to, TODO use timeout for better time
    if(arg.retry)
    {
      var at = 1000;
      function retry(){
        if(chan.ended || chan.opened) return; // means we're gone or received a packet
        chan.send(arg);
        if(at < 4000) at *= 2;
        arg.retry--;
        if(arg.retry) setTimeout(retry, at);
      };
      setTimeout(retry, at);
    }
  }

  return chan;
}

module.exports = {
  reliable : channel
  , raw    : raw
};
