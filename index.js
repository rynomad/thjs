


var debug    = require("./lib/debug.js").debug
  , warn     = require("./lib/debug.js").warn
  , defaults = require("./lib/defaultConfig.js")
  , Switch = require("./lib/Switch.js")
  , info     = function(){}
  , pathShareOrder = ["bluetooth","webrtc","ipv6","ipv4","http"]
  , exports  = {
      info     : function(cb){ info = cb; }
    , debug    : debug
    , defaults : defaults
    , switch   : thSwitch
  }
