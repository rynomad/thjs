module.exports = {
    debug : function(){console.log.apply(console,arguments)}
  , warn  : function(){console.log.apply(console,arguments); return undefined; }
};
