var warn = require("./debug.js").warn

function addSeed(arg)
{
  var self, seed
  self = this;
  if(!arg.parts)
    return warn("invalid args to addSeed",arg);

  seed = self.whokey(arg.parts , false , arg.keys);
  if(!seed)
    return warn("invalid seed info",arg);

  if(Array.isArray(arg.paths))
    arg.paths.forEach(function(path){
      path = seed.pathGet(path);
      path.seed = true;
    });

  seed.isSeed = true;
  self.seeds.push(seed);
  console.log("SEED", seed)
}

module.exports = {
  add: addSeed
}
