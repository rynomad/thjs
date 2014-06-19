var linkLoop = require("./linkLoop.js")

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

function pathSet (path, del)
{
  var existing;

  if(!path)
    return;

  if((existing = Path.match(path,self.paths)))
  {
    if(del)
      self.paths.splice(self.paths.indexOf(existing) , 1);
    return;
  }

  debug("local path add" , JSON.stringify(path));
  info("self" , path.type , JSON.stringify(path));

  self.paths.push(path);
  // trigger pings if we're online
  if( self.isOnline)
    linkLoop.maintainer(self);
}

module.exports = {
  match : pathMatch
  , set   : pathSet
}
