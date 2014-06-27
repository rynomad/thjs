var hex2nib = require("./etc.js").hex2nib

// XOR distance between two hex strings, high is furthest bit, 0 is closest bit, -1 is error
function dhash(h1, h2) {
  // convert to nibbles, easier to understand
  var n1 = hex2nib(h1);
  var n2 = hex2nib(h2);
  if(!n1.length || !n2.length) return -1;
  // compare nibbles
  var sbtab = [-1,0,1,1,2,2,2,2,3,3,3,3,3,3,3,3];
  var ret = 252;
  for (var i = 0; i < n1.length; i++) {
    if(!n2[i]) return ret;
    var diff = n1[i] ^ n2[i];
    if (diff) return ret + sbtab[diff];
    ret -= 4;
  }
  return ret;
}

module.exports = dhash
