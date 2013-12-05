var pokemon = require('./index.js');
var fs      = require('fs');

var skittypkx = fs.readFileSync('skitty_unencrypted.pkx');
var skitty = Object.create(pokemon.PKX);
skitty.load(skittypkx);
process.stdout.write(skitty.pkxEncrypted);

