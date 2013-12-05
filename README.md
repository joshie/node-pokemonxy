node-pokemonxy
==============

Various functions useful in making pokemonxy software

Quick Lazy Description:

Currenly this is good for loading pokemon pkx data and unencrypting/encrypting. You can use the library with the node-written proxy of your choice.

Somewhere in your code, after including this module, you want to do someting such as:
var pokemon = require('pokemonxy');

Then you're going to want to create a pkx object and load a buffer of pkx data (from a file, through a proxy, etc)
var dratiniPkx = readFileSync('dratini_encrypted.pkx');
var josh_pkmn  = Object.create(pokemon.PKX);
josh_pkmn      = Object.load(dratiniPkx);

The load function knows if the data is encryped or not, and regardless, makes both available.

you can reference the encryped and unencrypred buffers like so:
josh_pkmn.pkxEncryped
josh_pkmn.pkxUnencryped

If you modify the buffers, you can reencrypt like so:
josh_pkmn.encrypt();

You can write the buffers to network streams (probably unsuccessfully...), as well as files, or whatver your imagination desires :)

TODO: Make functions to modify all the details!
