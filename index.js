var bignum        = require('bignum');
var blockSize     = 56;
var offset        = 8;
var pokemon       = new Object;
pokemon.names     = require('./names.js');
module.exports    = pokemon;

var shifts = [
  [0,56,112,168],
  [0,56,168,112],
  [0,112,56,168],
  [0,112,168,56],
  [0,168,56,112],
  [0,168,112,56],
  [56,0,112,168],
  [56,0,168,112],
  [56,112,0,168],
  [56,112,168,0],
  [56,168,0,112],
  [56,168,112,0],
  [112,0,56,168],
  [112,0,168,56],
  [112,56,0,168],
  [112,56,168,0],
  [112,168,0,56],
  [112,168,56,0],
  [168,0,56,112],
  [168,0,112,56],
  [168,56,0,112],
  [168,56,112,0],
  [168,112,0,56],
  [168,112,56,0]
];

var LCRNG = {
  generate: function() {
    this.seed = this.seed.mul(0x41C64E6D).add(0x6073).and(0xFFFFFFFF);
    return(this.seed.toNumber() >>> 16);
  }
}

pokemon.PKX = {
  load: function(data,e) {
    if (data.length < 232) return false;
    this.encrypted = typeof(e) === 'boolean' ? e : data.readUInt32LE(228) > 0;
    this.pkxEncrypted   = new Buffer(data.length);
    this.pkxUnencrypted = new Buffer(data.length);
    this.dataLength     = data.length;
    data.copy(this.pkxEncrypted);
    data.copy(this.pkxUnencrypted);
    this.key    = data.readUInt32LE(0);
    this.shift  = shifts[((this.key & 0x3E000) >> 0xD) % 24]; 
    if (this.encrypted) {
      this.unencrypt();
    } else {
      this.encrypt();
    }
    this.loaded = true;
  },
  encrypt: function() {
    var writeTo  = 0;
    var readFrom = 0;
    var blocks   = this.pkxEncrypted.slice(8);
    var body     = this.pkxUnencrypted.slice(8);
    var prng     = Object.create(LCRNG);
    prng.seed    = bignum(this.key);
    for (writeTo = 0; writeTo < body.length; writeTo += 2) {
      curBlock = Math.floor(writeTo / blockSize);
      readFrom = curBlock > 3 ? writeTo : writeTo + (this.shift[curBlock] - curBlock * blockSize);
      blocks.writeUInt16LE(body.readUInt16LE(readFrom) ^ prng.generate(), writeTo);
    }
  },
  unencrypt: function() {
    var writeTo  = 0;
    var readFrom = 0;
    var blocks   = this.pkxUnencrypted.slice(8);
    var body     = this.pkxEncrypted.slice(8);
    var prng     = Object.create(LCRNG);
    prng.seed    = bignum(this.key);
    for (readFrom = 0; readFrom < body.length; readFrom += 2) {
      curBlock = Math.floor(readFrom / blockSize);
      writeTo = curBlock > 3 ? readFrom : readFrom + (this.shift[curBlock] - curBlock * blockSize);
      blocks.writeUInt16LE(body.readUInt16LE(readFrom) ^ prng.generate(), writeTo);
    }
  },
  copyEncrypted:             function(buff) { return this.pkxEncrypted.copy(buff) },
  copyUnencrypted:           function(buff) { return this.pkxUnencrypted.copy(buff) },
  readPkxEncryptionKey:      function() { return this.pkxUnencrypted.readUInt32LE(0x00) },
  readSanityPlaceholder:     function() { return this.pkxUnencrypted.readUInt16LE(0x04) },
  readChecksum:              function() { return this.pkxUnencrypted.readUInt16LE(0x06) },
  readNationalPokedexID:     function() { return this.pkxUnencrypted.readUInt16LE(0x08) },
  readHeldItem:              function() { return this.pkxUnencrypted.readUInt16LE(0x0A) },
  readOTID:                  function() { return this.pkxUnencrypted.readUInt16LE(0x0C) },
  readOTSecretID:            function() { return this.pkxUnencrypted.readUInt16LE(0x0E) },
  readExperiencePoints:      function() { return this.pkxUnencrypted.readUInt32LE(0x10) },
  readAbility:               function() { return this.pkxUnencrypted.readUInt8(0x14) },
  readAbilityNumber:         function() { return this.pkxUnencrypted.readUInt8(0x15) },
  readPersonalityValue:      function() { return this.pkxUnencrypted.readUInt32LE(0x18) },
  readNature:                function() { return this.pkxUnencrypted.readUInt8(0x1C) },
  readFatefulEncounter:      function() { return this.pkxUnencrypted.readUInt8(0x1D) & 0x80 >>> 7 },
  readGender:                function() { return this.pkxUnencrypted.readUInt8(0x1D) & 0x40 >>> 6 },
  readGenderless:            function() { return this.pkxUnencrypted.readUInt8(0x1D) & 0x20 >>> 5 },
  readForm:                  function() { return this.pkxUnencrypted.readUInt8(0x1D) & 0x1F},
  readHPEffortValue:         function() { return this.pkxUnencrypted.readUInt8(0x1E) },
  readAttackEffortValue:     function() { return this.pkxUnencrypted.readUInt8(0x1F) },
  readDefenseEffortValue:    function() { return this.pkxUnencrypted.readUInt8(0x20) },
  readSpeedEffortValue:      function() { return this.pkxUnencrypted.readUInt8(0x21) },
  readSPAttackEffortValue:   function() { return this.pkxUnencrypted.readUInt8(0x22) },
  readSPDefenseEffortValue:  function() { return this.pkxUnencrypted.readUInt8(0x23) },
  readPokerus:               function() { return this.pkxUnencrypted.readUInt8(0x2B) },
  readKalosRibbons:          function() { return this.pkxUnencrypted.readUInt32LE(0x30) },
  readNickname:              function() { return this.pkxUnencrypted.toString('utf8',0x40,0x57) },
  readMove1ID:               function() { return this.pkxUnencrypted.readUInt16LE(0x5A) },
  readMove2ID:               function() { return this.pkxUnencrypted.readUInt16LE(0x5C) },
  readMove3ID:               function() { return this.pkxUnencrypted.readUInt16LE(0x5E) },
  readMove4ID:               function() { return this.pkxUnencrypted.readUInt16LE(0x60) },
  readMove1CurrentPP:        function() { return this.pkxUnencrypted.readUInt8(0x62) },
  readMove2CurrentPP:        function() { return this.pkxUnencrypted.readUInt8(0x63) },
  readMove3CurrentPP:        function() { return this.pkxUnencrypted.readUInt8(0x64) },
  readMove4CurrentPP:        function() { return this.pkxUnencrypted.readUInt8(0x65) },
  readMovePPUps:             function() { return this.pkxUnencrypted.readUInt32LE(0x66) },
  readMove1IDAtHatching:     function() { return this.pkxUnencrypted.readUInt16LE(0x6A) },
  readMove2IDAtHatching:     function() { return this.pkxUnencrypted.readUInt16LE(0x6C) },
  readMove3IDAtHatching:     function() { return this.pkxUnencrypted.readUInt16LE(0x6E) },
  readMove4IDAtHatching:     function() { return this.pkxUnencrypted.readUInt16LE(0x70) },
  readMove4IDAtHatching:     function() { return this.pkxUnencrypted.readUInt16LE(0x72) },
  readIVHP:                  function() { return this.pkxUnencrypted.readUInt8(0x74) >>> 3 },
  readIVAttack:              function() { return this.pkxUnencrypted.readUInt16LE(0x74) & 0x07C0 >>> 6 },
  readIVDefense:             function() { return this.pkxUnencrypted.readUInt8(0x75) & 0x3E >>> 1 },
  readIVSpeed:               function() { return this.pkxUnencrypted.readUInt16LE(0x75) & 0x01F0 >>> 4 },
  readIVSPAttack:            function() { return this.pkxUnencrypted.readUInt16LE(0x76) & 0x0F80 >>> 7 },
  readIVSPDefense:           function() { return this.pkxUnencrypted.readUInt8(0x77) & 0x7C >>> 2 },
  readIsEgg:                 function() { return this.pkxUnencrypted.readUInt8(0x77) & 0x02 >>> 1 },
  readIsNicknamed:           function() { return this.pkxUnencrypted.readUInt8(0x77) & 0x01},
  readOTNameTradedTo:        function() { return this.pkxUnencrypted.toString('utf8',0x78,0x8F) },
  readOTName:                function() { return this.pkxUnencrypted.toString('utf8',0xB0,0xC7) },
  readYearEggReceived:       function() { return this.pkxUnencrypted.readUInt8(0xD3) },
  readMonthEggReceived:      function() { return this.pkxUnencrypted.readUInt8(0xD2) },
  readDayEggReceived:        function() { return this.pkxUnencrypted.readUInt8(0xD1) },
  readYearMet:               function() { return this.pkxUnencrypted.readUInt8(0xD4) },
  readMonthMet:              function() { return this.pkxUnencrypted.readUInt8(0xD5) },
  readDayMet:                function() { return this.pkxUnencrypted.readUInt8(0xD6) },
  readEggLocation:           function() { return this.pkxUnencrypted.readUInt16LE(0xD8) },
  readMetAtLocation:         function() { return this.pkxUnencrypted.readUInt16LE(0xDA) },
  readPokeball:              function() { return this.pkxUnencrypted.readUInt8(0xDC) },
  readEncounterLevel:        function() { return this.pkxUnencrypted.readUInt8(0xDD) >>> 1 }, 
  readOTGender:              function() { return this.pkxUnencrypted.readUInt8(0xDD) & 0x01 },
  readOTGameVersion:         function() { return this.pkxUnencrypted.readUInt8(0xDF) },
  readCountryID:             function() { return this.pkxUnencrypted.readUInt8(0xE0) },
  readRegionID:              function() { return this.pkxUnencrypted.readUInt8(0xE1) },
  read3DSregionID:           function() { return this.pkxUnencrypted.readUInt8(0xE2) },
  readOTlanguage:            function() { return this.pkxUnencrypted.readUInt8(0xE3) },
  readLevel:                 function() { return this.pkxUnencrypted.readUInt8(0xEC) },
  readCurrentHP:             function() { return this.pkxUnencrypted.readUInt16LE(0xF0) },
  readMaxHP:                 function() { return this.pkxUnencrypted.readUInt16LE(0xF2) },
  readAttack:                function() { return this.pkxUnencrypted.readUInt16LE(0xF4) },
  readDefense:               function() { return this.pkxUnencrypted.readUInt16LE(0xF6) },
  readSpeed:                 function() { return this.pkxUnencrypted.readUInt16LE(0xF8) },
  readSpecialAttack:         function() { return this.pkxUnencrypted.readUInt16LE(0xFA) },
  readSpecialDefense:        function() { return this.pkxUnencrypted.readUInt16LE(0xFC) },
  writePkxEncryptionKey:     function(i) { return this.pkxUnencrypted.writeUInt32LE(i,0x00) },
  writeSanityPlaceholder:    function(i) { return this.pkxUnencrypted.writeUInt16LE(i,0x04) },
  writeChecksum:             function(i) { return this.pkxUnencrypted.writeUInt16LE(i,0x06) },
  writeNationalPokedexID:    function(i) { return this.pkxUnencrypted.writeUInt16LE(i,0x08) },
  writeHeldItem:             function(i) { return this.pkxUnencrypted.writeUInt16LE(i,0x0A) },
  writeOTID:                 function(i) { return this.pkxUnencrypted.writeUInt16LE(i,0x0C) },
  writeOTSecretID:           function(i) { return this.pkxUnencrypted.writeUInt16LE(i,0x0E) },
  writeExperiencePoints:     function(i) { return this.pkxUnencrypted.writeUInt32LE(i,0x10) },
  writeAbility:              function(i) { return this.pkxUnencrypted.writeUInt8(i,0x14) },
  writeAbilityNumber:        function(i) { return this.pkxUnencrypted.writeUInt8(i,0x15) },
  writePersonalityValue:     function(i) { return this.pkxUnencrypted.writeUInt32LE(i,0x18) },
  writeNature:               function(i) { return this.pkxUnencrypted.writeUInt8(i,0x1C) },
  writeFatefulEncounter:     function(i) { 
                               return this.pkxUnencrypted.writeUInt8(
                                 i << 7 | (this.pkxUnencrypted.readUInt8(0x1D) & 0x7F), 0x1D
                               )
                             },
  writeGender:               function(i) {
                               return this.pkxUnencrypted.writeUInt8(
                                 i << 6 | (this.pkxUnencrypted.readUInt8(0x1D) & 0xBF), 0x1D
                               ) 
                             },
  writeGenderless:           function(i) {
                               return this.pkxUnencrypted.writeUInt8(
                                 i << 5 | (this.pkxUnencrypted.readUInt8(0x1D) & 0xDF), 0x1D
                               )
                             },
  writeForm:                 function(i) {
                               return this.pkxUnencrypted.writeUInt8(
                                 i | (this.pkxUnencrypted.readUInt8(0x1D) & 0xE0), 0x1D
                               )
                             },
  writeHPEffortValue:        function(i) { return this.pkxUnencrypted.writeUInt8(i,0x1E) },
  writeAttackEffortValue:    function(i) { return this.pkxUnencrypted.writeUInt8(i,0x1F) },
  writeDefenseEffortValue:   function(i) { return this.pkxUnencrypted.writeUInt8(i,0x20) },
  writeSpeedEffortValue:     function(i) { return this.pkxUnencrypted.writeUInt8(i,0x21) },
  writeSPAttackEffortValue:  function(i) { return this.pkxUnencrypted.writeUInt8(i,0x22) },
  writeSPDefenseEffortValue: function(i) { return this.pkxUnencrypted.writeUInt8(i,0x23) },
  writePokerus:              function(i) { return this.pkxUnencrypted.writeUInt8(i,0x2B) },
  writeKalosRibbons:         function(i) { return this.pkxUnencrypted.writeUInt32LE(i,0x30) },
  writeNickname:             function(i) {
                               this.pkxUnencrypted.fill(0,0x40,0x57);
                               return this.pkxUnencrypted.write(i,0x40,10,'utf8') 
                             },
  writeMove1ID:              function(i) { return this.pkxUnencrypted.writeUInt16LE(i,0x5A) },
  writeMove2ID:              function(i) { return this.pkxUnencrypted.writeUInt16LE(i,0x5C) },
  writeMove3ID:              function(i) { return this.pkxUnencrypted.writeUInt16LE(i,0x5E) },
  writeMove4ID:              function(i) { return this.pkxUnencrypted.writeUInt16LE(i,0x60) },
  writeMove1CurrentPP:       function(i) { return this.pkxUnencrypted.writeUInt8(i,0x62) },
  writeMove2CurrentPP:       function(i) { return this.pkxUnencrypted.writeUInt8(i,0x63) },
  writeMove3CurrentPP:       function(i) { return this.pkxUnencrypted.writeUInt8(i,0x64) },
  writeMove4CurrentPP:       function(i) { return this.pkxUnencrypted.writeUInt8(i,0x65) },
  writeMovePPUps:            function(i) { return this.pkxUnencrypted.writeUInt32LE(i,0x66) },
  writeMove1IDAtHatching:    function(i) { return this.pkxUnencrypted.writeUInt16LE(i,0x6A) },
  writeMove2IDAtHatching:    function(i) { return this.pkxUnencrypted.writeUInt16LE(i,0x6C) },
  writeMove3IDAtHatching:    function(i) { return this.pkxUnencrypted.writeUInt16LE(i,0x6E) },
  writeMove4IDAtHatching:    function(i) { return this.pkxUnencrypted.writeUInt16LE(i,0x70) },
  writeMove4IDAtHatching:    function(i) { return this.pkxUnencrypted.writeUInt16LE(i,0x72) },
  writeIVHP:                 function(i) {
                               return this.pkxUnencrypted.writeUInt8(
                                 i << 3 | (this.pkxUnencrypted.readUInt8(0x74) & 0x07), 0x74 
                               )
                             },
  writeIVAttack:             function(i) { 
                               return this.pkxUnencrypted.writeUInt16LE(
  														   i << 6 | (this.pkxUnencrypred.readUint16LE(0x74) & 0xF83F), 0x74
                               )
                             },
  writeIVDefense:            function(i) { 
                               return this.pkxUnencrypted.writeUInt8(
                                 i << 1 | (this.pkxUnencrypted.readUInt8(0x75) & 0xC1), 0x75
                               )
                             },
  writeIVSpeed:              function(i) { 
                               return this.pkxUnencrypted.writeUInt16LE(
                                 i << 4 | (this.pkxUnencrypred.readUint16LE(0x75) & 0xFE0F), 0x75
                               )
                             },
  writeIVSPAttack:           function(i) {
                               return this.pkxUnencrypted.writeUInt16LE(
                                 i << 7 | (this.pkxUnencrypred.readUint16LE(0x76) & 0xF07F), 0x76
                               )
                             },
  writeIVSPDefense:          function(i) {
                               return this.pkxUnencrypted.writeUInt8(
                                 i << 2 | (this.pkxUnencrypted.readUInt8(0x77) & 0x83), 0x77
                               )
                             },
  writeIsEgg:                function(i) {
                               return this.pkxUnencrypted.writeUInt8(
                                 i << 1 | (this.pkxUnencrypted.readUInt8(0x77) & 0xFD), 0x77
                               )
                             },
  writeIsNicknamed:          function(i) {
                               return this.pkxUnencrypted.writeUInt8(
                                 i | (this.pkxUnencrypted.readUInt8(0x77) & 0xFE), 0x77
                               )
                             },
  writeOTNameTradedTo:       function(i) {
                               this.pkxUnencrypred.fill(0,0x78,0x8F);
                               return this.pkxUnencrypted.write(i,0x78,10,'utf8')
                             },
  writeOTName:               function(i) { 
                               this.pkxUnencrypted.write(i,0xB0,0xC7);
                               return this.pkxUnencrypted.write(i,0xB0,10,'utf8')
                             },
  writeYearEggReceived:      function(i) { return this.pkxUnencrypted.writeUInt8(i,0xD3) },
  writeMonthEggReceived:     function(i) { return this.pkxUnencrypted.writeUInt8(i,0xD2) },
  writeDayEggReceived:       function(i) { return this.pkxUnencrypted.writeUInt8(i,0xD1) },
  writeYearMet:              function(i) { return this.pkxUnencrypted.writeUInt8(i,0xD4) },
  writeMonthMet:             function(i) { return this.pkxUnencrypted.writeUInt8(i,0xD5) },
  writeDayMet:               function(i) { return this.pkxUnencrypted.writeUInt8(i,0xD6) },
  writeEggLocation:          function(i) { return this.pkxUnencrypted.writeUInt16LE(i,0xD8) },
  writeMetAtLocation:        function(i) { return this.pkxUnencrypted.writeUInt16LE(i,0xDA) },
  writePokeball:             function(i) { return this.pkxUnencrypted.writeUInt8(i,0xDC) },
  writeEncounterLevel:       function(i) {
                               return this.pkxUnencrypted.writeUInt8(
                                 i << 1 | (this.pkxUnencrypted.readUInt8(0xDD) & 0x01), 0xDD
                               )
                             },
  writeOTGender:             function(i) {
                               return this.pkxUnencrypted.writeUInt8(
                                 i | (this.pkxUnencrypted.readUInt8(0xDD) & 0xFE), 0xDD
                               )
                             },
  writeOTGameVersion:        function(i) { return this.pkxUnencrypted.writeUInt8(i,0xDF) },
  writeCountryID:            function(i) { return this.pkxUnencrypted.writeUInt8(i,0xE0) },
  writeRegionID:             function(i) { return this.pkxUnencrypted.writeUInt8(i,0xE1) },
  write3DSregionID:          function(i) { return this.pkxUnencrypted.writeUInt8(i,0xE2) },
  writeOTlanguage:           function(i) { return this.pkxUnencrypted.writeUInt8(i,0xE3) },
  writeLevel:                function(i) { return this.pkxUnencrypted.writeUInt8(i,0xEC) },
  writeCurrentHP:            function(i) { return this.pkxUnencrypted.writeUInt16LE(i,0xF0) },
  writeMaxHP:                function(i) { return this.pkxUnencrypted.writeUInt16LE(i,0xF2) },
  writeAttack:               function(i) { return this.pkxUnencrypted.writeUInt16LE(i,0xF4) },
  writeDefense:              function(i) { return this.pkxUnencrypted.writeUInt16LE(i,0xF6) },
  writeSpeed:                function(i) { return this.pkxUnencrypted.writeUInt16LE(i,0xF8) },
  writeSpecialAttack:        function(i) { return this.pkxUnencrypted.writeUInt16LE(i,0xFA) },
  writeSpecialDefense:       function(i) { return this.pkxUnencrypted.writeUInt16LE(i,0xFC) }
}
