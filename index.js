var bignum     = require('bignum');
var blockSize  = 56;
var offset     = 8;
var pokemon    = new Object;
module.exports = pokemon;

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
  unencrypt: function () {
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
  copyEncrypted: function (buff) {
    return this.pkxEncrypted.copy(buff);
  },
  copyUnencrypted: function (buff) {
    return this.pkxEncrypted.copy(buff);
  },
}
