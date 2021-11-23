(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
'use strict'
const QUEUEIT_CUSTOMERID = "YOUR CUSTOMERID";
const QUEUEIT_SECRETKEY = "YOUR SECRET KEY";
const queueitHandler = require("./requestResponseHandler");

addEventListener('fetch', (event) => {

  event.respondWith(handleRequest(event.request))
})

const handleRequest = async function (request) {
  let queueitResponse = await queueitHandler.onQueueITRequest(request,QUEUEIT_CUSTOMERID, QUEUEIT_SECRETKEY);
  if (queueitResponse) {
    //it is a redirect- break the flow  
     return await queueitHandler.onQueueITResponse(queueitResponse);
  }
  else {
    //call backend 
    var response = await fetch(request);
    return await queueitHandler.onQueueITResponse(response);
  }
}
},{"./requestResponseHandler":16}],2:[function(require,module,exports){
exports.getHttpHandler = function(request, bodyString)
{   
  var httpProvider =  {
        getHttpRequest: function () {
            var httpRequest = {
                getUserAgent: function () {
                    return this.getHeader("user-agent");
                },
                getHeader: function (headerNameArg) {
                   return request.headers.get(headerNameArg) || "";
                },
                getAbsoluteUri: function () {
                    return request.url;
                },
                getUserHostAddress: function () {
                    return this.getHeader("cf-connecting-ip");
                },
                getCookieValue: function (cookieKey) {
                    if (!this.parsedCookieDic) {
                        this.parsedCookieDic = this.__parseCookies(this.getHeader('cookie'));
                    }                    
                    var cookieValue = this.parsedCookieDic[cookieKey];
                    
                    if(cookieValue)
                        return decodeURIComponent(cookieValue);
                    
                    return cookieValue;
                },
                getRequestBodyAsString: function() {
                    return bodyString;
                },
				 __parseCookies:function(cookieValue) {
				  let parsedCookie = [];
					  cookieValue.split(';').forEach(function (cookie) {
								if (cookie) {
									var parts = cookie.split('=');
									if (parts.length >= 2)
										parsedCookie[parts[0].trim()] = parts[1].trim();
								}
							});
					return parsedCookie;
				}
				
            };
            return httpRequest;
        },
        getHttpResponse: function () {
            var httpResponse = {
                setCookie: function (cookieName, cookieValue, domain, expiration) {

                    // expiration is in secs, but Date needs it in milisecs
                    let expirationDate = new Date(expiration * 1000);

                    var setCookieString = `${cookieName}=${encodeURIComponent(cookieValue)}; expires=${expirationDate.toGMTString()};`;
                    if (domain) {
                        setCookieString += ` domain=${domain};`;
                    }
                    setCookieString += " path=/";
                    httpProvider.outputCookie = setCookieString;

                }
            };
            return httpResponse;
        },
  };
  return httpProvider;
};

},{}],3:[function(require,module,exports){
const crypto = require('js-sha256');
const helpers = require('./queueitHelpers');
const __IntegrationConfixFieldName ="info";

exports.tryStoreIntegrationConfig= async function(request, integrationConfigKV ,secretKey)
{
   const bodyJSON = await request.clone().json();
   const hash = bodyJSON.hash;
   const configInHex = bodyJSON.integrationInfo;

  if(hash && configInHex && crypto.sha256.hmac(secretKey, configInHex) == hash)
  {
    await integrationConfigKV.put(__IntegrationConfixFieldName, helpers.hex2bin(configInHex));
    return true;
  }
  return false;
}
exports.getIntegrationConfig = async function(integrationConfigKV)
{
    return  await integrationConfigKV.get(__IntegrationConfixFieldName,"text");
}


},{"./queueitHelpers":15,"js-sha256":4}],4:[function(require,module,exports){
(function (process,global){(function (){
/**
 * [js-sha256]{@link https://github.com/emn178/js-sha256}
 *
 * @version 0.9.0
 * @author Chen, Yi-Cyuan [emn178@gmail.com]
 * @copyright Chen, Yi-Cyuan 2014-2017
 * @license MIT
 */
/*jslint bitwise: true */
(function () {
  'use strict';

  var ERROR = 'input is invalid type';
  var WINDOW = typeof window === 'object';
  var root = WINDOW ? window : {};
  if (root.JS_SHA256_NO_WINDOW) {
    WINDOW = false;
  }
  var WEB_WORKER = !WINDOW && typeof self === 'object';
  var NODE_JS = !root.JS_SHA256_NO_NODE_JS && typeof process === 'object' && process.versions && process.versions.node;
  if (NODE_JS) {
    root = global;
  } else if (WEB_WORKER) {
    root = self;
  }
  var COMMON_JS = !root.JS_SHA256_NO_COMMON_JS && typeof module === 'object' && module.exports;
  var AMD = typeof define === 'function' && define.amd;
  var ARRAY_BUFFER = !root.JS_SHA256_NO_ARRAY_BUFFER && typeof ArrayBuffer !== 'undefined';
  var HEX_CHARS = '0123456789abcdef'.split('');
  var EXTRA = [-2147483648, 8388608, 32768, 128];
  var SHIFT = [24, 16, 8, 0];
  var K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];
  var OUTPUT_TYPES = ['hex', 'array', 'digest', 'arrayBuffer'];

  var blocks = [];

  if (root.JS_SHA256_NO_NODE_JS || !Array.isArray) {
    Array.isArray = function (obj) {
      return Object.prototype.toString.call(obj) === '[object Array]';
    };
  }

  if (ARRAY_BUFFER && (root.JS_SHA256_NO_ARRAY_BUFFER_IS_VIEW || !ArrayBuffer.isView)) {
    ArrayBuffer.isView = function (obj) {
      return typeof obj === 'object' && obj.buffer && obj.buffer.constructor === ArrayBuffer;
    };
  }

  var createOutputMethod = function (outputType, is224) {
    return function (message) {
      return new Sha256(is224, true).update(message)[outputType]();
    };
  };

  var createMethod = function (is224) {
    var method = createOutputMethod('hex', is224);
    if (NODE_JS) {
      method = nodeWrap(method, is224);
    }
    method.create = function () {
      return new Sha256(is224);
    };
    method.update = function (message) {
      return method.create().update(message);
    };
    for (var i = 0; i < OUTPUT_TYPES.length; ++i) {
      var type = OUTPUT_TYPES[i];
      method[type] = createOutputMethod(type, is224);
    }
    return method;
  };

  var nodeWrap = function (method, is224) {
    var crypto = eval("require('crypto')");
    var Buffer = eval("require('buffer').Buffer");
    var algorithm = is224 ? 'sha224' : 'sha256';
    var nodeMethod = function (message) {
      if (typeof message === 'string') {
        return crypto.createHash(algorithm).update(message, 'utf8').digest('hex');
      } else {
        if (message === null || message === undefined) {
          throw new Error(ERROR);
        } else if (message.constructor === ArrayBuffer) {
          message = new Uint8Array(message);
        }
      }
      if (Array.isArray(message) || ArrayBuffer.isView(message) ||
        message.constructor === Buffer) {
        return crypto.createHash(algorithm).update(new Buffer(message)).digest('hex');
      } else {
        return method(message);
      }
    };
    return nodeMethod;
  };

  var createHmacOutputMethod = function (outputType, is224) {
    return function (key, message) {
      return new HmacSha256(key, is224, true).update(message)[outputType]();
    };
  };

  var createHmacMethod = function (is224) {
    var method = createHmacOutputMethod('hex', is224);
    method.create = function (key) {
      return new HmacSha256(key, is224);
    };
    method.update = function (key, message) {
      return method.create(key).update(message);
    };
    for (var i = 0; i < OUTPUT_TYPES.length; ++i) {
      var type = OUTPUT_TYPES[i];
      method[type] = createHmacOutputMethod(type, is224);
    }
    return method;
  };

  function Sha256(is224, sharedMemory) {
    if (sharedMemory) {
      blocks[0] = blocks[16] = blocks[1] = blocks[2] = blocks[3] =
        blocks[4] = blocks[5] = blocks[6] = blocks[7] =
        blocks[8] = blocks[9] = blocks[10] = blocks[11] =
        blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
      this.blocks = blocks;
    } else {
      this.blocks = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    }

    if (is224) {
      this.h0 = 0xc1059ed8;
      this.h1 = 0x367cd507;
      this.h2 = 0x3070dd17;
      this.h3 = 0xf70e5939;
      this.h4 = 0xffc00b31;
      this.h5 = 0x68581511;
      this.h6 = 0x64f98fa7;
      this.h7 = 0xbefa4fa4;
    } else { // 256
      this.h0 = 0x6a09e667;
      this.h1 = 0xbb67ae85;
      this.h2 = 0x3c6ef372;
      this.h3 = 0xa54ff53a;
      this.h4 = 0x510e527f;
      this.h5 = 0x9b05688c;
      this.h6 = 0x1f83d9ab;
      this.h7 = 0x5be0cd19;
    }

    this.block = this.start = this.bytes = this.hBytes = 0;
    this.finalized = this.hashed = false;
    this.first = true;
    this.is224 = is224;
  }

  Sha256.prototype.update = function (message) {
    if (this.finalized) {
      return;
    }
    var notString, type = typeof message;
    if (type !== 'string') {
      if (type === 'object') {
        if (message === null) {
          throw new Error(ERROR);
        } else if (ARRAY_BUFFER && message.constructor === ArrayBuffer) {
          message = new Uint8Array(message);
        } else if (!Array.isArray(message)) {
          if (!ARRAY_BUFFER || !ArrayBuffer.isView(message)) {
            throw new Error(ERROR);
          }
        }
      } else {
        throw new Error(ERROR);
      }
      notString = true;
    }
    var code, index = 0, i, length = message.length, blocks = this.blocks;

    while (index < length) {
      if (this.hashed) {
        this.hashed = false;
        blocks[0] = this.block;
        blocks[16] = blocks[1] = blocks[2] = blocks[3] =
          blocks[4] = blocks[5] = blocks[6] = blocks[7] =
          blocks[8] = blocks[9] = blocks[10] = blocks[11] =
          blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
      }

      if (notString) {
        for (i = this.start; index < length && i < 64; ++index) {
          blocks[i >> 2] |= message[index] << SHIFT[i++ & 3];
        }
      } else {
        for (i = this.start; index < length && i < 64; ++index) {
          code = message.charCodeAt(index);
          if (code < 0x80) {
            blocks[i >> 2] |= code << SHIFT[i++ & 3];
          } else if (code < 0x800) {
            blocks[i >> 2] |= (0xc0 | (code >> 6)) << SHIFT[i++ & 3];
            blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
          } else if (code < 0xd800 || code >= 0xe000) {
            blocks[i >> 2] |= (0xe0 | (code >> 12)) << SHIFT[i++ & 3];
            blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) << SHIFT[i++ & 3];
            blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
          } else {
            code = 0x10000 + (((code & 0x3ff) << 10) | (message.charCodeAt(++index) & 0x3ff));
            blocks[i >> 2] |= (0xf0 | (code >> 18)) << SHIFT[i++ & 3];
            blocks[i >> 2] |= (0x80 | ((code >> 12) & 0x3f)) << SHIFT[i++ & 3];
            blocks[i >> 2] |= (0x80 | ((code >> 6) & 0x3f)) << SHIFT[i++ & 3];
            blocks[i >> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
          }
        }
      }

      this.lastByteIndex = i;
      this.bytes += i - this.start;
      if (i >= 64) {
        this.block = blocks[16];
        this.start = i - 64;
        this.hash();
        this.hashed = true;
      } else {
        this.start = i;
      }
    }
    if (this.bytes > 4294967295) {
      this.hBytes += this.bytes / 4294967296 << 0;
      this.bytes = this.bytes % 4294967296;
    }
    return this;
  };

  Sha256.prototype.finalize = function () {
    if (this.finalized) {
      return;
    }
    this.finalized = true;
    var blocks = this.blocks, i = this.lastByteIndex;
    blocks[16] = this.block;
    blocks[i >> 2] |= EXTRA[i & 3];
    this.block = blocks[16];
    if (i >= 56) {
      if (!this.hashed) {
        this.hash();
      }
      blocks[0] = this.block;
      blocks[16] = blocks[1] = blocks[2] = blocks[3] =
        blocks[4] = blocks[5] = blocks[6] = blocks[7] =
        blocks[8] = blocks[9] = blocks[10] = blocks[11] =
        blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
    }
    blocks[14] = this.hBytes << 3 | this.bytes >>> 29;
    blocks[15] = this.bytes << 3;
    this.hash();
  };

  Sha256.prototype.hash = function () {
    var a = this.h0, b = this.h1, c = this.h2, d = this.h3, e = this.h4, f = this.h5, g = this.h6,
      h = this.h7, blocks = this.blocks, j, s0, s1, maj, t1, t2, ch, ab, da, cd, bc;

    for (j = 16; j < 64; ++j) {
      // rightrotate
      t1 = blocks[j - 15];
      s0 = ((t1 >>> 7) | (t1 << 25)) ^ ((t1 >>> 18) | (t1 << 14)) ^ (t1 >>> 3);
      t1 = blocks[j - 2];
      s1 = ((t1 >>> 17) | (t1 << 15)) ^ ((t1 >>> 19) | (t1 << 13)) ^ (t1 >>> 10);
      blocks[j] = blocks[j - 16] + s0 + blocks[j - 7] + s1 << 0;
    }

    bc = b & c;
    for (j = 0; j < 64; j += 4) {
      if (this.first) {
        if (this.is224) {
          ab = 300032;
          t1 = blocks[0] - 1413257819;
          h = t1 - 150054599 << 0;
          d = t1 + 24177077 << 0;
        } else {
          ab = 704751109;
          t1 = blocks[0] - 210244248;
          h = t1 - 1521486534 << 0;
          d = t1 + 143694565 << 0;
        }
        this.first = false;
      } else {
        s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        ab = a & b;
        maj = ab ^ (a & c) ^ bc;
        ch = (e & f) ^ (~e & g);
        t1 = h + s1 + ch + K[j] + blocks[j];
        t2 = s0 + maj;
        h = d + t1 << 0;
        d = t1 + t2 << 0;
      }
      s0 = ((d >>> 2) | (d << 30)) ^ ((d >>> 13) | (d << 19)) ^ ((d >>> 22) | (d << 10));
      s1 = ((h >>> 6) | (h << 26)) ^ ((h >>> 11) | (h << 21)) ^ ((h >>> 25) | (h << 7));
      da = d & a;
      maj = da ^ (d & b) ^ ab;
      ch = (h & e) ^ (~h & f);
      t1 = g + s1 + ch + K[j + 1] + blocks[j + 1];
      t2 = s0 + maj;
      g = c + t1 << 0;
      c = t1 + t2 << 0;
      s0 = ((c >>> 2) | (c << 30)) ^ ((c >>> 13) | (c << 19)) ^ ((c >>> 22) | (c << 10));
      s1 = ((g >>> 6) | (g << 26)) ^ ((g >>> 11) | (g << 21)) ^ ((g >>> 25) | (g << 7));
      cd = c & d;
      maj = cd ^ (c & a) ^ da;
      ch = (g & h) ^ (~g & e);
      t1 = f + s1 + ch + K[j + 2] + blocks[j + 2];
      t2 = s0 + maj;
      f = b + t1 << 0;
      b = t1 + t2 << 0;
      s0 = ((b >>> 2) | (b << 30)) ^ ((b >>> 13) | (b << 19)) ^ ((b >>> 22) | (b << 10));
      s1 = ((f >>> 6) | (f << 26)) ^ ((f >>> 11) | (f << 21)) ^ ((f >>> 25) | (f << 7));
      bc = b & c;
      maj = bc ^ (b & d) ^ cd;
      ch = (f & g) ^ (~f & h);
      t1 = e + s1 + ch + K[j + 3] + blocks[j + 3];
      t2 = s0 + maj;
      e = a + t1 << 0;
      a = t1 + t2 << 0;
    }

    this.h0 = this.h0 + a << 0;
    this.h1 = this.h1 + b << 0;
    this.h2 = this.h2 + c << 0;
    this.h3 = this.h3 + d << 0;
    this.h4 = this.h4 + e << 0;
    this.h5 = this.h5 + f << 0;
    this.h6 = this.h6 + g << 0;
    this.h7 = this.h7 + h << 0;
  };

  Sha256.prototype.hex = function () {
    this.finalize();

    var h0 = this.h0, h1 = this.h1, h2 = this.h2, h3 = this.h3, h4 = this.h4, h5 = this.h5,
      h6 = this.h6, h7 = this.h7;

    var hex = HEX_CHARS[(h0 >> 28) & 0x0F] + HEX_CHARS[(h0 >> 24) & 0x0F] +
      HEX_CHARS[(h0 >> 20) & 0x0F] + HEX_CHARS[(h0 >> 16) & 0x0F] +
      HEX_CHARS[(h0 >> 12) & 0x0F] + HEX_CHARS[(h0 >> 8) & 0x0F] +
      HEX_CHARS[(h0 >> 4) & 0x0F] + HEX_CHARS[h0 & 0x0F] +
      HEX_CHARS[(h1 >> 28) & 0x0F] + HEX_CHARS[(h1 >> 24) & 0x0F] +
      HEX_CHARS[(h1 >> 20) & 0x0F] + HEX_CHARS[(h1 >> 16) & 0x0F] +
      HEX_CHARS[(h1 >> 12) & 0x0F] + HEX_CHARS[(h1 >> 8) & 0x0F] +
      HEX_CHARS[(h1 >> 4) & 0x0F] + HEX_CHARS[h1 & 0x0F] +
      HEX_CHARS[(h2 >> 28) & 0x0F] + HEX_CHARS[(h2 >> 24) & 0x0F] +
      HEX_CHARS[(h2 >> 20) & 0x0F] + HEX_CHARS[(h2 >> 16) & 0x0F] +
      HEX_CHARS[(h2 >> 12) & 0x0F] + HEX_CHARS[(h2 >> 8) & 0x0F] +
      HEX_CHARS[(h2 >> 4) & 0x0F] + HEX_CHARS[h2 & 0x0F] +
      HEX_CHARS[(h3 >> 28) & 0x0F] + HEX_CHARS[(h3 >> 24) & 0x0F] +
      HEX_CHARS[(h3 >> 20) & 0x0F] + HEX_CHARS[(h3 >> 16) & 0x0F] +
      HEX_CHARS[(h3 >> 12) & 0x0F] + HEX_CHARS[(h3 >> 8) & 0x0F] +
      HEX_CHARS[(h3 >> 4) & 0x0F] + HEX_CHARS[h3 & 0x0F] +
      HEX_CHARS[(h4 >> 28) & 0x0F] + HEX_CHARS[(h4 >> 24) & 0x0F] +
      HEX_CHARS[(h4 >> 20) & 0x0F] + HEX_CHARS[(h4 >> 16) & 0x0F] +
      HEX_CHARS[(h4 >> 12) & 0x0F] + HEX_CHARS[(h4 >> 8) & 0x0F] +
      HEX_CHARS[(h4 >> 4) & 0x0F] + HEX_CHARS[h4 & 0x0F] +
      HEX_CHARS[(h5 >> 28) & 0x0F] + HEX_CHARS[(h5 >> 24) & 0x0F] +
      HEX_CHARS[(h5 >> 20) & 0x0F] + HEX_CHARS[(h5 >> 16) & 0x0F] +
      HEX_CHARS[(h5 >> 12) & 0x0F] + HEX_CHARS[(h5 >> 8) & 0x0F] +
      HEX_CHARS[(h5 >> 4) & 0x0F] + HEX_CHARS[h5 & 0x0F] +
      HEX_CHARS[(h6 >> 28) & 0x0F] + HEX_CHARS[(h6 >> 24) & 0x0F] +
      HEX_CHARS[(h6 >> 20) & 0x0F] + HEX_CHARS[(h6 >> 16) & 0x0F] +
      HEX_CHARS[(h6 >> 12) & 0x0F] + HEX_CHARS[(h6 >> 8) & 0x0F] +
      HEX_CHARS[(h6 >> 4) & 0x0F] + HEX_CHARS[h6 & 0x0F];
    if (!this.is224) {
      hex += HEX_CHARS[(h7 >> 28) & 0x0F] + HEX_CHARS[(h7 >> 24) & 0x0F] +
        HEX_CHARS[(h7 >> 20) & 0x0F] + HEX_CHARS[(h7 >> 16) & 0x0F] +
        HEX_CHARS[(h7 >> 12) & 0x0F] + HEX_CHARS[(h7 >> 8) & 0x0F] +
        HEX_CHARS[(h7 >> 4) & 0x0F] + HEX_CHARS[h7 & 0x0F];
    }
    return hex;
  };

  Sha256.prototype.toString = Sha256.prototype.hex;

  Sha256.prototype.digest = function () {
    this.finalize();

    var h0 = this.h0, h1 = this.h1, h2 = this.h2, h3 = this.h3, h4 = this.h4, h5 = this.h5,
      h6 = this.h6, h7 = this.h7;

    var arr = [
      (h0 >> 24) & 0xFF, (h0 >> 16) & 0xFF, (h0 >> 8) & 0xFF, h0 & 0xFF,
      (h1 >> 24) & 0xFF, (h1 >> 16) & 0xFF, (h1 >> 8) & 0xFF, h1 & 0xFF,
      (h2 >> 24) & 0xFF, (h2 >> 16) & 0xFF, (h2 >> 8) & 0xFF, h2 & 0xFF,
      (h3 >> 24) & 0xFF, (h3 >> 16) & 0xFF, (h3 >> 8) & 0xFF, h3 & 0xFF,
      (h4 >> 24) & 0xFF, (h4 >> 16) & 0xFF, (h4 >> 8) & 0xFF, h4 & 0xFF,
      (h5 >> 24) & 0xFF, (h5 >> 16) & 0xFF, (h5 >> 8) & 0xFF, h5 & 0xFF,
      (h6 >> 24) & 0xFF, (h6 >> 16) & 0xFF, (h6 >> 8) & 0xFF, h6 & 0xFF
    ];
    if (!this.is224) {
      arr.push((h7 >> 24) & 0xFF, (h7 >> 16) & 0xFF, (h7 >> 8) & 0xFF, h7 & 0xFF);
    }
    return arr;
  };

  Sha256.prototype.array = Sha256.prototype.digest;

  Sha256.prototype.arrayBuffer = function () {
    this.finalize();

    var buffer = new ArrayBuffer(this.is224 ? 28 : 32);
    var dataView = new DataView(buffer);
    dataView.setUint32(0, this.h0);
    dataView.setUint32(4, this.h1);
    dataView.setUint32(8, this.h2);
    dataView.setUint32(12, this.h3);
    dataView.setUint32(16, this.h4);
    dataView.setUint32(20, this.h5);
    dataView.setUint32(24, this.h6);
    if (!this.is224) {
      dataView.setUint32(28, this.h7);
    }
    return buffer;
  };

  function HmacSha256(key, is224, sharedMemory) {
    var i, type = typeof key;
    if (type === 'string') {
      var bytes = [], length = key.length, index = 0, code;
      for (i = 0; i < length; ++i) {
        code = key.charCodeAt(i);
        if (code < 0x80) {
          bytes[index++] = code;
        } else if (code < 0x800) {
          bytes[index++] = (0xc0 | (code >> 6));
          bytes[index++] = (0x80 | (code & 0x3f));
        } else if (code < 0xd800 || code >= 0xe000) {
          bytes[index++] = (0xe0 | (code >> 12));
          bytes[index++] = (0x80 | ((code >> 6) & 0x3f));
          bytes[index++] = (0x80 | (code & 0x3f));
        } else {
          code = 0x10000 + (((code & 0x3ff) << 10) | (key.charCodeAt(++i) & 0x3ff));
          bytes[index++] = (0xf0 | (code >> 18));
          bytes[index++] = (0x80 | ((code >> 12) & 0x3f));
          bytes[index++] = (0x80 | ((code >> 6) & 0x3f));
          bytes[index++] = (0x80 | (code & 0x3f));
        }
      }
      key = bytes;
    } else {
      if (type === 'object') {
        if (key === null) {
          throw new Error(ERROR);
        } else if (ARRAY_BUFFER && key.constructor === ArrayBuffer) {
          key = new Uint8Array(key);
        } else if (!Array.isArray(key)) {
          if (!ARRAY_BUFFER || !ArrayBuffer.isView(key)) {
            throw new Error(ERROR);
          }
        }
      } else {
        throw new Error(ERROR);
      }
    }

    if (key.length > 64) {
      key = (new Sha256(is224, true)).update(key).array();
    }

    var oKeyPad = [], iKeyPad = [];
    for (i = 0; i < 64; ++i) {
      var b = key[i] || 0;
      oKeyPad[i] = 0x5c ^ b;
      iKeyPad[i] = 0x36 ^ b;
    }

    Sha256.call(this, is224, sharedMemory);

    this.update(iKeyPad);
    this.oKeyPad = oKeyPad;
    this.inner = true;
    this.sharedMemory = sharedMemory;
  }
  HmacSha256.prototype = new Sha256();

  HmacSha256.prototype.finalize = function () {
    Sha256.prototype.finalize.call(this);
    if (this.inner) {
      this.inner = false;
      var innerHash = this.array();
      Sha256.call(this, this.is224, this.sharedMemory);
      this.update(this.oKeyPad);
      this.update(innerHash);
      Sha256.prototype.finalize.call(this);
    }
  };

  var exports = createMethod();
  exports.sha256 = exports;
  exports.sha224 = createMethod(true);
  exports.sha256.hmac = createHmacMethod();
  exports.sha224.hmac = createHmacMethod(true);

  if (COMMON_JS) {
    module.exports = exports;
  } else {
    root.sha256 = exports.sha256;
    root.sha224 = exports.sha224;
    if (AMD) {
      define(function () {
        return exports;
      });
    }
  }
})();

}).call(this)}).call(this,require('_process'),typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{"_process":5}],5:[function(require,module,exports){
// shim for using process in browser
var process = module.exports = {};

// cached from whatever global is present so that test runners that stub it
// don't break things.  But we need to wrap it in a try catch in case it is
// wrapped in strict mode code which doesn't define any globals.  It's inside a
// function because try/catches deoptimize in certain engines.

var cachedSetTimeout;
var cachedClearTimeout;

function defaultSetTimout() {
    throw new Error('setTimeout has not been defined');
}
function defaultClearTimeout () {
    throw new Error('clearTimeout has not been defined');
}
(function () {
    try {
        if (typeof setTimeout === 'function') {
            cachedSetTimeout = setTimeout;
        } else {
            cachedSetTimeout = defaultSetTimout;
        }
    } catch (e) {
        cachedSetTimeout = defaultSetTimout;
    }
    try {
        if (typeof clearTimeout === 'function') {
            cachedClearTimeout = clearTimeout;
        } else {
            cachedClearTimeout = defaultClearTimeout;
        }
    } catch (e) {
        cachedClearTimeout = defaultClearTimeout;
    }
} ())
function runTimeout(fun) {
    if (cachedSetTimeout === setTimeout) {
        //normal enviroments in sane situations
        return setTimeout(fun, 0);
    }
    // if setTimeout wasn't available but was latter defined
    if ((cachedSetTimeout === defaultSetTimout || !cachedSetTimeout) && setTimeout) {
        cachedSetTimeout = setTimeout;
        return setTimeout(fun, 0);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedSetTimeout(fun, 0);
    } catch(e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't trust the global object when called normally
            return cachedSetTimeout.call(null, fun, 0);
        } catch(e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error
            return cachedSetTimeout.call(this, fun, 0);
        }
    }


}
function runClearTimeout(marker) {
    if (cachedClearTimeout === clearTimeout) {
        //normal enviroments in sane situations
        return clearTimeout(marker);
    }
    // if clearTimeout wasn't available but was latter defined
    if ((cachedClearTimeout === defaultClearTimeout || !cachedClearTimeout) && clearTimeout) {
        cachedClearTimeout = clearTimeout;
        return clearTimeout(marker);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedClearTimeout(marker);
    } catch (e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't  trust the global object when called normally
            return cachedClearTimeout.call(null, marker);
        } catch (e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error.
            // Some versions of I.E. have different rules for clearTimeout vs setTimeout
            return cachedClearTimeout.call(this, marker);
        }
    }



}
var queue = [];
var draining = false;
var currentQueue;
var queueIndex = -1;

function cleanUpNextTick() {
    if (!draining || !currentQueue) {
        return;
    }
    draining = false;
    if (currentQueue.length) {
        queue = currentQueue.concat(queue);
    } else {
        queueIndex = -1;
    }
    if (queue.length) {
        drainQueue();
    }
}

function drainQueue() {
    if (draining) {
        return;
    }
    var timeout = runTimeout(cleanUpNextTick);
    draining = true;

    var len = queue.length;
    while(len) {
        currentQueue = queue;
        queue = [];
        while (++queueIndex < len) {
            if (currentQueue) {
                currentQueue[queueIndex].run();
            }
        }
        queueIndex = -1;
        len = queue.length;
    }
    currentQueue = null;
    draining = false;
    runClearTimeout(timeout);
}

process.nextTick = function (fun) {
    var args = new Array(arguments.length - 1);
    if (arguments.length > 1) {
        for (var i = 1; i < arguments.length; i++) {
            args[i - 1] = arguments[i];
        }
    }
    queue.push(new Item(fun, args));
    if (queue.length === 1 && !draining) {
        runTimeout(drainQueue);
    }
};

// v8 likes predictible objects
function Item(fun, array) {
    this.fun = fun;
    this.array = array;
}
Item.prototype.run = function () {
    this.fun.apply(null, this.array);
};
process.title = 'browser';
process.browser = true;
process.env = {};
process.argv = [];
process.version = ''; // empty string to avoid regexp issues
process.versions = {};

function noop() {}

process.on = noop;
process.addListener = noop;
process.once = noop;
process.off = noop;
process.removeListener = noop;
process.removeAllListeners = noop;
process.emit = noop;
process.prependListener = noop;
process.prependOnceListener = noop;

process.listeners = function (name) { return [] }

process.binding = function (name) {
    throw new Error('process.binding is not supported');
};

process.cwd = function () { return '/' };
process.chdir = function (dir) {
    throw new Error('process.chdir is not supported');
};
process.umask = function() { return 0; };

},{}],6:[function(require,module,exports){
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.ComparisonOperatorHelper = exports.HttpHeaderValidatorHelper = exports.RequestBodyValidatorHelper = exports.UserAgentValidatorHelper = exports.CookieValidatorHelper = exports.UrlValidatorHelper = exports.IntegrationEvaluator = void 0;
var IntegrationModels = __importStar(require("./IntegrationConfigModel"));
var Models_1 = require("../Models");
var IntegrationEvaluator = /** @class */ (function () {
    function IntegrationEvaluator() {
    }
    IntegrationEvaluator.prototype.getMatchedIntegrationConfig = function (customerIntegration, currentPageUrl, request) {
        if (!request)
            throw new Models_1.KnownUserException("request is null");
        if (!customerIntegration)
            throw new Models_1.KnownUserException("customerIntegration is null");
        for (var _i = 0, _a = customerIntegration.Integrations || []; _i < _a.length; _i++) {
            var integration = _a[_i];
            for (var _b = 0, _c = integration.Triggers; _b < _c.length; _b++) {
                var trigger = _c[_b];
                if (this.evaluateTrigger(trigger, currentPageUrl, request)) {
                    return integration;
                }
            }
        }
        return null;
    };
    IntegrationEvaluator.prototype.evaluateTrigger = function (trigger, currentPageUrl, request) {
        var part;
        if (trigger.LogicalOperator === IntegrationModels.LogicalOperatorType.Or) {
            for (var _i = 0, _a = trigger.TriggerParts; _i < _a.length; _i++) {
                part = _a[_i];
                if (this.evaluateTriggerPart(part, currentPageUrl, request))
                    return true;
            }
            return false;
        }
        else {
            for (var _b = 0, _c = trigger.TriggerParts; _b < _c.length; _b++) {
                part = _c[_b];
                if (!this.evaluateTriggerPart(part, currentPageUrl, request))
                    return false;
            }
            return true;
        }
    };
    IntegrationEvaluator.prototype.evaluateTriggerPart = function (triggerPart, currentPageUrl, request) {
        switch (triggerPart.ValidatorType) {
            case IntegrationModels.ValidatorType.UrlValidator:
                return UrlValidatorHelper.evaluate(triggerPart, currentPageUrl);
            case IntegrationModels.ValidatorType.CookieValidator:
                return CookieValidatorHelper.evaluate(triggerPart, request);
            case IntegrationModels.ValidatorType.UserAgentValidator:
                return UserAgentValidatorHelper.evaluate(triggerPart, request.getUserAgent());
            case IntegrationModels.ValidatorType.HttpHeaderValidator:
                return HttpHeaderValidatorHelper.evaluate(triggerPart, request.getHeader(triggerPart.HttpHeaderName));
            case IntegrationModels.ValidatorType.RequestBodyValidator:
                return RequestBodyValidatorHelper.evaluate(triggerPart, request.getRequestBodyAsString());
            default:
                return false;
        }
    };
    return IntegrationEvaluator;
}());
exports.IntegrationEvaluator = IntegrationEvaluator;
var UrlValidatorHelper = /** @class */ (function () {
    function UrlValidatorHelper() {
    }
    UrlValidatorHelper.evaluate = function (triggerPart, url) {
        return ComparisonOperatorHelper.evaluate(triggerPart.Operator, triggerPart.IsNegative, triggerPart.IsIgnoreCase, this.getUrlPart(triggerPart, url), triggerPart.ValueToCompare, triggerPart.ValuesToCompare);
    };
    UrlValidatorHelper.getUrlPart = function (triggerPart, url) {
        switch (triggerPart.UrlPart) {
            case IntegrationModels.UrlPartType.PagePath:
                return this.getPathFromUrl(url);
            case IntegrationModels.UrlPartType.PageUrl:
                return url;
            case IntegrationModels.UrlPartType.HostName:
                return this.getHostNameFromUrl(url);
            default:
                return "";
        }
    };
    UrlValidatorHelper.getHostNameFromUrl = function (url) {
        var urlMatcher = /^(([^:/\?#]+):)?(\/\/([^/\?#]*))?([^\?#]*)(\?([^#]*))?(#(.*))?/;
        var match = urlMatcher.exec(url);
        if (match && match[4])
            return match[4];
        return "";
    };
    UrlValidatorHelper.getPathFromUrl = function (url) {
        var urlMatcher = /^(([^:/\?#]+):)?(\/\/([^/\?#]*))?([^\?#]*)(\?([^#]*))?(#(.*))?/;
        var match = urlMatcher.exec(url);
        if (match && match[5])
            return match[5];
        return "";
    };
    return UrlValidatorHelper;
}());
exports.UrlValidatorHelper = UrlValidatorHelper;
var CookieValidatorHelper = /** @class */ (function () {
    function CookieValidatorHelper() {
    }
    CookieValidatorHelper.evaluate = function (triggerPart, request) {
        return ComparisonOperatorHelper.evaluate(triggerPart.Operator, triggerPart.IsNegative, triggerPart.IsIgnoreCase, this.getCookie(triggerPart.CookieName, request), triggerPart.ValueToCompare, triggerPart.ValuesToCompare);
    };
    CookieValidatorHelper.getCookie = function (cookieName, request) {
        var cookie = request.getCookieValue(cookieName);
        if (!cookie)
            return "";
        return cookie;
    };
    return CookieValidatorHelper;
}());
exports.CookieValidatorHelper = CookieValidatorHelper;
var UserAgentValidatorHelper = /** @class */ (function () {
    function UserAgentValidatorHelper() {
    }
    UserAgentValidatorHelper.evaluate = function (triggerPart, userAgent) {
        return ComparisonOperatorHelper.evaluate(triggerPart.Operator, triggerPart.IsNegative, triggerPart.IsIgnoreCase, userAgent, triggerPart.ValueToCompare, triggerPart.ValuesToCompare);
    };
    return UserAgentValidatorHelper;
}());
exports.UserAgentValidatorHelper = UserAgentValidatorHelper;
var RequestBodyValidatorHelper = /** @class */ (function () {
    function RequestBodyValidatorHelper() {
    }
    RequestBodyValidatorHelper.evaluate = function (triggerPart, bodyString) {
        return ComparisonOperatorHelper.evaluate(triggerPart.Operator, triggerPart.IsNegative, triggerPart.IsIgnoreCase, bodyString, triggerPart.ValueToCompare, triggerPart.ValuesToCompare);
    };
    return RequestBodyValidatorHelper;
}());
exports.RequestBodyValidatorHelper = RequestBodyValidatorHelper;
var HttpHeaderValidatorHelper = /** @class */ (function () {
    function HttpHeaderValidatorHelper() {
    }
    HttpHeaderValidatorHelper.evaluate = function (triggerPart, headerValue) {
        return ComparisonOperatorHelper.evaluate(triggerPart.Operator, triggerPart.IsNegative, triggerPart.IsIgnoreCase, headerValue, triggerPart.ValueToCompare, triggerPart.ValuesToCompare);
    };
    return HttpHeaderValidatorHelper;
}());
exports.HttpHeaderValidatorHelper = HttpHeaderValidatorHelper;
var ComparisonOperatorHelper = /** @class */ (function () {
    function ComparisonOperatorHelper() {
    }
    ComparisonOperatorHelper.evaluate = function (opt, isNegative, isIgnoreCase, value, valueToCompare, valuesToCompare) {
        value = value || "";
        valueToCompare = valueToCompare || "";
        valuesToCompare = valuesToCompare || [];
        switch (opt) {
            case IntegrationModels.ComparisonOperatorType.EqualS:
                return ComparisonOperatorHelper.equalS(value, valueToCompare, isNegative, isIgnoreCase);
            case IntegrationModels.ComparisonOperatorType.Contains:
                return ComparisonOperatorHelper.contains(value, valueToCompare, isNegative, isIgnoreCase);
            case IntegrationModels.ComparisonOperatorType.EqualsAny:
                return ComparisonOperatorHelper.equalsAny(value, valuesToCompare, isNegative, isIgnoreCase);
            case IntegrationModels.ComparisonOperatorType.ContainsAny:
                return ComparisonOperatorHelper.containsAny(value, valuesToCompare, isNegative, isIgnoreCase);
            default:
                return false;
        }
    };
    ComparisonOperatorHelper.contains = function (value, valueToCompare, isNegative, ignoreCase) {
        if (valueToCompare === "*" && value)
            return true;
        var evaluation = false;
        if (ignoreCase)
            evaluation = value.toUpperCase().indexOf(valueToCompare.toUpperCase()) !== -1;
        else
            evaluation = value.indexOf(valueToCompare) !== -1;
        if (isNegative)
            return !evaluation;
        else
            return evaluation;
    };
    ComparisonOperatorHelper.equalS = function (value, valueToCompare, isNegative, ignoreCase) {
        var evaluation = false;
        if (ignoreCase)
            evaluation = value.toUpperCase() === valueToCompare.toUpperCase();
        else
            evaluation = value === valueToCompare;
        if (isNegative)
            return !evaluation;
        else
            return evaluation;
    };
    ComparisonOperatorHelper.equalsAny = function (value, valuesToCompare, isNegative, isIgnoreCase) {
        for (var _i = 0, valuesToCompare_1 = valuesToCompare; _i < valuesToCompare_1.length; _i++) {
            var valueToCompare = valuesToCompare_1[_i];
            if (ComparisonOperatorHelper.equalS(value, valueToCompare, false, isIgnoreCase))
                return !isNegative;
        }
        return isNegative;
    };
    ComparisonOperatorHelper.containsAny = function (value, valuesToCompare, isNegative, isIgnoreCase) {
        for (var _i = 0, valuesToCompare_2 = valuesToCompare; _i < valuesToCompare_2.length; _i++) {
            var valueToCompare = valuesToCompare_2[_i];
            if (ComparisonOperatorHelper.contains(value, valueToCompare, false, isIgnoreCase))
                return !isNegative;
        }
        return isNegative;
    };
    return ComparisonOperatorHelper;
}());
exports.ComparisonOperatorHelper = ComparisonOperatorHelper;

},{"../Models":9,"./IntegrationConfigModel":7}],7:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ActionType = exports.LogicalOperatorType = exports.ComparisonOperatorType = exports.UrlPartType = exports.ValidatorType = exports.TriggerModel = exports.TriggerPart = exports.CustomerIntegration = exports.IntegrationConfigModel = void 0;
var IntegrationConfigModel = /** @class */ (function () {
    function IntegrationConfigModel() {
    }
    return IntegrationConfigModel;
}());
exports.IntegrationConfigModel = IntegrationConfigModel;
var CustomerIntegration = /** @class */ (function () {
    function CustomerIntegration() {
        this.Integrations = new Array();
        this.Version = -1;
    }
    return CustomerIntegration;
}());
exports.CustomerIntegration = CustomerIntegration;
var TriggerPart = /** @class */ (function () {
    function TriggerPart() {
    }
    return TriggerPart;
}());
exports.TriggerPart = TriggerPart;
var TriggerModel = /** @class */ (function () {
    function TriggerModel() {
        this.TriggerParts = new Array();
    }
    return TriggerModel;
}());
exports.TriggerModel = TriggerModel;
var ValidatorType = /** @class */ (function () {
    function ValidatorType() {
    }
    ValidatorType.UrlValidator = "UrlValidator";
    ValidatorType.CookieValidator = "CookieValidator";
    ValidatorType.UserAgentValidator = "UserAgentValidator";
    ValidatorType.HttpHeaderValidator = "HttpHeaderValidator";
    ValidatorType.RequestBodyValidator = "RequestBodyValidator";
    return ValidatorType;
}());
exports.ValidatorType = ValidatorType;
var UrlPartType = /** @class */ (function () {
    function UrlPartType() {
    }
    UrlPartType.HostName = "HostName";
    UrlPartType.PagePath = "PagePath";
    UrlPartType.PageUrl = "PageUrl";
    return UrlPartType;
}());
exports.UrlPartType = UrlPartType;
var ComparisonOperatorType = /** @class */ (function () {
    function ComparisonOperatorType() {
    }
    ComparisonOperatorType.EqualS = "Equals";
    ComparisonOperatorType.Contains = "Contains";
    ComparisonOperatorType.EqualsAny = "EqualsAny";
    ComparisonOperatorType.ContainsAny = "ContainsAny";
    return ComparisonOperatorType;
}());
exports.ComparisonOperatorType = ComparisonOperatorType;
var LogicalOperatorType = /** @class */ (function () {
    function LogicalOperatorType() {
    }
    LogicalOperatorType.Or = "Or";
    LogicalOperatorType.And = "And";
    return LogicalOperatorType;
}());
exports.LogicalOperatorType = LogicalOperatorType;
var ActionType = /** @class */ (function () {
    function ActionType() {
    }
    ActionType.IgnoreAction = "Ignore";
    ActionType.CancelAction = "Cancel";
    ActionType.QueueAction = "Queue";
    return ActionType;
}());
exports.ActionType = ActionType;

},{}],8:[function(require,module,exports){
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.KnownUser = void 0;
var UserInQueueService_1 = require("./UserInQueueService");
var UserInQueueStateCookieRepository_1 = require("./UserInQueueStateCookieRepository");
var Models_1 = require("./Models");
var QueueITHelpers_1 = require("./QueueITHelpers");
var IntegrationConfigHelpers = __importStar(require("./IntegrationConfig/IntegrationConfigHelpers"));
var KnownUser = /** @class */ (function () {
    function KnownUser() {
    }
    KnownUser.getUserInQueueService = function (httpContextProvider) {
        if (!this.UserInQueueService) {
            return new UserInQueueService_1.UserInQueueService(httpContextProvider, new UserInQueueStateCookieRepository_1.UserInQueueStateCookieRepository(httpContextProvider));
        }
        return this.UserInQueueService;
    };
    KnownUser.isQueueAjaxCall = function (httpContextProvider) {
        return !!httpContextProvider.getHttpRequest().getHeader(this.QueueITAjaxHeaderKey);
    };
    KnownUser.generateTargetUrl = function (originalTargetUrl, httpContextProvider) {
        return !this.isQueueAjaxCall(httpContextProvider) ?
            originalTargetUrl :
            QueueITHelpers_1.Utils.decodeUrl(httpContextProvider.getHttpRequest().getHeader(this.QueueITAjaxHeaderKey));
    };
    KnownUser.logExtraRequestDetails = function (debugEntries, httpContextProvider) {
        debugEntries["ServerUtcTime"] = (new Date()).toISOString().split('.')[0] + "Z";
        debugEntries["RequestIP"] = httpContextProvider.getHttpRequest().getUserHostAddress();
        debugEntries["RequestHttpHeader_Via"] = httpContextProvider.getHttpRequest().getHeader("Via");
        debugEntries["RequestHttpHeader_Forwarded"] = httpContextProvider.getHttpRequest().getHeader("Forwarded");
        debugEntries["RequestHttpHeader_XForwardedFor"] = httpContextProvider.getHttpRequest().getHeader("X-Forwarded-For");
        debugEntries["RequestHttpHeader_XForwardedHost"] = httpContextProvider.getHttpRequest().getHeader("X-Forwarded-Host");
        debugEntries["RequestHttpHeader_XForwardedProto"] = httpContextProvider.getHttpRequest().getHeader("X-Forwarded-Proto");
    };
    KnownUser.setDebugCookie = function (debugEntries, httpContextProvider) {
        var cookieValue = "";
        for (var key in debugEntries) {
            cookieValue += key + "=" + debugEntries[key] + "|";
        }
        if (cookieValue.lastIndexOf("|") === cookieValue.length - 1) {
            cookieValue = cookieValue.substring(0, cookieValue.length - 1);
        }
        if (!cookieValue)
            return;
        httpContextProvider.getHttpResponse().setCookie(this.QueueITDebugKey, cookieValue, null, QueueITHelpers_1.Utils.getCurrentTime() + 20 * 60, // now + 20 mins
        false, false);
    };
    KnownUser._resolveQueueRequestByLocalConfig = function (targetUrl, queueitToken, queueConfig, customerId, secretKey, httpContextProvider, debugEntries, isDebug) {
        if (isDebug) {
            debugEntries["SdkVersion"] = UserInQueueService_1.UserInQueueService.SDK_VERSION;
            debugEntries["TargetUrl"] = targetUrl;
            debugEntries["QueueitToken"] = queueitToken;
            debugEntries["OriginalUrl"] = httpContextProvider.getHttpRequest().getAbsoluteUri();
            debugEntries["QueueConfig"] = queueConfig !== null ? queueConfig.getString() : "NULL";
            this.logExtraRequestDetails(debugEntries, httpContextProvider);
        }
        if (!customerId)
            throw new Models_1.KnownUserException("customerId can not be null or empty.");
        if (!secretKey)
            throw new Models_1.KnownUserException("secretKey can not be null or empty.");
        if (!queueConfig)
            throw new Models_1.KnownUserException("queueConfig can not be null.");
        if (!queueConfig.eventId)
            throw new Models_1.KnownUserException("queueConfig.eventId can not be null or empty.");
        if (!queueConfig.queueDomain)
            throw new Models_1.KnownUserException("queueConfig.queueDomain can not be null or empty.");
        if (queueConfig.cookieValidityMinute <= 0)
            throw new Models_1.KnownUserException("queueConfig.cookieValidityMinute should be integer greater than 0.");
        var userInQueueService = this.getUserInQueueService(httpContextProvider);
        var result = userInQueueService.validateQueueRequest(targetUrl, queueitToken, queueConfig, customerId, secretKey);
        result.isAjaxResult = this.isQueueAjaxCall(httpContextProvider);
        return result;
    };
    KnownUser._cancelRequestByLocalConfig = function (targetUrl, queueitToken, cancelConfig, customerId, secretKey, httpContextProvider, debugEntries, isDebug) {
        targetUrl = this.generateTargetUrl(targetUrl, httpContextProvider);
        if (isDebug) {
            debugEntries["SdkVersion"] = UserInQueueService_1.UserInQueueService.SDK_VERSION;
            debugEntries["TargetUrl"] = targetUrl;
            debugEntries["QueueitToken"] = queueitToken;
            debugEntries["CancelConfig"] = cancelConfig !== null ? cancelConfig.getString() : "NULL";
            debugEntries["OriginalUrl"] = httpContextProvider.getHttpRequest().getAbsoluteUri();
            this.logExtraRequestDetails(debugEntries, httpContextProvider);
        }
        if (!targetUrl)
            throw new Models_1.KnownUserException("targetUrl can not be null or empty.");
        if (!customerId)
            throw new Models_1.KnownUserException("customerId can not be null or empty.");
        if (!secretKey)
            throw new Models_1.KnownUserException("secretKey can not be null or empty.");
        if (!cancelConfig)
            throw new Models_1.KnownUserException("cancelConfig can not be null.");
        if (!cancelConfig.eventId)
            throw new Models_1.KnownUserException("cancelConfig.eventId can not be null or empty.");
        if (!cancelConfig.queueDomain)
            throw new Models_1.KnownUserException("cancelConfig.queueDomain can not be null or empty.");
        var userInQueueService = this.getUserInQueueService(httpContextProvider);
        var result = userInQueueService.validateCancelRequest(targetUrl, cancelConfig, customerId, secretKey);
        result.isAjaxResult = this.isQueueAjaxCall(httpContextProvider);
        return result;
    };
    KnownUser.handleQueueAction = function (currentUrlWithoutQueueITToken, queueitToken, customerIntegrationInfo, customerId, secretKey, matchedConfig, httpContextProvider, debugEntries, isDebug) {
        var targetUrl;
        switch (matchedConfig.RedirectLogic) {
            case "ForcedTargetUrl":
                targetUrl = matchedConfig.ForcedTargetUrl;
                break;
            case "EventTargetUrl":
                targetUrl = "";
                break;
            default:
                targetUrl = this.generateTargetUrl(currentUrlWithoutQueueITToken, httpContextProvider);
                break;
        }
        var queueEventConfig = new Models_1.QueueEventConfig(matchedConfig.EventId, matchedConfig.LayoutName, matchedConfig.Culture, matchedConfig.QueueDomain, matchedConfig.ExtendCookieValidity, matchedConfig.CookieValidityMinute, matchedConfig.CookieDomain, matchedConfig.IsCookieHttpOnly, matchedConfig.IsCookieSecure, customerIntegrationInfo.Version, matchedConfig.Name);
        return this._resolveQueueRequestByLocalConfig(targetUrl, queueitToken, queueEventConfig, customerId, secretKey, httpContextProvider, debugEntries, isDebug);
    };
    KnownUser.handleCancelAction = function (currentUrlWithoutQueueITToken, queueitToken, customerIntegrationInfo, customerId, secretKey, matchedConfig, httpContextProvider, debugEntries, isDebug) {
        var cancelEventConfig = new Models_1.CancelEventConfig(matchedConfig.EventId, matchedConfig.QueueDomain, matchedConfig.CookieDomain, matchedConfig.IsCookieHttpOnly, matchedConfig.IsCookieSecure, customerIntegrationInfo.Version, matchedConfig.Name);
        var targetUrl = this.generateTargetUrl(currentUrlWithoutQueueITToken, httpContextProvider);
        return this._cancelRequestByLocalConfig(targetUrl, queueitToken, cancelEventConfig, customerId, secretKey, httpContextProvider, debugEntries, isDebug);
    };
    KnownUser.handleIgnoreAction = function (httpContextProvider, actionName) {
        var userInQueueService = this.getUserInQueueService(httpContextProvider);
        var result = userInQueueService.getIgnoreResult(actionName);
        result.isAjaxResult = this.isQueueAjaxCall(httpContextProvider);
        return result;
    };
    KnownUser.extendQueueCookie = function (eventId, cookieValidityMinute, cookieDomain, isCookieHttpOnly, isCookieSecure, secretKey, httpContextProvider) {
        if (!eventId)
            throw new Models_1.KnownUserException("eventId can not be null or empty.");
        if (!secretKey)
            throw new Models_1.KnownUserException("secretKey can not be null or empty.");
        if (cookieValidityMinute <= 0)
            throw new Models_1.KnownUserException("cookieValidityMinute should be integer greater than 0.");
        var userInQueueService = this.getUserInQueueService(httpContextProvider);
        userInQueueService.extendQueueCookie(eventId, cookieValidityMinute, cookieDomain, isCookieHttpOnly, isCookieSecure, secretKey);
    };
    KnownUser.resolveQueueRequestByLocalConfig = function (targetUrl, queueitToken, queueConfig, customerId, secretKey, httpContextProvider) {
        var debugEntries = {};
        var connectorDiagnostics = QueueITHelpers_1.ConnectorDiagnostics.verify(customerId, secretKey, queueitToken);
        if (connectorDiagnostics.hasError)
            return connectorDiagnostics.validationResult;
        try {
            targetUrl = this.generateTargetUrl(targetUrl, httpContextProvider);
            return this._resolveQueueRequestByLocalConfig(targetUrl, queueitToken, queueConfig, customerId, secretKey, httpContextProvider, debugEntries, connectorDiagnostics.isEnabled);
        }
        catch (e) {
            if (connectorDiagnostics.isEnabled)
                debugEntries["Exception"] = e.message;
            throw e;
        }
        finally {
            this.setDebugCookie(debugEntries, httpContextProvider);
        }
    };
    KnownUser.validateRequestByIntegrationConfig = function (currentUrlWithoutQueueITToken, queueitToken, integrationsConfigString, customerId, secretKey, httpContextProvider) {
        var debugEntries = {};
        var customerIntegrationInfo;
        var connectorDiagnostics = QueueITHelpers_1.ConnectorDiagnostics.verify(customerId, secretKey, queueitToken);
        if (connectorDiagnostics.hasError)
            return connectorDiagnostics.validationResult;
        try {
            if (connectorDiagnostics.isEnabled) {
                debugEntries["SdkVersion"] = UserInQueueService_1.UserInQueueService.SDK_VERSION;
                debugEntries["PureUrl"] = currentUrlWithoutQueueITToken;
                debugEntries["QueueitToken"] = queueitToken;
                debugEntries["OriginalUrl"] = httpContextProvider.getHttpRequest().getAbsoluteUri();
                this.logExtraRequestDetails(debugEntries, httpContextProvider);
            }
            customerIntegrationInfo = JSON.parse(integrationsConfigString);
            if (connectorDiagnostics.isEnabled) {
                debugEntries["ConfigVersion"] = customerIntegrationInfo && customerIntegrationInfo.Version ? customerIntegrationInfo.Version.toString() : "NULL";
            }
            if (!currentUrlWithoutQueueITToken)
                throw new Models_1.KnownUserException("currentUrlWithoutQueueITToken can not be null or empty.");
            if (!customerIntegrationInfo || !customerIntegrationInfo.Version)
                throw new Models_1.KnownUserException("integrationsConfigString can not be null or empty.");
            var configEvaluator = new IntegrationConfigHelpers.IntegrationEvaluator();
            var matchedConfig = configEvaluator.getMatchedIntegrationConfig(customerIntegrationInfo, currentUrlWithoutQueueITToken, httpContextProvider.getHttpRequest());
            if (connectorDiagnostics.isEnabled) {
                debugEntries["MatchedConfig"] = matchedConfig ? matchedConfig.Name : "NULL";
            }
            if (!matchedConfig)
                return new Models_1.RequestValidationResult(null, null, null, null, null, null);
            switch (matchedConfig.ActionType) {
                case Models_1.ActionTypes.QueueAction: {
                    return this.handleQueueAction(currentUrlWithoutQueueITToken, queueitToken, customerIntegrationInfo, customerId, secretKey, matchedConfig, httpContextProvider, debugEntries, connectorDiagnostics.isEnabled);
                }
                case Models_1.ActionTypes.CancelAction: {
                    return this.handleCancelAction(currentUrlWithoutQueueITToken, queueitToken, customerIntegrationInfo, customerId, secretKey, matchedConfig, httpContextProvider, debugEntries, connectorDiagnostics.isEnabled);
                }
                default: {
                    return this.handleIgnoreAction(httpContextProvider, matchedConfig.Name);
                }
            }
        }
        catch (e) {
            if (connectorDiagnostics.isEnabled)
                debugEntries["Exception"] = e.message;
            throw e;
        }
        finally {
            this.setDebugCookie(debugEntries, httpContextProvider);
        }
    };
    KnownUser.cancelRequestByLocalConfig = function (targetUrl, queueitToken, cancelConfig, customerId, secretKey, httpContextProvider) {
        var debugEntries = {};
        var connectorDiagnostics = QueueITHelpers_1.ConnectorDiagnostics.verify(customerId, secretKey, queueitToken);
        if (connectorDiagnostics.hasError)
            return connectorDiagnostics.validationResult;
        try {
            return this._cancelRequestByLocalConfig(targetUrl, queueitToken, cancelConfig, customerId, secretKey, httpContextProvider, debugEntries, connectorDiagnostics.isEnabled);
        }
        catch (e) {
            if (connectorDiagnostics.isEnabled)
                debugEntries["Exception"] = e.message;
            throw e;
        }
        finally {
            this.setDebugCookie(debugEntries, httpContextProvider);
        }
    };
    KnownUser.QueueITTokenKey = "queueittoken";
    KnownUser.QueueITDebugKey = "queueitdebug";
    KnownUser.QueueITAjaxHeaderKey = "x-queueit-ajaxpageurl";
    KnownUser.UserInQueueService = null;
    return KnownUser;
}());
exports.KnownUser = KnownUser;

},{"./IntegrationConfig/IntegrationConfigHelpers":6,"./Models":9,"./QueueITHelpers":10,"./UserInQueueService":11,"./UserInQueueStateCookieRepository":12}],9:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ActionTypes = exports.KnownUserException = exports.RequestValidationResult = exports.CancelEventConfig = exports.QueueEventConfig = void 0;
var QueueITHelpers_1 = require("./QueueITHelpers");
var QueueEventConfig = /** @class */ (function () {
    function QueueEventConfig(eventId, layoutName, culture, queueDomain, extendCookieValidity, cookieValidityMinute, cookieDomain, isCookieHttpOnly, isCookieSecure, version, actionName) {
        if (actionName === void 0) { actionName = 'unspecified'; }
        this.eventId = eventId;
        this.layoutName = layoutName;
        this.culture = culture;
        this.queueDomain = queueDomain;
        this.extendCookieValidity = extendCookieValidity;
        this.cookieValidityMinute = cookieValidityMinute;
        this.cookieDomain = cookieDomain;
        this.isCookieHttpOnly = isCookieHttpOnly;
        this.isCookieSecure = isCookieSecure;
        this.version = version;
        this.actionName = actionName;
    }
    QueueEventConfig.prototype.getString = function () {
        return "EventId:" + this.eventId + "&Version:" + this.version + "&ActionName:" + this.actionName + "&QueueDomain:" + this.queueDomain +
            ("&CookieDomain:" + this.cookieDomain + "&IsCookieHttpOnly:" + this.isCookieHttpOnly + "&IsCookieSecure:" + this.isCookieSecure) +
            ("&ExtendCookieValidity:" + this.extendCookieValidity) +
            ("&CookieValidityMinute:" + this.cookieValidityMinute + "&LayoutName:" + this.layoutName + "&Culture:" + this.culture);
    };
    return QueueEventConfig;
}());
exports.QueueEventConfig = QueueEventConfig;
var CancelEventConfig = /** @class */ (function () {
    function CancelEventConfig(eventId, queueDomain, cookieDomain, isCookieHttpOnly, isCookieSecure, version, actionName) {
        if (actionName === void 0) { actionName = 'unspecified'; }
        this.eventId = eventId;
        this.queueDomain = queueDomain;
        this.cookieDomain = cookieDomain;
        this.isCookieHttpOnly = isCookieHttpOnly;
        this.isCookieSecure = isCookieSecure;
        this.version = version;
        this.actionName = actionName;
    }
    CancelEventConfig.prototype.getString = function () {
        return "EventId:" + this.eventId + "&Version:" + this.version +
            ("&QueueDomain:" + this.queueDomain) +
            ("&CookieDomain:" + this.cookieDomain + "&IsCookieHttpOnly:" + this.isCookieHttpOnly + "&IsCookieSecure:" + this.isCookieSecure) +
            ("&ActionName:" + this.actionName);
    };
    return CancelEventConfig;
}());
exports.CancelEventConfig = CancelEventConfig;
var RequestValidationResult = /** @class */ (function () {
    function RequestValidationResult(actionType, eventId, queueId, redirectUrl, redirectType, actionName) {
        this.actionType = actionType;
        this.eventId = eventId;
        this.queueId = queueId;
        this.redirectUrl = redirectUrl;
        this.redirectType = redirectType;
        this.actionName = actionName;
    }
    RequestValidationResult.prototype.doRedirect = function () {
        return !!this.redirectUrl;
    };
    RequestValidationResult.prototype.getAjaxQueueRedirectHeaderKey = function () {
        return "x-queueit-redirect";
    };
    RequestValidationResult.prototype.getAjaxRedirectUrl = function () {
        if (this.redirectUrl) {
            return QueueITHelpers_1.Utils.encodeUrl(this.redirectUrl);
        }
        return "";
    };
    return RequestValidationResult;
}());
exports.RequestValidationResult = RequestValidationResult;
var KnownUserException = /** @class */ (function () {
    function KnownUserException(message) {
        this.message = message;
    }
    return KnownUserException;
}());
exports.KnownUserException = KnownUserException;
var ActionTypes = /** @class */ (function () {
    function ActionTypes() {
    }
    ActionTypes.QueueAction = "Queue";
    ActionTypes.CancelAction = "Cancel";
    ActionTypes.IgnoreAction = "Ignore";
    return ActionTypes;
}());
exports.ActionTypes = ActionTypes;

},{"./QueueITHelpers":10}],10:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ConnectorDiagnostics = exports.CookieHelper = exports.QueueParameterHelper = exports.QueueUrlParams = exports.Utils = exports.ErrorCode = void 0;
var Models_1 = require("./Models");
var ErrorCode;
(function (ErrorCode) {
    ErrorCode["Hash"] = "hash";
    ErrorCode["Timestamp"] = "timestamp";
    ErrorCode["CookieSessionState"] = "connector/sessionstate";
})(ErrorCode = exports.ErrorCode || (exports.ErrorCode = {}));
var Utils = /** @class */ (function () {
    function Utils() {
    }
    Utils.encodeUrl = function (url) {
        if (!url)
            return "";
        return encodeURIComponent(url).replace(/[!'()*]/g, function (c) {
            // More stringent in adhering to RFC 3986 (which reserves!, ', (, ), and *)
            // https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/encodeURIComponent
            return '%' + c.charCodeAt(0).toString(16);
        });
    };
    Utils.decodeUrl = function (url) {
        return decodeURIComponent(url);
    };
    Utils.generateSHA256Hash = function (secretKey, stringToHash) {
        throw new Models_1.KnownUserException("Missing implementation for generateSHA256Hash");
    };
    Utils.endsWith = function (str, search) {
        if (str === search)
            return true;
        if (!str || !search)
            return false;
        return str.substring(str.length - search.length, str.length) === search;
    };
    Utils.getCurrentTime = function () {
        return Math.floor(new Date().getTime() / 1000);
    };
    return Utils;
}());
exports.Utils = Utils;
var QueueUrlParams = /** @class */ (function () {
    function QueueUrlParams() {
        this.timeStamp = 0;
        this.extendableCookie = false;
    }
    return QueueUrlParams;
}());
exports.QueueUrlParams = QueueUrlParams;
var QueueParameterHelper = /** @class */ (function () {
    function QueueParameterHelper() {
    }
    QueueParameterHelper.extractQueueParams = function (queueitToken) {
        if (!queueitToken) {
            return null;
        }
        var result = new QueueUrlParams();
        result.queueITToken = queueitToken;
        var paramList = result.queueITToken.split(QueueParameterHelper.KeyValueSeparatorGroupChar);
        for (var _i = 0, paramList_1 = paramList; _i < paramList_1.length; _i++) {
            var paramKeyValue = paramList_1[_i];
            var keyValueArr = paramKeyValue.split(QueueParameterHelper.KeyValueSeparatorChar);
            if (keyValueArr.length !== 2) {
                continue;
            }
            switch (keyValueArr[0]) {
                case QueueParameterHelper.HashKey:
                    result.hashCode = keyValueArr[1] || "";
                    break;
                case QueueParameterHelper.TimeStampKey: {
                    result.timeStamp = parseInt(keyValueArr[1]);
                    if (!result.timeStamp) {
                        result.timeStamp = 0;
                    }
                    break;
                }
                case QueueParameterHelper.CookieValidityMinutesKey: {
                    result.cookieValidityMinutes = parseInt(keyValueArr[1]);
                    if (!result.cookieValidityMinutes) {
                        result.cookieValidityMinutes = null;
                    }
                    break;
                }
                case QueueParameterHelper.EventIdKey:
                    result.eventId = keyValueArr[1] || "";
                    break;
                case QueueParameterHelper.ExtendableCookieKey: {
                    var extendCookie = (keyValueArr[1] || "false").toLowerCase();
                    result.extendableCookie = extendCookie === "true";
                    break;
                }
                case QueueParameterHelper.QueueIdKey:
                    result.queueId = keyValueArr[1] || "";
                    break;
                case QueueParameterHelper.RedirectTypeKey:
                    result.redirectType = keyValueArr[1] || "";
                    break;
                case QueueParameterHelper.HashedIPKey:
                    result.hashedIp = keyValueArr[1] || "";
                    break;
            }
        }
        var hashWithPrefix = "" + QueueParameterHelper.KeyValueSeparatorGroupChar + QueueParameterHelper.HashKey + QueueParameterHelper.KeyValueSeparatorChar + result.hashCode;
        result.queueITTokenWithoutHash = result.queueITToken.replace(hashWithPrefix, "");
        return result;
    };
    QueueParameterHelper.TimeStampKey = "ts";
    QueueParameterHelper.ExtendableCookieKey = "ce";
    QueueParameterHelper.CookieValidityMinutesKey = "cv";
    QueueParameterHelper.HashKey = "h";
    QueueParameterHelper.EventIdKey = "e";
    QueueParameterHelper.QueueIdKey = "q";
    QueueParameterHelper.RedirectTypeKey = "rt";
    QueueParameterHelper.HashedIPKey = 'hip';
    QueueParameterHelper.KeyValueSeparatorChar = '_';
    QueueParameterHelper.KeyValueSeparatorGroupChar = '~';
    return QueueParameterHelper;
}());
exports.QueueParameterHelper = QueueParameterHelper;
var CookieHelper = /** @class */ (function () {
    function CookieHelper() {
    }
    CookieHelper.toMapFromValue = function (cookieValue) {
        try {
            var result = {};
            var items = cookieValue.split('&');
            for (var _i = 0, items_1 = items; _i < items_1.length; _i++) {
                var item = items_1[_i];
                var keyValue = item.split('=');
                result[keyValue[0]] = keyValue[1];
            }
            return result;
        }
        catch (_a) {
            return {};
        }
    };
    CookieHelper.toValueFromKeyValueCollection = function (cookieValues) {
        var values = new Array();
        for (var _i = 0, cookieValues_1 = cookieValues; _i < cookieValues_1.length; _i++) {
            var keyVal = cookieValues_1[_i];
            values.push(keyVal.key + "=" + keyVal.value);
        }
        return values.join("&");
    };
    return CookieHelper;
}());
exports.CookieHelper = CookieHelper;
var ConnectorDiagnostics = /** @class */ (function () {
    function ConnectorDiagnostics() {
        this.isEnabled = false;
        this.hasError = false;
    }
    ConnectorDiagnostics.prototype.setStateWithTokenError = function (customerId, errorCode) {
        this.hasError = true;
        var redirectUrl = "https://" + customerId + ".api2.queue-it.net/" + customerId + "/diagnostics/connector/error/?code=" + errorCode;
        this.validationResult = new Models_1.RequestValidationResult("ConnectorDiagnosticsRedirect", null, null, redirectUrl, null, null);
    };
    ConnectorDiagnostics.prototype.setStateWithSetupError = function () {
        this.hasError = true;
        this.validationResult = new Models_1.RequestValidationResult("ConnectorDiagnosticsRedirect", null, null, "https://api2.queue-it.net/diagnostics/connector/error/?code=setup", null, null);
    };
    ConnectorDiagnostics.verify = function (customerId, secretKey, queueitToken) {
        var diagnostics = new ConnectorDiagnostics();
        var qParams = QueueParameterHelper.extractQueueParams(queueitToken);
        if (qParams == null)
            return diagnostics;
        if (qParams.redirectType == null)
            return diagnostics;
        if (qParams.redirectType !== "debug")
            return diagnostics;
        if (!(customerId && secretKey)) {
            diagnostics.setStateWithSetupError();
            return diagnostics;
        }
        if (Utils.generateSHA256Hash(secretKey, qParams.queueITTokenWithoutHash) != qParams.hashCode) {
            diagnostics.setStateWithTokenError(customerId, ErrorCode.Hash);
            return diagnostics;
        }
        if (qParams.timeStamp < Utils.getCurrentTime()) {
            diagnostics.setStateWithTokenError(customerId, ErrorCode.Timestamp);
            return diagnostics;
        }
        diagnostics.isEnabled = true;
        return diagnostics;
    };
    return ConnectorDiagnostics;
}());
exports.ConnectorDiagnostics = ConnectorDiagnostics;

},{"./Models":9}],11:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UserInQueueService = void 0;
var QueueITHelpers_1 = require("./QueueITHelpers");
var Models_1 = require("./Models");
var UserInQueueService = /** @class */ (function () {
    function UserInQueueService(httpContextProvider, userInQueueStateRepository) {
        this.httpContextProvider = httpContextProvider;
        this.userInQueueStateRepository = userInQueueStateRepository;
    }
    UserInQueueService.prototype.getValidTokenResult = function (config, queueParams, secretKey) {
        this.userInQueueStateRepository.store(config.eventId, queueParams.queueId, queueParams.cookieValidityMinutes, config.cookieDomain, config.isCookieHttpOnly, config.isCookieSecure, queueParams.redirectType, queueParams.hashedIp, secretKey);
        return new Models_1.RequestValidationResult(Models_1.ActionTypes.QueueAction, config.eventId, queueParams.queueId, null, queueParams.redirectType, config.actionName);
    };
    UserInQueueService.prototype.getErrorResult = function (customerId, targetUrl, config, qParams, errorCode, state) {
        var queueItTokenParam = qParams ? "&queueittoken=" + qParams.queueITToken : '';
        var query = this.getQueryString(customerId, config.eventId, config.version, config.culture, config.layoutName, config.actionName, state.getInvalidCookieReason()) +
            queueItTokenParam +
            ("&ts=" + QueueITHelpers_1.Utils.getCurrentTime()) +
            (targetUrl ? "&t=" + QueueITHelpers_1.Utils.encodeUrl(targetUrl) : "");
        var uriPath = "error/" + errorCode + "/";
        var redirectUrl = this.generateRedirectUrl(config.queueDomain, uriPath, query);
        return new Models_1.RequestValidationResult(Models_1.ActionTypes.QueueAction, config.eventId, null, redirectUrl, null, config.actionName);
    };
    UserInQueueService.prototype.getQueueResult = function (targetUrl, config, customerId, state) {
        var query = this.getQueryString(customerId, config.eventId, config.version, config.culture, config.layoutName, config.actionName) +
            (targetUrl ? "&t=" + QueueITHelpers_1.Utils.encodeUrl(targetUrl) : "");
        var redirectUrl = this.generateRedirectUrl(config.queueDomain, "", query);
        return new Models_1.RequestValidationResult(Models_1.ActionTypes.QueueAction, config.eventId, null, redirectUrl, null, config.actionName);
    };
    UserInQueueService.prototype.getQueryString = function (customerId, eventId, configVersion, culture, layoutName, actionName, invalidCookieReason) {
        var queryStringList = new Array();
        queryStringList.push("c=" + QueueITHelpers_1.Utils.encodeUrl(customerId));
        queryStringList.push("e=" + QueueITHelpers_1.Utils.encodeUrl(eventId));
        queryStringList.push("ver=" + UserInQueueService.SDK_VERSION);
        queryStringList.push("cver=" + configVersion);
        queryStringList.push("man=" + QueueITHelpers_1.Utils.encodeUrl(actionName));
        if (culture)
            queryStringList.push("cid=" + QueueITHelpers_1.Utils.encodeUrl(culture));
        if (layoutName)
            queryStringList.push("l=" + QueueITHelpers_1.Utils.encodeUrl(layoutName));
        if (invalidCookieReason)
            queryStringList.push("icr=" + QueueITHelpers_1.Utils.encodeUrl(invalidCookieReason));
        return queryStringList.join("&");
    };
    UserInQueueService.prototype.generateRedirectUrl = function (queueDomain, uriPath, query) {
        if (!QueueITHelpers_1.Utils.endsWith(queueDomain, "/"))
            queueDomain = queueDomain + "/";
        return "https://" + queueDomain + uriPath + "?" + query;
    };
    UserInQueueService.prototype.validateQueueRequest = function (targetUrl, queueitToken, config, customerId, secretKey) {
        var state = this.userInQueueStateRepository.getState(config.eventId, config.cookieValidityMinute, secretKey, true);
        if (state.isValid) {
            if (state.isStateExtendable() && config.extendCookieValidity) {
                this.userInQueueStateRepository.store(config.eventId, state.queueId, null, config.cookieDomain, config.isCookieHttpOnly, config.isCookieSecure, state.redirectType, state.hashedIp, secretKey);
            }
            return new Models_1.RequestValidationResult(Models_1.ActionTypes.QueueAction, config.eventId, state.queueId, null, state.redirectType, config.actionName);
        }
        var queueTokenParams = QueueITHelpers_1.QueueParameterHelper.extractQueueParams(queueitToken);
        var requestValidationResult;
        var isTokenValid = false;
        if (queueTokenParams) {
            var tokenValidationResult = this.validateToken(config, queueTokenParams, secretKey);
            isTokenValid = tokenValidationResult.isValid;
            if (isTokenValid) {
                requestValidationResult = this.getValidTokenResult(config, queueTokenParams, secretKey);
            }
            else {
                requestValidationResult = this.getErrorResult(customerId, targetUrl, config, queueTokenParams, tokenValidationResult.errorCode, state);
            }
        }
        else if (state.isBoundToAnotherIp) {
            requestValidationResult = this.getErrorResult(customerId, targetUrl, config, queueTokenParams, QueueITHelpers_1.ErrorCode.CookieSessionState, state);
        }
        else {
            requestValidationResult = this.getQueueResult(targetUrl, config, customerId, state);
        }
        if (state.isFound && !isTokenValid) {
            this.userInQueueStateRepository.cancelQueueCookie(config.eventId, config.cookieDomain, config.isCookieHttpOnly, config.isCookieSecure);
        }
        return requestValidationResult;
    };
    UserInQueueService.prototype.validateCancelRequest = function (targetUrl, config, customerId, secretKey) {
        //we do not care how long cookie is valid while canceling cookie
        var state = this.userInQueueStateRepository.getState(config.eventId, -1, secretKey, false);
        if (state.isValid) {
            this.userInQueueStateRepository.cancelQueueCookie(config.eventId, config.cookieDomain, config.isCookieHttpOnly, config.isCookieSecure);
            var query = this.getQueryString(customerId, config.eventId, config.version, null, null, config.actionName) +
                (targetUrl ? "&r=" + QueueITHelpers_1.Utils.encodeUrl(targetUrl) : "");
            var uriPath = "cancel/" + customerId + "/" + config.eventId;
            if (state.queueId) {
                uriPath += "/" + state.queueId;
            }
            var redirectUrl = this.generateRedirectUrl(config.queueDomain, uriPath, query);
            return new Models_1.RequestValidationResult(Models_1.ActionTypes.CancelAction, config.eventId, state.queueId, redirectUrl, state.redirectType, config.actionName);
        }
        else {
            return new Models_1.RequestValidationResult(Models_1.ActionTypes.CancelAction, config.eventId, null, null, null, config.actionName);
        }
    };
    UserInQueueService.prototype.extendQueueCookie = function (eventId, cookieValidityMinutes, cookieDomain, isCookieHttpOnly, isCookieSecure, secretKey) {
        this.userInQueueStateRepository.reissueQueueCookie(eventId, cookieValidityMinutes, cookieDomain, isCookieHttpOnly, isCookieSecure, secretKey);
    };
    UserInQueueService.prototype.getIgnoreResult = function (actionName) {
        return new Models_1.RequestValidationResult(Models_1.ActionTypes.IgnoreAction, null, null, null, null, actionName);
    };
    UserInQueueService.prototype.validateToken = function (config, queueParams, secretKey) {
        var calculatedHash = QueueITHelpers_1.Utils.generateSHA256Hash(secretKey, queueParams.queueITTokenWithoutHash);
        if (calculatedHash !== queueParams.hashCode)
            return new TokenValidationResult(false, "hash");
        if (queueParams.eventId !== config.eventId)
            return new TokenValidationResult(false, "eventid");
        if (queueParams.timeStamp < QueueITHelpers_1.Utils.getCurrentTime())
            return new TokenValidationResult(false, "timestamp");
        var clientIp = this.httpContextProvider.getHttpRequest().getUserHostAddress();
        if (queueParams.hashedIp && clientIp) {
            var hashedIp = QueueITHelpers_1.Utils.generateSHA256Hash(secretKey, clientIp);
            if (hashedIp !== queueParams.hashedIp) {
                return new TokenValidationResult(false, "ip");
            }
        }
        return new TokenValidationResult(true, null);
    };
    UserInQueueService.SDK_VERSION = "v3-javascript-" + "3.7.4";
    return UserInQueueService;
}());
exports.UserInQueueService = UserInQueueService;
var TokenValidationResult = /** @class */ (function () {
    function TokenValidationResult(isValid, errorCode) {
        this.isValid = isValid;
        this.errorCode = errorCode;
    }
    return TokenValidationResult;
}());

},{"./Models":9,"./QueueITHelpers":10}],12:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.StateInfo = exports.UserInQueueStateCookieRepository = exports.QueueItAcceptedCookie = exports.CookieValidationResult = void 0;
var QueueITHelpers_1 = require("./QueueITHelpers");
var CookieValidationResult;
(function (CookieValidationResult) {
    CookieValidationResult[CookieValidationResult["NotFound"] = 0] = "NotFound";
    CookieValidationResult[CookieValidationResult["Expired"] = 1] = "Expired";
    CookieValidationResult[CookieValidationResult["WaitingRoomMismatch"] = 2] = "WaitingRoomMismatch";
    CookieValidationResult[CookieValidationResult["HashMismatch"] = 3] = "HashMismatch";
    CookieValidationResult[CookieValidationResult["Error"] = 4] = "Error";
    CookieValidationResult[CookieValidationResult["Valid"] = 5] = "Valid";
    CookieValidationResult[CookieValidationResult["IpBindingMismatch"] = 6] = "IpBindingMismatch";
})(CookieValidationResult = exports.CookieValidationResult || (exports.CookieValidationResult = {}));
var QueueItAcceptedCookie = /** @class */ (function () {
    function QueueItAcceptedCookie(storedHash, issueTimeString, queueId, eventIdFromCookie, redirectType, fixedCookieValidityMinutes, isCookieHttpOnly, isCookieSecure, hashedIp) {
        this.storedHash = storedHash;
        this.issueTimeString = issueTimeString;
        this.queueId = queueId;
        this.eventIdFromCookie = eventIdFromCookie;
        this.redirectType = redirectType;
        this.fixedCookieValidityMinutes = fixedCookieValidityMinutes;
        this.isCookieHttpOnly = isCookieHttpOnly;
        this.isCookieSecure = isCookieSecure;
        this.hashedIp = hashedIp;
    }
    QueueItAcceptedCookie.fromCookieHeader = function (cookieHeaderValue) {
        var cookieValueMap = QueueITHelpers_1.CookieHelper.toMapFromValue(cookieHeaderValue);
        var storedHash = cookieValueMap[QueueItAcceptedCookie.HashKey] || "";
        var issueTimeString = cookieValueMap[QueueItAcceptedCookie.IssueTimeKey] || "";
        var queueId = cookieValueMap[QueueItAcceptedCookie.QueueIdKey] || "";
        var eventIdFromCookie = cookieValueMap[QueueItAcceptedCookie.EventIdKey] || "";
        var redirectType = cookieValueMap[QueueItAcceptedCookie.RedirectTypeKey] || "";
        var fixedCookieValidityMinutes = cookieValueMap[QueueItAcceptedCookie.FixedCookieValidityMinutesKey] || "";
        var isCookieHttpOnly = cookieValueMap[QueueItAcceptedCookie.IsCookieHttpOnly] || false;
        var isCookieSecure = cookieValueMap[QueueItAcceptedCookie.IsCookieSecure] || false;
        var hashedIpValue = cookieValueMap[QueueItAcceptedCookie.HashedIpKey] || "";
        return new QueueItAcceptedCookie(storedHash, issueTimeString, queueId, eventIdFromCookie, redirectType, fixedCookieValidityMinutes, isCookieHttpOnly, isCookieSecure, hashedIpValue);
    };
    QueueItAcceptedCookie.HashKey = "Hash";
    QueueItAcceptedCookie.IssueTimeKey = "IssueTime";
    QueueItAcceptedCookie.QueueIdKey = "QueueId";
    QueueItAcceptedCookie.EventIdKey = "EventId";
    QueueItAcceptedCookie.RedirectTypeKey = "RedirectType";
    QueueItAcceptedCookie.FixedCookieValidityMinutesKey = "FixedValidityMins";
    QueueItAcceptedCookie.IsCookieHttpOnly = "IsCookieHttpOnly";
    QueueItAcceptedCookie.IsCookieSecure = "IsCookieSecure";
    QueueItAcceptedCookie.HashedIpKey = "Hip";
    return QueueItAcceptedCookie;
}());
exports.QueueItAcceptedCookie = QueueItAcceptedCookie;
var UserInQueueStateCookieRepository = /** @class */ (function () {
    function UserInQueueStateCookieRepository(httpContextProvider) {
        this.httpContextProvider = httpContextProvider;
    }
    UserInQueueStateCookieRepository.getCookieKey = function (eventId) {
        return UserInQueueStateCookieRepository._QueueITDataKey + "_" + eventId;
    };
    UserInQueueStateCookieRepository.prototype.store = function (eventId, queueId, fixedCookieValidityMinutes, cookieDomain, isCookieHttpOnly, isCookieSecure, redirectType, hashedIp, secretKey) {
        isCookieHttpOnly = isCookieHttpOnly == null ? false : isCookieHttpOnly;
        isCookieSecure = isCookieSecure == null ? false : isCookieSecure;
        this.createCookie(eventId, queueId, fixedCookieValidityMinutes ? fixedCookieValidityMinutes.toString() : "", redirectType, hashedIp, cookieDomain, isCookieHttpOnly, isCookieSecure, secretKey);
    };
    UserInQueueStateCookieRepository.prototype.createCookie = function (eventId, queueId, fixedCookieValidityMinutes, redirectType, hashedIp, cookieDomain, isCookieHttpOnly, isCookieSecure, secretKey) {
        var cookieKey = UserInQueueStateCookieRepository.getCookieKey(eventId);
        var issueTime = QueueITHelpers_1.Utils.getCurrentTime().toString();
        var cookieValues = new Array();
        cookieValues.push({ key: QueueItAcceptedCookie.EventIdKey, value: eventId });
        cookieValues.push({ key: QueueItAcceptedCookie.QueueIdKey, value: queueId });
        if (fixedCookieValidityMinutes) {
            cookieValues.push({
                key: QueueItAcceptedCookie.FixedCookieValidityMinutesKey,
                value: fixedCookieValidityMinutes
            });
        }
        cookieValues.push({ key: QueueItAcceptedCookie.RedirectTypeKey, value: redirectType.toLowerCase() });
        cookieValues.push({ key: QueueItAcceptedCookie.IssueTimeKey, value: issueTime });
        if (hashedIp) {
            cookieValues.push({ key: QueueItAcceptedCookie.HashedIpKey, value: hashedIp });
        }
        cookieValues.push({
            key: QueueItAcceptedCookie.HashKey,
            value: this.generateHash(eventId.toLowerCase(), queueId, fixedCookieValidityMinutes, redirectType.toLowerCase(), issueTime, hashedIp, secretKey)
        });
        var tomorrow = new Date();
        tomorrow.setDate(tomorrow.getDate() + 1);
        var expire = Math.floor(tomorrow.getTime() / 1000);
        this.httpContextProvider.getHttpResponse().setCookie(cookieKey, QueueITHelpers_1.CookieHelper.toValueFromKeyValueCollection(cookieValues), cookieDomain, expire, isCookieHttpOnly, isCookieSecure);
    };
    UserInQueueStateCookieRepository.prototype.getState = function (eventId, cookieValidityMinutes, secretKey, validateTime) {
        var qitAcceptedCookie = null;
        try {
            var cookieKey = UserInQueueStateCookieRepository.getCookieKey(eventId);
            var cookie = this.httpContextProvider.getHttpRequest().getCookieValue(cookieKey);
            if (!cookie)
                return new StateInfo("", null, "", null, CookieValidationResult.NotFound, null);
            qitAcceptedCookie = QueueItAcceptedCookie.fromCookieHeader(cookie);
            var cookieValidationResult = this.isCookieValid(secretKey, qitAcceptedCookie, eventId, cookieValidityMinutes, validateTime);
            if (cookieValidationResult != CookieValidationResult.Valid) {
                return new StateInfo("", null, "", qitAcceptedCookie.hashedIp, cookieValidationResult, qitAcceptedCookie);
            }
            return new StateInfo(qitAcceptedCookie.queueId, qitAcceptedCookie.fixedCookieValidityMinutes
                ? parseInt(qitAcceptedCookie.fixedCookieValidityMinutes)
                : null, qitAcceptedCookie.redirectType, qitAcceptedCookie.hashedIp, CookieValidationResult.Valid, qitAcceptedCookie);
        }
        catch (ex) {
            return new StateInfo("", null, "", qitAcceptedCookie === null || qitAcceptedCookie === void 0 ? void 0 : qitAcceptedCookie.hashedIp, CookieValidationResult.Error, qitAcceptedCookie);
        }
    };
    UserInQueueStateCookieRepository.prototype.isCookieValid = function (secretKey, cookie, eventId, cookieValidityMinutes, validateTime) {
        try {
            var expectedHash = this.generateHash(cookie.eventIdFromCookie, cookie.queueId, cookie.fixedCookieValidityMinutes, cookie.redirectType, cookie.issueTimeString, cookie.hashedIp, secretKey);
            if (expectedHash !== cookie.storedHash)
                return CookieValidationResult.HashMismatch;
            if (eventId.toLowerCase() !== cookie.eventIdFromCookie.toLowerCase())
                return CookieValidationResult.WaitingRoomMismatch;
            if (validateTime) {
                var validity = cookie.fixedCookieValidityMinutes ? parseInt(cookie.fixedCookieValidityMinutes) : cookieValidityMinutes;
                var expirationTime = parseInt(cookie.issueTimeString) + validity * 60;
                if (expirationTime < QueueITHelpers_1.Utils.getCurrentTime())
                    return CookieValidationResult.Expired;
            }
            var userHostAddress = this.httpContextProvider.getHttpRequest().getUserHostAddress();
            if (cookie.hashedIp && userHostAddress) {
                var hashedUserHostAddress = QueueITHelpers_1.Utils.generateSHA256Hash(secretKey, userHostAddress);
                if (cookie.hashedIp !== hashedUserHostAddress) {
                    return CookieValidationResult.IpBindingMismatch;
                }
            }
            return CookieValidationResult.Valid;
        }
        catch (_a) {
            return CookieValidationResult.Error;
        }
    };
    UserInQueueStateCookieRepository.prototype.cancelQueueCookie = function (eventId, cookieDomain, isCookieHttpOnly, isCookieSecure) {
        var cookieKey = UserInQueueStateCookieRepository.getCookieKey(eventId);
        this.httpContextProvider.getHttpResponse()
            .setCookie(cookieKey, "", cookieDomain, 0, isCookieHttpOnly, isCookieSecure);
    };
    UserInQueueStateCookieRepository.prototype.reissueQueueCookie = function (eventId, cookieValidityMinutes, cookieDomain, isCookieHttpOnly, isCookieSecure, secretKey) {
        var cookieKey = UserInQueueStateCookieRepository.getCookieKey(eventId);
        var cookie = this.httpContextProvider.getHttpRequest().getCookieValue(cookieKey);
        if (!cookie)
            return;
        var qitAcceptedCookie = QueueItAcceptedCookie.fromCookieHeader(cookie);
        if (!this.isCookieValid(secretKey, qitAcceptedCookie, eventId, cookieValidityMinutes, true))
            return;
        var fixedCookieValidityMinutes = "";
        if (qitAcceptedCookie.fixedCookieValidityMinutes)
            fixedCookieValidityMinutes = qitAcceptedCookie.fixedCookieValidityMinutes.toString();
        this.createCookie(eventId, qitAcceptedCookie.queueId, fixedCookieValidityMinutes, qitAcceptedCookie.redirectType, qitAcceptedCookie.hashedIp, cookieDomain, isCookieHttpOnly, isCookieSecure, secretKey);
    };
    UserInQueueStateCookieRepository.prototype.generateHash = function (eventId, queueId, fixedCookieValidityMinutes, redirectType, issueTime, hashedIp, secretKey) {
        var valueToHash = eventId
            + queueId
            + (fixedCookieValidityMinutes ? fixedCookieValidityMinutes : "")
            + redirectType
            + issueTime
            + (hashedIp ? hashedIp : "");
        return QueueITHelpers_1.Utils.generateSHA256Hash(secretKey, valueToHash);
    };
    UserInQueueStateCookieRepository._QueueITDataKey = "QueueITAccepted-SDFrts345E-V3";
    UserInQueueStateCookieRepository._IsCookieHttpOnly = "IsCookieHttpOnly";
    UserInQueueStateCookieRepository._IsCookieSecure = "IsCookieSecure";
    UserInQueueStateCookieRepository._HashedIpKey = "Hip";
    return UserInQueueStateCookieRepository;
}());
exports.UserInQueueStateCookieRepository = UserInQueueStateCookieRepository;
var StateInfo = /** @class */ (function () {
    function StateInfo(queueId, fixedCookieValidityMinutes, redirectType, hashedIp, cookieValidationResult, cookie) {
        this.queueId = queueId;
        this.fixedCookieValidityMinutes = fixedCookieValidityMinutes;
        this.redirectType = redirectType;
        this.hashedIp = hashedIp;
        this.cookieValidationResult = cookieValidationResult;
        this.cookie = cookie;
    }
    Object.defineProperty(StateInfo.prototype, "isValid", {
        get: function () {
            return this.cookieValidationResult === CookieValidationResult.Valid;
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(StateInfo.prototype, "isFound", {
        get: function () {
            return this.cookieValidationResult !== CookieValidationResult.NotFound;
        },
        enumerable: false,
        configurable: true
    });
    Object.defineProperty(StateInfo.prototype, "isBoundToAnotherIp", {
        get: function () {
            return this.cookieValidationResult === CookieValidationResult.IpBindingMismatch;
        },
        enumerable: false,
        configurable: true
    });
    StateInfo.prototype.isStateExtendable = function () {
        return this.isValid && !this.fixedCookieValidityMinutes;
    };
    StateInfo.prototype.getInvalidCookieReason = function () {
        if (this.isValid) {
            return "";
        }
        var details = new Array();
        switch (this.cookieValidationResult) {
            case CookieValidationResult.HashMismatch:
                details.push("hash");
                details.push("h:" + this.cookie.storedHash);
                break;
            case CookieValidationResult.Expired:
                details.push("expired");
                break;
            case CookieValidationResult.Error:
                details.push("error");
                break;
            case CookieValidationResult.NotFound:
                break;
            case CookieValidationResult.IpBindingMismatch:
                details.push("ip");
                details.push("hip:" + this.cookie.hashedIp);
                break;
        }
        if (this.isFound) {
            if (this.redirectType) {
                details.push("r:" + this.redirectType);
            }
            if (this.queueId) {
                details.push("q:" + this.queueId);
            }
            details.push("st:" + Date.now());
        }
        return details.join(",");
    };
    return StateInfo;
}());
exports.StateInfo = StateInfo;

},{"./QueueITHelpers":10}],13:[function(require,module,exports){
"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    Object.defineProperty(o, k2, { enumerable: true, get: function() { return m[k]; } });
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.QueueUrlParams = exports.QueueParameterHelper = exports.Utils = exports.KnownUser = void 0;
var KnownUser_1 = require("./KnownUser");
Object.defineProperty(exports, "KnownUser", { enumerable: true, get: function () { return KnownUser_1.KnownUser; } });
__exportStar(require("./Models"), exports);
var QueueITHelpers_1 = require("./QueueITHelpers");
Object.defineProperty(exports, "Utils", { enumerable: true, get: function () { return QueueITHelpers_1.Utils; } });
Object.defineProperty(exports, "QueueParameterHelper", { enumerable: true, get: function () { return QueueITHelpers_1.QueueParameterHelper; } });
Object.defineProperty(exports, "QueueUrlParams", { enumerable: true, get: function () { return QueueITHelpers_1.QueueUrlParams; } });

},{"./KnownUser":8,"./Models":9,"./QueueITHelpers":10}],14:[function(require,module,exports){
module.exports={
  "name": "@queue-it/cloudflare",
  "version": "1.2.1",
  "description": "KnownUserV3.Cloudflare",
  "repository": "https://github.com/queueit/KnownUser.V3.Cloudflare",
  "main": "dist/index.js",
  "author": {
    "name": "Queue-it"
  },
  "license": "MIT",
  "scripts": {
    "build": "tsc && gulp",
    "build:watch": "nodemon --exec \"npm run build\"",
    "buildArtifacts": "gulp buildArtifacts",
    "serve": "ts-node test/testServer.ts",
    "serve:watch": "nodemon test/testServer.ts"
  },
  "dependencies": {
    "js-sha256": "^0.9.0",
    "queueit-knownuser": "^3.7.4"
  },
  "devDependencies": {
    "@types/concat-stream": "^1.6.1",
    "@types/express": "^4.17.13",
    "@types/node": "^14.17.34",
    "browserify": "^17.0.0",
    "concat-stream": "^2.0.0",
    "express": "^4.17.1",
    "fast-sha256": "^1.3.0",
    "gulp": "^4.0.2",
    "gulp-json-modify": "^1.0.2",
    "gulp-zip": "^5.1.0",
    "https": "^1.0.0",
    "ts-node": "^10.4.0",
    "typescript": "^4.5.2",
    "vinyl-source-stream": "^2.0.0"
  },
  "nodemonConfig": {
    "ignore": [
      "app.bundle.js"
    ],
    "delay": 2500
  }
}

},{}],15:[function(require,module,exports){

const crypto = require('js-sha256');
const CLOUDFLARE_SDK_VERSION = require('./package.json').version;
exports.getParameterByName = function( url, name) {
    if (!url) url = window.location.href;
    name = name.replace(/[\[\]]/g, '\\$&');
    var regex = new RegExp('[?&]' + name + '(=([^&#]*)|&|#|$)'),
        results = regex.exec(url);
    if (!results) return null;
    if (!results[2]) return '';
    return decodeURIComponent(results[2].replace(/\+/g, ' '));
}
exports.configureKnownUserHashing= function(Utils) {
    Utils.generateSHA256Hash = function (secretKey, stringToHash) {      
        const hash = crypto.sha256.hmac(secretKey, stringToHash)
        return hash;
    };
}

exports.addKUPlatformVersion= function(redirectQueueUrl)
{
    return redirectQueueUrl + "&kupver=cloudflare-" + CLOUDFLARE_SDK_VERSION;
}

// $CVSHeader: _freebeer/www/lib/bin2hex.js,v 1.2 2004/03/07 17:51:35 ross Exp $

// Copyright (c) 2002-2004, Ross Smith.  All rights reserved.
// Licensed under the BSD or LGPL License. See license.txt for details.


var _hex2bin = [
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0, // 0-9
     0,10,11,12,13,14,15, 0, 0, 0, 0, 0, 0, 0, 0, 0, // A-F
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0,10,11,12,13,14,15, 0, 0, 0, 0, 0, 0, 0, 0, 0, // a-f
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];


exports.hex2bin = function(str) {
    var len = str.length;
    var rv = '';
    var i = 0;

    var c1;
    var c2;

    while (len > 1) {
        h1 = str.charAt(i++);
        c1 = h1.charCodeAt(0);
        h2 = str.charAt(i++);
        c2 = h2.charCodeAt(0);
        
        rv += String.fromCharCode((_hex2bin[c1] << 4) + _hex2bin[c2]);
        len -= 2;
    }

    return rv;
}
},{"./package.json":14,"js-sha256":4}],16:[function(require,module,exports){
// Set to true, if you have any trigger(s) containing experimental 'RequestBody' condition.
const READ_REQUEST_BODY = false;
const QUEUEIT_FAILED_HEADERNAME = "x-queueit-failed";

const knownUser = require("queueit-knownuser").KnownUser;
const utils = require("queueit-knownuser").Utils;
var httpProvider = null;
const contextProvider = require("./contextProvider.js");
const helpers = require("./queueitHelpers.js");
const integrationConfigProvider = require("./integrationConfigProvider.js");

//this function returns a response object where the execution follow should break 
//if it returns null then caller should decide how to procced with the request
exports.onQueueITRequest = async function (request, customerId, secretKey) {

    if (request.url.indexOf('__push_queueit_config') > 0) {
        var result = await integrationConfigProvider.tryStoreIntegrationConfig(request, IntegrationConfigKV, secretKey);
        return new Response(result ? "Success!" : "Fail!");
    }

    try {
        let integrationConfigJson = await integrationConfigProvider.getIntegrationConfig(IntegrationConfigKV) || "";

        helpers.configureKnownUserHashing(utils);

        let bodyText = "";
        if (READ_REQUEST_BODY) {
            //reading maximum 2k characters of body to do the mathcing
            bodyText = (await request.clone().text() || "").substring(0, 2048);
        }
        httpProvider = contextProvider.getHttpHandler(request, bodyText);

        var queueitToken = helpers.getParameterByName(request.url, knownUser.QueueITTokenKey);
        var requestUrl = request.url;
        var requestUrlWithoutToken = requestUrl.replace(new RegExp("([\?&])(" + knownUser.QueueITTokenKey + "=[^&]*)", 'i'), "");
        // The requestUrlWithoutToken is used to match Triggers and as the Target url (where to return the users to).
        // It is therefor important that this is exactly the url of the users browsers. So, if your webserver is
        // behind e.g. a load balancer that modifies the host name or port, reformat requestUrlWithoutToken before proceeding.


        var validationResult = knownUser.validateRequestByIntegrationConfig(
            requestUrlWithoutToken, queueitToken, integrationConfigJson,
            customerId, secretKey, httpProvider);

        if (validationResult.doRedirect()) {
            if (validationResult.isAjaxResult) {
                let response = new Response();
                // In case of ajax call send the user to the queue by sending a custom queue-it header and redirecting user to queue from javascript
                response.headers.set(validationResult.getAjaxQueueRedirectHeaderKey(), helpers.addKUPlatformVersion(validationResult.getAjaxRedirectUrl()));
                addNoCacheHeaders(response);
                return response;

            }
            else {
                let response = new Response(null, { status: 302 });
                // Send the user to the queue - either because hash was missing or because is was invalid
                response.headers.set('Location', helpers.addKUPlatformVersion(validationResult.redirectUrl));
                addNoCacheHeaders(response);
                return response;
            }
        }
        else {
            // Request can continue - we remove queueittoken form querystring parameter to avoid sharing of user specific token
            if (requestUrl !== requestUrlWithoutToken && validationResult.actionType === 'Queue') {
                let response = new Response(null, { status: 302 });
                response.headers.set('Location', requestUrlWithoutToken);
                addNoCacheHeaders(response);
                return response;
            }
            else {
                // lets caller decides the next step
                return null;
            }
        }
    }
    catch (e) {
        // There was an error validationg the request
        // Use your own logging framework to log the Exception
        if (console && console.log) {
            console.log("ERROR:" + e);
        }
        if (httpProvider) {
            httpProvider.isError = true;
        }
        // lets caller decides the next step
        return null;
    }

}

exports.onQueueITResponse = async function (response) {

    let newResponse = new Response(response.body, response);
    if (httpProvider) {
        if (httpProvider.outputCookie) {
            newResponse.headers.append("Set-Cookie", httpProvider.outputCookie);
        }
        if (httpProvider.isError) {
            newResponse.headers.append(QUEUEIT_FAILED_HEADERNAME, "true");
        }
    }
    return newResponse;
}

let addNoCacheHeaders = function (response) {
    // Adding no cache headers to prevent browsers to cache requests
    response.headers.set('Cache-Control', 'no-cache, no-store, must-revalidate, max-age=0');
    response.headers.set('Pragma', 'no-cache');
    response.headers.set('Expires', 'Fri, 01 Jan 1990 00:00:00 GMT');
}

},{"./contextProvider.js":2,"./integrationConfigProvider.js":3,"./queueitHelpers.js":15,"queueit-knownuser":13}]},{},[1]);
