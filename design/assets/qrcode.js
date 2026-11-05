// 订阅二维码编码器（ISO/IEC 18004，字节模式，纠错等级 M，版本 1-15）。
// 链接里含订阅 Token，必须在浏览器本地生成，不能交给第三方二维码接口。
(function () {
  "use strict";

  // 纠错等级 M 下各版本的每块纠错码字数与分块数，下标为版本号。
  var ECC_PER_BLOCK = [0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24];
  var BLOCK_COUNT = [0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10];
  var MAX_VERSION = 15;

  function rawCodewordBits(version) {
    var bits = (16 * version + 128) * version + 64;
    if (version >= 2) {
      var align = Math.floor(version / 7) + 2;
      bits -= (25 * align - 10) * align - 55;
      if (version >= 7) bits -= 36;
    }
    return bits;
  }

  function dataCodewords(version) {
    return Math.floor(rawCodewordBits(version) / 8) - ECC_PER_BLOCK[version] * BLOCK_COUNT[version];
  }

  function gfMultiply(x, y) {
    var result = 0;
    for (var bit = 7; bit >= 0; bit -= 1) {
      result = (result << 1) ^ ((result >>> 7) * 0x11d);
      result ^= ((y >>> bit) & 1) * x;
    }
    return result;
  }

  function reedSolomonDivisor(degree) {
    var divisor = new Array(degree).fill(0);
    divisor[degree - 1] = 1;
    var root = 1;
    for (var i = 0; i < degree; i += 1) {
      for (var j = 0; j < degree; j += 1) {
        divisor[j] = gfMultiply(divisor[j], root);
        if (j + 1 < degree) divisor[j] ^= divisor[j + 1];
      }
      root = gfMultiply(root, 2);
    }
    return divisor;
  }

  function reedSolomonRemainder(data, divisor) {
    var remainder = new Array(divisor.length).fill(0);
    data.forEach(function (value) {
      var factor = value ^ remainder.shift();
      remainder.push(0);
      divisor.forEach(function (coefficient, index) {
        remainder[index] ^= gfMultiply(coefficient, factor);
      });
    });
    return remainder;
  }

  function buildCodewords(bytes, version) {
    var capacity = dataCodewords(version);
    var bits = [];
    function push(value, length) {
      for (var i = length - 1; i >= 0; i -= 1) bits.push((value >>> i) & 1);
    }
    push(4, 4);
    push(bytes.length, version < 10 ? 8 : 16);
    bytes.forEach(function (value) { push(value, 8); });
    push(0, Math.min(4, capacity * 8 - bits.length));
    push(0, (8 - bits.length % 8) % 8);
    for (var pad = 0xec; bits.length < capacity * 8; pad ^= 0xec ^ 0x11) push(pad, 8);
    var data = [];
    for (var i = 0; i < bits.length; i += 8) {
      var value = 0;
      for (var j = 0; j < 8; j += 1) value = (value << 1) | bits[i + j];
      data.push(value);
    }

    // 分块、计算纠错码后交错排列；短块比长块少一个数据码字。
    var blockTotal = BLOCK_COUNT[version];
    var eccLength = ECC_PER_BLOCK[version];
    var rawLength = Math.floor(rawCodewordBits(version) / 8);
    var shortBlocks = blockTotal - rawLength % blockTotal;
    var shortLength = Math.floor(rawLength / blockTotal) - eccLength;
    var divisor = reedSolomonDivisor(eccLength);
    var dataBlocks = [];
    var eccBlocks = [];
    var offset = 0;
    for (var b = 0; b < blockTotal; b += 1) {
      var length = shortLength + (b < shortBlocks ? 0 : 1);
      var block = data.slice(offset, offset + length);
      offset += length;
      dataBlocks.push(block);
      eccBlocks.push(reedSolomonRemainder(block, divisor));
    }
    var result = [];
    for (var column = 0; column <= shortLength; column += 1) {
      dataBlocks.forEach(function (item) {
        if (column < item.length) result.push(item[column]);
      });
    }
    for (var e = 0; e < eccLength; e += 1) {
      eccBlocks.forEach(function (item) { result.push(item[e]); });
    }
    return result;
  }

  function alignmentPositions(version) {
    if (version === 1) return [];
    var count = Math.floor(version / 7) + 2;
    var step = Math.floor((version * 8 + count * 3 + 5) / (count * 4 - 4)) * 2;
    var positions = [6];
    for (var position = version * 4 + 10; positions.length < count; position -= step) {
      positions.splice(1, 0, position);
    }
    return positions;
  }

  function createMatrix(version) {
    var size = version * 4 + 17;
    var modules = [];
    var reserved = [];
    for (var y = 0; y < size; y += 1) {
      modules.push(new Array(size).fill(false));
      reserved.push(new Array(size).fill(false));
    }
    function setFunction(x, y, dark) {
      modules[y][x] = dark;
      reserved[y][x] = true;
    }
    for (var i = 0; i < size; i += 1) {
      setFunction(6, i, i % 2 === 0);
      setFunction(i, 6, i % 2 === 0);
    }
    function drawFinder(cx, cy) {
      for (var dy = -4; dy <= 4; dy += 1) {
        for (var dx = -4; dx <= 4; dx += 1) {
          var x = cx + dx;
          var y = cy + dy;
          var distance = Math.max(Math.abs(dx), Math.abs(dy));
          if (x >= 0 && x < size && y >= 0 && y < size) setFunction(x, y, distance !== 2 && distance !== 4);
        }
      }
    }
    drawFinder(3, 3);
    drawFinder(size - 4, 3);
    drawFinder(3, size - 4);
    var aligns = alignmentPositions(version);
    aligns.forEach(function (ay, row) {
      aligns.forEach(function (ax, column) {
        var overlapsFinder = (row === 0 && column === 0)
          || (row === 0 && column === aligns.length - 1)
          || (row === aligns.length - 1 && column === 0);
        if (overlapsFinder) return;
        for (var dy = -2; dy <= 2; dy += 1) {
          for (var dx = -2; dx <= 2; dx += 1) {
            setFunction(ax + dx, ay + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
          }
        }
      });
    });
    drawFormatBits(modules, reserved, size, 0);
    if (version >= 7) {
      var remainder = version;
      for (var r = 0; r < 12; r += 1) remainder = (remainder << 1) ^ ((remainder >>> 11) * 0x1f25);
      var versionBits = (version << 12) | remainder;
      for (var bit = 0; bit < 18; bit += 1) {
        var dark = ((versionBits >>> bit) & 1) === 1;
        var near = size - 11 + bit % 3;
        var far = Math.floor(bit / 3);
        setFunction(near, far, dark);
        setFunction(far, near, dark);
      }
    }
    return { size: size, modules: modules, reserved: reserved };
  }

  function drawFormatBits(modules, reserved, size, mask) {
    // 纠错等级 M 的格式位为 00。
    var data = mask;
    var remainder = data;
    for (var i = 0; i < 10; i += 1) remainder = (remainder << 1) ^ ((remainder >>> 9) * 0x537);
    var bits = ((data << 10) | remainder) ^ 0x5412;
    function set(x, y, bit) {
      modules[y][x] = ((bits >>> bit) & 1) === 1;
      reserved[y][x] = true;
    }
    for (var a = 0; a <= 5; a += 1) set(8, a, a);
    set(8, 7, 6);
    set(8, 8, 7);
    set(7, 8, 8);
    for (var b = 9; b < 15; b += 1) set(14 - b, 8, b);
    for (var c = 0; c < 8; c += 1) set(size - 1 - c, 8, c);
    for (var d = 8; d < 15; d += 1) set(8, size - 15 + d, d);
    modules[size - 8][8] = true;
    reserved[size - 8][8] = true;
  }

  function drawCodewords(matrix, codewords) {
    var size = matrix.size;
    var index = 0;
    for (var right = size - 1; right >= 1; right -= 2) {
      if (right === 6) right = 5;
      for (var vertical = 0; vertical < size; vertical += 1) {
        for (var j = 0; j < 2; j += 1) {
          var x = right - j;
          var upward = ((right + 1) & 2) === 0;
          var y = upward ? size - 1 - vertical : vertical;
          if (matrix.reserved[y][x] || index >= codewords.length * 8) continue;
          matrix.modules[y][x] = ((codewords[index >>> 3] >>> (7 - (index & 7))) & 1) === 1;
          index += 1;
        }
      }
    }
  }

  function maskApplies(mask, x, y) {
    switch (mask) {
      case 0: return (x + y) % 2 === 0;
      case 1: return y % 2 === 0;
      case 2: return x % 3 === 0;
      case 3: return (x + y) % 3 === 0;
      case 4: return (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0;
      case 5: return (x * y) % 2 + (x * y) % 3 === 0;
      case 6: return ((x * y) % 2 + (x * y) % 3) % 2 === 0;
      default: return ((x + y) % 2 + (x * y) % 3) % 2 === 0;
    }
  }

  function applyMask(matrix, mask) {
    for (var y = 0; y < matrix.size; y += 1) {
      for (var x = 0; x < matrix.size; x += 1) {
        if (!matrix.reserved[y][x] && maskApplies(mask, x, y)) matrix.modules[y][x] = !matrix.modules[y][x];
      }
    }
  }

  function linePenalty(line) {
    var score = 0;
    var run = 1;
    for (var i = 1; i <= line.length; i += 1) {
      if (i < line.length && line[i] === line[i - 1]) {
        run += 1;
      } else {
        if (run >= 5) score += run - 2;
        run = 1;
      }
    }
    // 与定位图形相似的 1011101 + 前后四格空白。
    var text = line.map(function (dark) { return dark ? "1" : "0"; }).join("");
    ["10111010000", "00001011101"].forEach(function (pattern) {
      for (var at = text.indexOf(pattern); at >= 0; at = text.indexOf(pattern, at + 1)) score += 40;
    });
    return score;
  }

  function maskPenalty(matrix) {
    var size = matrix.size;
    var modules = matrix.modules;
    var score = 0;
    var dark = 0;
    for (var y = 0; y < size; y += 1) {
      score += linePenalty(modules[y]);
      score += linePenalty(modules.map(function (row) { return row[y]; }));
      for (var x = 0; x < size; x += 1) {
        if (modules[y][x]) dark += 1;
        if (x + 1 < size && y + 1 < size) {
          var color = modules[y][x];
          if (color === modules[y][x + 1] && color === modules[y + 1][x] && color === modules[y + 1][x + 1]) score += 3;
        }
      }
    }
    return score + Math.floor(Math.abs(dark * 20 - size * size * 10) / (size * size)) * 10;
  }

  // 返回 { version, size, modules }，modules[y][x] 为 true 表示深色模块；内容超出容量时抛错。
  function encode(text) {
    var bytes = Array.from(new TextEncoder().encode(String(text)));
    var version = 1;
    while (version <= MAX_VERSION && 4 + (version < 10 ? 8 : 16) + bytes.length * 8 > dataCodewords(version) * 8) version += 1;
    if (version > MAX_VERSION) throw new Error("内容过长，无法生成二维码");
    var matrix = createMatrix(version);
    drawCodewords(matrix, buildCodewords(bytes, version));
    var bestMask = 0;
    var bestScore = Infinity;
    for (var mask = 0; mask < 8; mask += 1) {
      applyMask(matrix, mask);
      drawFormatBits(matrix.modules, matrix.reserved, matrix.size, mask);
      var score = maskPenalty(matrix);
      if (score < bestScore) {
        bestScore = score;
        bestMask = mask;
      }
      applyMask(matrix, mask);
    }
    applyMask(matrix, bestMask);
    drawFormatBits(matrix.modules, matrix.reserved, matrix.size, bestMask);
    return { version: version, size: matrix.size, modules: matrix.modules };
  }

  window.ClashQr = { encode: encode };
})();
