/*!
 * SworfishGuard — Photo metadata viewer and cleaner
 *
 * Phones hide extra data inside every photo (EXIF): the exact GPS location
 * where it was taken, the phone model, the date and time, sometimes the
 * owner's name. When you send the original file, the other person gets all
 * of that too.
 *
 * This module reads that data from JPEG and PNG files and builds a clean
 * copy WITHOUT re-compressing the image: it only removes the metadata
 * blocks, so the photo keeps the same quality. The only thing kept is the
 * rotation (Orientation), so the photo does not appear sideways.
 *
 * Everything works on bytes in memory; nothing is uploaded.
 *
 * Author: Asaf Rojas (Sworfish Tech) — MIT License
 */
(function (root) {
  'use strict';

  var MAX_BYTES = 40 * 1024 * 1024;

  // TIFF tags we show (EXIF 2.32 numbers)
  var TAGS = {
    0x010F: 'make', 0x0110: 'model', 0x0131: 'software', 0x0132: 'modified', 0x013B: 'artist',
    0x8298: 'copyright', 0x0112: 'orientation', 0x010E: 'description',
    0x9003: 'taken', 0xA430: 'owner', 0xA431: 'serial', 0xA434: 'lens', 0xA433: 'lensMake'
  };
  var PTR_EXIF = 0x8769, PTR_GPS = 0x8825;
  var TYPE_SIZE = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8 };

  function ascii(bytes, start, len) {
    var s = '';
    for (var i = 0; i < len && start + i < bytes.length; i++) {
      var c = bytes[start + i];
      if (c === 0) break;
      s += String.fromCharCode(c);
    }
    return s.replace(/[\u0000-\u001F\u007F]/g, '').trim();
  }

  function detectFormat(bytes) {
    if (bytes.length > 3 && bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) return 'jpeg';
    if (bytes.length > 8 && bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) return 'png';
    if (bytes.length > 12 && ascii(bytes, 0, 4) === 'RIFF' && ascii(bytes, 8, 4) === 'WEBP') return 'webp';
    if (bytes.length > 12 && ascii(bytes, 4, 4) === 'ftyp') return 'heic';
    return 'unknown';
  }

  // ------------------------------------------------------------- TIFF / EXIF
  /** Reads a TIFF block (the inside of EXIF). Returns {tags, gps} or null. */
  function readTiff(bytes, base, end) {
    if (end - base < 8) return null;
    var little;
    if (bytes[base] === 0x49 && bytes[base + 1] === 0x49) little = true;
    else if (bytes[base] === 0x4D && bytes[base + 1] === 0x4D) little = false;
    else return null;
    function u16(o) { o += base; if (o + 2 > end) throw new RangeError('eof'); return little ? bytes[o] | bytes[o + 1] << 8 : bytes[o] << 8 | bytes[o + 1]; }
    function u32(o) {
      o += base; if (o + 4 > end) throw new RangeError('eof');
      return little ? (bytes[o] | bytes[o + 1] << 8 | bytes[o + 2] << 16) + bytes[o + 3] * 16777216
                    : bytes[o] * 16777216 + (bytes[o + 1] << 16 | bytes[o + 2] << 8 | bytes[o + 3]);
    }
    if (u16(2) !== 42) return null;

    var out = { tags: {}, gps: null };
    var seen = {};

    function value(type, count, valueOffset) {
      var size = (TYPE_SIZE[type] || 1) * count;
      var at = size <= 4 ? valueOffset : u32(valueOffset);
      if (at < 0 || base + at + size > end) return null;
      if (type === 2) return ascii(bytes, base + at, Math.min(count, 256));
      if (type === 3) return count === 1 ? u16(at) : null;
      if (type === 4) return count === 1 ? u32(at) : null;
      if (type === 5) {
        var list = [];
        for (var i = 0; i < Math.min(count, 4); i++) {
          var d = u32(at + i * 8 + 4);
          list.push(d ? u32(at + i * 8) / d : 0);
        }
        return list;
      }
      if (type === 1 || type === 7) {
        var raw = [];
        for (var j = 0; j < Math.min(count, 8); j++) raw.push(bytes[base + at + j]);
        return raw;
      }
      return null;
    }

    function readIfd(offset, into, isGps) {
      if (!offset || seen[offset] || offset + 2 > end - base) return;
      seen[offset] = true;  // protects against loops in malformed files
      var n = u16(offset);
      if (n > 512) return;
      for (var i = 0; i < n; i++) {
        var e = offset + 2 + i * 12;
        if (base + e + 12 > end) return;
        var tag = u16(e), type = u16(e + 2), count = u32(e + 4);
        if (!isGps && tag === PTR_EXIF) { readIfd(u32(e + 8), into, false); continue; }
        if (!isGps && tag === PTR_GPS) { out.gps = {}; readIfd(u32(e + 8), out.gps, true); continue; }
        var v;
        try { v = value(type, count, e + 8); } catch (err) { v = null; }
        if (v === null || v === undefined || v === '') continue;
        if (isGps) into[tag] = v;
        else if (TAGS[tag]) into[TAGS[tag]] = v;
      }
    }
    try { readIfd(u32(4), out.tags, false); } catch (err) { /* truncated file: keep what was read */ }
    return out;
  }

  function dms(list, ref) {
    if (!list || list.length < 3) return null;
    var v = list[0] + list[1] / 60 + list[2] / 3600;
    if (!isFinite(v)) return null;
    if (ref === 'S' || ref === 'W') v = -v;
    return Math.round(v * 1e6) / 1e6;
  }

  function gpsInfo(g) {
    if (!g) return null;
    var lat = dms(g[2], g[1]), lon = dms(g[4], g[3]);
    if (lat === null || lon === null || (lat === 0 && lon === 0) || Math.abs(lat) > 90 || Math.abs(lon) > 180) return null;
    var alt = g[6] && g[6].length ? Math.round(g[6][0]) : null;
    if (alt !== null && g[5] && g[5][0] === 1) alt = -alt;
    return { lat: lat, lon: lon, altitude: alt };
  }

  // -------------------------------------------------------------------- JPEG
  function jpegSegments(bytes) {
    var segs = [];
    var o = 2;
    while (o + 4 <= bytes.length) {
      if (bytes[o] !== 0xFF) return { segs: segs, dataStart: o, broken: true };
      var marker = bytes[o + 1];
      if (marker === 0xFF) { o++; continue; }               // fill byte
      if (marker === 0xDA || marker === 0xD9) return { segs: segs, dataStart: o };  // start of scan
      var len = bytes[o + 2] << 8 | bytes[o + 3];
      if (len < 2 || o + 2 + len > bytes.length) return { segs: segs, dataStart: o, broken: true };
      segs.push({ marker: marker, start: o, end: o + 2 + len, dataStart: o + 4 });
      o += 2 + len;
    }
    return { segs: segs, dataStart: o, broken: true };
  }

  function readJpeg(bytes) {
    var info = { exif: null, xmp: false, iptc: false, comment: '', icc: false };
    var parsed = jpegSegments(bytes);
    parsed.segs.forEach(function (s) {
      if (s.marker === 0xE1 && ascii(bytes, s.dataStart, 4) === 'Exif' && !info.exif) {
        info.exif = readTiff(bytes, s.dataStart + 6, s.end);
      } else if (s.marker === 0xE1 && ascii(bytes, s.dataStart, 28) === 'http://ns.adobe.com/xap/1.0/') {
        info.xmp = true;
      } else if (s.marker === 0xED) {
        info.iptc = true;
      } else if (s.marker === 0xFE) {
        info.comment = ascii(bytes, s.dataStart, Math.min(s.end - s.dataStart, 200));
      } else if (s.marker === 0xE2 && ascii(bytes, s.dataStart, 11) === 'ICC_PROFILE') {
        info.icc = true;
      }
    });
    info.broken = !!parsed.broken;
    return info;
  }

  /** Minimal EXIF block that only says how to rotate the photo. */
  function orientationSegment(orientation) {
    var tiff = [0x4D, 0x4D, 0x00, 0x2A, 0, 0, 0, 8,   // big-endian header, IFD0 at 8
      0, 1,                                             // 1 entry
      0x01, 0x12, 0, 3, 0, 0, 0, 1, 0, orientation, 0, 0, // Orientation SHORT = n
      0, 0, 0, 0];                                      // no next IFD
    var payload = [0x45, 0x78, 0x69, 0x66, 0, 0].concat(tiff); // "Exif\0\0"
    var len = payload.length + 2;
    return [0xFF, 0xE1, len >> 8, len & 0xFF].concat(payload);
  }

  function cleanJpeg(bytes, orientation) {
    var parsed = jpegSegments(bytes);
    if (parsed.broken && parsed.dataStart >= bytes.length) throw new Error('broken');
    var parts = [bytes.subarray(0, 2)];
    var removed = 0;
    if (orientation && orientation >= 2 && orientation <= 8) parts.push(new Uint8Array(orientationSegment(orientation)));
    parsed.segs.forEach(function (s) {
      var isApp = s.marker >= 0xE1 && s.marker <= 0xEF;
      var keepIcc = s.marker === 0xE2 && ascii(bytes, s.dataStart, 11) === 'ICC_PROFILE'; // colors only, no personal data
      if ((isApp && !keepIcc) || s.marker === 0xFE) { removed += s.end - s.start; return; }
      parts.push(bytes.subarray(s.start, s.end));
    });
    parts.push(bytes.subarray(parsed.dataStart));
    return { bytes: concat(parts), removedBytes: removed };
  }

  // --------------------------------------------------------------------- PNG
  var PNG_META = ['tEXt', 'zTXt', 'iTXt', 'eXIf', 'tIME'];

  function pngChunks(bytes) {
    var list = [];
    var o = 8;
    while (o + 12 <= bytes.length) {
      var len = (bytes[o] * 16777216) + (bytes[o + 1] << 16 | bytes[o + 2] << 8 | bytes[o + 3]);
      var type = ascii(bytes, o + 4, 4);
      var end = o + 12 + len;
      if (end > bytes.length || !/^[A-Za-z]{4}$/.test(type)) break;
      list.push({ type: type, start: o, dataStart: o + 8, dataEnd: o + 8 + len, end: end });
      o = end;
      if (type === 'IEND') break;
    }
    return list;
  }

  function readPng(bytes) {
    var info = { exif: null, texts: [], time: false };
    pngChunks(bytes).forEach(function (c) {
      if (c.type === 'eXIf' && !info.exif) info.exif = readTiff(bytes, c.dataStart, c.dataEnd);
      else if (c.type === 'tEXt' || c.type === 'iTXt' || c.type === 'zTXt') {
        var key = ascii(bytes, c.dataStart, Math.min(79, c.dataEnd - c.dataStart));
        var text = c.type === 'tEXt' ? ascii(bytes, c.dataStart + key.length + 1, Math.min(160, c.dataEnd - c.dataStart - key.length - 1)) : '';
        info.texts.push({ key: key, text: text });
      } else if (c.type === 'tIME') info.time = true;
    });
    return info;
  }

  function cleanPng(bytes) {
    var chunks = pngChunks(bytes);
    if (!chunks.length) throw new Error('broken');
    var parts = [bytes.subarray(0, 8)];
    var removed = 0;
    chunks.forEach(function (c) {
      if (PNG_META.indexOf(c.type) !== -1) { removed += c.end - c.start; return; }
      parts.push(bytes.subarray(c.start, c.end));
    });
    return { bytes: concat(parts), removedBytes: removed };
  }

  function concat(parts) {
    var total = parts.reduce(function (n, p) { return n + p.length; }, 0);
    var out = new Uint8Array(total);
    var o = 0;
    parts.forEach(function (p) { out.set(p, o); o += p.length; });
    return out;
  }

  // ------------------------------------------------------------------ public
  /**
   * Reads the metadata of an image.
   * @param {Uint8Array} bytes
   * @returns {{format, supported, gps, device, dates, people, software, extras[], risk, count}}
   */
  function inspect(bytes) {
    var format = detectFormat(bytes);
    var res = { format: format, supported: format === 'jpeg' || format === 'png', gps: null, fields: [], extras: [], orientation: 1 };
    if (!res.supported) { res.risk = 'unknown'; return res; }
    var raw = format === 'jpeg' ? readJpeg(bytes) : readPng(bytes);
    var tags = raw.exif ? raw.exif.tags : {};
    res.gps = raw.exif ? gpsInfo(raw.exif.gps) : null;
    res.orientation = typeof tags.orientation === 'number' ? tags.orientation : 1;

    function add(id, v, group) { if (v !== undefined && v !== null && v !== '') res.fields.push({ id: id, value: String(v), group: group }); }
    add('device', [tags.make, tags.model].filter(Boolean).join(' ').replace(/^(\S+) \1 /i, '$1 '), 'device');
    add('lens', tags.lens, 'device');
    add('serial', tags.serial, 'person');
    add('owner', tags.owner, 'person');
    add('artist', tags.artist, 'person');
    add('copyright', tags.copyright, 'person');
    add('taken', tags.taken || tags.modified, 'date');
    add('software', tags.software, 'device');
    add('description', tags.description, 'person');
    if (format === 'jpeg') {
      if (raw.xmp) res.extras.push('xmp');
      if (raw.iptc) res.extras.push('iptc');
      if (raw.comment) add('comment', raw.comment, 'person');
    } else {
      raw.texts.forEach(function (tx) { add('pngText', tx.key + (tx.text ? ': ' + tx.text : ''), tx.key === 'XML:com.adobe.xmp' ? 'device' : 'person'); });
      if (raw.time) res.extras.push('pngTime');
    }
    var hasPerson = res.fields.some(function (f) { return f.group === 'person'; });
    res.risk = res.gps ? 'high' : hasPerson ? 'medium' : (res.fields.length || res.extras.length) ? 'low' : 'none';
    res.count = res.fields.length + res.extras.length + (res.gps ? 1 : 0);
    return res;
  }

  /** Clean copy, same image data. Throws for formats it cannot rewrite. */
  function clean(bytes) {
    var format = detectFormat(bytes);
    if (format === 'jpeg') {
      var info = inspect(bytes);
      return cleanJpeg(bytes, info.orientation);
    }
    if (format === 'png') return cleanPng(bytes);
    throw new Error('unsupported');
  }

  var api = { MAX_BYTES: MAX_BYTES, detectFormat: detectFormat, inspect: inspect, clean: clean, orientationSegment: orientationSegment };
  root.SworfishGuard = root.SworfishGuard || {};
  root.SworfishGuard.metadata = Object.freeze(api);
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
