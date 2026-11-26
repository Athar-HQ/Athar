-- athar.nse: runs Athar rules in Nmap.
--
-- SPDX-License-Identifier: MIT
--
-- Copyright (c) 2026 Athar contributors
--
-- Permission is hereby granted, free of charge, to any person obtaining a copy
-- of this software and associated documentation files (the "Software"), to
-- deal in the Software without restriction, including without limitation the
-- rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
-- sell copies of the Software, and to permit persons to whom the Software is
-- furnished to do so, subject to the following conditions:
--
-- The above copyright notice and this permission notice shall be included in
-- all copies or substantial portions of the Software.
--
-- THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
-- IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
-- FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
-- AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
-- LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
-- FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
-- IN THE SOFTWARE.
--
-- The rules this script reads are data files written by "athar convert -t nse".
-- Each keeps its own author and licence (Detection Rule License 1.1 for the
-- rules in the Athar repository), and every match this script reports names
-- the rule's author.

local base64 = require "base64"
local json = require "json"
local lfs = require "lfs"
local nmap = require "nmap"
local openssl = require "openssl"
local stdnse = require "stdnse"
local zlib = require "zlib"

description = [[
Fingerprints services with Athar rules (https://github.com/Athar-HQ/Athar).

"athar convert -t nse -o <folder> <rules>" writes this script and one data
file per rule into <folder>/athar-rules/. On every open TCP port the script
collects what athar scan collects: a banner if a rule needs one, the TLS
certificate, GET / without following redirects, and the favicon. It then
reports each rule that matched, with the rule's author, as the Detection Rule
License 1.1 asks. A match of a rule whose conversion is not exact says so
under "fidelity".

Custom probes declared by rules are only sent with the script argument
athar.probes, like athar scan's -probes.
]]

---
-- @usage
-- nmap -sT -Pn -p 80,443,8443 --script ./athar.nse <target>
-- nmap -sT -Pn -p 8787 --script ./athar.nse --script-args athar.probes <target>
--
-- @args athar.rules A rule data file, or a folder of them. Default: the folder
--       athar-rules next to this script.
-- @args athar.probes Also send the custom probes rules declare. Off by default.
-- @args athar.timeout Connect, handshake and read timeout. Default: 3s.
--
-- @output
-- PORT     STATE SERVICE
-- 8787/tcp open  unknown
-- | athar:
-- |   Agentic Offensive Framework - ARTEX family:
-- |     rule: 0ce69e91-baee-4475-81ee-4b8eca1a6c3b
-- |     author: Gameel Ali (@MalGamy12)
-- |     family: artex
-- |     category: offensive-tool
-- |     confidence: high
-- |     tls: false
-- |     extracted:
-- |_      brand: NKW
--
-- @xmloutput
-- <table key="Agentic Offensive Framework - ARTEX family">
--   <elem key="rule">0ce69e91-baee-4475-81ee-4b8eca1a6c3b</elem>
--   <elem key="author">Gameel Ali (@MalGamy12)</elem>
--   <elem key="family">artex</elem>
--   <elem key="category">offensive-tool</elem>
--   <elem key="confidence">high</elem>
--   <elem key="tls">false</elem>
--   <table key="extracted">
--     <elem key="brand">NKW</elem>
--   </table>
-- </table>

author = "Athar contributors"
license = "MIT"
categories = {"discovery", "safe"}

-- The data file format this script reads.
local FORMAT = 1

local MAX_BODY = 1 << 20      -- body bytes kept, as athar scan
local MAX_HEADER = 64 << 10   -- header block limit
local MAX_BANNER = 8 << 10    -- banner bytes kept
local BANNER_TAIL = 1000      -- ms a banner may go on after the wait for it
local MAX_RAW = 8 << 20       -- raw body bytes read at most
local USER_AGENT = "Mozilla/5.0 (compatible; athar-nse; +https://github.com/Athar-HQ/Athar)"

local byte, char, find, sub, gsub = string.byte, string.char, string.find, string.sub, string.gsub
local concat = table.concat

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

---------------------------------------------------------------------------
-- Text helpers that behave like Go's, which athar scan uses.
---------------------------------------------------------------------------

local LOWER = {}
for c = 65, 90 do LOWER[char(c)] = char(c + 32) end

-- ASCII lower case; string.lower depends on the locale.
local function lower(s)
  return (gsub(s, "[A-Z]", LOWER))
end

-- Go's utf8.DecodeRuneInString: the rune at i and its width; an invalid
-- byte is U+FFFD of width 1; -1 and 0 at the end.
local function decode_rune(s, i)
  local c = byte(s, i)
  if not c then return -1, 0 end
  if c < 0x80 then return c, 1 end
  local c1 = byte(s, i + 1)
  if c >= 0xC2 and c <= 0xDF then
    if c1 and c1 >= 0x80 and c1 <= 0xBF then
      return ((c & 0x1F) << 6) | (c1 & 0x3F), 2
    end
    return 0xFFFD, 1
  end
  local lo, hi = 0x80, 0xBF
  if c == 0xE0 then lo = 0xA0 elseif c == 0xED then hi = 0x9F
  elseif c == 0xF0 then lo = 0x90 elseif c == 0xF4 then hi = 0x8F end
  if not c1 or c1 < lo or c1 > hi then return 0xFFFD, 1 end
  local c2 = byte(s, i + 2)
  if not c2 or c2 < 0x80 or c2 > 0xBF then return 0xFFFD, 1 end
  if c >= 0xE0 and c <= 0xEF then
    return ((c & 0x0F) << 12) | ((c1 & 0x3F) << 6) | (c2 & 0x3F), 3
  end
  if c >= 0xF0 and c <= 0xF4 then
    local c3 = byte(s, i + 3)
    if c3 and c3 >= 0x80 and c3 <= 0xBF then
      return ((c & 0x07) << 18) | ((c1 & 0x3F) << 12) | ((c2 & 0x3F) << 6) | (c3 & 0x3F), 4
    end
  end
  return 0xFFFD, 1
end

-- Unicode white space (Go's unicode.IsSpace) becomes an ASCII space.
local function ascii_spaces(s)
  s = gsub(s, "\xC2[\x85\xA0]", " ")
  s = gsub(s, "\xE1\x9A\x80", " ")
  s = gsub(s, "\xE2\x80[\x80-\x8A\xA8\xA9\xAF]", " ")
  s = gsub(s, "\xE2\x81\x9F", " ")
  s = gsub(s, "\xE3\x80\x80", " ")
  return s
end

-- strings.Fields joined by single spaces.
local function collapse(s)
  local words = {}
  for w in ascii_spaces(s):gmatch("[^\t\n\v\f\r ]+") do words[#words + 1] = w end
  return concat(words, " ")
end

local SPACE_RUNE = {[0x09] = true, [0x0A] = true, [0x0B] = true, [0x0C] = true, [0x0D] = true,
  [0x20] = true, [0x85] = true, [0xA0] = true, [0x1680] = true, [0x2028] = true, [0x2029] = true,
  [0x202F] = true, [0x205F] = true, [0x3000] = true}
for r = 0x2000, 0x200A do SPACE_RUNE[r] = true end

-- strings.TrimSpace.
local function trim_space(s)
  local i, j = 1, #s
  while i <= j do
    local r, w = decode_rune(s, i)
    if not SPACE_RUNE[r] then break end
    i = i + w
  end
  while j >= i do
    local k = j
    while k > i and j - k < 3 and (byte(s, k) & 0xC0) == 0x80 do k = k - 1 end
    local r, w = decode_rune(s, k)
    if k + w - 1 ~= j or not SPACE_RUNE[r] then break end
    j = k - 1
  end
  return sub(s, i, j)
end

-- HTML entities: the HTML 4 set, &apos; and the upper-case aliases, as Go's
-- html package decodes them. Names marked * also work without a semicolon.
-- Other HTML5 names are left as they are.
local ENTITY_LIST = [[
AElig* 198 AMP* 38 Aacute* 193 Acirc* 194 Agrave* 192 Alpha 913 Aring* 197
Atilde* 195 Auml* 196 Beta 914 COPY* 169 Ccedil* 199 Chi 935 Dagger 8225
Delta 916 ETH* 208 Eacute* 201 Ecirc* 202 Egrave* 200 Epsilon 917 Eta 919
Euml* 203 GT* 62 Gamma 915 Iacute* 205 Icirc* 206 Igrave* 204 Iota 921
Iuml* 207 Kappa 922 LT* 60 Lambda 923 Mu 924 Ntilde* 209 Nu 925 OElig 338
Oacute* 211 Ocirc* 212 Ograve* 210 Omega 937 Omicron 927 Oslash* 216
Otilde* 213 Ouml* 214 Phi 934 Pi 928 Prime 8243 Psi 936 QUOT* 34 REG* 174
Rho 929 Scaron 352 Sigma 931 THORN* 222 Tau 932 Theta 920 Uacute* 218
Ucirc* 219 Ugrave* 217 Upsilon 933 Uuml* 220 Xi 926 Yacute* 221 Yuml 376
Zeta 918 aacute* 225 acirc* 226 acute* 180 aelig* 230 agrave* 224
alefsym 8501 alpha 945 amp* 38 and 8743 ang 8736 apos 39 aring* 229
asymp 8776 atilde* 227 auml* 228 bdquo 8222 beta 946 brvbar* 166 bull 8226
cap 8745 ccedil* 231 cedil* 184 cent* 162 chi 967 circ 710 clubs 9827
cong 8773 copy* 169 crarr 8629 cup 8746 curren* 164 dArr 8659 dagger 8224
darr 8595 deg* 176 delta 948 diams 9830 divide* 247 eacute* 233 ecirc* 234
egrave* 232 empty 8709 emsp 8195 ensp 8194 epsilon 949 equiv 8801 eta 951
eth* 240 euml* 235 euro 8364 exist 8707 fnof 402 forall 8704 frac12* 189
frac14* 188 frac34* 190 frasl 8260 gamma 947 ge 8805 gt* 62 hArr 8660
harr 8596 hearts 9829 hellip 8230 iacute* 237 icirc* 238 iexcl* 161
igrave* 236 image 8465 infin 8734 int 8747 iota 953 iquest* 191 isin 8712
iuml* 239 kappa 954 lArr 8656 lambda 955 lang 10216 laquo* 171 larr 8592
lceil 8968 ldquo 8220 le 8804 lfloor 8970 lowast 8727 loz 9674 lrm 8206
lsaquo 8249 lsquo 8216 lt* 60 macr* 175 mdash 8212 micro* 181 middot* 183
minus 8722 mu 956 nabla 8711 nbsp* 160 ndash 8211 ne 8800 ni 8715 not* 172
notin 8713 nsub 8836 ntilde* 241 nu 957 oacute* 243 ocirc* 244 oelig 339
ograve* 242 oline 8254 omega 969 omicron 959 oplus 8853 or 8744 ordf* 170
ordm* 186 oslash* 248 otilde* 245 otimes 8855 ouml* 246 para* 182 part 8706
permil 8240 perp 8869 phi 966 pi 960 piv 982 plusmn* 177 pound* 163
prime 8242 prod 8719 prop 8733 psi 968 quot* 34 rArr 8658 radic 8730
rang 10217 raquo* 187 rarr 8594 rceil 8969 rdquo 8221 real 8476 reg* 174
rfloor 8971 rho 961 rlm 8207 rsaquo 8250 rsquo 8217 sbquo 8218 scaron 353
sdot 8901 sect* 167 shy* 173 sigma 963 sigmaf 962 sim 8764 spades 9824
sub 8834 sube 8838 sum 8721 sup 8835 sup1* 185 sup2* 178 sup3* 179 supe 8839
szlig* 223 tau 964 there4 8756 theta 952 thetasym 977 thinsp 8201 thorn* 254
tilde 732 times* 215 trade 8482 uArr 8657 uacute* 250 uarr 8593 ucirc* 251
ugrave* 249 uml* 168 upsih 978 upsilon 965 uuml* 252 weierp 8472 xi 958
yacute* 253 yen* 165 yuml* 255 zeta 950 zwj 8205 zwnj 8204
]]

local ENTITY = {}
for name, legacy, cp in ENTITY_LIST:gmatch("(%a[%w]*)(%*?)%s+(%d+)") do
  ENTITY[name .. ";"] = utf8.char(tonumber(cp))
  if legacy == "*" then ENTITY[name] = utf8.char(tonumber(cp)) end
end

-- Numeric references to 0x80-0x9F are read as Windows-1252.
local CP1252 = {
  0x20AC, 0x0081, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
  0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0x008D, 0x017D, 0x008F,
  0x0090, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
  0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0x009D, 0x017E, 0x0178,
}

local function wrap32(x)
  return ((x + 0x80000000) % 0x100000000) - 0x80000000
end

local function is_alnum(c)
  return c and ((c >= 48 and c <= 57) or (c >= 65 and c <= 90) or (c >= 97 and c <= 122))
end

-- One character reference at s[i] == "&", as Go's html.unescapeEntity: the
-- replacement and the index after what it consumed.
local function unescape_entity(s, i)
  local len = #s - i + 1
  if len <= 1 then return "&", i + 1 end
  if byte(s, i + 1) == 35 then -- '#'
    if len <= 3 then return "&", i + 1 end
    local g = 2
    local c = byte(s, i + g)
    local hex = false
    if c == 120 or c == 88 then
      hex = true
      g = g + 1
    end
    local x = 0
    while g < len do
      c = byte(s, i + g)
      g = g + 1
      local d
      if hex then
        if c >= 48 and c <= 57 then d = c - 48
        elseif c >= 97 and c <= 102 then d = c - 87
        elseif c >= 65 and c <= 70 then d = c - 55 end
        if d then x = wrap32(16 * x + d) end
      elseif c >= 48 and c <= 57 then
        d = c - 48
        x = wrap32(10 * x + d)
      end
      if not d then
        if c ~= 59 then g = g - 1 end
        break
      end
    end
    if g <= 3 then return "&", i + 1 end
    if x >= 0x80 and x <= 0x9F then
      x = CP1252[x - 0x80 + 1]
    elseif x <= 0 or (x >= 0xD800 and x <= 0xDFFF) or x > 0x10FFFF then
      x = 0xFFFD
    end
    return utf8.char(x), i + g
  end
  local g = 1
  while g < len do
    local c = byte(s, i + g)
    g = g + 1
    if not is_alnum(c) then
      if c ~= 59 then g = g - 1 end
      break
    end
  end
  local name = sub(s, i + 1, i + g - 1)
  if #name > 0 then
    local v = ENTITY[name]
    if v then return v, i + g end
    for j = math.min(#name - 1, 6), 2, -1 do
      v = ENTITY[sub(name, 1, j)]
      if v and not find(sub(name, 1, j), ";", 1, true) then return v, i + j + 1 end
    end
  end
  return sub(s, i, i + g - 1), i + g
end

-- html.UnescapeString.
local function unescape_html(s)
  if not find(s, "&", 1, true) then return s end
  local out, i = {}, 1
  while i <= #s do
    local a = find(s, "&", i, true)
    if not a then
      out[#out + 1] = sub(s, i)
      break
    end
    out[#out + 1] = sub(s, i, a - 1)
    local v
    v, i = unescape_entity(s, a)
    out[#out + 1] = v
  end
  return concat(out)
end

-- The first <title>, entity-decoded and whitespace-collapsed, or nil.
local function html_title(body)
  local lb = lower(body)
  local a = find(lb, "<title", 1, true)
  if not a then return nil end
  local b = find(lb, ">", a + 6, true)
  if not b then return nil end
  local c = find(lb, "</title>", b + 1, true)
  if not c then return nil end
  return collapse(unescape_html(sub(body, b + 1, c - 1)))
end

---------------------------------------------------------------------------
-- Matching.
---------------------------------------------------------------------------

-- Case-insensitive comparison folds both sides to one rune per case-folding
-- orbit: ASCII letters to lower case, other runes as the rule's fold table
-- says. athar convert folds the values and writes the table.
local function canon(s, fold)
  s = gsub(s, "[A-Z]", LOWER)
  if fold then
    s = gsub(s, "[\xC2-\xDF][\x80-\xBF]", fold)
    s = gsub(s, "[\xE0-\xEF][\x80-\xBF][\x80-\xBF]", fold)
    s = gsub(s, "[\xF0-\xF4][\x80-\xBF][\x80-\xBF][\x80-\xBF]", fold)
  end
  return s
end

-- Regular expressions arrive compiled by Go's regexp/syntax and run here on
-- a Pike VM, which finds the same leftmost-first match and groups as Go.
local ALT, CAP, EMPTY, MATCH, FAIL, NOP, RUNE, ANY, ANYNL = 1, 2, 3, 4, 5, 6, 7, 8, 9

local function is_word(r)
  return (r >= 48 and r <= 57) or (r >= 65 and r <= 90) or (r >= 97 and r <= 122) or r == 95
end

-- syntax.EmptyOpContext.
local function context(r1, r2)
  local op, boundary = 32, false
  if is_word(r1) then boundary = true
  elseif r1 == 10 then op = op | 1
  elseif r1 < 0 then op = op | 5 end
  if is_word(r2) then boundary = not boundary
  elseif r2 == 10 then op = op | 2
  elseif r2 < 0 then op = op | 10 end
  if boundary then op = op ~ 48 end
  return op
end

local function in_ranges(inst, r)
  local lo, hi = 1, (#inst - 2) // 2
  while lo <= hi do
    local m = (lo + hi) // 2
    if r < inst[2 * m + 1] then hi = m - 1
    elseif r > inst[2 * m + 2] then lo = m + 1
    else return true end
  end
  return false
end

local function new_queue() return {n = 0, pc = {}, cap = {}, sp = {}} end

local function add_thread(q, insts, pc, pos, cap, ctx)
  while true do
    local j = q.sp[pc]
    if j and j <= q.n and q.pc[j] == pc then return end
    local n = q.n + 1
    q.n, q.pc[n], q.cap[n], q.sp[pc] = n, pc, false, n
    local i = insts[pc]
    local op = i[1]
    if op == ALT then
      add_thread(q, insts, i[2], pos, cap, ctx)
      pc = i[3]
    elseif op == EMPTY then
      if ctx & i[3] ~= i[3] then return end
      pc = i[2]
    elseif op == NOP then
      pc = i[2]
    elseif op == CAP then
      local k = i[3] + 1
      if k <= #cap then
        local old = cap[k]
        cap[k] = pos
        add_thread(q, insts, i[2], pos, cap, ctx)
        cap[k] = old
        return
      end
      pc = i[2]
    elseif op == FAIL then
      return
    else
      q.cap[n] = table.move(cap, 1, #cap, 1, {})
      return
    end
  end
end

-- Searches s; ncap is how many group positions to track (0 for yes or no).
-- Returns whether it matched and the positions (1-based, end exclusive).
local function regex_search(prog, s, ncap)
  local insts, start, anchored = prog.i, prog.s, prog.a
  local runq, nextq = new_queue(), new_queue()
  local matched, mcap = false, nil
  local pos = 1
  local r, w = decode_rune(s, pos)
  local r1, w1 = -1, 0
  if w > 0 then r1, w1 = decode_rune(s, pos + w) end
  local ctx = context(-1, r)
  local scratch = {}
  while true do
    if runq.n == 0 then
      if anchored and pos ~= 1 then break end
      if matched then break end
    end
    if not matched and (pos == 1 or not anchored) then
      for k = 1, ncap do scratch[k] = -1 end
      if ncap > 0 then scratch[1] = pos end
      add_thread(runq, insts, start, pos, scratch, ctx)
    end
    local nctx = context(r, r1)
    local npos = pos + w
    for j = 1, runq.n do
      local cap = runq.cap[j]
      if cap then
        local i = insts[runq.pc[j]]
        local op = i[1]
        if op == MATCH then
          if ncap > 0 then
            cap[2] = pos
            mcap = cap
          end
          matched = true
          break -- leftmost-first: lower-priority threads are dropped
        end
        local ok
        if op == RUNE then ok = r >= 0 and in_ranges(i, r)
        elseif op == ANY then ok = r >= 0
        elseif op == ANYNL then ok = r >= 0 and r ~= 10 end
        if ok then add_thread(nextq, insts, i[2], npos, cap, nctx) end
      end
    end
    runq.n = 0
    if w == 0 then break end
    if ncap == 0 and matched then break end
    pos = npos
    r, w = r1, w1
    if w > 0 then r1, w1 = decode_rune(s, pos + w) end
    ctx = nctx
    runq, nextq = nextq, runq
  end
  return matched, mcap
end

local function to_string(v)
  if v == true then return "true" elseif v == false then return "false" end
  return tostring(v)
end

-- strconv.ParseFloat for decimal numbers.
local function to_number(v)
  if math.type(v) then return v end
  local s = to_string(v)
  if s:match("^[+-]?%d+%.?%d*$") or s:match("^[+-]?%.%d+$") or
     s:match("^[+-]?%d+%.?%d*[eE][+-]?%d+$") or s:match("^[+-]?%.%d+[eE][+-]?%d+$") then
    return tonumber(s)
  end
  local l = lower(s):gsub("^[+-]", "")
  if l == "inf" or l == "infinity" then
    return sub(s, 1, 1) == "-" and -math.huge or math.huge
  end
  return nil
end

local function match_value(v, t, ctx)
  local m = t.m
  if m == "num" then
    local x = to_number(v)
    if not x then return false end
    if t.o == "gt" then return x > t.x
    elseif t.o == "gte" then return x >= t.x
    elseif t.o == "lt" then return x < t.x end
    return x <= t.x
  end
  local s = to_string(v)
  if m == "re" then
    return (regex_search(ctx.rule.re[t.r], s, 0))
  end
  if not t.c then
    local cs = ctx.canon[s]
    if not cs then
      cs = canon(s, ctx.rule.fold)
      ctx.canon[s] = cs
    end
    s = cs
  end
  local val = t.v
  if m == "eq" then return s == val
  elseif m == "contains" then return find(s, val, 1, true) ~= nil
  elseif m == "startswith" then return sub(s, 1, #val) == val end
  return #val <= #s and sub(s, #s - #val + 1) == val
end

local function any_element(v, t, ctx)
  if type(v) == "table" then
    for _, e in ipairs(v) do
      if match_value(e, t, ctx) then return true end
    end
    return false
  end
  return match_value(v, t, ctx)
end

local KEYWORD_FIELDS = {"service.banner", "http.headers_raw", "http.body"}

local function eval_term(t, ctx)
  local f = ctx.resp[t.p or "default"]
  if not f then return false end
  if t.k then
    for _, name in ipairs(KEYWORD_FIELDS) do
      local v = f[name]
      if v ~= nil and any_element(v, t, ctx) then return true end
    end
    return false
  end
  local v = f[t.f]
  if t.m == "exists" then return (v ~= nil) == t.x end
  if v == nil then return false end
  return any_element(v, t, ctx)
end

local function eval_node(node, ctx)
  local kind = node[1]
  if kind == "and" then
    for i = 2, #node do
      if not eval_node(node[i], ctx) then return false end
    end
    return true
  elseif kind == "or" then
    for i = 2, #node do
      if eval_node(node[i], ctx) then return true end
    end
    return false
  end
  local r = eval_term(node, ctx)
  if node.n then return not r end
  return r
end

---------------------------------------------------------------------------
-- Extraction.
---------------------------------------------------------------------------

-- strconv.FormatFloat(x, 'f', -1, 64).
local function go_float(x)
  if x ~= x then return "NaN" end
  if x == math.huge then return "+Inf" elseif x == -math.huge then return "-Inf" end
  local e_str
  for p = 0, 16 do
    e_str = string.format("%." .. p .. "e", x)
    if tonumber(e_str) == x then break end
  end
  local sign, int, frac, exp = e_str:match("^(-?)(%d)%.?(%d*)e([+-]%d+)$")
  local digits = (int .. frac):gsub("0+$", "")
  if digits == "" then return sign .. "0" end
  local e = tonumber(exp)
  local out
  if e >= #digits - 1 then
    out = digits .. string.rep("0", e - #digits + 1)
  elseif e >= 0 then
    out = sub(digits, 1, e + 1) .. "." .. sub(digits, e + 2)
  else
    out = "0." .. string.rep("0", -e - 1) .. digits
  end
  return sign .. out
end

local function json_value(s, path)
  local ok, doc = json.parse(s)
  if not ok then return nil end
  for _, seg in ipairs(path) do
    local mt = type(doc) == "table" and getmetatable(doc)
    if not (mt and mt.json == "object") then return nil end
    doc = doc[seg]
    if doc == nil then return nil end
  end
  if type(doc) == "table" then return nil end -- object, array or null
  if type(doc) == "number" then return go_float(doc + 0.0) end
  return to_string(doc)
end

-- extracted_text prints the extracted values for Nmap's readable output.
-- Nmap escapes control characters there, but not the line feed and the tab:
-- a value from the service could add lines that read like another match.
-- Both are shown the way Nmap shows the others, as \x0A and \x09. The XML
-- output keeps the values. Six spaces is Nmap's indent at this depth.
local function extracted_text(t)
  local lines = {}
  for k, v in pairs(t) do
    lines[#lines + 1] = "\n      " .. k .. ": " ..
      gsub(v, "[\n\t]", function(c) return string.format("\\x%02X", byte(c)) end)
  end
  return concat(lines)
end

local function run_extract(rule, f)
  if not rule.extract then return nil end
  local out, any = stdnse.output_table(), false
  getmetatable(out).__tostring = extracted_text
  for _, x in ipairs(rule.extract) do
    local v = f[x.f]
    if v ~= nil then
      local values = type(v) == "table" and v or {v}
      for _, e in ipairs(values) do
        local s, got = to_string(e), nil
        if x.r then
          local g = x.g or 0
          local ok, cap = regex_search(rule.re[x.r], s, 2 * (g + 1))
          if ok then
            local a, b = cap[2 * g + 1], cap[2 * g + 2]
            got = (a and a >= 0) and sub(s, a, b - 1) or ""
          end
        elseif x.j then
          got = json_value(s, x.j)
        end
        if got then
          out[x.name] = got
          any = true
          break
        end
      end
    end
  end
  return any and out or nil
end

---------------------------------------------------------------------------
-- Hashes.
---------------------------------------------------------------------------

local M32 = 0xffffffff

local function rotl32(x, r)
  return ((x << r) | (x >> (32 - r))) & M32
end

-- 32-bit MurmurHash3 with seed 0, signed, as Python's mmh3.hash.
local function mmh3(data)
  local c1, c2 = 0xcc9e2d51, 0x1b873593
  local h = 0
  local n = #data // 4
  for i = 0, n - 1 do
    local k = string.unpack("<I4", data, i * 4 + 1)
    k = rotl32((k * c1) & M32, 15)
    k = (k * c2) & M32
    h = rotl32(h ~ k, 13)
    h = (h * 5 + 0xe6546b64) & M32
  end
  local base, tail = n * 4, #data % 4
  local k = 0
  if tail == 3 then k = k ~ (byte(data, base + 3) << 16) end
  if tail >= 2 then k = k ~ (byte(data, base + 2) << 8) end
  if tail >= 1 then
    k = k ~ byte(data, base + 1)
    k = rotl32((k * c1) & M32, 15)
    k = (k * c2) & M32
    h = h ~ k
  end
  h = h ~ (#data & M32)
  h = h ~ (h >> 16)
  h = (h * 0x85ebca6b) & M32
  h = h ~ (h >> 13)
  h = (h * 0xc2b2ae35) & M32
  h = h ~ (h >> 16)
  if h >= 0x80000000 then h = h - 0x100000000 end
  return h
end

-- The Shodan favicon hash: mmh3 over base64 with a newline every 76
-- characters and at the end.
local function favicon_mmh3(icon)
  local enc = base64.enc(icon)
  local lines = {}
  for i = 1, #enc, 76 do lines[#lines + 1] = sub(enc, i, i + 75) .. "\n" end
  return mmh3(concat(lines))
end

local function hex(b) return stdnse.tohex(b) end

---------------------------------------------------------------------------
-- HTTP, as athar scan sends and reads it.
---------------------------------------------------------------------------

local function recv(sock, deadline)
  local left = deadline - nmap.clock_ms()
  if left <= 0 then return nil end
  sock:set_timeout(math.max(1, math.floor(left)))
  local ok, data = sock:receive()
  if not ok then return nil end
  return data
end

local function trim_ws(s) -- textproto's trim: ASCII space, tab, CR, LF
  return (s:match("^[ \t\r\n]*(.-)[ \t\r\n]*$"))
end

local function bytewise_less(a, b)
  local n = math.min(#a, #b)
  for i = 1, n do
    local x, y = byte(a, i), byte(b, i)
    if x ~= y then return x < y end
  end
  return #a < #b
end

local function has_token(values, token)
  for _, v in ipairs(values or {}) do
    for part in (v .. ","):gmatch("([^,]*),") do
      if lower(part:match("^[ \t]*(.-)[ \t]*$")) == token then return true end
    end
  end
  return false
end

-- Parses the header block as Go's net/http.ReadResponse does. Returns nil
-- where Go rejects the response.
local function parse_head(head, method)
  local lines = {}
  for line in head:gmatch("([^\n]*)\n") do lines[#lines + 1] = (line:gsub("\r$", "")) end
  local proto, rest = (lines[1] or ""):match("^([^ ]*) (.*)$")
  if not proto then return nil end
  local code = rest:gsub("^ +", ""):match("^([^ ]*)")
  if #code ~= 3 or not code:match("^[+-]?%d+$") then return nil end
  local status = tonumber(code)
  if status < 0 then return nil end
  local major, minor
  if proto == "HTTP/1.1" then major, minor = 1, 1
  elseif proto == "HTTP/1.0" then major, minor = 1, 0
  else
    local a, b = proto:match("^HTTP/(%d)%.(%d)$")
    if not a then return nil end
    major, minor = tonumber(a), tonumber(b)
  end

  local kvs = {}
  if lines[2] and lines[2]:match("^[ \t]") then return nil end
  for i = 2, #lines do
    local line = lines[i]
    if not find(line, "[^\r]") then break end
    if line:match("^[ \t]") then
      kvs[#kvs] = kvs[#kvs] .. " " .. trim_ws(line)
    else
      if not find(line, ":", 1, true) then return nil end
      kvs[#kvs + 1] = trim_ws(line)
    end
  end
  local order, header = {}, {}
  for _, kv in ipairs(kvs) do
    local k, v = kv:match("^([^:]*):(.*)$")
    if #k == 0 or find(k, "[^0-9A-Za-z!#$%%&'*+%-.^_`|~ ]") then return nil end
    if find(v, "[\0-\8\10-\31\127]") then return nil end
    v = v:gsub("^[ \t]+", "")
    local name = lower(k)
    if not header[name] then
      header[name] = {}
      order[#order + 1] = name
    end
    table.insert(header[name], v)
  end
  -- The fields hold every header as received; what is removed below only
  -- decides how the body is read.
  local received = {}
  for name, values in pairs(header) do received[name] = values end

  -- What net/http's readTransfer removes or rejects.
  local tmajor, tminor = major, minor
  if tmajor == 0 and tminor == 0 then tmajor, tminor = 1, 1 end
  if major >= 1 and not (major == 1 and minor == 0) and has_token(header["connection"], "close") then
    header["connection"] = nil
  end
  local chunked = false
  local te = header["transfer-encoding"]
  if te then
    header["transfer-encoding"] = nil
    if tmajor > 1 or (tmajor == 1 and tminor >= 1) then
      if #te ~= 1 or lower(te[1]) ~= "chunked" then return nil end
      chunked = true
    end
  end
  local cl = header["content-length"]
  local length = -1
  if cl then
    local first = trim_ws(cl[1])
    for k = 2, #cl do
      if trim_ws(cl[k]) ~= first then return nil end
    end
    if #cl > 1 then header["content-length"] = {first} end
    length = first:match("^%d+$") and math.tointeger(tonumber(first))
    if not length then return nil end
  end
  local nobody = method == "HEAD" or status // 100 == 1 or status == 204 or status == 304
  local mode
  if nobody then
    mode = "none"
  elseif chunked then
    header["content-length"] = nil
    mode = "chunked"
  elseif length >= 0 then
    mode = length == 0 and "none" or "length"
  else
    mode = "eof"
  end
  if chunked and header["trailer"] then
    for _, v in ipairs(header["trailer"]) do
      for part in (v .. ","):gmatch("([^,]*),") do
        local key = lower(part:match("^[ \t]*(.-)[ \t]*$"))
        if key == "transfer-encoding" or key == "trailer" or key == "content-length" then return nil end
      end
    end
    header["trailer"] = nil
  end
  return {status = status, header = header, received = received, order = order, mode = mode, length = length}
end

-- Decodes chunked data as it arrives, like Go's chunked reader.
local function chunk_feed(st, data)
  st.raw = st.raw .. data
  while not st.done do
    if st.left > 0 then
      local take = math.min(st.left, #st.raw)
      if take == 0 then return end
      st.out[#st.out + 1] = sub(st.raw, 1, take)
      st.size = st.size + take
      st.raw = sub(st.raw, take + 1)
      st.left = st.left - take
      if st.left > 0 then return end
      st.crlf = true
    elseif st.crlf then
      if #st.raw < 2 then return end
      if sub(st.raw, 1, 2) ~= "\r\n" then st.done = true return end
      st.raw = sub(st.raw, 3)
      st.crlf = false
    else
      local nl = find(st.raw, "\n", 1, true)
      if not nl then
        if #st.raw >= 4096 then st.done = true end
        return
      end
      local line = sub(st.raw, 1, nl)
      st.raw = sub(st.raw, nl + 1)
      if find(line, "\r", 1, true) ~= #line - 1 or #line - 2 >= 4096 then st.done = true return end
      line = sub(line, 1, -3):gsub("[ \t\r\n]+$", ""):match("^[^;]*")
      if #line == 0 or #line > 16 or find(line, "[^0-9a-fA-F]") then st.done = true return end
      local n = tonumber(line, 16)
      if not n or n <= 0 then st.done = true return end
      st.left = n
    end
  end
end

-- Where the deflate data of a gzip member starts, or nil where Go's
-- gzip.NewReader rejects the header (RFC 1952: magic, method, optional
-- extra field, name, comment and header CRC).
local function gzip_data_start(data)
  if #data < 10 or sub(data, 1, 3) ~= "\x1f\x8b\x08" then return nil end
  local flags, pos = byte(data, 4), 11
  if flags & 4 ~= 0 then
    if #data < pos + 1 then return nil end
    pos = pos + 2 + (byte(data, pos) | (byte(data, pos + 1) << 8))
    if pos - 1 > #data then return nil end
  end
  for _, flag in ipairs({8, 16}) do -- name, comment: zero-terminated, under 512 bytes
    if flags & flag ~= 0 then
      local z = find(data, "\0", pos, true)
      if not z or z - pos >= 512 then return nil end
      pos = z + 1
    end
  end
  if flags & 2 ~= 0 then
    if #data < pos + 1 then return nil end
    if zlib.crc32(0, sub(data, 1, pos - 1)) & 0xffff ~= (byte(data, pos) | (byte(data, pos + 1) << 8)) then
      return nil
    end
    pos = pos + 2
  end
  return pos
end

-- Decodes a gzip body as athar scan does: without a valid gzip header it is
-- kept as sent (nil); otherwise it is what decodes, which is all of a
-- truncated body that arrived and nothing of corrupt data. The header is
-- parsed here and the deflate data inflated raw, so zlib's own header checks
-- don't apply. zlib.decompress never returns on truncated input, so the
-- stream interface is used.
local function gunzip(data)
  local start = gzip_data_start(data)
  if not start then return nil end
  local ok, stream = pcall(zlib.inflate, sub(data, start), -15)
  if not ok then return "" end
  local parts, n = {}, 0
  while n < MAX_BODY do
    local ok2, piece = pcall(stream.read, stream, 65536)
    if not ok2 or not piece or piece == "" then break end
    parts[#parts + 1] = piece
    n = n + #piece
  end
  pcall(stream.close, stream)
  return concat(parts)
end

-- Where the header block ends: the first line that is empty but for CRs.
local function head_end(s, from)
  local pos = from
  while true do
    local nl = find(s, "\n", pos, true)
    if not nl then return nil, pos end
    if not find(sub(s, pos, nl - 1), "[^\r]") then return nl, pos end
    pos = nl + 1
  end
end

local function check_request(method, path, headers)
  if find(method, "[\0- \127]") or find(path, "[\0- \127]") then return false end
  for k, v in pairs(headers or {}) do
    if find(k, "[\r\n\0: \t]") or find(v, "[\r\n\0]") then return false end
  end
  return true
end

-- Sends one request on sock and reads the response, as athar scan's
-- httpExchange. Returns nil if there is no valid HTTP response.
local function http_exchange(sock, hosthdr, method, path, headers, deadline)
  if not check_request(method, path, headers) then return nil end
  local req = {method, " ", path, " HTTP/1.1\r\nHost: ", hosthdr, "\r\nUser-Agent: ", USER_AGENT,
    "\r\nAccept: */*\r\nConnection: close\r\n"}
  local names = {}
  for k in pairs(headers or {}) do names[#names + 1] = k end
  table.sort(names, bytewise_less)
  for _, k in ipairs(names) do
    local lk = lower(k)
    if lk ~= "host" and lk ~= "connection" then
      req[#req + 1] = k .. ": " .. headers[k] .. "\r\n"
    end
  end
  req[#req + 1] = "\r\n"
  if not sock:send(concat(req)) then return nil end

  local buf, from, hend = "", 1, nil
  while true do
    hend, from = head_end(buf, from)
    if hend then break end
    if #buf > MAX_HEADER then return nil end
    local data = recv(sock, deadline)
    if not data then return nil end
    buf = buf .. data
  end
  if hend > MAX_HEADER or sub(buf, 1, 5) ~= "HTTP/" then return nil end
  local head = sub(buf, 1, hend)
  local resp = parse_head(head, method)
  if not resp then return nil end

  local gzip = resp.header["content-encoding"] and lower(resp.header["content-encoding"][1]) == "gzip"
  local rest = sub(buf, hend + 1)
  local body
  if resp.mode == "none" then
    body = ""
  elseif resp.mode == "chunked" then
    local st = {raw = "", out = {}, size = 0, left = 0, crlf = false, done = false}
    chunk_feed(st, rest)
    local limit = gzip and MAX_RAW or MAX_BODY
    while not st.done and st.size < limit do
      local data = recv(sock, deadline)
      if not data then break end
      chunk_feed(st, data)
    end
    body = concat(st.out)
  else
    local parts, have = {rest}, #rest
    local want = resp.mode == "length" and resp.length or math.huge
    local limit = math.min(want, gzip and MAX_RAW or MAX_BODY)
    while have < limit do
      local data = recv(sock, deadline)
      if not data then break end
      parts[#parts + 1] = data
      have = have + #data
    end
    body = concat(parts)
    if resp.mode == "length" then body = sub(body, 1, resp.length) end
  end
  if gzip and #body > 0 then
    body = gunzip(body) or body
  end
  if #body > MAX_BODY then body = sub(body, 1, MAX_BODY) end
  resp.raw = head
  resp.body = body
  return resp
end

local function http_fields(f, resp)
  f["service.protocol"] = "http"
  f["http.status_code"] = resp.status
  f["http.headers_raw"] = resp.raw
  for _, name in ipairs(resp.order) do
    local values = resp.received[name]
    f["http.headers." .. name] = #values == 1 and values[1] or values
  end
  f["http.body"] = resp.body
  f["http.body.mmh3"] = mmh3(resp.body)
  f["http.body.sha256"] = hex(openssl.digest("sha256", resp.body))
  local t = html_title(resp.body)
  if t then f["http.title"] = t end
end

---------------------------------------------------------------------------
-- Favicon: <link rel="icon"> first, else /favicon.ico.
---------------------------------------------------------------------------

local SPACE = "[\t\n\f\r ]" -- RE2's \s

-- The first attribute value of name in a tag, as the regexp
-- \bname\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)), entity-decoded.
local function tag_attr(tag, name)
  local lt = lower(tag)
  local from = 1
  while true do
    local i, j = find(lt, name, from, true)
    if not i then return "" end
    from = i + 1
    local prev = i > 1 and byte(lt, i - 1)
    if not (prev and (is_alnum(prev) or prev == 95)) then
      local k = lt:match("^" .. SPACE .. "*()", j + 1)
      if sub(lt, k, k) == "=" then
        k = lt:match("^" .. SPACE .. "*()", k + 1)
        local c, v = sub(tag, k, k), nil
        if c == '"' then v = tag:match('^"([^"]*)"', k)
        elseif c == "'" then v = tag:match("^'([^']*)'", k) end
        if v == nil then v = tag:match("^([^\t\n\f\r >]+)", k) end
        if v ~= nil then return unescape_html(v) end
      end
    end
  end
end

-- The href of the first <link> whose rel lists "icon", or "".
local function favicon_ref(body)
  local lb = lower(body)
  local from = 1
  while true do
    local i = find(lb, "<lin", from, true)
    if not i then return "" end
    local after
    if sub(lb, i + 4, i + 4) == "k" then after = i + 5
    elseif sub(lb, i + 4, i + 6) == "\xE2\x84\xAA" then after = i + 7 end -- Kelvin sign
    local nb = after and byte(lb, after)
    if after and not (nb and (is_alnum(nb) or nb == 95)) then
      local gt = find(lb, ">", after, true)
      if not gt then return "" end
      local tag = sub(body, i, gt)
      local rel = ascii_spaces(lower(tag_attr(tag, "rel")):gsub("\xC4\xB0", "i"))
      for tok in rel:gmatch("[^\t\n\v\f\r ]+") do
        if tok == "icon" then return trim_space(tag_attr(tag, "href")) end
      end
      from = gt + 1
    else
      from = i + 1
    end
  end
end

local function is_hex(c)
  return c and ((c >= 48 and c <= 57) or (c >= 65 and c <= 70) or (c >= 97 and c <= 102))
end

-- url.PathUnescape-style decoding; nil on a bad escape.
local function unescape_pct(s)
  local out, i = {}, 1
  while i <= #s do
    local c = byte(s, i)
    if c == 37 then
      if not (is_hex(byte(s, i + 1)) and is_hex(byte(s, i + 2))) then return nil end
      out[#out + 1] = char(tonumber(sub(s, i + 1, i + 2), 16))
      i = i + 3
    else
      out[#out + 1] = char(c)
      i = i + 1
    end
  end
  return concat(out)
end

local function decode_data_uri(s)
  local meta, data = sub(s, 6):match("^([^,]*),(.*)$")
  if not meta then return nil end
  if lower(meta):sub(-7) == ";base64" then
    data = gsub(ascii_spaces(data), "[\t\n\v\f\r ]", "")
    if #data % 4 ~= 0 then return nil end
    local body, pad = data:match("^([A-Za-z0-9+/]*)(=*)$")
    if not body or #pad > 2 then return nil end
    return base64.dec(data)
  end
  return unescape_pct(data)
end

local PATH_OK = "[^0-9A-Za-z%-_.~!$&'()*+,;=:@%[%]%%/]"   -- validEncoded(path)
local PATH_KEEP = "[^0-9A-Za-z%-_.~$&+,/:;=@]"              -- escape(path)

-- net/url's resolvePath against "/".
local function resolve_path(ref)
  local full = sub(ref, 1, 1) == "/" and ref or "/" .. ref
  local dst, first = {"/"}, true
  local elem
  local remaining, found = full, true
  while found do
    local cut = find(remaining, "/", 1, true)
    if cut then elem, remaining = sub(remaining, 1, cut - 1), sub(remaining, cut + 1)
    else elem, found = remaining, false end
    if elem == "." then
      first = false
    elseif elem == ".." then
      local str = sub(concat(dst), 2)
      local idx = str:match(".*()/")
      if not idx then
        dst, first = {"/"}, true
      else
        dst = {"/", sub(str, 1, idx - 1)}
      end
    else
      if not first then dst[#dst + 1] = "/" end
      dst[#dst + 1] = elem
      first = false
    end
  end
  if elem == "." or elem == ".." then dst[#dst + 1] = "/" end
  local r = concat(dst)
  if #r > 1 and sub(r, 2, 2) == "/" then r = sub(r, 2) end
  return r
end

-- Where the favicon comes from, as athar scan's faviconSource: a path on the
-- same service, or the icon bytes of a data: URI. References that url.Parse
-- rejects, that point at another host or port, or that have no path ("#",
-- "?v=2") fall back to /favicon.ico.
local function favicon_source(ref, hostname, portnum)
  local fallback = "/favicon.ico"
  if ref == "" then return fallback end
  if lower(sub(ref, 1, 5)) == "data:" then
    local b = decode_data_uri(ref)
    if b then return nil, b end
    return fallback
  end
  local rest, frag = ref:match("^([^#]*)#?(.*)$")
  if find(rest, "[\0-\31\127]") then return fallback end
  if find(ref, "#", 1, true) and not unescape_pct(frag) then return fallback end
  -- Scheme.
  local scheme = rest:match("^(%a[%w+%-.]*):")
  if rest:match("^:") then return fallback end
  if scheme then rest = sub(rest, #scheme + 2) end
  local query = ""
  local q = find(rest, "?", 1, true)
  if q then rest, query = sub(rest, 1, q - 1), sub(rest, q + 1) end
  if sub(rest, 1, 1) ~= "/" then
    if scheme then return fallback end -- opaque: no path
    local seg = rest:match("^[^/]*")
    if find(seg, ":", 1, true) then return fallback end
  end
  if sub(rest, 1, 2) == "//" and (scheme or sub(rest, 1, 3) ~= "///") then
    local authority = sub(rest, 3)
    local slash = find(authority, "/", 1, true)
    if slash then authority, rest = sub(authority, 1, slash - 1), sub(authority, slash)
    else rest = "" end
    local at = authority:match(".*()@")
    local hostport = authority
    if at then
      if find(sub(authority, 1, at - 1), "[^0-9A-Za-z%-_.~!$&'()*+,;=:@%%]") then return fallback end
      hostport = sub(authority, at + 1)
    end
    local h, p
    if sub(hostport, 1, 1) == "[" then
      local close = find(hostport, "]", 1, true)
      if not close then return fallback end
      h = sub(hostport, 2, close - 1)
      p = sub(hostport, close + 1)
      if p ~= "" and not p:match("^:%d*$") then return fallback end
      p = sub(p, 2)
    else
      local colon = hostport:match(".*():")
      if colon then
        p = sub(hostport, colon + 1)
        if not p:match("^%d*$") then return fallback end
        h = sub(hostport, 1, colon - 1)
      else
        h, p = hostport, ""
      end
      if find(h, "[ \\^`{|}]") then return fallback end -- not allowed in a host name
      h = unescape_pct(h)
      if not h then return fallback end
    end
    if hostport ~= "" then
      if lower(h) ~= lower(hostname) or (p ~= "" and p ~= tostring(portnum)) then return fallback end
    end
  end
  if rest == "" then return fallback end -- no path: the page itself
  local path = unescape_pct(rest)
  if not path then return fallback end
  local escaped = rest
  if find(rest, PATH_OK) then
    escaped = gsub(path, PATH_KEEP, function(c) return string.format("%%%02X", byte(c)) end)
  end
  local uri = resolve_path(escaped)
  if query ~= "" then uri = uri .. "?" .. query end
  return uri
end

local function favicon_fields(f, icon)
  if #icon == 0 then return end
  f["http.favicon.mmh3"] = favicon_mmh3(icon)
  f["http.favicon.md5"] = hex(openssl.md5(icon))
  f["http.favicon.sha256"] = hex(openssl.digest("sha256", icon))
end

---------------------------------------------------------------------------
-- TLS certificate fields, read from the DER like Go's crypto/x509.
---------------------------------------------------------------------------

local function der_tlv(s, pos)
  local tag, len = byte(s, pos, pos + 1)
  if not len then return nil end
  local p = pos + 2
  if len >= 0x80 then
    local n = len - 0x80
    if n < 1 or n > 4 then return nil end
    len = 0
    for k = 0, n - 1 do
      local b = byte(s, p + k)
      if not b then return nil end
      len = len * 256 + b
    end
    p = p + n
  end
  local e = p + len - 1
  if e > #s then return nil end
  return tag, p, e
end

local function der_children(s, p, e)
  return function()
    if p > e then return nil end
    local tag, cp, ce = der_tlv(s, p)
    if not tag or ce > e then
      p = e + 1
      return nil
    end
    p = ce + 1
    return tag, cp, ce
  end
end

local function asn1_string(tag, v)
  if tag == 0x0C or tag == 0x13 or tag == 0x16 or tag == 0x12 then return v end
  if tag == 0x14 then -- T61String, read as Latin-1
    return (gsub(v, "[\x80-\xff]", function(c) return utf8.char(byte(c)) end))
  end
  if tag == 0x1E then -- BMPString
    if #v % 2 ~= 0 then return nil end
    if #v >= 2 and sub(v, -2) == "\0\0" then v = sub(v, 1, -3) end
    local out = {}
    for k = 1, #v, 2 do
      local cp = (byte(v, k) << 8) | byte(v, k + 1)
      if cp == 0xFFFE or cp == 0xFFFF or (cp >= 0xFDD0 and cp <= 0xFDEF) or (cp >= 0xD800 and cp <= 0xDFFF) then
        return nil
      end
      out[#out + 1] = utf8.char(cp)
    end
    return concat(out)
  end
  return nil
end

local OID_CN, OID_O, OID_SAN = "\x55\x04\x03", "\x55\x04\x0a", "\x55\x1d\x11"

local function parse_name(s, p, e)
  local cn, orgs = nil, {}
  for tag, sp, se in der_children(s, p, e) do
    if tag == 0x31 then
      for t2, ap, ae in der_children(s, sp, se) do
        if t2 == 0x30 then
          local it = der_children(s, ap, ae)
          local ot, op, oe = it()
          local vt, vp, ve = it()
          if ot == 0x06 and vt then
            local val = asn1_string(vt, sub(s, vp, ve))
            local oid = sub(s, op, oe)
            if val then
              if oid == OID_CN then cn = val elseif oid == OID_O then orgs[#orgs + 1] = val end
            end
          end
        end
      end
    end
  end
  return cn, orgs
end

-- net.IP.String.
local function ip_string(b)
  if #b == 4 then return string.format("%d.%d.%d.%d", byte(b, 1, 4)) end
  if #b ~= 16 then return nil end
  if sub(b, 1, 10) == string.rep("\0", 10) and sub(b, 11, 12) == "\xff\xff" then
    return string.format("%d.%d.%d.%d", byte(b, 13, 16))
  end
  local g = {}
  for i = 0, 7 do g[i + 1] = (byte(b, 2 * i + 1) << 8) | byte(b, 2 * i + 2) end
  local best, bestlen, i = 0, 0, 1
  while i <= 8 do
    if g[i] == 0 then
      local j = i
      while j <= 8 and g[j] == 0 do j = j + 1 end
      if j - i > bestlen then best, bestlen = i, j - i end
      i = j
    else
      i = i + 1
    end
  end
  if bestlen < 2 then best = 0 end
  local s = ""
  i = 1
  while i <= 8 do
    if i == best then
      s = s .. "::"
      i = i + bestlen
    else
      if #s > 0 and sub(s, -1) ~= ":" then s = s .. ":" end
      s = s .. string.format("%x", g[i])
      i = i + 1
    end
  end
  return s
end

-- big.Int.Text(16) of a DER INTEGER.
local function serial_hex(v)
  if #v == 0 then return "0" end
  local neg = byte(v, 1) >= 0x80
  if neg then
    local b = {byte(v, 1, -1)}
    for i = 1, #b do b[i] = 255 - b[i] end
    for i = #b, 1, -1 do
      b[i] = b[i] + 1
      if b[i] < 256 then break end
      b[i] = 0
    end
    v = char(table.unpack(b))
  end
  local h = hex(v):gsub("^0+", "")
  if h == "" then h = "0" end
  return neg and "-" .. h or h
end

local function set_list(f, key, list)
  if #list == 1 then f[key] = list[1] elseif #list > 1 then f[key] = list end
end

local function cert_fields(f, cert)
  if not cert or not cert.pem then return end
  local b64 = cert.pem:gsub("%-%-%-%-%-[^\n]*%-%-%-%-%-", ""):gsub("%s", "")
  local der = base64.dec(b64)
  if not der or #der == 0 then return end
  f["tls.cert.sha256"] = hex(openssl.digest("sha256", der))
  f["tls.cert.sha1"] = hex(openssl.digest("sha1", der))
  local tag, p, e = der_tlv(der, 1)
  if tag ~= 0x30 then return end
  local tt, tp, te = der_children(der, p, e)()
  if tt ~= 0x30 then return end
  local kids = {}
  for t, cp, ce in der_children(der, tp, te) do kids[#kids + 1] = {t, cp, ce} end
  local k = (kids[1] and kids[1][1] == 0xA0) and 2 or 1
  local serial, issuer, subject = kids[k], kids[k + 2], kids[k + 4]
  if not subject then return end
  if serial[1] == 0x02 then f["tls.cert.serial"] = serial_hex(sub(der, serial[2], serial[3])) end
  local cn, orgs = parse_name(der, subject[2], subject[3])
  if cn and cn ~= "" then f["tls.cert.subject.cn"] = cn end
  set_list(f, "tls.cert.subject.o", orgs)
  cn, orgs = parse_name(der, issuer[2], issuer[3])
  if cn and cn ~= "" then f["tls.cert.issuer.cn"] = cn end
  set_list(f, "tls.cert.issuer.o", orgs)
  local dns, ips = {}, {}
  for j = k + 6, #kids do
    if kids[j][1] == 0xA3 then
      local st, sp, se = der_tlv(der, kids[j][2])
      if st == 0x30 then
        for xt, xp, xe in der_children(der, sp, se) do
          if xt == 0x30 then
            local it = der_children(der, xp, xe)
            local ot, op, oe = it()
            local vt, vp, ve = it()
            if vt == 0x01 then vt, vp, ve = it() end
            if ot == 0x06 and sub(der, op, oe) == OID_SAN and vt == 0x04 then
              local gt, gp, ge = der_tlv(der, vp)
              if gt == 0x30 and ge <= ve then
                for nt, np, ne in der_children(der, gp, ge) do
                  if nt == 0x82 then
                    dns[#dns + 1] = sub(der, np, ne)
                  elseif nt == 0x87 then
                    ips[#ips + 1] = ip_string(sub(der, np, ne))
                  end
                end
              end
            end
          end
        end
      end
    end
  end
  for _, ip in ipairs(ips) do dns[#dns + 1] = ip end
  set_list(f, "tls.cert.san", dns)
end

---------------------------------------------------------------------------
-- The baseline probe and custom probes, as athar scan's prober.
---------------------------------------------------------------------------

local function settings()
  local timeout = 3000
  local arg = stdnse.get_script_args("athar.timeout")
  if arg then
    local secs = stdnse.parse_timespec(arg)
    if secs and secs > 0 then timeout = math.floor(secs * 1000) end
  end
  return {
    timeout = timeout,
    connect = math.min(1500, timeout),
    banner = math.min(2000, timeout),
    probes = stdnse.get_script_args("athar.probes") ~= nil,
  }
end

local function dial(host, port, cfg)
  local sock = nmap.new_socket()
  sock:set_timeout(cfg.connect)
  if not sock:connect(host, port, "tcp") then
    sock:close()
    return nil
  end
  return sock
end

-- Ends at the latest BANNER_TAIL after wait or after limit, so a server that
-- drips bytes can't hold it.
local function read_banner(sock, wait, limit)
  local stop = nmap.clock_ms() + math.min(wait + BANNER_TAIL, limit)
  sock:set_timeout(math.min(wait, limit))
  local ok, data = sock:receive()
  if not ok then return "" end
  local parts, n = {data}, #data
  while n < MAX_BANNER do
    local left = stop - nmap.clock_ms()
    if left <= 0 then break end
    sock:set_timeout(math.max(1, math.floor(math.min(250, left))))
    local ok2, more = sock:receive()
    if not ok2 then break end
    parts[#parts + 1] = more
    n = n + #more
  end
  return sub(concat(parts), 1, MAX_BANNER)
end

local function banner_fields(f, b)
  f["service.banner"] = b
  if sub(b, 1, 4) == "SSH-" then
    f["ssh.banner"] = (b:match("^[^\n]*"):gsub("\r+$", ""))
    f["service.protocol"] = "ssh"
  end
end

local function target_name(host)
  return host.targetname or host.ip
end

local function host_header(host, port, tls)
  local h = target_name(host)
  if find(h, ":", 1, true) then h = "[" .. h .. "]" end
  if (tls and port.number == 443) or (not tls and port.number == 80) then return h end
  return h .. ":" .. port.number
end

-- A new connection to a service already seen, with TLS if it spoke TLS.
local function reconnect(host, port, svc, cfg)
  local sock = dial(host, port, cfg)
  if not sock then return nil end
  sock:set_timeout(cfg.timeout)
  if svc.tls and not sock:reconnect_ssl() then
    sock:close()
    return nil
  end
  return sock
end

local function http_probe(host, port, svc, sock, cfg, needs)
  local deadline = nmap.clock_ms() + cfg.timeout
  local resp = http_exchange(sock, host_header(host, port, svc.tls), "GET", "/", nil, deadline)
  if not resp then return end
  http_fields(svc.fields, resp)
  if not needs.favicon then return end
  local path, inline = favicon_source(favicon_ref(resp.body), target_name(host), port.number)
  if inline then
    favicon_fields(svc.fields, inline)
    return
  end
  local ic = reconnect(host, port, svc, cfg)
  if not ic then return end
  local icon = http_exchange(ic, host_header(host, port, svc.tls), "GET", path, nil, nmap.clock_ms() + cfg.timeout)
  ic:close()
  if icon and icon.status == 200 then favicon_fields(svc.fields, icon.body) end
end

local function baseline(host, port, needs, cfg)
  local sock = dial(host, port, cfg)
  if not sock then return nil end
  local svc = {tls = false, fields = {["service.port"] = port.number, ["service.transport"] = "tcp"}}
  local f = svc.fields

  if needs.banner then
    local b = read_banner(sock, cfg.banner, cfg.timeout)
    if #b > 0 then
      banner_fields(f, b)
      sock:close()
      return svc
    end
  end

  if needs.tls then
    sock:set_timeout(cfg.timeout)
    if sock:reconnect_ssl() then
      svc.tls = true
      cert_fields(f, sock:get_ssl_certificate())
      if needs.banner then
        local b = read_banner(sock, cfg.banner, cfg.timeout)
        if #b > 0 then
          banner_fields(f, b)
          sock:close()
          return svc
        end
      end
      if needs.http then http_probe(host, port, svc, sock, cfg, needs) end
      sock:close()
      return svc
    end
    sock:close()
    sock = nil
  end

  if not needs.http then
    if sock then sock:close() end
    return svc
  end
  sock = sock or dial(host, port, cfg)
  if not sock then return svc end
  http_probe(host, port, svc, sock, cfg, needs)
  sock:close()
  return svc
end

local function custom_probe(host, port, svc, p, cfg)
  local sock = reconnect(host, port, svc, cfg)
  if not sock then return nil end
  local f = {["service.port"] = port.number, ["service.transport"] = "tcp"}
  local ok = false
  if p.proto == "http" then
    local resp = http_exchange(sock, host_header(host, port, svc.tls), p.method, p.path, p.headers,
      nmap.clock_ms() + cfg.timeout)
    if resp then
      http_fields(f, resp)
      ok = true
    end
  elseif p.proto == "tcp" then
    if p.send and #p.send > 0 and not sock:send(p.send) then
      sock:close()
      return nil
    end
    -- A rule may shorten the read, not extend it past the timeout.
    local b = read_banner(sock, math.min(p.wait or cfg.timeout, cfg.timeout), cfg.timeout)
    if #b > (p.max or MAX_BANNER) then b = sub(b, 1, p.max) end
    if #b > 0 then
      banner_fields(f, b)
      ok = true
    end
  end
  sock:close()
  return ok and f or nil
end

---------------------------------------------------------------------------
-- Rules.
---------------------------------------------------------------------------

local function rules_path()
  local arg = stdnse.get_script_args("athar.rules")
  if arg then return arg end
  local dir = (SCRIPT_PATH or ""):match("^(.*)[/\\]") or "."
  return dir .. "/athar-rules"
end

local function load_rules()
  local path = rules_path()
  local cached = nmap.registry.athar
  if cached and cached.path == path then return cached end

  local files = {}
  local isdir, iter, state = pcall(lfs.dir, path) -- Nmap's lfs has only dir and link
  if isdir then
    for name in iter, state do
      if name:match("%.lua$") then files[#files + 1] = path .. "/" .. name end
    end
    table.sort(files, bytewise_less)
  else
    files[1] = path
  end

  local set = {path = path, rules = {}, probes = {}, needs = {}}
  local seen = {}
  for _, file in ipairs(files) do
    local fh = io.open(file, "rb")
    local src = fh and fh:read("a")
    if fh then fh:close() end
    -- Data only: the chunk runs without access to any library.
    local chunk = src and load(src, "@" .. file, "t", {})
    local ok, r = false, nil
    if chunk then ok, r = pcall(chunk) end
    if ok and type(r) == "table" and r.nse == FORMAT and r.condition then
      set.rules[#set.rules + 1] = r
      for k, v in pairs(r.needs or {}) do set.needs[k] = set.needs[k] or v end
      for _, p in pairs(r.probes or {}) do
        if not seen[p.key] then
          seen[p.key] = true
          set.probes[#set.probes + 1] = p
        end
      end
    else
      stdnse.debug1("skipping %s: not an athar rule data file (format %d)", file, FORMAT)
    end
  end
  table.sort(set.probes, function(a, b) return bytewise_less(a.key, b.key) end)
  nmap.registry.athar = set
  return set
end

local CONFIDENCE = {certain = 4, high = 3, medium = 2, low = 1}

action = function(host, port)
  local set = load_rules()
  if #set.rules == 0 then
    return stdnse.format_output(false, "no rules in " .. set.path)
  end
  local cfg = settings()
  local svc = baseline(host, port, set.needs, cfg)
  if not svc then return nil end

  local custom = {}
  if cfg.probes then
    for _, p in ipairs(set.probes) do
      custom[p.key] = custom_probe(host, port, svc, p, cfg) or false
    end
  end

  local hits = {}
  for _, r in ipairs(set.rules) do
    if not ((r.tls == "required" and not svc.tls) or (r.tls == "none" and svc.tls)) then
      local resp, probes = {default = svc.fields}, {"default"}
      for id, p in pairs(r.probes or {}) do
        if custom[p.key] then
          resp[id] = custom[p.key]
          probes[#probes + 1] = id
        end
      end
      local ctx = {resp = resp, rule = r, canon = {}}
      if eval_node(r.condition, ctx) then
        table.sort(probes, bytewise_less)
        hits[#hits + 1] = {rule = r, extracted = run_extract(r, svc.fields), probes = probes}
      end
    end
  end
  if #hits == 0 then return nil end
  table.sort(hits, function(a, b)
    local x, y = CONFIDENCE[a.rule.confidence] or 0, CONFIDENCE[b.rule.confidence] or 0
    if x ~= y then return x > y end
    return bytewise_less(a.rule.title or "", b.rule.title or "")
  end)

  local out = stdnse.output_table()
  for _, h in ipairs(hits) do
    local r = h.rule
    local o = stdnse.output_table()
    o.rule = r.id
    o.author = r.author
    o.product = r.product
    o.vendor = r.vendor
    o.family = r.family
    o.category = r.category
    o.cpe = r.cpe
    o.confidence = r.confidence
    if r.fidelity ~= "exact" then o.fidelity = r.fidelity end
    o.tls = svc.tls
    if #h.probes > 1 then o.probes = h.probes end
    o.extracted = h.extracted
    local key = r.title or r.id
    if out[key] then key = key .. " (" .. r.id .. ")" end
    out[key] = o
  end
  return out
end
