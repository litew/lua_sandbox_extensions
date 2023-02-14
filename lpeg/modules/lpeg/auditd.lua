local l     = require "lpeg"
l.locale(l)
local es    = require "lpeg.escape_sequences"

local rawset = rawset

local M = {}
setfenv(1, M) -- Remove external access to contain everything in the module

-- local type_value    = ((l.upper + l.S'_') + l.digit)^1 -- get all record types
local type_value    = l.P"EXECVE" + l.P"PROCTITLE" + l.P"ANOM_ABEND" -- OR we can filter here
                                                                     -- what messages we want to parse
                                                                     -- and drop unparsed msgs with <<DROP>> token in
                                                                     -- decoders_syslog table 

local ident_byte    = 1 - (l.R"\1\32" + l.S'=')
local string_byte   = 1 - l.S'"\\'
local garbage       = 1 - ident_byte
local space         = l.space
local ident         = ident_byte^1
local hostname      = (l.alnum + l.punct + l.S"-.")^1
local node          = l.Cg(l.C(l.P"node") * "=" * l.C(hostname))
local rec_type      = l.Cg(l.C(l.P"type") * "=" * l.C(type_value))
local msg           = l.Cg(l.C(l.P"msg")  * "=" * l.Ct(l.P'audit(' * l.C(l.digit^1) * l.P"." * l.C(l.digit^1) * l.P":" * l.C(l.digit^1) * l.P"):"))
local key           = l.C(ident)
local value         = l.C(l.P{'"' * ((1 - l.S'"') + l.V(1))^0 * '"'}) + l.C(ident)
local pair          = garbage^0 * l.Cg((key * "=" * value) + (key * "=" * l.C"") + (key * l.Cc(true)))

grammar = l.Cf(l.Ct"" * node^0 * space^0 * rec_type * space * msg * space * pair^0, rawset)

return M