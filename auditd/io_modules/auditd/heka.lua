local module_name = ...
local module_cfg  = require "string".gsub(module_name, "%.", "_")
local cfg         = read_config(module_cfg) or error(module_name .. " configuration not found")

local string      = require "string"
local es          = require "lpeg.escape_sequences"
local tonumber    = tonumber
local tostring    = tostring

local M = {}
setfenv(1, M) -- Remove external access to contain everything in the module.

-- audit(1676159910.880:1447):
function parse_audit_msg(msg, field_name)
    if not msg.Fields then return end
    local value = msg.Fields[field_name]
    local timestamp, milli, event_id = string.match(value, "audit%((%d+)%.(%d+):(%d+)%):")
    msg.Timestamp = timestamp * 1e9 + milli * 1e6
    msg.Fields["event_id"] = event_id
--    msg.Fields["msg"] = nil -- FIXME: unfortunately msg field is not unique
                              -- (another one passwd in USER_AUTH record type)
                              -- so we can't just clear it
end

local function hex_to_string(str)
  local value_decoded = ""
  local cd = ""
  local need_decode = str:sub(1,1) ~= '"'
  if need_decode then
    for c in string.gmatch(str, '%w%w') do
      if c == "00" then cd = " " else cd = es.hex_to_char(c) end
      value_decoded = value_decoded .. cd
    end
    return value_decoded
  else
    return nil
  end
end

function parse_proctitle(msg, field_name)
    if not msg.Fields[field_name] then return end
    local value = msg.Fields[field_name]
    msg.Fields["proctitle_decoded"] = hex_to_string(value)
end

function parse_execve_arg(msg, field_name)
    if not msg.Fields[field_name] then return end
    local argc = tonumber(msg.Fields[field_name])
    for arg = 0, argc - 1 do
        msg.Fields["a" .. arg .. "_decoded"] = hex_to_string(msg.Fields["a" .. arg])
    end
end

return M