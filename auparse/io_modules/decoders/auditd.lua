-- Imports
local module_name          = ...
local module_cfg           = string.gsub(module_name, "%.", "_")
local string               = require "string"
local aup                  = require "auparse"
local sdu                  = require "lpeg.sub_decoder_util"
local read_config          = read_config
local type                 = type
local assert               = assert
local inject_message       = inject_message

local cfg = read_config(module_cfg)
assert(type(cfg) == "table", module_cfg .. " must be a table")

-- /usr/include/auparse-defs.h
-- auparse_type_t
local auparse_type = {
        UNCLASSIFIED = 0,
        UID = 1,
        GID = 2,
        SYSCALL = 3,
        ARCH = 4,
        EXIT = 5,
        ESCAPED = 6,
        PERM = 7,
        MODE = 8,
        SOCKADDR = 9,
        FLAGS = 10,
        PROMISC = 11,
        CAPABILITY = 12,
        SUCCESS = 13,
        A0 = 14, A1 = 15, A2 = 16, A3 = 17,
        SIGNAL = 18,
        LIST = 19,
        TTY_DATA = 20,
        SESSION = 21,
        CAP_BITMAP = 22,
        NFPROTO = 23,
        ICMPTYPE = 24,
        PROTOCOL = 25,
        ADDR = 26,
        PERSONALITY = 27,
        SECCOMP = 28,
        OFLAG = 29,
        MMAP = 30,
        MODE_SHORT = 31,
        MAC_LABEL = 32,
        PROCTITLE = 33,
        HOOK = 34,
        NETACTION = 35,
        MACPROTO = 36,
        IOCTL_REQ = 37,
        ESCAPED_KEY = 38,
        ESCAPED_FILE = 39,
        FANOTIFY = 40,
        NLMCGRP = 41,
        RESOLVE = 42
}

local fname = nil
local ftype = nil
local fval = nil

local M = {}
setfenv(1, M) -- Remove external access to contain everything in the module

function decode(data, dh, mutable)
  local msg = sdu.copy_message(dh, mutable)
  msg.Fields = {}
  data = data .. "\n"
  au = aup.auparse_init(3, data)
  aup.auparse_first_record(au)
  msg.Type = aup.auparse_get_type_name(au)
  msg.EnvVersion = "0.1"
--  msg.Hostname = aup.auparse_get_node(au) -- FIXME: MEMORYLEAK, node gets strdup'ed (man 3 auparse_get_node)
--  msg.Timestamp = aup.auparse_get_time(au) -- FIXME: MEMORYLEAK, SWIG calls malloc without marking it for Lua's GC
  msg.Payload = "ENRICHED"
  msg.Fields.event_id = aup.auparse_get_serial(au)
  aup.auparse_first_field(au)
  repeat
    fname = aup.auparse_get_field_name(au)
    ftype = aup.auparse_get_field_type(au)
    if (ftype == auparse_type.ESCAPED) or
       (ftype == auparse_type.ESCAPED_KEY) or
       (ftype == auparse_type.ESCAPED_FILE) or
       (ftype == auparse_type.SOCKADDR) or
       (ftype == auparse_type.PROCTITLE) or
       (ftype == auparse_type.SIGNAL) or
       (ftype == auparse_type.EXIT) or
       (ftype == auparse_type.TTY_DATA) then fval = aup.auparse_interpret_field(au)
-- we don't want to interpret *uid,*gid fields here since auparse will try
-- to resolve all of them with *uids and *gids from system on which it's running;
-- make sure you have set 'log_format = ENRICHED' option in /etc/audit/auditd.conf
-- on all auditlog-emitters for proper *UID, *GID extracting 
    elseif (ftype == auparse_type.UID) or
           (ftype == auparse_type.GID) or
           (ftype == auparse_type.SYSCALL) or
           (ftype == auparse_type.SESSION) then fval = aup.auparse_get_field_int(au)
    else fval = aup.auparse_get_field_str(au)
    end
    msg.Fields[fname] = fval
  until (aup.auparse_next_field(au) == 0)
  aup.auparse_destroy_ext(au, 0)
  msg.Pid = msg.Fields.pid
  msg.Hostname = msg.Fields.node
  msg.Fields.pid = nil
  msg.Fields.node = nil
  msg.Fields.type = nil
--  if msg.Type == 'AVC' and string.match(msg.Hostname,'test-.+') then
  inject_message(msg)
--  end
end

return M

