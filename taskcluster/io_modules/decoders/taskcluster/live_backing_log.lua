-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at http://mozilla.org/MPL/2.0/.

--[[
# Taskcluster Live Backing Log Decoder Module.
Parses the Taskcluster live_backing.log

## Decoder Configuration Table
decoders_taskcluster_live_backing_log = {
    -- taskcluster_schema_path = "/usr/share/luasandbox/schemas/taskcluster" -- default
    -- base_taskcluster_url = "https://firefox-ci-tc.services.mozilla.com/api/queue/v1" -- default
    -- integration_test = nil -- default
}

## Functions

### decode

Decode and inject the resulting message

*Arguments*
- data (string) - Data to write to the msg.Payload
- default_headers (optional table) - Heka message table containing the default
  header values to use, if they are not populated by the decoder. If 'Fields'
  is specified it should be in the hashed based format see:
  http://mozilla-services.github.io/lua_sandbox/heka/message.html

*Return*
- nil - throws an error on inject_message failure.

--]]

-- Imports
local module_name   = ...
local string        = require "string"
local module_cfg    = string.gsub(module_name, "%.", "_")
local cfg           = read_config(module_cfg) or {}
assert(type(cfg) == "table", module_cfg .. " must be a table")
cfg.taskcluster_schema_path = cfg.task_cluster_schema_path or "/usr/share/luasandbox/schemas/taskcluster"

local bg        = require "lpeg.printf".build_grammar
local cjson     = require "cjson"
local rjson     = require "rjson"
local date      = require "date"
local dt        = require "lpeg.date_time"
local gzfile    = require "gzfile"
local io        = require "io"
local l         = require "lpeg";l.locale(l)
local os        = require "os"
local sdu       = require "lpeg.sub_decoder_util"
local string    = require "string"
local table     = require "table"

local assert    = assert
local ipairs    = ipairs
local pairs     = pairs
local pcall     = pcall
local print     = print
local tostring  = tostring
local tonumber  = tonumber
local type      = type

local inject_message = inject_message
local read_config    = read_config

local M = {}
setfenv(1, M) -- Remove external access to contain everything in the module

local doc           = rjson.parse("{}") -- reuse this object to avoid creating a lot of GC
local base_tc_url   = cfg.base_taskcluster_url or "https://firefox-ci-tc.services.mozilla.com/api/queue/v1"
local logger        = read_config("Logger")
local tmp_path      = "/var/tmp"
local mms           = read_config("max_message_size")

local pulse_task_schema_file = cfg.taskcluster_schema_path .. "/pulse_task.1.schema.json"
local fh = assert(io.open(pulse_task_schema_file, "r"))
local pulse_task_schema = fh:read("*a")
pulse_task_schema = rjson.parse_schema(pulse_task_schema)
fh:close()

local task_definition_schema_file = cfg.taskcluster_schema_path .. "/task_definition.1.schema.json"
fh = assert(io.open(task_definition_schema_file, "r"))
local task_definition_schema = fh:read("*a")
task_definition_schema = rjson.parse_schema(task_definition_schema)
fh:close()

local perfherder_schema_file = cfg.taskcluster_schema_path .. "/perfherder.1.schema.json"
fh = assert(io.open(perfherder_schema_file, "r"))
local perfherder_schema = fh:read("*a")
perfherder_schema = rjson.parse_schema(perfherder_schema)
fh:close()

local artifact_list_schema_file = cfg.taskcluster_schema_path .. "/artifact_list.1.schema.json"
fh = assert(io.open(artifact_list_schema_file, "r"))
local artifact_list_schema = fh:read("*a")
artifact_list_schema = rjson.parse_schema(artifact_list_schema)
fh:close()

local resource_monitor_schema_file = cfg.taskcluster_schema_path .. "/resource_monitor.49.schema.json"
fh = assert(io.open(resource_monitor_schema_file, "r"))
local resource_monitor_schema = fh:read("*a")
resource_monitor_schema = rjson.parse_schema(resource_monitor_schema)
fh:close()
local resource_monitor_path = "public/monitoring/resource-monitor.json"

local function get_url(path)
    return base_tc_url .. "/" .. path
end


if cfg.integration_test then
    get_url = function (path) return "file://" .. string.gsub(path, "[?=/]", "_") end
end

-- taskcluster live_backing.log
-- multiple timestamp formats https://github.com/taskcluster/taskcluster/pull/3468
local time          = l.Ct(dt.date_fullyear * "-" * dt.date_month * "-" * dt.date_mday * l.S"T " * dt.time_hour * ":" * dt.time_minute * ":" * dt.time_second * dt.time_secfrac^-1 * (l.P"Z" + l.P"+00:00"))
local time_header   = l.P"[" * l.Cg(l.alpha^1, "name") * l.space^1 * l.Cg(time, "date_time") * "]" * l.space^1
local task_header   = l.Cg(l.Ct(dt.time_hour * ":" * dt.time_minute * ":" * dt.time_second), "time") * l.space^1 * l.Cg(l.alpha^1, "priority") * l.space^1 * "-" + (dt.rfc3339_full_date * "T" * dt.rfc3339_full_time)
local message       = l.space^0 * l.Cg(l.Cp(), "msg")
local log_line      = l.Ct((time_header^-1 * task_header^-1) * message)

-- https://github.com/taskcluster/taskcluster/blob/master/services/treeherder/src/util/route_parser.js#L20
--route "tc-treeherder.v2.try.3710d33fa6f3b6d453fc9af1b477af57a600a782.376368"
local function parse_project(s)
    local p = s:find("/")
    if p then
        return s:sub(p + 1), "github.com", s:sub(1, p - 1)
    end
    return s, "hg.mozilla.org", nil
end

local not_dot           = l.P"." ^-1 * l.C((l.P(1) - ".")^1)
local tc_project        = not_dot / parse_project
local tc_route          = l.P"tc-treeherder.v2." * tc_project * not_dot * (not_dot / tonumber)^-1

local md_remove_path    = function(s) return s:match("[^/]+$") end
local md_protocol       = l.P"http" * l.P"s"^-1 * "://"
local md_revision       = l.C(l.xdigit^1)
local md_any            = l.C((l.P(1) - "/")^1) * l.P("/")^-1
local md_hg_file        = l.P"/" * (l.P"file" + "raw-file") * l.P"/"
local md_hg             = l.C("hg.mozilla.org") * "/" * l.Cc(nil) * ((l.P(1) - md_hg_file)^1 / md_remove_path * md_hg_file * md_revision)^-1
local md_gh_eop         = l.P"/" + (".git" * l.P"/"^-1) + l.P(-1)
local md_gh_project     = l.C((l.P(1) - md_gh_eop)^1)
local md_gh_api         = l.C("api.github.com") * "/repos/" * md_any * md_gh_project
local md_gh             = l.C("github.com") * "/" * md_any * md_gh_project * md_gh_eop * (l.P"raw" * "/" * md_revision)^-1
local md_source         = md_protocol * (md_hg + md_gh + md_gh_api + l.C(l.P(1)^1))


local function add_fields(msg, fields)
    if not fields then return end

    if msg.Fields then
        for k,v in pairs(fields) do
            msg.Fields[k] = v
        end
    else
        msg.Fields = fields
    end
    msg.Fields["_"] = nil
end


local function merge_table(dest, src)
    for k,v in pairs(src) do
        dest[k] = v
    end
end


local function inject_validated_msg(j, name, schema, file, tid)
    local payload = cjson.encode(j)
    doc:parse(payload)
    local ok, err, report = doc:validate(schema)
    if not err then
        local msg = {
            Type    = name,
            Payload = payload
        }
        inject_message(msg)
    else
        local msg = {
            Type = "error.schema." .. name,
            Payload = err,
            Fields = {
                taskId  = tid,
                schema  = file,
                detail  = report,
                data    = payload
            }
        }
        inject_message(msg)
    end
end


local function inject_pulse_task(j, dh)
    local ns
    local state = j.status.state
    if j.runId and j.status.runs then
        local run = j.status.runs[j.runId + 1]
        if state == "pending" then
            ns = dt.time_to_ns(time:match(run.scheduled))
        elseif state == "running" then
            ns = dt.time_to_ns(time:match(run.started))
        elseif state == "completed" or state == "failed" or state == "exception" then
            ns = dt.time_to_ns(time:match(run.started or run.scheduled)) -- keep the start/end in same table partition
        end
    end
    -- dt.time_to_ns returns 0 when given a nil argument
    if not ns or ns == 0 then ns = dh.Timestamp or os.time() * 1e9 end -- task defined has no time, use the original ingestion time
    j.time = date.format(ns, "%Y-%m-%dT%H:%M:%SZ")
    inject_validated_msg(j, "pulse_task", pulse_task_schema, pulse_task_schema_file, j.status.taskId)
end


local function inject_artifact_list(j)
    if not j then return end
    inject_validated_msg(j, "artifact_list", artifact_list_schema, artifact_list_file, j.taskId)
end


local function inject_task_definition(tid, td)
    local payload_o  = td.payload
    local extra_o    = td.extra
    local tags_o     = td.tags
    -- fix up the task definition json for BigQuery
    local tags = {nil}
    local tag_cnt = 0
    for k,v in pairs(td.tags) do
        tag_cnt = tag_cnt + 1
        tags[tag_cnt] = {key = k, value = v}
    end
    td.taskId   = tid
    td.payload  = cjson.encode(td.payload)
    td.extra    = cjson.encode(td.extra)
    td.tags     = tags
    inject_validated_msg(td, "task_definition", task_definition_schema, task_definition_schema_file, tid)
    -- restore the original objects
    td.payload = payload_o
    td.extra   = extra_o
    td.tags    = tags_o
end


local normalize_test = (l.P(1) - "/tests/")^0 * l.C(l.P(1)^1) + l.Carg(1)
local function inject_timing_msg(g, base_msg, level, fields)
    local msg = sdu.copy_message(base_msg, false)
    msg.Type                    = "timing"
    msg.Fields.component        = g.Component
    msg.Fields.subComponent     = g.SubComponent
    if fields and not fields.result then fields.result = "success" end
    add_fields(msg, fields)

    if g.Component == "test" then
        msg.Fields.file = normalize_test:match(msg.Fields.file, nil, msg.Fields.file)
    end

    msg.Fields.level = level
    msg.Fields.duration = (msg.Fields.logEnd - msg.Fields.logStart) / 1e9
    msg.Fields.logStart = date.format(msg.Fields.logStart, "%Y-%m-%dT%H:%M:%SZ")
    msg.Fields.logEnd = date.format(msg.Fields.logEnd, "%Y-%m-%dT%H:%M:%SZ")
    msg.Fields.result = string.lower(msg.Fields.result)
    -- remove pulse metadata before encoding
    local priority = msg.Fields.priority
    msg.Fields.priority = nil
    msg.Fields.content_type = nil
    msg.Fields.exchange = nil
    msg.Fields.queue_name = nil
    msg.Fields.routing_key = nil
    msg.Payload = cjson.encode(msg.Fields)
    -- add near real time fields back in
    msg.Fields.priority = priority
    -- remove the fields not needed by the tests or anomaly detection after encoding
    msg.Fields.created = nil
    msg.Fields.kind = nil
    msg.Fields.testtype = nil
    msg.Fields.jobKind = nil
    msg.Fields.collection = nil
    msg.Fields.logEnd = nil
    msg.Fields.logStart = nil
    msg.Fields.owner = nil
    msg.Fields.projectOwner = nil
    msg.Fields.pushId = nil
    msg.Fields.resolved = nil
    msg.Fields.revision = nil
    --msg.Fields.scheduled = nil
    --msg.Fields.started = nil
    msg.Fields.taskGroupId = nil
    msg.Fields.workerGroup = nil
    inject_message(msg)
end


local vcs_suites = {clone = true, pull = true, update = true}
local function perfherder_decode(g, b, json)
    if not json then return end

    local j = cjson.decode(json)
    if type(j.framework) ~= "table" then
        if json:match("^{}") then return end
        return "missing framework"
    end

    local line = b.current
    local ns = dt.time_to_ns(line.date_time)
    if j.framework.name == "vcs" then
        for _,v in ipairs(j.suites) do
            if vcs_suites[v.name] then
                local f = {
                    component = j.framework.name,
                    subComponent = v.name,
                    logStart = ns - v.value * 1e9,
                    logEnd   = ns,
                }
                if line.date_time == line.pts then
                    f.logStart = ns
                    f.logEnd   = ns + v.value * 1e9
                end
                inject_timing_msg(g, b.base_msg, b.level, f)
            end
        end
    elseif j.framework.name == "build_metrics" then
        for _,v in ipairs(j.suites) do
            if v.name == "build times" then
                local bg = b.stack[b.level]
                local bc = b.cache[bg]
                local ns = 0
                if bc and bc.logStart then
                    ns = bc.logStart -- overlay the timestamps into the parent block i.e. mozharness
                else
                    ns = dt.time_to_ns(b.pmts)
                end
                local f = {
                    component = j.framework.name,
                    subComponent = v.name,
                    logEnd = ns,
                }
                for _,r in ipairs(v.subtests) do
                    f.subComponent = r.name
                    f.logStart = f.logEnd
                    f.logEnd = f.logEnd + r.value * 1e9
                    inject_timing_msg(g, b.base_msg, b.level, f)
                end
            end
        end
    elseif j.framework.name == "browsertime" then
        if b.base_msg.Fields.testtype == "raptor" then
            if not b.cache.global.raptor_embedded then b.cache.global.raptor_embedded = {} end
            b.cache.global.raptor_embedded["public/test_info/perfherder-data.json"] = true
            j.recordingDate = b.cache.global.raptor_recording_date
        end
    elseif j.framework.name == "raptor" then
        if not b.cache.global.raptor_embedded then b.cache.global.raptor_embedded = {} end
        local f = j.suites[1]
        if f.type == "power" then
            b.cache.global.raptor_embedded["public/test_info/perfherder-data-power.json"] = true
        elseif f.type == "cpu" then
            b.cache.global.raptor_embedded["public/test_info/perfherder-data-cpu.json"] = true
        elseif f.type == "memory" then
            b.cache.global.raptor_embedded["public/test_info/perfherder-data-memory.json"] = true
        elseif f.type == "mozproxy" then
            b.cache.global.raptor_embedded["public/test_info/perfherder-data-mozproxy.json"] = true
        else
            b.cache.global.raptor_embedded["public/test_info/perfherder-data.json"] = true
        end
        j.recordingDate = b.cache.global.raptor_recording_date
    -- fix up inconsistent schemas
    elseif j.framework.name == "js-bench" then
        for i,v in ipairs(j.suites) do
            v.unit = v.units
            v.units = nil
        end
    elseif j.framework.name == "awsy" then
        for i,v in ipairs(j.suites) do
            for m,n in ipairs(v.subtests) do
                n.unit = n.units
                n.units = nil
            end
            v.unit = v.units
            v.units = nil
        end
    end
    j.collection    = b.base_msg.Fields.collection
    j.framework     = j.framework.name
    j.groupSymbol   = b.base_msg.Fields.groupSymbol
    j.platform      = b.base_msg.Fields.platform or "" -- non treeherder metrics
    j.project       = b.base_msg.Fields.project or "" -- non treeherder metrics
    j.pushId        = b.base_msg.Fields.pushId
    j.revision      = b.base_msg.Fields.revision or "" -- non treeherder metrics
    j.symbol        = b.base_msg.Fields.symbol
    j.taskGroupId   = b.base_msg.Fields.taskGroupId
    j.taskId        = b.base_msg.Fields.taskId
    j.tier          = b.base_msg.Fields.tier
    j.runId         = b.base_msg.Fields.runId
    j.time          = date.format(ns, "%Y-%m-%dT%H:%M:%SZ")
    inject_validated_msg(j, "perfherder", perfherder_schema, perfherder_schema_file, j.taskId)
    return nil
end


local function set_date_time(f, b)
    if f.date_time then
        b.current.date_time = f.date_time
        f.date_time = nil
    end
    return dt.time_to_ns(b.current.date_time)
end


local function eval_log(g, b)
    local cache = b.cache[g]
    if g.Sequence then
        for i = cache.sidx, #g.Sequence do
            local v = g.Sequence[i]
            local nmcb = b.next_match_cb
            local matched = v.fn(v, b)
            if matched then
                if nmcb then
                    nmcb(b.current.date_time)
                    if b.next_match_cb == nmcb then
                        b.next_match_cb = nil
                    end
                end
                b.pmts = b.current.date_time
                cache.sidx = i -- top level log sequences are treated as ordered and zero or one instance
                return true
            end
        end
    end
    return false
end


local function eval_end_block(g, b, level, cache)
    local f = g.End:match(b.current.line, b.current.msg)
    if not f then return false end

    b.stack[level] = nil
    b.level = level - 1
    f.logEnd = set_date_time(f, b)
    cache.logEnd = f.logEnd
    if g.EndPrev then
        local prev = b.buffer_head + 1
        if prev == 4 then prev = 1 end
        local t = g.EndPrev:match(b.buffer[prev].line, b.buffer[prev].msg)
        if t then merge_table(f, t) end
    end

    merge_table(cache.Fields, f)
    if not g.cache_on_completion then
        inject_timing_msg(g, b.base_msg, b.level, cache.Fields)
        b.cache[g] = nil
    end
    return true
end


local function eval_block(g, b)
    local matched = false
    local cache = b.cache[g]
    if not cache then
        local f = g.Start:match(b.current.line, b.current.msg)
        if f then
            b.level = b.level + 1
            b.stack[b.level] = g
            f.logStart = set_date_time(f, b)
            cache = {sidx = 1}
            b.cache[g] = cache
            cache.logStart = f.logStart
            cache.Fields = f
            return true
        end
    else
        matched = eval_end_block(g, b, b.level, cache)
        if not matched and g.Sequence then
            for i = cache.sidx, #g.Sequence do
                local v = g.Sequence[i]
                local nmcb = b.next_match_cb
                matched = v.fn(v, b)
                if matched then
                    if nmcb then
                        nmcb(b.current.date_time)
                        if b.next_match_cb == nmcb then
                            b.next_match_cb = nil
                        end
                    end
                    b.pmts = b.current.date_time
                    cache.sidx = 1 -- nested block sequences are treated as unordered and zero or more instances
                    return true
                end
            end
        end
        local level = b.level - 1 -- check for the end of the outer blocks since mal-formed logs are not uncommon
        while not matched and level > 1  do
            g = b.stack[level]
            cache = b.cache[g]
            matched = eval_end_block(g, b, level, cache)
            level = level - 1
        end
    end
    return matched
end


local function eval_tc_task_exit(g, b)
    local f = g.Grammar:match(b.current.line, b.current.msg)
    if not f then return false end

    b.tc_task_result = f.result
    return true
end


local function eval_line(g, b)
    local f = g.Grammar:match(b.current.line, b.current.msg)
    if not f then return false end

    f.logStart = set_date_time(f, b)
    f.logEnd   = f.logStart
    if f.s then
        f.logStart = f.logEnd - f.s * 1e9
        f.s = nil
    elseif f.ms then
        f.logStart = f.logEnd - f.ms * 1e6
        f.ms = nil
    end
    inject_timing_msg(g, b.base_msg, b.level, f)
    return true
end


local function eval_line_n(g, b)
    local f = g.Grammar:match(b.current.line, b.current.msg)
    if not f then return false end

    f.logStart = set_date_time(f, b)
    f.logEnd = dt.time_to_ns(b.buffer[b.buffer_head].date_time)
    inject_timing_msg(g, b.base_msg, b.level, f)
    return true
end


local function eval_line_pm(g, b)
    local f = g.Grammar:match(b.current.line, b.current.msg)
    if not f then return false end

    f.logStart = dt.time_to_ns(b.pmts)
    f.logEnd = set_date_time(f, b)
    inject_timing_msg(g, b.base_msg, b.level, f)
    return true
end


local function eval_line_nm(g, b)
    local f = g.Grammar:match(b.current.line, b.current.msg)
    if not f then return false end

    f.logStart = set_date_time(f, b)
    b.next_match_cb = function(ts)
        f.logEnd = dt.time_to_ns(ts)
        inject_timing_msg(g, b.base_msg, b.level, f)
    end
    return true
end


local function eval_line_js(g, b)
    local json = g.Grammar:match(b.current.line, b.current.msg)
    if not json then return false end

    local ok, err = pcall(g.fn_js, g, b, json)
    if not ok or err then
        inject_message({
            Type = "error.parse.perfherder",
            Payload = err,
            Fields = {
                taskId  = b.base_msg.Fields["taskId"],
                data    = json
            }
        })
    end
    return true
end


local function new_log(sequence)
    return {
        Type        = "block",
        Component   = "task",
        SubComponent= "total",
        Sequence    = sequence,
        fn          = eval_log,
    }
end


local normalize_result = (l.P"successful" + "succeeded") / "success" + (l.P"unsuccessful" + "error" + "fail") / "failed" + l.Carg(1)
local function new_task_completion(g, b, cache)
    local sof = dt.time_to_ns(b.sts)
    local eof = dt.time_to_ns(b.pts)
    local f = {
        component    = g.Component,
        subComponent = g.SubComponent,
        logStart     = sof,
        logEnd       = eof,
        result       = "success",
    }
    local level = 1
    local result = string.lower(cache.Fields.result or b.tc_task_result or b.tc_result)
    result = normalize_result:match(result, nil, result)

    if cache.logStart and cache.logEnd then
        f.logStart = sof
        f.logEnd = cache.logStart
        f.subComponent = "setup"
        inject_timing_msg(g, b.base_msg, level, f)

        cache.Fields.result = result
        inject_timing_msg(g, b.base_msg, level, cache.Fields)

        f.logStart = cache.logEnd
        f.logEnd = eof
        f.subComponent = "teardown"
        inject_timing_msg(g, b.base_msg, level, f)
        b.cache[g] = nil
    else
        f.result = result
        inject_timing_msg(g, b.base_msg, level, f)
    end
end


local function new_task(sequence)
    return {
        Type        = "block",
        Component   = "taskcluster",
        SubComponent= "task",
        Start       = bg{"=== Task Starting ==="},
        End         = bg{"=== Task Finished ==="},
        EndPrev     = bg{"Result: %s", "result"},
        Sequence    = sequence,
        cache_on_completion = new_task_completion,
        fn          = eval_block,
    }
end


local function new_mozharness(sequence)
    return {
        Type        = "block",
        Component   = "mozharness",
        SubComponent= nil, -- set by the parser
        Start       = bg{"[mozharness: %s] Running %s.", l.Cg(time, "date_time"), "subComponent"},
        End         = bg{"[mozharness: %s] Finished %s (%s)", l.Cg(time, "date_time"), "subComponent", "result"},
        Sequence    = sequence,
        fn          = eval_block
    }
end


local function update_global(g, b)
    local f = g.Grammar:match(b.current.line, b.current.msg)
    if not f then return false end
    merge_table(b.cache.global, f)
    return true
end

local raptor_recording_date = {
    Type        = "update_global",
    Component   = "perfherder",
    SubComponent= "raptor",
    Grammar     = bg{"raptor-perftest Info: Playback recording date: %.10s", "raptor_recording_date"},
    -- "raptor-perftest Info: Playback recording date not available",
    -- "raptor-perftest Info: Playback recording information not available"
    fn          = update_global
}

local perfherder = {
    Type        = "line_js",
    Component   = "perfherder",
    SubComponent= nil, -- set by the parser
    Grammar     = l.P"PERFHERDER_DATA: " * l.C(l.P(1)^1), -- this does not include raptor
    fn          = eval_line_js,
    fn_js       = perfherder_decode
}

local raptor_perfherder = {
    Type        = "line_js",
    Component   = "perftest",
    SubComponent= nil, -- set by the parser
    Grammar     = l.P"perftest-output Info: PERFHERDER_DATA: " * l.C(l.P(1)^1),
    fn          = eval_line_js,
    fn_js       = perfherder_decode
}

local result_exit_code = l.Cg(l.digit^1 / function(s) if s == "0" then return "success" end return "failed" end, "result")
local gecko = {
    Type        = "block",
    Component   = "gecko",
    SubComponent= "startup",
    Start       = bg{"TEST-INFO | started process GECKO(%d)", "_"},
    End         = bg{"SimpleTest START"}
                    + bg{"*** Start BrowserChrome Test Results ***"}
                    + bg{"TEST-START"}
                    + bg{"TEST-INFO | Main app process: exit %d", result_exit_code},
    fn          = eval_block
}

local android_simple = (l.digit^1 * l.space * l.P"INFO ")^-1
local test_errors = l.P"TIMEOUT" + "ERROR" + "FAIL" + "KNOWN-FAIL(EXPECTED RANDOM)" + "KNOWN-FAIL" + "UNEXPECTED-FAIL" + "UNEXPECTED-TIMEOUT" + "UNEXPECTED-NOTRUN" + "END" -- most of these don't have timing
local test_status = l.P"TEST-" * l.Cg((l.P"OK" + "PASS" + test_errors), "result")
local test = {
    Type        = "line",
    Component   = "test",
    SubComponent= "general",
    Grammar     = android_simple * bg{"%s | %s | took %dms", test_status, "file", "ms"},
    fn          = eval_line
}

--[[
Multiple entries with the same test name but with different args
Waiting until this data is actually requested as this grammar would have to
change, some options are.
1) sum up the individual test+arg timings as a single test entry (recommended)
2) include the args as part of the test name
local test_sm = {
    Type        = "line",
    Component   = "test",
    SubComponent= "spidermonkey",
    Grammar     = bg{"%s | %s | %s [%g s]", test_status, file, "_", "s"},
    fn          = eval_line
}
--]]

local gtest_status = l.P"TEST-" * l.Cg((l.P"PASS" + test_errors), "result")
local test_gtest = {
    Type        = "line",
    Component   = "test",
    SubComponent= "gtest",
    Grammar     = bg{"%s | %s | test completed (time: %dms)", gtest_status, "file", "ms"},
    fn          = eval_line
}


local reftest_status = l.P"REFTEST TEST-" * l.Cg((l.P"PASS(EXPECTED RANDOM)" + "PASS" + "SKIP" + test_errors), "result")
local test_ref = {
    Type        = "block",
    Component   = "test",
    SubComponent= "ref",
    Start       = bg{"REFTEST TEST-START | %s == %s", "file", "_"},
    End         = bg{"%s | %s %s", reftest_status, "file", l.P(1)^0},
    fn          = eval_block
}


local package_tests = {
    Type        = "line",
    Component   = "package",
    SubComponent= "tests",
    Grammar     = bg{"package-tests> Wrote %d files in %d bytes to %s in %gs", "_", "_", "file", "s"},
    fn          = eval_line
}


local function finalize_log(g, b)
    local sof = dt.time_to_ns(b.sts)
    local eof = dt.time_to_ns(b.pts)
    local f = {
        component       = g.Component,
        subComponent    = g.SubComponent,
        result          = b.tc_result,
        logStart        = sof,
        logEnd          = eof,
    }
    inject_timing_msg(g, b.base_msg, 0, f)

    if not g.Sequence then return end

    local errors = {}
    for k,v in pairs(b.cache) do
        if k.cache_on_completion then
            k.cache_on_completion(k, b, v)
            v = b.cache[k] -- completion can clear the cache, so reset the state
        end
        if v and v.Fields then
            errors[#errors + 1] = string.format("Grammar %s, %s unfinished", k.Component, tostring(v.Fields.subComponent or k.SubComponent))
        end
    end

    if #errors > 0 and b.base_msg.Fields["state"] == "completed" then
        local msg = {
            Type = "error.schema.log",
            Payload = "unclosed block",
            Fields = {
                taskId  = b.base_msg.Fields["taskId"],
                detail  = table.concat(errors, "|")
            }
        }
        inject_message(msg)
    end
end


local function get_base_msg(dh, mutable, pj, td)
    local msg = sdu.copy_message(dh, mutable)
    if not msg.Fields then msg.Fields = {} end
    local f = msg.Fields
    f["taskGroupId"]    = pj.status.taskGroupId
    f["taskId"]         = pj.status.taskId
    f["provisionerId"]  = pj.status.provisionerId
    f["workerType"]     = pj.status.workerType
    f["created"]        = td.created
    f["kind"]           = td.tags.kind
    f["testtype"]       = td.tags["test-type"]
    f["os"]             = td.tags.os
    f["suite"]          = td.extra.suite
    f["priority"]       = td.priority

    for i,v in ipairs(td.routes) do
        local project, origin, owner, revision, pushId = tc_route:match(v)
        if project then
            f["project"]      = project
            f["origin"]       = origin
            f["projectOwner"] = owner
            f["revision"]     = revision
            f["pushId"]       = pushId
            break
        end
    end

    local md = td.metadata
    if type(md) == "table" then
        f["owner"] = md.owner
        if not f["project"] and md.source then
            local origin, owner, project, revision = md_source:match(md.source)
            if origin then
                f["origin"]       = origin
                f["projectOwner"] = owner
                f["project"]      = project
                f["revision"]     = revision
            end
        end
    end

    if not f.project then
        local c = td.payload.command
        if type(c) == "table" then
            for i,v in ipairs(c) do
                if type(v) == "string" then
                    f.project = v:match('%-%-project=([^%s"]+)')
                end
            end
        end
    end

    local th = td.extra.treeherder
    if type(th) == "table" then
        f["jobKind"]      = th.jobKind
        f["groupSymbol"]  = th.groupSymbol
        f["symbol"]       = th.symbol
        f["tier"]         = th.tier
        local m = th.machine or {}
        f["platform"]     = m.platform

        if type(th.collection) == "table" then
            local collection = {}
            for k,v in pairs(th.collection) do
                collection[#collection + 1] = k
            end
            if #collection > 0 then
                f["collection"] = collection
            end
        end
    end

    if not f.platform then f.platform = pj.status.workerType end

    return msg
end


local function update_task_summary_run(run, f)
    if not run.started then run.started = run.resolved end -- deadline-exceeded, make the timing zero
    f["reasonResolved"] = run.reasonResolved
    f["runId"]          = run.runId
    f["state"]          = run.state
    f["scheduled"]      = run.scheduled
    f["started"]        = run.started
    f["resolved"]       = run.resolved
    f["workerGroup"]    = run.workerGroup
    f["result"]         = run.reasonResolved
    f["logStart"]       = dt.time_to_ns(time:match(run.started))
    f["logEnd"]         = dt.time_to_ns(time:match(run.resolved))
end


local no_schema = new_log()
-- handle any exception runs reported in the history as they don't have their own resolution messages
-- https://bugzilla.mozilla.org/show_bug.cgi?id=1585673
local function process_exceptions(pj, msg)
    local rid = pj.runId + 1
    for i=1, rid - 1 do
        local run = pj.status.runs[i]
        if run.state == "exception" and run.resolved then
            update_task_summary_run(run, msg.Fields)
            inject_timing_msg(no_schema, msg, 0, nil)
        end
    end
    update_task_summary_run(pj.status.runs[rid], msg.Fields)
end


local default_schema = new_log({new_task({perfherder})})
local schemas_map = {
    ["release-update-verify"]   = default_schema,
    ["source-test"]             = default_schema,
    build                       = new_log({new_task({new_mozharness({package_tests,perfherder}),perfherder})}),
    gtest                       = new_log({new_task({new_mozharness({test_gtest,perfherder}),perfherder})}),
--    sm                          = new_log({new_task({new_mozharness({test_sm}),perfherder})}),
    mochitest                   = new_log({new_task({new_mozharness({test,gecko,perfherder}),perfherder})}),
    partials                    = new_log({new_task()}),
    raptor                      = new_log({new_task({new_mozharness({raptor_recording_date,raptor_perfherder}),perfherder})}),
    reftest                     = new_log({new_task({new_mozharness({test_ref,perfherder}),perfherder})}),
    test                        = new_log({new_task({new_mozharness({test,perfherder}),perfherder})}),
}
local function get_parser(f)
    local s
    if f.jobKind == "test" then
        if f.symbol == "GTest" then
            s = schemas_map.gtest
--        elseif f.symbol:match("Jit") then
--            s = schemas_map.sm
        else
            s = schemas_map[f.testtype or ""] or schemas_map[f.kind or ""] or schemas_map.test
        end
    elseif f.jobKind == "build" then
        if f.kind == "partials" then
           s = schemas_map.partials
        else
           s = schemas_map.build
        end
    end

    return s or default_schema
end


local function json_decode(json, tid, recover, logtype)
    if not json then return end

    local ok, j = pcall(cjson.decode, json)
    if not ok then
        inject_message({
            Type = "error.parse.json." .. logtype,
            Payload = j,
            Fields = {
                taskId = tid,
                detail = json,
                data   = cjson.encode(recover)}})
        return
    end
    return j
end


local function json_decode_api(json, tid, recover, logtype)
    local j = json_decode(json, tid, data, logtype)
    if j and (j.code or j.error) then -- make sure the responses isn't API error JSON
        inject_message({
            Type = "error.api." .. logtype,
            Payload = j.code or j.error,
            Fields = {
                taskId = tid,
                detail = json,
                data   = cjson.encode(recover)}})
        return
    end
    return j
end


local function get_artifact_path(tid, rid, path)
    return string.format("task/%s/runs/%d/artifacts/%s", tid, rid, path)
end


local tfn = string.format("%s/%s_curl", tmp_path, logger)
local function get_artifact_handle(tid, path, recover, logtype)
    local url = get_url(path)
    local cmd = string.format("rm -f %s;curl -L -s -f --retry 2 -m 90 --max-filesize 500000000 %s -o %s ", tfn, url, tfn)

    -- put the original pulse message in the error data to simplify the retry see issue #454
    local rv = os.execute(cmd)
    if rv == 8960 then rv = os.execute(cmd) end -- CURLE_SSL_CONNECT_ERROR happens tens of times per day, but worth a retry to avoid a backfill later
    if rv ~= 0 then
        inject_message({Type = string.format("error.curl.%s", logtype),
            Payload = tostring(rv/256),
            Fields = {
                taskId = tid,
                detail = cmd,
                data   = cjson.encode(recover)}})
        return
    end

    local fh = gzfile.open(tfn, "rb", 64 * 1024)
    if not fh then
        inject_message({Type = string.format("error.open.%s", logtype),
            Payload = "file not found",
            Fields = {
                taskId = tid,
                detail = cmd,
                data   = cjson.encode(recover)}})
    end
    return fh
end


local function get_artifact_string(tid, path, recover, logtype)
    local url = get_url(path)
    local cmd = string.format("rm -f %s;curl -L -s -f --retry 2 -m 60 --max-filesize %d %s -o %s", tfn, mms, url, tfn)

    local rv = os.execute(cmd)
    if rv == 8960 then rv = os.execute(cmd) end -- CURLE_SSL_CONNECT_ERROR happens tens of times per day, but worth a retry to avoid a backfill later
    if rv ~= 0 then
        inject_message({Type = string.format("error.curl.%s", logtype),
            Payload = tostring(rv/256),
            Fields = {
                taskId = tid,
                detail = cmd,
                data   = cjson.encode(recover)}})
        return
    end

    local ok, s = pcall(gzfile.string, tfn, "rb", 64 * 1024, mms)
    if not ok then
        inject_message({Type = string.format("error.open.%s", logtype),
            Payload = s,
            Fields = {
                taskId = tid,
                detail = cmd,
                data   = cjson.encode(recover)}})
        return
    end
    return s
end


local function get_artifact_list(pj, rid, recover, token)
    local logtype   = "artifact_list"
    local tid       = pj.status.taskId
    local path      = string.format("task/%s/runs/%d/artifacts", tid, rid)
    if token then
        path = path .. "?continuationToken=" .. token
    end

    local s = get_artifact_string(tid, path, recover, logtype)
    local j = json_decode_api(s, tid, recover, logtype)
    if not j or not j.artifacts then return end

     if j.continuationToken then
        local cj = get_artifact_list(pj, rid, recover, j.continuationToken)
        if cj and cj.artifacts then
            for i,v in ipairs(cj.artifacts) do
                j.artifacts[#j.artifacts + 1] = v
            end
        end
        j.continuationToken = nil
    end

    if not token then
        j.taskId        = tid
        j.provisionerId = pj.status.provisionerId
        j.taskGroupId   = pj.status.taskGroupId
        j.workerType    = pj.status.workerType
        j.workerGroup   = pj.workerGroup
        j.workerId      = pj.workerId
        j.runId         = rid
        j.time          = pj.status.runs[rid + 1].started
    end
    return j
end


local function process_resource_monitor(pj, recover)
    local logtype   = "resource_monitor"
    local tid       = pj.status.taskId
    local rid       = pj.runId
    local path      = get_artifact_path(tid, rid, resource_monitor_path)

    local s = get_artifact_string(tid, path, recover, logtype)
    local j = json_decode_api(s, tid, recover, logtype)
    if not j or not j.version then return end

    local t = {}
    t.taskId        = tid
    t.provisionerId = pj.status.provisionerId
    t.taskGroupId   = pj.status.taskGroupId
    t.workerType    = pj.status.workerType
    t.workerGroup   = pj.workerGroup
    t.workerId      = pj.workerId
    t.runId         = rid
    t.time          = pj.status.runs[rid + 1].started
    t.payload       = j
    inject_validated_msg(t, logtype, resource_monitor_schema, resource_moniter_file, tid)
end


local function process_artifact_history(pj, recover)
    local rid = pj.runId + 1
    local j
    for i=1, rid  do
        local run = pj.status.runs[i]
        if (i == rid or run.state == "exception") and run.started then
            recover.runId = i - 1
            j = get_artifact_list(pj, recover.runId, recover)
            inject_artifact_list(j)
        end
    end
    return j
end


local function get_external_perfherder_artifacts(state, tid, rid, al)
    local files = {}
    for i,v in ipairs(al.artifacts) do
        if v.name:match("perfherder%-data") and v.storageType ~= "error" then
            local fetch = false
            if state.cache.global.raptor_embedded then
                if not state.cache.global.raptor_embedded[v.name] then
                    fetch = true
                end
            else
                fetch = true
            end
            if fetch then files[#files + 1] = get_artifact_path(tid, rid, v.name) end
        end
    end
    if #files == 0 then return nil end

    local recover = {
        path        = nil,
        base_msg    = state.base_msg,
        current = {
            date_time = state.current.date_time
        },
        cache = {
            global = state.cache.global
        }
    }
    for i,v in ipairs(files) do
        recover.path = v
        local s = get_artifact_string(tid, v, recover, "perfherder")
        perfherder_decode(nil, state, s)
    end
end


local function parse_log(lfh, base_msg, al)
    if not lfh then return end

    local f = base_msg.Fields
    local g = get_parser(f)
    -- the timeStarted does not match what is in the log only use it as a last resort
    local state = {
        stack           = {g},
        level           = 1,
        sts             = nil,
        pts             = time:match(f.started),
        pmts            = nil,
        next_match_cb   = nil,
        tc_result       = f.reasonResolved,
        tc_task_result  = nil,
        buffer          = {nil, nil, nil},
        buffer_head     = 0,
        current         = nil,
        cache           = {[g] = {sidx = 1}, global = {}},
        data            = data,
        line            = nil,
        base_msg        = base_msg,
    }
    state.pmts = state.pts

    local terminated = false
    local rtime = os.time();
    local cnt = 0
    for line in lfh:lines() do
        if #line > 1024 * 5 then
            local tmp = line:sub(1, 1024)
            if not tmp:match("PERFHERDER_DATA: {") then -- talos messages can be very large
                line = ""
            end
        end
        local data = log_line:match(line)
        if data then
            data.line = line
            if not data.date_time then
                if data.time then
                    if data.time.hour < state.pts.hour then -- day wrapped
                        local timet = os.time(state.pts) + 86400
                        data.date_time = os.date("*t", timet)
                    else
                        data.date_time = {year = state.pts.year, month = state.pts.month, day = state.pts.day}
                    end
                    data.date_time.hour = data.time.hour
                    data.date_time.min  = data.time.min
                    data.date_time.sec  = data.time.sec
                    data.date_time.sec_frac = 0
                else
                    data.date_time = state.pts
                end
            end
            state.current = state.buffer[state.buffer_head]
            state.buffer_head = state.buffer_head + 1
            if state.buffer_head > 3 then state.buffer_head = 1 end
            state.buffer[state.buffer_head] = data

            if state.current then
                local block = state.stack[state.level]
                block.fn(block, state)
            end
            state.pts = data.date_time
            if not state.sts then
                state.sts = {year = state.pts.year, month = state.pts.month, day = state.pts.day,
                    hour = state.pts.hour, min = state.pts.min, sec = state.pts.sec, sec_frac = state.pts.sec_frac}
            end
        end
        cnt = cnt + 1
        if cnt % 10000 == 0 then
            local delta = os.time() - rtime
            if delta > 30 then
                terminated = true
                inject_message({
                    Type = "error.parse.log",
                    Payload = "timed out",
                    Fields = {
                        taskId  = f.taskId,
                        detail  = string.format("line: %d", cnt)}})
                break
            end
        end
    end
    lfh:close()
    state.current = state.buffer[state.buffer_head] -- process the last line
    if state.current then
        g.fn(g, state) -- scan from the root and check everything incase the log was mal-formed
    end

    if not state.sts or terminated then -- no timing information in the log, use what was provided in the pulse json
        state.sts = state.pts
        state.pts = time:match(f.resolved)
    end
    finalize_log(g, state)

    if al and f.testtype == "raptor" and f.state == "completed" then -- talos appears to always be embedded in the log
        get_external_perfherder_artifacts(state, f.taskId, f.runId, al)
    end
end


local function get_task_definition(tid, recover)
    local logtype = "task_definition"
    local path = string.format("task/%s", tid)
    local s = get_artifact_string(tid, path, recover, logtype)
    local j = json_decode_api(s, tid, recover, logtype)
    return j
end


local function get_log_file(pj, base_msg, recover)
    if pj.status.state == "exception"
    or pj.status.provisionerId == "scriptworker-k8s"
    or pj.status.provisionerId == "built-in"
    or pj.status.schedulerId == "taskcluster-github"
    or (pj.task and pj.task.tags.kind == "pr") then
        inject_timing_msg(no_schema, base_msg, 0, nil) -- not processing the log, output the timing summary only
        return
    end

    local tid = pj.status.taskId
    local path = get_artifact_path(tid, pj.runId, "public/logs/live_backing.log")
    local fh = get_artifact_handle(tid, path, recover, "log")
    if not fh and not recover then
        inject_timing_msg(no_schema, base_msg, 0, nil) -- unable to backfill the log just output the timing summary
    end
    return fh
end


local function get_resource_monitor(pj, al, recover)
    if al then
        for i,v in ipairs(al.artifacts) do
            if v.name == resource_monitor_path and v.storageType ~= "error" then
                process_resource_monitor(pj, recover)
                break
            end
        end
    end
end


function decode(data, dh, mutable)
    local pj = cjson.decode(data)
    inject_pulse_task(pj, dh) -- forward all task related pulse messages to BigQuery

    local ex = dh.Fields.exchange.value[1]
    if ex == "exchange/taskcluster-queue/v1/task-completed"
    or ex == "exchange/taskcluster-queue/v1/task-failed"
    or ex == "exchange/taskcluster-queue/v1/task-exception" then
        local recover = { pj = pj }
        recover.al = process_artifact_history(pj, recover)
        get_resource_monitor(pj, recover.al, recover)
        recover.td = get_task_definition(pj.status.taskId, recover)
        if recover.td then
            inject_task_definition(pj.status.taskId, recover.td)
            local base_msg = get_base_msg(dh, mutable, pj, recover.td)
            process_exceptions(pj, base_msg)
            local lfh = get_log_file(pj, base_msg, recover)
            parse_log(lfh, base_msg, recover.al)
        end
        os.execute("rm -f " .. tfn)
    end
end


-- Partial load (backfill) decoders to fill in data that was unavailable at the time
function decode_artifact_list_error(data, dh, mutable)
    local recover   = cjson.decode(data)
    local pj        = recover.pj
    local al        = get_artifact_list(pj, recover.runId)
    inject_artifact_list(al)
    if recover.runId == pj.runId then get_resource_monitor(pj, al) end
end


function decode_resource_monitor_error(data, dh, mutable)
    local recover   = cjson.decode(data)
    local pj        = recover.pj
    process_resource_monitor(pj)
end


function decode_task_definition_error(data, dh, mutable)
    local recover = cjson.decode(data)
    local pj = recover.pj
    local al = recover.al or get_artifact_list(pj, pj.runId)
    local td = get_task_definition(pj.status.taskId, nil)
    if not td then return nil end

    inject_task_definition(pj.status.taskId, td)
    local base_msg = get_base_msg(dh, mutable, pj, td)
    process_exceptions(recover.pj, base_msg)
    local lfh = get_log_file(pj, base_msg)
    parse_log(lfh, base_msg, recover.al)
end


function decode_log_error(data, dh, mutable)
    local recover = cjson.decode(data)
    local pj = recover.pj
    local al = recover.al or get_artifact_list(pj, pj.runId)
    local td = recover.td
    local base_msg = get_base_msg(dh, mutable, pj, td)
    update_task_summary_run(pj.status.runs[pj.runId + 1], base_msg.Fields)
    local lfh = get_log_file(pj, base_msg)
    parse_log(lfh, base_msg, recover.al)
end


function decode_perfherder_error(data, dh, mutable)
    local state = cjson.decode(data)
    local s = get_artifact_string(state.base_msg.Fields.taskId, state.path, nil, "perfherder")
    perfherder_decode(nil, state, s)
end


return M
