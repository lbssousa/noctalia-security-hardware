--!nonstrict
-- Runs the noctalia-security-hw helper: one process per operation, one JSON event per line
-- (see helper/noctalia_security_hw/cli.py). The last event is always {type = "end"}.

local M = {}

local function command()
  local path = noctalia.getConfig("helper")
  return if type(path) == "string" and path ~= "" then path else "noctalia-security-hw"
end

local function quote(text)
  return "'" .. (string.gsub(text, "'", "'\\''")) .. "'"
end

-- Starts `noctalia-security-hw <args…>`; `onEvent` gets every decoded event. Returns whether it started.
function M.run(args, onEvent)
  local parts = { quote(command()) }
  for _, arg in ipairs(args) do
    table.insert(parts, quote(arg))
  end
  return noctalia.runStream(table.concat(parts, " ") .. " 2>/dev/null", function(line)
    local event = noctalia.json.decode(line or "")
    if type(event) == "table" and type(event.type) == "string" then
      onEvent(event)
    end
  end)
end

function M.stop(pid)
  if type(pid) == "number" then
    noctalia.runAsync({ "kill", "-TERM", tostring(math.floor(pid)) })
  end
end

-- The PIN goes to the helper in a fresh 0600 file under $XDG_RUNTIME_DIR/noctalia-security-hw,
-- which the helper reads and removes at once: never on a command line or in the environment.
-- Calls cb(path), or cb(nil) when the file can't be written.
function M.pinFile(pin, cb)
  local runtime = noctalia.getenv("XDG_RUNTIME_DIR")
  if runtime == nil or runtime == "" then
    cb(nil)
    return
  end
  local dir = runtime .. "/noctalia-security-hw"
  noctalia.runAsync({ "mkdir", "-p", "-m", "700", dir }, function(result)
    local name = string.format("pin-%d-%d", math.floor(noctalia.nowMs()), math.random(100000000, 999999999))
    local file = dir .. "/" .. name
    if result.exitCode ~= 0 or not noctalia.writeFile(file, pin) then
      cb(nil)
      return
    end
    cb(file)
  end)
end

return M
