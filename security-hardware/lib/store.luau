--!nonstrict
-- The panel's state and the one helper operation that may run at a time. Every module of the
-- panel entry shares this table (modules are cached per entry).

local helper = require("./helper.luau")
local model = require("./model.luau")

local S = {
  open = false,
  loading = false,
  helperFailed = false,
  state = nil, -- the helper's last "state" event
  chosenTab = "",
  -- The operation running: { op, tab, stage, status, pid }; nil when idle.
  busy = nil,
  -- One message per tab: { text, error }.
  messages = {},
  -- The PIN dialog: { tab, title, detail, args(pinPath) -> {…}, error, key }; nil when closed.
  pin = nil,
  pinValue = "",
  pinKey = 0,
  -- Destructive buttons ask for a second press: the id of the one armed.
  armed = "",
  fp = { selected = "", enrolled = {}, loadedFor = "", picking = false, pickIndex = 1, done = 0, total = -1 },
  gpg = { file = "" },
  ssh = { form = nil, created = nil, replaceFor = nil, persistFor = "", persistValue = 0 },
  probing = false,
  render = function() end,
}

function S.setMessage(tab, text, isError)
  S.messages[tab] = if text == nil or text == "" then nil else { text = text, error = isError == true }
end

function S.isBusy()
  return S.busy ~= nil
end

local function applyState(event)
  S.state = event
  S.loading = false
  S.helperFailed = false
end

-- Reloads everything the panel shows.
function S.refresh()
  if S.loading then
    return
  end
  S.loading = true
  local started = helper.run({ "state" }, function(event)
    if event.type == "state" then
      applyState(event)
      S.afterState()
    elseif event.type == "end" then
      S.loading = false
      S.render()
    end
  end)
  if not started then
    S.loading = false
    S.helperFailed = true
  end
  S.render()
end

-- Hook for tabs that load more after a state (the fingerprint list); set by the panel.
S.afterState = function() end

-- Hot plug: while nothing runs, compares the connected keys with the last state.
function S.probe()
  if S.probing or S.loading or S.busy ~= nil or S.state == nil then
    return
  end
  S.probing = true
  local started = helper.run({ "probe" }, function(event)
    if event.type == "probe" then
      local known = {}
      for _, device in ipairs(S.state.devices or {}) do
        table.insert(known, device.path)
      end
      local changed = #known ~= #(event.devices or {})
      for i, path in ipairs(event.devices or {}) do
        changed = changed or known[i] ~= path
      end
      if changed then
        S.probing = false
        S.refresh()
      end
    elseif event.type == "end" then
      S.probing = false
    end
  end)
  if not started then
    S.probing = false
  end
end

-- Runs one operation for <tab>. handlers: busy(event), done(event) -> message?, error(event) -> message?
-- (return nil to use the default text), cancelled(), finished(). A state event updates the panel.
function S.run(tab, op, args, handlers)
  if S.busy ~= nil then
    return false
  end
  handlers = handlers or {}
  S.armed = ""
  S.setMessage(tab, nil)
  S.busy = { op = op, tab = tab, stage = "", status = "", pid = nil }
  local started = helper.run(args, function(event)
    local busy = S.busy
    if event.type == "pid" then
      if busy ~= nil then
        busy.pid = event.pid
      end
    elseif event.type == "busy" then
      if busy ~= nil then
        busy.stage = event.stage or ""
        busy.status = event.status or ""
      end
      if handlers.busy then
        handlers.busy(event)
      end
    elseif event.type == "state" then
      applyState(event)
      S.afterState()
    elseif event.type == "done" then
      local text = if handlers.done then handlers.done(event) else nil
      S.setMessage(tab, text, false)
    elseif event.type == "error" then
      local text = if handlers.error then handlers.error(event) else nil
      S.setMessage(tab, text or model.errorText(event.code, event.detail), true)
    elseif event.type == "cancelled" then
      S.setMessage(tab, nil)
      if handlers.cancelled then
        handlers.cancelled()
      end
    elseif event.type == "end" then
      S.busy = nil
      if handlers.finished then
        handlers.finished()
      end
    end
    S.render()
  end)
  if not started then
    S.busy = nil
    S.setMessage(tab, model.errorText("helper", ""), true)
  end
  S.render()
  return started
end

function S.cancel()
  if S.busy ~= nil then
    helper.stop(S.busy.pid)
  end
end

-- Opens the PIN dialog for an operation that needs the key's PIN. `spec`:
--   { tab, op, title, detail, args = function(pinPath) -> {…}, handlers }
-- A wrong PIN keeps the dialog open with the error, to try again.
function S.askPin(spec)
  if S.busy ~= nil then
    return
  end
  S.pin = spec
  S.pin.error = nil
  S.pinValue = ""
  S.pinKey += 1
  S.render()
end

function S.closePin()
  S.pin = nil
  S.pinValue = ""
  S.pinKey += 1
  S.render()
end

function S.submitPin()
  local spec = S.pin
  if spec == nil or S.busy ~= nil then
    return
  end
  local pin = S.pinValue
  S.pinValue = ""
  S.pinKey += 1
  if pin == "" then
    spec.error = noctalia.tr("error.pin-required")
    S.render()
    return
  end
  helper.pinFile(pin, function(path)
    if path == nil then
      spec.error = model.errorText("write-failed", "$XDG_RUNTIME_DIR/noctalia-security-hw")
      S.render()
      return
    end
    local handlers = spec.handlers or {}
    local wrapped = table.clone(handlers)
    wrapped.error = function(event)
      if event.code == "pin-invalid" or event.code == "pin-required" then
        -- Back to the dialog, which says it; the tab says nothing.
        spec.error = model.errorText(event.code, event.detail)
        S.pin = spec
        return ""
      end
      if handlers.error then
        return handlers.error(event)
      end
      return nil
    end
    wrapped.finished = function()
      if S.messages[spec.tab] ~= nil and S.messages[spec.tab].text == "" then
        S.messages[spec.tab] = nil
      end
      if handlers.finished then
        handlers.finished()
      end
    end
    S.pin = nil
    S.run(spec.tab, spec.op, spec.args(path), wrapped)
  end)
end

-- Runs an operation that may need the PIN: asks for it when the key has one.
function S.withPin(spec)
  local device = model.device(S.state)
  if device ~= nil and device.clientPin then
    S.askPin(spec)
  else
    S.run(spec.tab, spec.op, spec.args(nil), spec.handlers)
  end
end

-- A destructive button: the first press arms it, the second runs it.
function S.confirm(id, action)
  if S.armed == id then
    S.armed = ""
    action()
  else
    S.armed = id
    S.render()
  end
end

function S.reset()
  S.cancel()
  S.pin = nil
  S.pinValue = ""
  S.pinKey += 1
  S.armed = ""
  S.messages = {}
  S.fp.picking = false
  S.ssh.form = nil
  S.ssh.created = nil
  S.ssh.replaceFor = nil
  S.ssh.persistFor = ""
end

return S
