--!nonstrict
-- Fingerprint readers, FIDO2/U2F keys and the OpenPGP card. Every hardware operation runs the
-- noctalia-security-hw helper: short ones with runAsync (one JSON line), long ones (enroll,
-- verify, register, test, import) with runStream, whose last line is {"event": "done"}.

local PANEL = "lbssousa/security-hardware:panel"

-- fprintd finger names, right hand first (thumb, index, middle), like GNOME Settings.
local FINGERS = {
  "right-thumb", "right-index-finger", "right-middle-finger", "right-ring-finger", "right-little-finger",
  "left-thumb", "left-index-finger", "left-middle-finger", "left-ring-finger", "left-little-finger",
}

local isOpen = false

local fp = {
  loaded = false, available = false, devices = {}, selected = "", enrolled = {},
  mode = "idle", -- idle | picking | enrolling | verifying
  pickIndex = 1, stagesDone = 0, stagesTotal = -1, pid = nil,
  status = "", statusError = false,
}
local key = {
  loaded = false, tools = false, tester = false, testService = false, authfile = "",
  connected = {}, credentials = {}, busy = "", -- "" | register | test
  pin = "", pinKey = 0, pid = nil, status = "", statusError = false,
}
local gpg = {
  loaded = false, available = false, card = nil, state = "unknown", trusted = false,
  busy = false, pid = nil, filePath = "", status = "", statusError = false,
}

-- ── helpers ────────────────────────────────────────────────────────────────────────────────

local function helper()
  local path = noctalia.getConfig("helper")
  return if type(path) == "string" and path ~= "" then path else "noctalia-security-hw"
end

local function shellQuote(text)
  return "'" .. string.gsub(text, "'", "'\\''") .. "'"
end

local function decode(line)
  local value = noctalia.json.decode(line or "")
  return if type(value) == "table" then value else nil
end

local function call(args, cb)
  local argv = { helper() }
  for _, arg in ipairs(args) do
    table.insert(argv, arg)
  end
  noctalia.runAsync(argv, function(result)
    local lastLine = nil
    for line in string.gmatch(result.stdout or "", "[^\n]+") do
      lastLine = line
    end
    cb(decode(lastLine) or { ok = false, error = "generic", message = result.stderr })
  end)
end

-- Streams one helper operation; `onEvent` gets every decoded line.
local function stream(args, onEvent)
  local parts = { shellQuote(helper()) }
  for _, arg in ipairs(args) do
    table.insert(parts, shellQuote(arg))
  end
  return noctalia.runStream(table.concat(parts, " ") .. " 2>/dev/null", function(line)
    local event = decode(line)
    if event ~= nil then
      onEvent(event)
    end
  end)
end

local function stop(pid)
  if type(pid) == "number" then
    noctalia.runAsync({ "kill", "-TERM", tostring(math.floor(pid)) })
  end
end

local function contains(list, value)
  for _, item in ipairs(list) do
    if item == value then
      return true
    end
  end
  return false
end

local function fingerLabel(finger)
  local short = string.gsub(finger, "%-finger$", "")
  return noctalia.tr("fingerprint.finger." .. short)
end

-- ── fingerprint ────────────────────────────────────────────────────────────────────────────

local function fpError(result)
  local code = result.error or "generic"
  if code == "generic" then
    return noctalia.tr("fingerprint.error.generic", { message = result.message or "" })
  end
  return noctalia.tr("fingerprint.error." .. code)
end

-- fprintd scan feedback shared by enroll and verify ("enroll-retry-scan", "verify-retry-scan").
local function scanFeedback(code)
  if string.find(code, "retry%-scan$") then
    return noctalia.tr("fingerprint.status.retry-scan")
  elseif string.find(code, "swipe%-too%-short$") then
    return noctalia.tr("fingerprint.status.swipe-too-short")
  elseif string.find(code, "finger%-not%-centered$") then
    return noctalia.tr("fingerprint.status.finger-not-centered")
  elseif string.find(code, "remove%-and%-retry$") then
    return noctalia.tr("fingerprint.status.remove-and-retry")
  end
  return nil
end

local function touchHint()
  for _, device in ipairs(fp.devices) do
    if device.path == fp.selected and device.scan_type == "swipe" then
      return noctalia.tr("fingerprint.status.swipe")
    end
  end
  return noctalia.tr("fingerprint.status.touch")
end

local function setFpStatus(text, isError)
  fp.status = text or ""
  fp.statusError = isError == true
  render()
end

local function loadEnrolled()
  if fp.selected == "" then
    fp.enrolled = {}
    render()
    return
  end
  call({ "fp", "list", fp.selected }, function(result)
    if result.ok then
      fp.enrolled = result.enrolled or {}
    else
      fp.enrolled = {}
      setFpStatus(fpError(result), true)
    end
    render()
  end)
end

local function loadFingerprint()
  call({ "fp", "state" }, function(result)
    fp.loaded = true
    fp.available = result.available == true
    fp.devices = result.devices or {}
    local keep = false
    for _, device in ipairs(fp.devices) do
      keep = keep or device.path == fp.selected
    end
    if not keep then
      fp.selected = if type(result.default) == "string" and result.default ~= "" then result.default
        elseif fp.devices[1] ~= nil then fp.devices[1].path
        else ""
    end
    loadEnrolled()
  end)
end

local function availableFingers()
  local out = {}
  for _, finger in ipairs(FINGERS) do
    if not contains(fp.enrolled, finger) then
      table.insert(out, finger)
    end
  end
  return out
end

function onSelectDevice(index)
  local device = fp.devices[(tonumber(index) or 0) + 1]
  if device ~= nil and fp.mode == "idle" then
    fp.selected = device.path
    setFpStatus("", false)
    loadEnrolled()
  end
end

function onAddFingerprint()
  fp.mode = "picking"
  fp.pickIndex = 1
  setFpStatus(noctalia.tr("fingerprint.choose-finger"), false)
end

function onPickFinger(index)
  fp.pickIndex = (tonumber(index) or 0) + 1
  render()
end

function onStartEnroll()
  local finger = availableFingers()[fp.pickIndex]
  if finger == nil then
    return
  end
  fp.mode = "enrolling"
  fp.stagesDone = 0
  fp.stagesTotal = -1
  fp.enrollFinger = finger
  setFpStatus(noctalia.tr("fingerprint.status.preparing"), false)
  local started = stream({ "fp", "enroll", fp.selected, finger }, function(event)
    if event.pid ~= nil then
      fp.pid = event.pid
    elseif event.event == "status" then
      fp.stagesTotal = event.stages_total or -1
      local code = event.code or ""
      if code == "enroll-stage-passed" then
        fp.stagesDone += 1
        setFpStatus(noctalia.tr("fingerprint.status.stage-passed"), false)
      else
        local feedback = scanFeedback(code)
        if feedback ~= nil then
          setFpStatus(feedback, true)
        end
      end
    elseif event.event == "done" then
      fp.mode = "idle"
      fp.pid = nil
      local code = event.code or ""
      if event.ok then
        setFpStatus(noctalia.tr("fingerprint.status.enroll-completed"), false)
      elseif code == "cancelled" then
        setFpStatus("", false)
      elseif code == "enroll-duplicate" then
        setFpStatus(noctalia.tr("fingerprint.status.duplicate"), true)
      elseif code == "enroll-data-full" then
        setFpStatus(noctalia.tr("fingerprint.status.data-full"), true)
      elseif code == "enroll-disconnected" then
        setFpStatus(noctalia.tr("fingerprint.status.disconnected"), true)
      elseif string.sub(code, 1, 7) == "enroll-" then
        setFpStatus(noctalia.tr("fingerprint.status.enroll-failed"), true)
      else
        setFpStatus(fpError({ error = code, message = event.message }), true)
      end
      loadEnrolled()
    end
  end)
  if started then
    setFpStatus(touchHint(), false)
  else
    fp.mode = "idle"
    setFpStatus(fpError({ error = "generic", message = helper() }), true)
  end
end

function onStartVerify()
  fp.mode = "verifying"
  setFpStatus(noctalia.tr("fingerprint.status.preparing"), false)
  local matched = "any"
  local started = stream({ "fp", "verify", fp.selected }, function(event)
    if event.pid ~= nil then
      fp.pid = event.pid
      setFpStatus(touchHint(), false)
    elseif event.event == "finger" then
      matched = event.finger or "any"
    elseif event.event == "status" then
      local feedback = scanFeedback(event.code or "")
      if feedback ~= nil then
        setFpStatus(feedback, true)
      elseif event.code == "verify-no-match" then
        setFpStatus(noctalia.tr("fingerprint.status.no-match"), true)
      end
    elseif event.event == "done" then
      fp.mode = "idle"
      fp.pid = nil
      local code = event.code or ""
      if event.ok then
        if matched ~= "any" and matched ~= "" then
          setFpStatus(noctalia.tr("fingerprint.status.match-finger", { finger = fingerLabel(matched) }), false)
        else
          setFpStatus(noctalia.tr("fingerprint.status.match"), false)
        end
      elseif code == "cancelled" then
        setFpStatus("", false)
      elseif code == "verify-no-match" then
        setFpStatus(noctalia.tr("fingerprint.status.no-match"), true)
      elseif code == "verify-timeout" then
        setFpStatus(noctalia.tr("fingerprint.status.verify-timeout"), true)
      elseif code == "verify-disconnected" then
        setFpStatus(noctalia.tr("fingerprint.status.disconnected"), true)
      elseif string.sub(code, 1, 7) == "verify-" then
        setFpStatus(noctalia.tr("fingerprint.status.verify-failed"), true)
      else
        setFpStatus(fpError({ error = code, message = event.message }), true)
      end
    end
  end)
  if not started then
    fp.mode = "idle"
    setFpStatus(fpError({ error = "generic", message = helper() }), true)
  end
end

function onCancelFingerprint()
  if fp.mode == "picking" then
    fp.mode = "idle"
    setFpStatus("", false)
    return
  end
  stop(fp.pid)
end

local function deleteFinger(finger)
  call({ "fp", "delete", fp.selected, finger }, function(result)
    if result.ok then
      setFpStatus(noctalia.tr("fingerprint.status.deleted", { finger = fingerLabel(finger) }), false)
    else
      setFpStatus(fpError(result), true)
    end
    loadEnrolled()
  end)
end

-- ── FIDO2 / U2F ────────────────────────────────────────────────────────────────────────────

local function setKeyStatus(text, isError)
  key.status = text or ""
  key.statusError = isError == true
  render()
end

local function loadKeys()
  call({ "key", "state" }, function(result)
    key.loaded = true
    key.tools = result.tools == true
    key.tester = result.tester == true
    key.testService = result.test_service == true
    key.authfile = result.authfile or ""
    key.connected = result.connected or {}
    key.credentials = result.credentials or {}
    render()
  end)
end

local function keyStatusText(event)
  local code = event.code or ""
  if code == "register-failed" then
    return noctalia.tr("security-keys.fido.status.register-failed", { message = event.message or "" })
  elseif code == "write-failed" then
    return noctalia.tr("security-keys.fido.status.write-failed", { path = event.path or key.authfile })
  end
  return noctalia.tr("security-keys.fido.status." .. code)
end

function onPinChange(value)
  key.pin = if type(value) == "string" then value else ""
end

local function startRegister(pinFile)
  local args = { "key", "register" }
  if pinFile ~= nil then
    table.insert(args, pinFile)
  end
  key.busy = "register"
  setKeyStatus(noctalia.tr("security-keys.fido.status.touch"), false)
  local started = stream(args, function(event)
    if event.pid ~= nil then
      key.pid = event.pid
    elseif event.event == "done" then
      key.busy = ""
      key.pid = nil
      if event.code == "cancelled" then
        setKeyStatus("", false)
      else
        setKeyStatus(keyStatusText(event), not event.ok)
      end
      loadKeys()
    end
  end)
  if not started then
    key.busy = ""
    setKeyStatus(keyStatusText({ code = "register-failed", message = helper() }), true)
  end
end

function onRegisterKey()
  if key.busy ~= "" then
    return
  end
  local pin = key.pin
  key.pin = ""
  key.pinKey += 1
  if pin == "" then
    startRegister(nil)
    return
  end
  -- The PIN goes to the helper in a 0600 file it reads and removes, never on a command line.
  local runtime = noctalia.getenv("XDG_RUNTIME_DIR")
  if runtime == nil or runtime == "" then
    setKeyStatus(keyStatusText({ code = "register-failed", message = "XDG_RUNTIME_DIR" }), true)
    return
  end
  local dir = runtime .. "/noctalia-security-hw"
  noctalia.runAsync({ "mkdir", "-p", "-m", "700", dir }, function(result)
    local file = dir .. "/pin-" .. tostring(math.random(100000000, 999999999))
    if result.exitCode ~= 0 or not noctalia.writeFile(file, pin) then
      setKeyStatus(keyStatusText({ code = "register-failed", message = dir }), true)
      return
    end
    startRegister(file)
  end)
end

function onTestKey()
  if key.busy ~= "" then
    return
  end
  key.busy = "test"
  setKeyStatus(noctalia.tr("security-keys.fido.status.testing"), false)
  local started = stream({ "key", "test" }, function(event)
    if event.pid ~= nil then
      key.pid = event.pid
    elseif event.event == "status" then
      setKeyStatus(keyStatusText(event), false)
    elseif event.event == "done" then
      key.busy = ""
      key.pid = nil
      if event.code == "cancelled" then
        setKeyStatus("", false)
      else
        setKeyStatus(keyStatusText(event), not event.ok)
      end
    end
  end)
  if not started then
    key.busy = ""
    setKeyStatus(keyStatusText({ code = "test-no-key" }), true)
  end
end

function onStopKey()
  stop(key.pid)
end

local function removeCredential(index)
  call({ "key", "remove", tostring(index - 1) }, function(result)
    if result.ok then
      setKeyStatus(noctalia.tr("security-keys.fido.status.removed"), false)
    else
      setKeyStatus(keyStatusText({ code = result.error or "register-failed", message = result.message }), true)
    end
    loadKeys()
  end)
end

-- ── OpenPGP card ───────────────────────────────────────────────────────────────────────────

local function setGpgStatus(text, isError)
  gpg.status = text or ""
  gpg.statusError = isError == true
  render()
end

local function loadGpg()
  call({ "gpg", "state" }, function(result)
    gpg.loaded = true
    gpg.available = result.gpg == true
    gpg.card = if type(result.card) == "table" then result.card else nil
    gpg.state = result.state or "unknown"
    gpg.trusted = result.trusted == true
    render()
  end)
end

local function gpgStatusText(event)
  local code = event.code or "import-failed"
  if code == "import-file-failed" or code == "trust-failed" then
    return noctalia.tr("security-keys.gpg.status." .. code, { message = event.message or "" })
  end
  return noctalia.tr("security-keys.gpg.status." .. code)
end

local function gpgStream(args)
  if gpg.busy then
    return
  end
  gpg.busy = true
  render()
  local started = stream(args, function(event)
    if event.pid ~= nil then
      gpg.pid = event.pid
    elseif event.event == "status" then
      setGpgStatus(gpgStatusText(event), false)
    elseif event.event == "done" then
      gpg.busy = false
      gpg.pid = nil
      setGpgStatus(gpgStatusText(event), not event.ok)
      loadGpg()
    end
  end)
  if not started then
    gpg.busy = false
    setGpgStatus(gpgStatusText({ code = "import-failed" }), true)
  end
end

function onImportKey()
  gpgStream({ "gpg", "import" })
end

function onFilePathChange(value)
  gpg.filePath = if type(value) == "string" then value else ""
end

function onImportFile()
  local path = noctalia.string.trim(gpg.filePath)
  if path == "" then
    return
  end
  gpgStream({ "gpg", "import-file", noctalia.expandPath(path) })
end

function onTrustKey()
  if gpg.busy then
    return
  end
  gpg.busy = true
  render()
  call({ "gpg", "trust" }, function(result)
    gpg.busy = false
    setGpgStatus(gpgStatusText(if result.ok then { code = "trusted" } else result), not result.ok)
    loadGpg()
  end)
end

-- ── rendering ──────────────────────────────────────────────────────────────────────────────

local function heading(text, description)
  return ui.column({ gap = 2 }, {
    ui.label({ text = text, fontSize = 16, fontWeight = "bold", color = "primary" }),
    ui.label({ text = description, color = "on_surface_variant", maxLines = 3 }),
  })
end

local function status(text, isError)
  if text == "" then
    return nil
  end
  return ui.label({ text = text, color = if isError then "error" else "on_surface", maxLines = 3 })
end

local function infoRow(label, value)
  return ui.row({ gap = 6, align = "center" }, {
    ui.label({ text = label, color = "on_surface_variant" }),
    ui.label({ text = value, color = "on_surface", flexGrow = 1, maxLines = 2 }),
  })
end

local function append(list, item)
  if item ~= nil then
    table.insert(list, item)
  end
end

-- Closures need distinct names per row: buttons call these with the row's value.
local rowActions = {}

local function rowButton(id, text, glyph, action)
  rowActions[id] = action
  return ui.button({ text = text, glyph = glyph, variant = "ghost", controlSize = "sm", onClick = function()
    local fn = rowActions[id]
    if fn ~= nil then
      fn()
    end
  end })
end

local function fingerprintSection()
  local items = { heading(noctalia.tr("fingerprint.label"), noctalia.tr("fingerprint.description")) }
  if not fp.loaded then
    return items
  end
  if not fp.available or #fp.devices == 0 then
    table.insert(items, ui.label({ text = noctalia.tr("fingerprint.no-reader"), color = "on_surface_variant" }))
    return items
  end

  if #fp.devices > 1 then
    local names, selected = {}, 0
    for i, device in ipairs(fp.devices) do
      table.insert(names, device.name)
      if device.path == fp.selected then
        selected = i - 1
      end
    end
    table.insert(items, ui.row({ gap = 8, align = "center" }, {
      ui.label({ text = noctalia.tr("fingerprint.reader") }),
      ui.select({ options = names, selectedIndex = selected, enabled = fp.mode == "idle", onChange = "onSelectDevice",
        flexGrow = 1 }),
    }))
  end

  table.insert(items, ui.label({ text = noctalia.tr("fingerprint.enrolled"), fontWeight = "medium" }))
  if #fp.enrolled == 0 then
    table.insert(items, ui.label({ text = noctalia.tr("fingerprint.none-enrolled"), color = "on_surface_variant" }))
  end
  for _, finger in ipairs(fp.enrolled) do
    table.insert(items, ui.row({ gap = 8, align = "center" }, {
      ui.glyph({ name = "fingerprint", size = 18, color = "on_surface_variant" }),
      ui.label({ text = fingerLabel(finger), flexGrow = 1 }),
      rowButton("fp-delete-" .. finger, "", "trash", function()
        if fp.mode == "idle" then
          deleteFinger(finger)
        end
      end),
    }))
  end

  if fp.mode == "picking" then
    local choices = {}
    for _, finger in ipairs(availableFingers()) do
      table.insert(choices, fingerLabel(finger))
    end
    table.insert(items, ui.row({ gap = 8, align = "center" }, {
      ui.select({ options = choices, selectedIndex = fp.pickIndex - 1, onChange = "onPickFinger", flexGrow = 1 }),
      ui.button({ text = noctalia.tr("fingerprint.add"), variant = "primary", onClick = "onStartEnroll" }),
      ui.button({ text = noctalia.tr("cancel"), variant = "outline", onClick = "onCancelFingerprint" }),
    }))
  elseif fp.mode == "enrolling" then
    if fp.stagesTotal > 0 then
      table.insert(items, ui.progress({ progress = math.min(1, fp.stagesDone / fp.stagesTotal), height = 6 }))
      table.insert(items, ui.label({
        text = noctalia.tr("fingerprint.stages", { done = tostring(fp.stagesDone), total = tostring(fp.stagesTotal) }),
        color = "on_surface_variant",
      }))
    end
    table.insert(items, ui.row({ justify = "end" }, {
      ui.button({ text = noctalia.tr("cancel"), variant = "outline", onClick = "onCancelFingerprint" }),
    }))
  else
    table.insert(items, ui.row({ gap = 8, justify = "end" }, {
      ui.button({
        text = if fp.mode == "verifying" then noctalia.tr("fingerprint.stop-test") else noctalia.tr("fingerprint.test"),
        variant = "outline",
        enabled = #fp.enrolled > 0,
        onClick = if fp.mode == "verifying" then "onCancelFingerprint" else "onStartVerify",
      }),
      ui.button({
        text = noctalia.tr("fingerprint.add"),
        glyph = "plus",
        variant = "primary",
        enabled = fp.mode == "idle" and #availableFingers() > 0,
        onClick = "onAddFingerprint",
      }),
    }))
  end
  append(items, status(fp.status, fp.statusError))
  return items
end

local function keysSection()
  local items = { heading(noctalia.tr("security-keys.fido.label"), noctalia.tr("security-keys.fido.description")) }
  if not key.loaded then
    return items
  end
  table.insert(items, ui.label({ text = noctalia.tr("security-keys.fido.connected"), fontWeight = "medium" }))
  if #key.connected == 0 then
    table.insert(items, ui.label({ text = noctalia.tr("security-keys.fido.none-connected"), color = "on_surface_variant" }))
  end
  for _, name in ipairs(key.connected) do
    table.insert(items, ui.row({ gap = 8, align = "center" }, {
      ui.glyph({ name = "key", size = 18, color = "on_surface_variant" }),
      ui.label({ text = name, flexGrow = 1 }),
    }))
  end

  table.insert(items, ui.label({ text = noctalia.tr("security-keys.fido.registered"), fontWeight = "medium" }))
  if #key.credentials == 0 then
    table.insert(items, ui.label({ text = noctalia.tr("security-keys.fido.none-registered"), color = "on_surface_variant" }))
  end
  for i, cred in ipairs(key.credentials) do
    local handle = cred.handle or ""
    if #handle > 16 then
      handle = string.sub(handle, 1, 16) .. "…"
    end
    table.insert(items, ui.row({ gap = 8, align = "center" }, {
      ui.label({
        text = noctalia.tr("security-keys.fido.credential", { index = tostring(i), handle = handle }),
        flexGrow = 1,
      }),
      rowButton("key-remove-" .. tostring(i) .. "-" .. (cred.handle or ""), "", "trash", function()
        if key.busy == "" then
          removeCredential(i)
        end
      end),
    }))
  end
  if key.authfile ~= "" then
    table.insert(items, ui.label({
      text = noctalia.tr("security-keys.fido.authfile", { path = key.authfile }),
      color = "on_surface_variant",
      fontSize = 12,
    }))
  end

  if key.tools then
    table.insert(items, ui.label({ text = noctalia.tr("security-keys.fido.pin-hint"), color = "on_surface_variant",
      maxLines = 2 }))
    table.insert(items, ui.row({ gap = 8, align = "center" }, {
      ui.input({
        key = "pin-" .. tostring(key.pinKey),
        value = "",
        placeholder = noctalia.tr("security-keys.fido.pin-placeholder"),
        password = true,
        enabled = key.busy == "",
        onChange = "onPinChange",
        onSubmit = "onRegisterKey",
        flexGrow = 1,
      }),
      ui.button({
        text = noctalia.tr("security-keys.fido.register"),
        glyph = "plus",
        variant = "primary",
        enabled = key.busy == "",
        onClick = "onRegisterKey",
      }),
    }))
  end
  local testing = key.busy ~= ""
  table.insert(items, ui.row({ gap = 8, justify = "end" }, {
    ui.button({
      text = if testing then noctalia.tr("security-keys.fido.stop-test") else noctalia.tr("security-keys.fido.test"),
      variant = "outline",
      enabled = testing or (key.tester and key.testService and #key.credentials > 0),
      onClick = if testing then "onStopKey" else "onTestKey",
    }),
  }))
  append(items, status(key.status, key.statusError))
  return items
end

local function gpgSection()
  local items = { heading(noctalia.tr("security-keys.gpg.label"), noctalia.tr("security-keys.gpg.description")) }
  if not gpg.loaded or not gpg.available then
    return items
  end
  local card = gpg.card
  if card == nil then
    table.insert(items, ui.label({ text = noctalia.tr("security-keys.gpg.no-card"), color = "on_surface_variant" }))
  else
    local cardText = card.vendor ~= "" and card.vendor or card.reader
    if card.serial ~= "" then
      cardText ..= " · " .. noctalia.tr("security-keys.gpg.serial", { serial = card.serial })
    end
    table.insert(items, infoRow(noctalia.tr("security-keys.gpg.card"), cardText))
    if card.holder ~= "" then
      table.insert(items, infoRow(noctalia.tr("security-keys.gpg.holder"), card.holder))
    end
    if #card.fingerprints > 0 then
      table.insert(items, infoRow(noctalia.tr("security-keys.gpg.fingerprint"), card.fingerprints[1]))
    end
    if card.url ~= "" then
      table.insert(items, infoRow(noctalia.tr("security-keys.gpg.url"), card.url))
    end
    local stateKey = if #card.fingerprints == 0 then "no-key" elseif gpg.state == "unknown" then "missing" else gpg.state
    table.insert(items, infoRow(noctalia.tr("security-keys.gpg.state.label"), noctalia.tr("security-keys.gpg.state." .. stateKey)))
    if gpg.state ~= "missing" and #card.fingerprints > 0 then
      table.insert(items, infoRow(
        noctalia.tr("security-keys.gpg.trust.label"),
        noctalia.tr(if gpg.trusted then "security-keys.gpg.trust.ultimate" else "security-keys.gpg.trust.not-ultimate")
      ))
    end

    if #card.fingerprints > 0 then
      local buttons = {}
      if gpg.state ~= "ready" then
        table.insert(buttons, ui.button({ text = noctalia.tr("security-keys.gpg.import"), variant = "primary",
          enabled = not gpg.busy, onClick = "onImportKey" }))
      end
      if gpg.state ~= "missing" and not gpg.trusted then
        table.insert(buttons, ui.button({ text = noctalia.tr("security-keys.gpg.trust-button"), variant = "outline",
          enabled = not gpg.busy, onClick = "onTrustKey" }))
      end
      if #buttons > 0 then
        table.insert(items, ui.row({ gap = 8, justify = "end" }, buttons))
      end
      if gpg.state ~= "ready" then
        table.insert(items, ui.row({ gap = 8, align = "center" }, {
          ui.input({ key = "gpg-file", value = "", placeholder = noctalia.tr("security-keys.gpg.import-file-title"),
            enabled = not gpg.busy, onChange = "onFilePathChange", onSubmit = "onImportFile", flexGrow = 1 }),
          ui.button({ text = noctalia.tr("security-keys.gpg.import-file"), variant = "outline", enabled = not gpg.busy,
            onClick = "onImportFile" }),
        }))
      end
    end
  end
  append(items, status(gpg.status, gpg.statusError))
  return items
end

function render()
  if not isOpen then
    return
  end
  rowActions = {}
  local sections = {}
  for _, build in ipairs({ fingerprintSection, keysSection, gpgSection }) do
    if #sections > 0 then
      table.insert(sections, ui.separator({ spacing = 4 }))
    end
    table.insert(sections, ui.column({ gap = 8 }, build()))
  end
  panel.render(ui.column({ padding = 16, gap = 12, align = "stretch" }, {
    ui.row({ gap = 10, align = "center" }, {
      ui.glyph({ name = "shield-lock", size = 26, color = "primary" }),
      ui.label({ text = noctalia.tr("title"), fontSize = 18, fontWeight = "bold", flexGrow = 1 }),
      ui.button({ glyph = "refresh", variant = "ghost", controlSize = "sm", tooltip = noctalia.tr("refresh"),
        onClick = "onRefresh" }),
    }),
    ui.scroll({ gap = 16, flexGrow = 1 }, sections),
  }))
end

function onRefresh()
  loadFingerprint()
  loadKeys()
  if not gpg.busy then
    loadGpg()
  end
end

function onOpen(_context)
  isOpen = true
  render()
  onRefresh()
end

function onClose()
  isOpen = false
  -- Nothing keeps running once the panel is gone: release the reader, stop pamu2fcfg/pamtester.
  if fp.mode == "picking" then
    fp.mode = "idle"
  end
  stop(fp.pid)
  stop(key.pid)
  key.pin = ""
  key.pinKey += 1
end
