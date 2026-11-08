-- Runs the security-hardware panel against a mock of the Noctalia plugin API:
--   python3 tests/bundle.py tests/panel_test.luau [en|pt-BR] > /tmp/t.luau && luau /tmp/t.luau
-- Every ui.* node is checked against the props the shell knows, every noctalia.tr() key must exist
-- with all of its {placeholders} filled, and the panel is driven through each tab's flows by
-- feeding it helper events.

--@@TRANSLATIONS@@

local failures = 0
local function check(cond, message)
  if not cond then
    failures += 1
    print("FAIL: " .. message .. "\n" .. debug.traceback())
  end
end

-- ui.* ------------------------------------------------------------------------------------------

local COMMON = { key = true, width = true, height = true, flexGrow = true, opacity = true, visible = true }
local PROPS = {
  column = "gap padding paddingH paddingV align justify fill radius border borderWidth minWidth minHeight onClick onHover tooltip",
  row = "gap padding paddingH paddingV align justify fill radius border borderWidth minWidth minHeight onClick onHover tooltip",
  scroll = "gap padding paddingH paddingV align justify fill radius border borderWidth stickToBottom onScroll scrollToBottomRev revealKey",
  label = "text fontSize color fontWeight fontFamily baseline maxWidth maxLines textAlign",
  glyph = "name size color",
  separator = "thickness color spacing orientation",
  spacer = "",
  progress = "progress fill track marker markerColor radius",
  button = "text glyph fontSize glyphSize variant contentAlign controlSize tooltip enabled selected onClick onRightClick onHover",
  toggle = "checked enabled onChange",
  slider = "min max step value controlSize enabled onChange onDragEnd",
  select = "options selectedIndex placeholder controlSize enabled onChange",
  input = "value placeholder fontSize controlSize password multiline submitOnEnter frameVisible focus enabled onChange onSubmit",
}
local VARIANTS = { default = true, primary = true, secondary = true, destructive = true, outline = true, ghost = true }

ui = {}
for kind, list in pairs(PROPS) do
  local allowed = {}
  for name in string.gmatch(list, "%S+") do
    allowed[name] = true
  end
  ui[kind] = function(props, children)
    props = props or {}
    for name, value in pairs(props) do
      check(allowed[name] or COMMON[name], "ui." .. kind .. " has no prop '" .. tostring(name) .. "'")
      if string.sub(name, 1, 2) == "on" then
        check(type(value) == "function", "ui." .. kind .. "." .. name .. " is not a function")
      end
    end
    if kind == "button" and props.variant ~= nil then
      check(VARIANTS[props.variant], "unknown button variant " .. tostring(props.variant))
    end
    if kind == "label" then
      check(type(props.text) == "string", "label without text")
    end
    if children ~= nil then
      for i, child in pairs(children) do
        check(type(child) == "table" and child.kind ~= nil, "ui." .. kind .. " child " .. tostring(i) .. " is not a node")
      end
    end
    return { kind = kind, props = props, children = children or {} }
  end
end

-- noctalia.* ------------------------------------------------------------------------------------

local streams = {}
local async = {}
local files = {}
local clipboard = nil
local tree = nil

local function encode(value)
  if type(value) == "table" then
    local parts = {}
    for k, v in pairs(value) do
      table.insert(parts, string.format("%q:%s", tostring(k), encode(v)))
    end
    table.sort(parts)
    return "{" .. table.concat(parts, ",") .. "}"
  elseif type(value) == "string" then
    return string.format("%q", value)
  end
  return tostring(value)
end

noctalia = {
  tr = function(key, subst)
    local text = __TRANSLATIONS[key]
    check(text ~= nil, "missing translation '" .. tostring(key) .. "'")
    text = text or key
    for name, value in pairs(subst or {}) do
      text = string.gsub(text, "{" .. name .. "}", (string.gsub(tostring(value), "%%", "%%%%")))
    end
    check(not string.find(text, "{%a+}"), "unfilled placeholder in '" .. key .. "': " .. text)
    return text
  end,
  getConfig = function(_key)
    return "/nix/store/x-noctalia-security-hw/bin/noctalia-security-hw"
  end,
  getSetting = function(_path)
    return false
  end,
  getenv = function(name)
    return if name == "XDG_RUNTIME_DIR" then "/run/user/1000" else nil
  end,
  nowMs = function()
    return 987000
  end,
  setUpdateInterval = function(_ms) end,
  json = {
    decode = function(line)
      return line -- the mock streams hand events over as tables
    end,
    encode = encode,
  },
  runStream = function(cmd, onLine)
    table.insert(streams, { cmd = cmd, onLine = onLine })
    return true
  end,
  runAsync = function(argv, cb)
    table.insert(async, argv)
    if cb then
      cb({ exitCode = 0, stdout = "", stderr = "" })
    end
    return true
  end,
  writeFile = function(path, contents)
    files[path] = contents
    return true
  end,
  copyToClipboard = function(text, _mime)
    clipboard = text
    return true
  end,
}
panel = {
  render = function(node)
    tree = node
  end,
}

-- helpers -----------------------------------------------------------------------------------------

local function walk(node, visit)
  visit(node)
  for _, child in ipairs(node.children or {}) do
    walk(child, visit)
  end
end

local function find(key)
  local found = nil
  walk(tree, function(node)
    if node.props.key == key then
      found = node
    end
  end)
  return found
end

local function texts()
  local out = {}
  walk(tree, function(node)
    if node.kind == "label" then
      table.insert(out, node.props.text)
    elseif node.kind == "button" and node.props.text then
      table.insert(out, node.props.text)
    end
  end)
  return table.concat(out, "\n")
end

-- Texts are checked in English; other languages run for their keys and placeholders only.
local function shows(text)
  return __LANG ~= "en" or string.find(texts(), text, 1, true) ~= nil
end

local function click(key)
  local node = find(key)
  check(node ~= nil, "no node with key " .. key)
  if node ~= nil then
    check(node.props.enabled ~= false, key .. " is disabled")
    node.props.onClick()
  end
end

local function lastStream()
  return streams[#streams]
end

local function feed(stream, events)
  for _, event in ipairs(events) do
    stream.onLine(event)
  end
end

local function inputs()
  local out = {}
  walk(tree, function(node)
    if node.kind == "input" then
      table.insert(out, node)
    end
  end)
  return out
end

-- The panel, bundled with its modules by tests/bundle.py:
--@@PANEL@@

-- the scenario ------------------------------------------------------------------------------------

local SSH_NAME = "id_ed25519_sk_rk_github.com_work"
local function state(extra)
  local s = {
    type = "state",
    devices = { { path = "/dev/hidraw1", name = "Yubico YubiKey OTP+FIDO+CCID", rk = true, clientPin = true,
      pinRetries = 8 } },
    credentials = { { handle = "HANDLEONE111", label = "HANDLEONE1", unused = false } },
    target = { kind = "own", path = "/home/ada/.config/Yubico/u2f_keys" },
    otherCount = 0,
    pinRequired = true,
    testService = "noctalia-lock-u2f",
    card = { vendor = "Yubico", serial = "20373235", holder = "Ada Lovelace", url = "https://keys.example/ada.asc",
      fingerprints = { "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333" } },
    keyState = "ready",
    trusted = false,
    sshKeys = { { name = SSH_NAME, application = "ssh:github.com", type = "ed25519-sk", user = "work",
      fingerprint = "SHA256:abc", publicKey = "sk-ssh-ed25519@openssh.com AAAA ada@host", encrypted = false,
      host = "github.com", hostState = "off", persistMinutes = 0 } },
    sshDefaults = { user = "0123456789abcdef", comment = "ada@host" },
    sshInclude = "ok",
    fingerprint = { available = true, devices = { { path = "/net/reactivated/Fprint/Device/0", name = "Goodix",
      scanType = "press" } }, default = "/net/reactivated/Fprint/Device/0" },
  }
  for k, v in pairs(extra or {}) do
    s[k] = v
  end
  return s
end

-- Opening asks for the state, then the fingerprints of the default reader.
onOpen({})
check(string.find(lastStream().cmd, "'state'", 1, true) ~= nil, "onOpen runs state")
feed(lastStream(), { { type = "pid", pid = 10 }, state(), { type = "end", op = "state" } })
check(string.find(lastStream().cmd, "'fp' 'list' '/net/reactivated/Fprint/Device/0'", 1, true) ~= nil,
  "the fingerprint list loads")
feed(lastStream(), { { type = "done", op = "fp.list", enrolled = { "right-index-finger" } }, { type = "end" } })
for _, tab in ipairs({ "fingerprint", "fido", "gpg", "ssh" }) do
  check(find("tab-" .. tab) ~= nil, "tab " .. tab .. " shown")
end
check(shows("Right index finger"), "enrolled finger listed")

-- Fingerprint: enroll a finger, with progress.
click("fp-add")
click("fp-enroll-start")
local enroll = lastStream()
check(string.find(enroll.cmd, "'fp' 'enroll'", 1, true) ~= nil, "enroll runs")
feed(enroll, { { type = "pid", pid = 11 },
  { type = "busy", op = "fp.enroll", stage = "scan", status = "started", stagesTotal = 4 },
  { type = "busy", op = "fp.enroll", stage = "scan", status = "enroll-stage-passed", stagesTotal = 4 } })
check(shows("Scan 1 of 4"), "enroll progress")
feed(enroll, { { type = "done", op = "fp.enroll", finger = "right-thumb" }, { type = "end", op = "fp.enroll" } })
check(shows("Fingerprint enrolled."), "enroll message")
feed(lastStream(), { { type = "done", op = "fp.list", enrolled = { "right-index-finger", "right-thumb" } },
  { type = "end" } })
-- Deleting asks twice.
click("fp-delete-right-thumb")
check(shows("Remove? Press again"), "delete armed")
click("fp-delete-right-thumb")
check(string.find(lastStream().cmd, "'fp' 'delete'", 1, true) ~= nil, "delete runs")
feed(lastStream(), { { type = "error", op = "fp.delete", code = "fp-in-use", detail = "" }, { type = "end" } })
check(shows("in use by another program"), "fprint error text")
feed(lastStream(), { { type = "end" } })

-- FIDO2: register with a PIN; a wrong PIN keeps the dialog.
click("tab-fido")
check(shows("Key 1 · HANDLEONE1"), "credential listed")
click("fido-register")
check(find("pin-dialog") ~= nil, "PIN dialog open")
local pinInput = inputs()[1]
check(pinInput.props.password == true and pinInput.props.focus == true, "PIN input masked and focused")
pinInput.props.onChange("1234")
pinInput.props.onSubmit()
local register = lastStream()
check(string.find(register.cmd, "'fido' 'register' '--pin-file' '/run/user/1000/noctalia-security-hw/pin-", 1, true)
  ~= nil, "register gets a PIN file")
check(not string.find(register.cmd, "'1234'", 1, true) and not string.find(register.cmd, "-1234-", 1, true),
  "the PIN is never on the command line")
local pinPath = nil
for path, contents in pairs(files) do
  if contents == "1234" then
    pinPath = path
  end
end
check(pinPath ~= nil, "the PIN went to a file")
feed(register, { { type = "pid", pid = 12 }, { type = "error", op = "fido.register", code = "pin-invalid", detail = "" },
  { type = "end" } })
check(find("pin-dialog") ~= nil and shows("Wrong PIN."), "wrong PIN keeps the dialog")
inputs()[1].props.onChange("4321")
inputs()[1].props.onSubmit()
feed(lastStream(), { { type = "busy", op = "fido.register", stage = "touch" } })
check(shows("Touch the key when it blinks"), "touch prompt")
feed(lastStream(), { { type = "done", op = "fido.register" }, state(), { type = "end" } })
check(find("pin-dialog") == nil and shows("Key registered."), "registered")
click("fido-remove-HANDLEONE111")
click("fido-remove-HANDLEONE111")
check(string.find(lastStream().cmd, "'fido' 'remove' 'HANDLEONE111'", 1, true) ~= nil, "remove by handle")
feed(lastStream(), { { type = "done" }, { type = "end" } })
click("fido-test")
check(string.find(lastStream().cmd, "'fido' 'test'", 1, true) ~= nil, "test runs")
feed(lastStream(), { { type = "error", op = "fido.test", code = "test-failed", detail = "x" }, { type = "end" } })

-- Another file read by PAM: a notice, no register button enabled.
feed(lastStream(), { state({ target = { kind = "other-file", path = "/etc/u2f_mappings" }, otherCount = 2 }) })
check(shows("/etc/u2f_mappings (yours there: 2)"), "other-file notice")
check(find("fido-register").props.enabled == false, "register disabled for another file")
feed(lastStream(), { state() })

-- OpenPGP.
click("tab-gpg")
check(shows("AAAA BBBB CCCC DDDD EEEE  FFFF 0000 1111 2222 3333"), "grouped fingerprint")
check(shows("Update key"), "update when ready")
click("gpg-trust")
check(string.find(lastStream().cmd, "'gpg' 'trust'", 1, true) ~= nil, "trust runs")
feed(lastStream(), { { type = "done", op = "gpg.trust" }, state({ trusted = true }), { type = "end" } })
check(find("gpg-trust") == nil and shows("Ultimately trusted."), "trusted")
click("gpg-remove")
click("gpg-remove")
feed(lastStream(), { { type = "error", op = "gpg.remove", code = "secret-on-disk", detail = "" }, { type = "end" } })
check(shows("nothing was removed"), "secret on disk")
feed(lastStream(), { state({ keyState = "missing" }) })
check(shows("Import public key"), "import when missing")
check(find("gpg-file") ~= nil, "import from file offered")

-- SSH: import, new key with replace, host, reuse, delete.
click("tab-ssh")
check(shows("ssh:github.com") and shows("SHA256:abc"), "key listed")
click("ssh-import")
inputs()[1].props.onChange("1234")
inputs()[1].props.onSubmit()
check(string.find(lastStream().cmd, "'ssh' 'import' '--pin-file'", 1, true) ~= nil, "import runs")
feed(lastStream(), { { type = "done", op = "ssh.import", imported = { "id_ed25519_sk_rk_x" }, skipped = { SSH_NAME } },
  { type = "end" } })
check(shows("Imported: ~/.ssh/id_ed25519_sk_rk_x"), "imported message")

click("ssh-new")
check(find("ssh-form") ~= nil, "form open")
local fields = inputs()
fields[1].props.onChange("bad..app")
click("ssh-form-create")
check(shows("without \"..\""), "invalid application refused before the PIN")
fields[1].props.onChange("github.com")
click("ssh-form-create")
inputs()[1].props.onChange("1234")
inputs()[1].props.onSubmit()
local create = lastStream()
check(string.find(create.cmd, "'ssh' 'create' '--pin-file'", 1, true) ~= nil, "create runs")
check(string.find(create.cmd, '"application":"github.com"', 1, true) ~= nil, "create options in JSON")
feed(create, { { type = "error", op = "ssh.create", code = "ssh-exists", detail = "ssh:github.com" }, { type = "end" } })
check(find("ssh-replace") ~= nil, "replace offered")
click("ssh-replace")
inputs()[1].props.onChange("1234")
inputs()[1].props.onSubmit()
check(string.find(lastStream().cmd, '"replace":true', 1, true) ~= nil, "replace asked for")
feed(lastStream(), { { type = "done", op = "ssh.create", name = "id_ed25519_sk_rk_github.com_new", host = "github.com",
  publicKey = "sk-ssh-ed25519@openssh.com BBBB ada@host" }, state(), { type = "end" } })
check(find("ssh-created") ~= nil and find("ssh-form") == nil, "created card")
click("ssh-created-copy")
check(clipboard == "sk-ssh-ed25519@openssh.com BBBB ada@host", "public key copied")
click("ssh-created-close")

click("ssh-host-" .. SSH_NAME)
check(string.find(lastStream().cmd, "'ssh' 'host' '" .. SSH_NAME .. "' 'on'", 1, true) ~= nil, "host on")
local on = state()
on.sshKeys[1].hostState = "on"
feed(lastStream(), { { type = "done", op = "ssh.host", name = SSH_NAME, host = "github.com", enabled = true }, on,
  { type = "end" } })
check(shows("ssh now uses this key for github.com."), "host enabled")
click("ssh-persist-" .. SSH_NAME)
local slider = nil
walk(tree, function(node)
  if node.kind == "slider" then
    slider = node
  end
end)
check(slider ~= nil, "reuse slider")
slider.props.onChange("30")
click("ssh-persist-apply-" .. SSH_NAME)
check(string.find(lastStream().cmd, "'ssh' 'persist' '" .. SSH_NAME .. "' '30'", 1, true) ~= nil, "persist runs")
feed(lastStream(), { { type = "done", op = "ssh.persist", name = SSH_NAME, host = "github.com", minutes = 30 },
  { type = "end" } })
check(shows("reused for 30 minutes"), "persist message")

click("ssh-delete-" .. SSH_NAME)
check(shows("can't be recovered"), "delete warning when armed")
click("ssh-delete-" .. SSH_NAME)
check(find("pin-dialog") ~= nil, "delete asks for the PIN")
inputs()[1].props.onChange("1234")
inputs()[1].props.onSubmit()
check(string.find(lastStream().cmd, "'ssh' 'delete' '--pin-file'", 1, true) ~= nil, "delete runs")
feed(lastStream(), { { type = "error", op = "ssh.delete", code = "ssh-not-on-key", detail = "~/.ssh/x" },
  { type = "end" } })
check(shows("nothing was deleted"), "not on key")

-- home-manager's ~/.ssh/config without the Include.
feed(lastStream(), { state({ sshInclude = "link" }) })
check(shows("programs.ssh.includes"), "include notice")

-- Keyboard.
onKey("ctrl+tab", true)
onKey("alt+i", true)
check(find("tab-gpg").props.selected == true, "Alt+I shows the OpenPGP tab")
check(string.find(lastStream().cmd, "'gpg' 'import'", 1, true) ~= nil, "Alt+I imports")
feed(lastStream(), { { type = "pid", pid = 13 } })
onClose()
local killed = false
for _, argv in ipairs(async) do
  if type(argv) == "table" and argv[1] == "kill" and argv[3] == "13" then
    killed = true
  end
end
check(killed, "closing stops what runs")
feed(lastStream(), { { type = "cancelled" }, { type = "end" } })

-- No hardware at all.
onOpen({})
local empty = state({ devices = {}, credentials = {}, sshKeys = {},
  fingerprint = { available = false, devices = {}, default = "" } })
empty.card = nil -- JSON null
feed(lastStream(), { empty, { type = "end" } })
check(shows("Plug in your security key") or shows("Conecte sua chave"), "empty state")
-- Hot plug: a key appears.
update()
feed(lastStream(), { { type = "probe", devices = { "/dev/hidraw1" } } })
check(string.find(lastStream().cmd, "'state'", 1, true) ~= nil, "a new key refreshes the state")

if failures > 0 then
  error(failures .. " check(s) failed")
end
print("panel test: all checks passed")
