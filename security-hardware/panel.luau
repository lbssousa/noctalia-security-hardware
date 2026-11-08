--!nonstrict
-- Security hardware panel: one tab per thing the hardware here can do (fingerprint reader,
-- FIDO2 key for pam_u2f, OpenPGP card, resident SSH keys), shown only when it can.
--
-- Keyboard (capture_keys): Ctrl+Tab / Ctrl+Shift+Tab switch tabs, F5 refreshes, and each
-- action's Alt key is shown on its button. Escape always closes the panel (the shell keeps it).
-- Everything goes through the noctalia-security-hw helper (lib/helper.luau).

local S = require("./lib/store.luau")
local W = require("./lib/widgets.luau")
local model = require("./lib/model.luau")

local TABS = {
  fingerprint = require("./tabs/fingerprint.luau"),
  fido = require("./tabs/fido.luau"),
  gpg = require("./tabs/gpg.luau"),
  ssh = require("./tabs/ssh.luau"),
}

local GLYPHS = { fingerprint = "fingerprint", fido = "key", gpg = "certificate", ssh = "terminal-2" }
local POLL_MS = 2000

local function visibleTabs()
  return model.tabs(S.state)
end

local function currentTab()
  return model.currentTab(visibleTabs(), S.chosenTab)
end

local function selectTab(tab)
  if tab ~= "" and tab ~= currentTab() then
    S.chosenTab = tab
    S.armed = ""
    S.render()
  end
end

local function pinDialog()
  local spec = S.pin
  local device = model.device(S.state)
  local rows = {
    ui.row({ gap = 10, align = "center" }, {
      ui.glyph({ name = "lock", size = 22, color = "primary" }),
      ui.label({ text = spec.title, fontSize = 15, fontWeight = "bold", flexGrow = 1, maxLines = 2 }),
    }),
  }
  if spec.detail ~= nil and spec.detail ~= "" then
    table.insert(rows, W.text(spec.detail, if spec.op == "ssh.delete" then "error" else "on_surface"))
  end
  if device ~= nil and device.pinRetries ~= nil and device.pinRetries >= 0 then
    table.insert(rows, W.hint(noctalia.tr("pin-retries", { count = device.pinRetries })))
  end
  table.insert(rows, ui.input({
    key = "pin-" .. tostring(S.pinKey),
    value = "",
    placeholder = noctalia.tr("pin-placeholder"),
    password = true,
    focus = true,
    flexGrow = 1,
    onChange = function(value)
      S.pinValue = value or ""
    end,
    onSubmit = function()
      S.submitPin()
    end,
  }))
  if spec.error ~= nil then
    table.insert(rows, W.text(spec.error, "error"))
  end
  table.insert(rows, W.hint(noctalia.tr("pin-touch")))
  table.insert(rows, W.buttons({
    ui.button({ text = noctalia.tr("cancel"), variant = "outline", onClick = S.closePin }),
    ui.button({ text = noctalia.tr("continue"), variant = if spec.op == "ssh.delete" then "destructive" else "primary",
      onClick = S.submitPin }),
  }))
  return W.card("pin-dialog", rows, if spec.op == "ssh.delete" then "error" else nil)
end

local function emptyState()
  if S.helperFailed then
    return { W.text(noctalia.tr("error.helper"), "error") }
  end
  if S.state == nil then
    return { W.text(noctalia.tr("working"), "on_surface_variant") }
  end
  return {
    ui.column({ gap = 8, align = "center", paddingV = 40 }, {
      ui.glyph({ name = "usb", size = 40, color = "on_surface_variant" }),
      ui.label({ text = noctalia.tr("connect"), fontSize = 15, fontWeight = "bold" }),
      ui.label({ text = noctalia.tr("connect-hint"), color = "on_surface_variant", maxLines = 3, textAlign = "center" }),
    }),
  }
end

function render()
  if not S.open then
    return
  end
  local tabs = visibleTabs()
  local tab = currentTab()
  local header = ui.row({ gap = 10, align = "center" }, {
    ui.glyph({ name = "shield-lock", size = 26, color = "primary" }),
    ui.label({ text = noctalia.tr("title"), fontSize = 18, fontWeight = "bold", flexGrow = 1 }),
    ui.button({ glyph = "refresh", variant = "ghost", controlSize = "sm", tooltip = noctalia.tr("refresh") .. "  F5",
      enabled = not S.loading and not S.isBusy(), onClick = S.refresh }),
  })
  local children = { header }
  if #tabs > 1 then
    local bar = {}
    for _, name in ipairs(tabs) do
      table.insert(bar, ui.button({
        key = "tab-" .. name,
        text = noctalia.tr("tab." .. name),
        glyph = GLYPHS[name],
        variant = "ghost",
        selected = name == tab,
        controlSize = "sm",
        flexGrow = 1,
        onClick = function()
          selectTab(name)
        end,
      }))
    end
    table.insert(children, ui.row({ gap = 4 }, bar))
  end
  local content
  if S.pin ~= nil then
    content = { pinDialog() }
  elseif tab == "" then
    content = emptyState()
  else
    content = TABS[tab].build()
  end
  table.insert(children, ui.scroll({ key = "content-" .. tab, gap = 12, flexGrow = 1 }, content))
  table.insert(children, ui.label({ text = noctalia.tr("keys"), color = "on_surface_variant", fontSize = 11,
    maxLines = 2 }))
  panel.render(ui.column({ padding = 16, gap = 12, align = "stretch" }, children))
end

S.render = render
S.afterState = function()
  TABS.fingerprint.load(false)
end

noctalia.setUpdateInterval(POLL_MS)

function update()
  if S.open then
    S.probe()
  end
end

function onKey(chord, pressed)
  if not pressed or not S.open then
    return
  end
  if S.pin ~= nil then
    return
  end
  if chord == "f5" then
    S.refresh()
  elseif chord == "ctrl+tab" then
    selectTab(model.nextTab(visibleTabs(), currentTab(), 1))
  elseif chord == "ctrl+shift+tab" then
    selectTab(model.nextTab(visibleTabs(), currentTab(), -1))
  else
    -- Each action's key works from any tab: it shows its own tab first.
    local owners = {
      ["alt+r"] = "fido",
      ["alt+i"] = "gpg",
      ["alt+s"] = "ssh",
    }
    local owner = owners[chord]
    if owner ~= nil and model.contains(visibleTabs(), owner) then
      selectTab(owner)
      TABS[owner].key(chord)
    elseif TABS[currentTab()] ~= nil then
      TABS[currentTab()].key(chord)
    end
  end
end

function onOpen(_context)
  S.open = true
  S.reset()
  render()
  S.refresh()
end

function onClose()
  S.open = false
  -- Nothing keeps running once the panel is gone: release the reader, stop pamu2fcfg,
  -- ssh-keygen or pamtester, forget PINs and half-filled forms.
  S.reset()
end
