--!nonstrict
-- FIDO2/U2F keys for pam_u2f: register the key plugged in where sudo and polkit read keys,
-- remove registrations, test the key against the lock screen's PAM service.

local S = require("../lib/store.luau")
local W = require("../lib/widgets.luau")
local model = require("../lib/model.luau")

local M = {}
local TAB = "fido"

local NOTICES = {
  ["no-pam"] = "fido.target.no-pam",
  ["other-file"] = "fido.target.other-file",
  ["mixed"] = "fido.target.mixed",
}

local function canRegister()
  local state = S.state
  local device = model.device(state)
  return device ~= nil and state.target ~= nil and state.target.kind == "own"
    and not (state.pinRequired and not device.clientPin)
end

function M.register()
  if not canRegister() then
    return
  end
  local first = #(S.state.credentials or {}) == 0
  S.withPin({
    tab = TAB,
    op = "fido.register",
    title = noctalia.tr("fido.register"),
    detail = noctalia.tr("fido.register-detail"),
    args = function(pinPath)
      return if pinPath then { "fido", "register", "--pin-file", pinPath } else { "fido", "register" }
    end,
    handlers = {
      done = function()
        return noctalia.tr(if first then "fido.registered-first" else "fido.registered")
      end,
    },
  })
end

function M.test()
  S.run(TAB, "fido.test", { "fido", "test" }, {
    done = function()
      return noctalia.tr("fido.test-ok")
    end,
  })
end

local function remove(handle)
  S.run(TAB, "fido.remove", { "fido", "remove", handle }, {
    done = function()
      return noctalia.tr("fido.removed")
    end,
  })
end

function M.build()
  local state = S.state
  local items = { W.heading(noctalia.tr("fido.title"), noctalia.tr("fido.subtitle")) }
  local device = model.device(state)

  local target = state.target or { kind = "own", path = "" }
  local notice = NOTICES[target.kind]
  if notice ~= nil then
    table.insert(items, W.card("fido-target", {
      W.text(noctalia.tr(notice, { path = target.path, count = tostring(state.otherCount or 0) }), "error"),
    }, "error"))
  elseif device ~= nil and state.pinRequired and not device.clientPin then
    table.insert(items, W.card("fido-no-pin", { W.text(noctalia.tr("error.no-pin"), "error") }, "error"))
  end

  if device ~= nil then
    local details = { device.name }
    if device.clientPin and device.pinRetries ~= nil and device.pinRetries >= 0 then
      table.insert(details, noctalia.tr("pin-retries", { count = device.pinRetries }))
    end
    table.insert(items, ui.row({ gap = 8, align = "center" }, {
      ui.glyph({ name = "usb", size = 18, color = "on_surface_variant" }),
      ui.label({ text = table.concat(details, " · "), color = "on_surface_variant", flexGrow = 1, maxLines = 2 }),
    }))
  end

  local rows = {}
  local credentials = state.credentials or {}
  if #credentials == 0 then
    table.insert(rows, W.text(noctalia.tr("fido.none"), "on_surface_variant"))
  end
  for i, credential in ipairs(credentials) do
    local label = noctalia.tr(if credential.unused then "fido.credential-unused" else "fido.credential",
      { index = i, label = credential.label })
    table.insert(rows, ui.row({ key = "cred-" .. credential.handle, gap = 8, align = "center" }, {
      ui.glyph({ name = "key", size = 18, color = if credential.unused then "on_surface_variant" else "primary" }),
      ui.label({ text = label, flexGrow = 1, maxLines = 2,
        color = if credential.unused then "on_surface_variant" else "on_surface" }),
      W.confirmButton("fido-remove-" .. credential.handle, noctalia.tr("remove"), noctalia.tr("confirm-remove"),
        function()
          remove(credential.handle)
        end),
    }))
  end
  table.insert(items, W.card("fido-list", rows))
  if target.kind == "own" then
    table.insert(items, W.hint(noctalia.tr("fido.authfile", { path = target.path })))
  end

  W.append(items, W.status(TAB))
  local buttons = {}
  if state.testService ~= nil and state.testService ~= "" then
    table.insert(buttons, W.button("fido-test", noctalia.tr("fido.test"), {
      enabled = device ~= nil and #credentials > 0, shortcut = "Alt+T", onClick = M.test,
      tooltip = noctalia.tr("fido.test-detail", { service = state.testService }) }))
  end
  table.insert(buttons, W.button("fido-register",
    noctalia.tr(if #credentials == 0 then "fido.register" else "fido.register-another"),
    { glyph = "plus", variant = "primary", enabled = canRegister(), shortcut = "Alt+R", onClick = M.register }))
  table.insert(items, W.buttons(buttons))
  return items
end

function M.key(chord)
  if S.isBusy() then
    return
  end
  if chord == "alt+r" then
    M.register()
  elseif chord == "alt+t" and S.state.testService ~= "" and model.device(S.state) ~= nil then
    M.test()
  end
end

return M
