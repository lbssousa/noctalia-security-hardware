--!nonstrict
-- The OpenPGP card: import (or update) its public key, link it to the card, trust it, or take it
-- out of the keyring again.

local S = require("../lib/store.luau")
local W = require("../lib/widgets.luau")
local model = require("../lib/model.luau")

local M = {}
local TAB = "gpg"

function M.import()
  local state = S.state
  if state.card == nil or #(state.card.fingerprints or {}) == 0 then
    return
  end
  if noctalia.getSetting("shell.offline_mode") == true then
    S.setMessage(TAB, noctalia.tr("gpg.offline"), true)
    S.render()
    return
  end
  S.run(TAB, "gpg.import", { "gpg", "import" }, {
    done = function(event)
      return noctalia.tr(if event.updated then "gpg.updated" else "gpg.imported")
    end,
  })
end

function M.importFile()
  local path = S.gpg.file
  if path == "" then
    return
  end
  S.run(TAB, "gpg.import-file", { "gpg", "import-file", path }, {
    done = function()
      return noctalia.tr("gpg.imported")
    end,
  })
end

function M.trust()
  S.run(TAB, "gpg.trust", { "gpg", "trust" }, {
    done = function()
      return noctalia.tr("gpg.trusted-done")
    end,
  })
end

local function remove()
  S.run(TAB, "gpg.remove", { "gpg", "remove" }, {
    done = function()
      return noctalia.tr("gpg.removed")
    end,
  })
end

function M.build()
  local state = S.state
  local card = state.card
  local items = { W.heading(noctalia.tr("gpg.title"), noctalia.tr("gpg.subtitle")) }
  local rows = {}
  local title = card.vendor ~= "" and card.vendor or "OpenPGP"
  if card.serial ~= "" then
    title ..= " · " .. noctalia.tr("gpg.serial", { serial = card.serial })
  end
  table.insert(rows, ui.label({ text = title, fontWeight = "bold" }))
  if card.holder ~= "" then
    table.insert(rows, W.infoRow(noctalia.tr("gpg.holder"), card.holder))
  end
  local fpr = (card.fingerprints or {})[1]
  if fpr ~= nil then
    table.insert(rows, ui.row({ gap = 8, align = "center" }, {
      ui.label({ text = noctalia.tr("gpg.fingerprint"), color = "on_surface_variant" }),
      ui.label({ text = model.formatFingerprint(fpr), fontFamily = "monospace", flexGrow = 1, maxLines = 2 }),
      ui.button({ glyph = "copy", variant = "ghost", controlSize = "sm", tooltip = noctalia.tr("copy"),
        onClick = function()
          noctalia.copyToClipboard(fpr, "text/plain")
          S.setMessage(TAB, noctalia.tr("copied"), false)
          S.render()
        end }),
    }))
  else
    table.insert(rows, W.text(noctalia.tr("gpg.no-key"), "on_surface_variant"))
  end
  if card.url ~= "" then
    table.insert(rows, W.infoRow(noctalia.tr("gpg.url"), card.url))
  end
  if fpr ~= nil then
    local stateKey = "gpg.state." .. (state.keyState or "missing")
    table.insert(rows, ui.row({ gap = 8, align = "center" }, {
      ui.glyph({ name = if state.keyState == "ready" then "circle-check" else "info-circle", size = 18,
        color = if state.keyState == "ready" then "primary" else "on_surface_variant" }),
      ui.label({ text = noctalia.tr(stateKey), flexGrow = 1, maxLines = 2 }),
    }))
    if state.trusted then
      table.insert(rows, ui.row({ gap = 8, align = "center" }, {
        ui.glyph({ name = "shield-check", size = 18, color = "primary" }),
        ui.label({ text = noctalia.tr("gpg.trusted"), flexGrow = 1 }),
      }))
    end
  end
  table.insert(items, W.card("gpg-card", rows))
  W.append(items, W.status(TAB))

  if fpr ~= nil then
    local keyState = state.keyState
    local buttons = {}
    if keyState == "ready" or keyState == "public" then
      table.insert(buttons, W.confirmButton("gpg-remove", noctalia.tr("gpg.remove"), noctalia.tr("gpg.confirm-remove"),
        remove, { size = "md" }))
    end
    if keyState ~= "missing" and keyState ~= "none" and not state.trusted then
      table.insert(buttons, W.button("gpg-trust", noctalia.tr("gpg.trust"), { shortcut = "Alt+T", onClick = M.trust }))
    end
    local importKey = if keyState == "ready" then "gpg.update" elseif keyState == "public" then "gpg.link"
      else "gpg.import"
    table.insert(buttons, W.button("gpg-import", noctalia.tr(importKey), { glyph = "cloud-download",
      variant = "primary", shortcut = "Alt+I", onClick = M.import }))
    table.insert(items, W.buttons(buttons))
    if keyState ~= "ready" then
      table.insert(items, ui.row({ gap = 8, align = "center" }, {
        ui.input({ key = "gpg-file", value = S.gpg.file, placeholder = noctalia.tr("gpg.file-placeholder"),
          enabled = not S.isBusy(), flexGrow = 1,
          onChange = function(value)
            S.gpg.file = value or ""
          end,
          onSubmit = function()
            M.importFile()
          end }),
        W.button("gpg-import-file", noctalia.tr("gpg.import-file"), { glyph = "file-import", onClick = M.importFile }),
      }))
    end
  end
  return items
end

function M.key(chord)
  if S.isBusy() or S.state.card == nil then
    return
  end
  if chord == "alt+i" then
    M.import()
  elseif chord == "alt+t" and S.state.keyState ~= "missing" and not S.state.trusted then
    M.trust()
  end
end

return M
