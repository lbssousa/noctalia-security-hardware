--!nonstrict
-- Fingerprint readers (fprintd): enroll, test and delete fingers, picking the reader when there
-- is more than one.

local S = require("../lib/store.luau")
local W = require("../lib/widgets.luau")
local helper = require("../lib/helper.luau")
local model = require("../lib/model.luau")

local M = {}
local TAB = "fingerprint"

local function readers()
  return (S.state and S.state.fingerprint and S.state.fingerprint.devices) or {}
end

local function reader()
  for _, device in ipairs(readers()) do
    if device.path == S.fp.selected then
      return device
    end
  end
  return nil
end

local function available()
  local out = {}
  for _, finger in ipairs(model.FINGERS) do
    if not model.contains(S.fp.enrolled, finger) then
      table.insert(out, finger)
    end
  end
  return out
end

-- The enrolled fingers of the reader picked; loaded after every state, once per reader.
function M.load(force)
  local fp = S.state and S.state.fingerprint
  if fp == nil or not fp.available then
    return
  end
  if reader() == nil then
    S.fp.selected = if fp.default ~= "" then fp.default elseif readers()[1] then readers()[1].path else ""
  end
  if S.fp.selected == "" or (S.fp.loadedFor == S.fp.selected and not force) then
    return
  end
  local path = S.fp.selected
  S.fp.loadedFor = path
  helper.run({ "fp", "list", path }, function(event)
    if event.type == "done" and path == S.fp.selected then
      S.fp.enrolled = event.enrolled or {}
    elseif event.type == "error" then
      S.fp.enrolled = {}
      S.setMessage(TAB, model.errorText(event.code, event.detail), true)
    end
    S.render()
  end)
end

local function scanText(status)
  if status == "started" then
    local device = reader()
    return noctalia.tr(if device and device.scanType == "swipe" then "fingerprint.status.swipe"
      else "fingerprint.status.touch")
  elseif string.find(status, "stage%-passed$") then
    return noctalia.tr("fingerprint.status.stage-passed")
  elseif string.find(status, "retry%-scan$") then
    return noctalia.tr("fingerprint.status.retry-scan")
  elseif string.find(status, "swipe%-too%-short$") then
    return noctalia.tr("fingerprint.status.swipe-too-short")
  elseif string.find(status, "finger%-not%-centered$") then
    return noctalia.tr("fingerprint.status.finger-not-centered")
  elseif string.find(status, "remove%-and%-retry$") then
    return noctalia.tr("fingerprint.status.remove-and-retry")
  elseif status == "verify-no-match" then
    return noctalia.tr("fingerprint.status.no-match")
  end
  return nil
end

local RESULTS = {
  ["enroll-duplicate"] = "fingerprint.status.duplicate",
  ["enroll-data-full"] = "fingerprint.status.data-full",
  ["enroll-disconnected"] = "fingerprint.status.disconnected",
  ["verify-disconnected"] = "fingerprint.status.disconnected",
  ["verify-no-match"] = "fingerprint.status.no-match",
  ["verify-timeout"] = "fingerprint.status.verify-timeout",
}

local function resultText(event)
  local key = RESULTS[event.code]
  if key ~= nil then
    return noctalia.tr(key)
  elseif string.sub(event.code or "", 1, 7) == "enroll-" then
    return noctalia.tr("fingerprint.status.enroll-failed")
  elseif string.sub(event.code or "", 1, 7) == "verify-" then
    return noctalia.tr("fingerprint.status.verify-failed")
  end
  return nil
end

function M.enroll()
  local finger = available()[S.fp.pickIndex]
  if finger == nil then
    return
  end
  S.fp.picking = false
  S.fp.done = 0
  S.fp.total = -1
  S.run(TAB, "fp.enroll", { "fp", "enroll", S.fp.selected, finger }, {
    busy = function(event)
      S.fp.total = event.stagesTotal or S.fp.total
      if string.find(event.status or "", "stage%-passed$") then
        S.fp.done += 1
      end
    end,
    done = function()
      return noctalia.tr("fingerprint.status.enroll-completed")
    end,
    error = resultText,
    finished = function()
      M.load(true)
    end,
  })
end

function M.verify()
  S.run(TAB, "fp.verify", { "fp", "verify", S.fp.selected }, {
    done = function(event)
      if event.finger ~= nil and event.finger ~= "" and event.finger ~= "any" then
        return noctalia.tr("fingerprint.status.match-finger", { finger = model.fingerLabel(event.finger) })
      end
      return noctalia.tr("fingerprint.status.match")
    end,
    error = resultText,
  })
end

local function delete(finger)
  S.run(TAB, "fp.delete", { "fp", "delete", S.fp.selected, finger }, {
    done = function()
      return noctalia.tr("fingerprint.status.deleted", { finger = model.fingerLabel(finger) })
    end,
    finished = function()
      M.load(true)
    end,
  })
end

function M.build()
  local items = { W.heading(noctalia.tr("fingerprint.title"), noctalia.tr("fingerprint.subtitle")) }
  local list = readers()
  if #list > 1 then
    local names, selected = {}, 0
    for i, device in ipairs(list) do
      table.insert(names, device.name)
      if device.path == S.fp.selected then
        selected = i - 1
      end
    end
    table.insert(items, ui.row({ gap = 8, align = "center" }, {
      ui.label({ text = noctalia.tr("fingerprint.reader") }),
      ui.select({ options = names, selectedIndex = selected, enabled = not S.isBusy(), flexGrow = 1,
        onChange = function(index)
          local device = list[(tonumber(index) or 0) + 1]
          if device ~= nil then
            S.fp.selected = device.path
            S.fp.enrolled = {}
            M.load(true)
          end
        end }),
    }))
  end

  local rows = {}
  if #S.fp.enrolled == 0 then
    table.insert(rows, W.text(noctalia.tr("fingerprint.none"), "on_surface_variant"))
  end
  for _, finger in ipairs(S.fp.enrolled) do
    table.insert(rows, ui.row({ key = "finger-" .. finger, gap = 8, align = "center" }, {
      ui.glyph({ name = "fingerprint", size = 18, color = "on_surface_variant" }),
      ui.label({ text = model.fingerLabel(finger), flexGrow = 1 }),
      W.confirmButton("fp-delete-" .. finger, noctalia.tr("remove"), noctalia.tr("confirm-remove"), function()
        delete(finger)
      end),
    }))
  end
  table.insert(items, W.card("fp-list", rows))

  local busy = S.busy
  if busy ~= nil and busy.op == "fp.enroll" then
    if S.fp.total > 0 then
      table.insert(items, ui.progress({ progress = math.min(1, S.fp.done / S.fp.total), height = 6 }))
      table.insert(items, W.hint(noctalia.tr("fingerprint.stages", { done = S.fp.done, total = S.fp.total })))
    end
  end
  if busy ~= nil and busy.tab == TAB and busy.status ~= "" then
    local text = scanText(busy.status)
    if text ~= nil then
      table.insert(items, ui.row({ gap = 8, align = "center" }, {
        ui.glyph({ name = "fingerprint", size = 20, color = "primary" }),
        ui.label({ text = text, color = "primary", flexGrow = 1 }),
        ui.button({ text = noctalia.tr("cancel"), variant = "outline", controlSize = "sm", onClick = S.cancel }),
      }))
    end
  else
    W.append(items, W.status(TAB))
  end

  if S.fp.picking then
    local choices = {}
    for _, finger in ipairs(available()) do
      table.insert(choices, model.fingerLabel(finger))
    end
    table.insert(items, ui.row({ gap = 8, align = "center" }, {
      ui.select({ options = choices, selectedIndex = S.fp.pickIndex - 1, flexGrow = 1, onChange = function(index)
        S.fp.pickIndex = (tonumber(index) or 0) + 1
        S.render()
      end }),
      W.button("fp-enroll-start", noctalia.tr("fingerprint.enroll"), { variant = "primary", onClick = M.enroll }),
      W.button("fp-enroll-cancel", noctalia.tr("cancel"), { onClick = function()
        S.fp.picking = false
        S.render()
      end }),
    }))
  elseif busy == nil then
    table.insert(items, W.buttons({
      W.button("fp-verify", noctalia.tr("fingerprint.verify"), { enabled = #S.fp.enrolled > 0, onClick = M.verify,
        shortcut = "Alt+T" }),
      W.button("fp-add", noctalia.tr("fingerprint.add"), { glyph = "plus", variant = "primary",
        enabled = #available() > 0, shortcut = "Alt+N", onClick = function()
          S.fp.picking = true
          S.fp.pickIndex = 1
          S.render()
        end }),
    }))
  end
  return items
end

-- Keyboard: Alt+N picks a finger to add, Alt+T tests.
function M.key(chord)
  if S.isBusy() then
    return
  end
  if chord == "alt+n" and #available() > 0 then
    S.fp.picking = true
    S.fp.pickIndex = 1
    S.render()
  elseif chord == "alt+t" and #S.fp.enrolled > 0 then
    M.verify()
  end
end

return M
