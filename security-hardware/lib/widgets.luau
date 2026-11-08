--!nonstrict
-- Building blocks shared by the tabs, in the style of the shell's own settings pages.

local S = require("./store.luau")

local W = {}

function W.heading(title, subtitle)
  return ui.column({ gap = 2 }, {
    ui.label({ text = title, fontSize = 16, fontWeight = "bold", color = "primary" }),
    ui.label({ text = subtitle, color = "on_surface_variant", maxLines = 3 }),
  })
end

function W.text(text, color, extra)
  local props = { text = text, color = color or "on_surface", maxLines = 6 }
  for k, v in pairs(extra or {}) do
    props[k] = v
  end
  return ui.label(props)
end

function W.hint(text)
  return ui.label({ text = text, color = "on_surface_variant", fontSize = 12, maxLines = 5 })
end

-- A rounded box around a group of rows.
function W.card(key, children, emphasis)
  return ui.column({
    key = key,
    gap = 8,
    padding = 12,
    radius = 12,
    fill = if emphasis == "error" then "error/0.10" else "surface_container",
    border = if emphasis == "error" then "error/0.5" else "outline_variant/0.6",
    borderWidth = 1,
  }, children)
end

function W.infoRow(label, value)
  return ui.row({ gap = 8, align = "center" }, {
    ui.label({ text = label, color = "on_surface_variant" }),
    ui.label({ text = value, color = "on_surface", flexGrow = 1, maxLines = 3 }),
  })
end

-- The tab's last message, or what the running operation waits for.
function W.status(tab)
  local busy = S.busy
  if busy ~= nil and busy.tab == tab then
    local text = if busy.stage == "touch" then noctalia.tr("touch") else noctalia.tr("working")
    return ui.row({ gap = 8, align = "center" }, {
      ui.glyph({ name = if busy.stage == "touch" then "hand-finger" else "loader-2", size = 18, color = "primary" }),
      ui.label({ text = text, color = "primary", flexGrow = 1, maxLines = 3 }),
      ui.button({ text = noctalia.tr("cancel"), variant = "outline", controlSize = "sm", onClick = S.cancel }),
    })
  end
  local message = S.messages[tab]
  if message == nil then
    return nil
  end
  return ui.row({ gap = 8, align = "center" }, {
    ui.glyph({ name = if message.error then "alert-triangle" else "circle-check", size = 18,
      color = if message.error then "error" else "primary" }),
    ui.label({ text = message.text, color = if message.error then "error" else "on_surface", flexGrow = 1,
      maxLines = 6 }),
  })
end

-- A button; `key` (e.g. "Alt+R") is shown after its label.
function W.button(id, text, opts)
  opts = opts or {}
  local label = if opts.shortcut then text .. "  " .. opts.shortcut else text
  return ui.button({
    key = id,
    text = label,
    glyph = opts.glyph,
    variant = opts.variant or "outline",
    controlSize = opts.size or "md",
    enabled = (opts.enabled ~= false) and not S.isBusy(),
    tooltip = opts.tooltip,
    onClick = opts.onClick,
  })
end

-- A destructive button that asks for a second press ("Remove?" in its place).
function W.confirmButton(id, text, confirmText, action, opts)
  opts = opts or {}
  local armed = S.armed == id
  return ui.button({
    key = id,
    text = if armed then confirmText else text,
    glyph = opts.glyph or "trash",
    variant = if armed or opts.destructive then "destructive" else "ghost",
    controlSize = opts.size or "sm",
    enabled = (opts.enabled ~= false) and not S.isBusy(),
    onClick = function()
      S.confirm(id, action)
    end,
  })
end

function W.append(list, item)
  if item ~= nil then
    table.insert(list, item)
  end
  return list
end

function W.buttons(children)
  return ui.row({ gap = 8, justify = "end", align = "center" }, children)
end

return W
