--!nonstrict
-- Resident SSH keys: copy them from the security key into ~/.ssh, make new ones, remove a copy or
-- delete a key from the security key for good, and set ssh up for the git host a key names.

local S = require("../lib/store.luau")
local W = require("../lib/widgets.luau")
local model = require("../lib/model.luau")

local M = {}
local TAB = "ssh"
local ALGORITHMS = { "ed25519-sk", "ecdsa-sk" }

local function names(list)
  local out = {}
  for _, name in ipairs(list or {}) do
    table.insert(out, "~/.ssh/" .. name)
  end
  return table.concat(out, ", ")
end

function M.import()
  if model.device(S.state) == nil then
    return
  end
  S.withPin({
    tab = TAB,
    op = "ssh.import",
    title = noctalia.tr("ssh.import"),
    detail = noctalia.tr("ssh.import-detail"),
    args = function(pinPath)
      return if pinPath then { "ssh", "import", "--pin-file", pinPath } else { "ssh", "import" }
    end,
    handlers = {
      done = function(event)
        local parts = {}
        if #(event.imported or {}) > 0 then
          table.insert(parts, noctalia.tr("ssh.imported", { names = names(event.imported) }))
        end
        if #(event.skipped or {}) > 0 then
          table.insert(parts, noctalia.tr("ssh.skipped", { names = names(event.skipped) }))
        end
        return table.concat(parts, "\n")
      end,
    },
  })
end

function M.openForm()
  if model.device(S.state) == nil or S.isBusy() then
    return
  end
  local defaults = S.state.sshDefaults or {}
  S.ssh.formKey = (S.ssh.formKey or 0) + 1
  S.ssh.form = {
    algorithm = 1,
    application = "",
    user = defaults.user or "",
    comment = defaults.comment or "",
    verify = true,
    touch = true,
    problem = "",
  }
  S.ssh.created = nil
  S.ssh.replaceFor = nil
  S.render()
end

-- The same checks as the helper's create_problem(), to say what is wrong before asking for the PIN.
local function problem(form)
  local app, user, comment = form.application, form.user, form.comment
  if app ~= "" and (not string.match(app, "^[%w][%w%._@:%-]*$") or string.find(app, "..", 1, true)
      or not string.match(app, "[%w]$")) then
    return "ssh.invalid-application"
  end
  if user ~= "" and (not string.match(user, "^[%w][%w%._@%-]*$") or string.find(user, "..", 1, true)
      or not string.match(user, "[%w]$")) then
    return "ssh.invalid-user"
  end
  if #comment > 128 or string.find(comment, "[^\32-\126]") then
    return "ssh.invalid-comment"
  end
  return ""
end

local function create(options)
  S.withPin({
    tab = TAB,
    op = "ssh.create",
    title = noctalia.tr(if options.replace then "ssh.replace" else "ssh.create-key"),
    detail = noctalia.tr("ssh.create-detail"),
    args = function(pinPath)
      local json = noctalia.json.encode(options)
      return if pinPath then { "ssh", "create", "--pin-file", pinPath, json } else { "ssh", "create", json }
    end,
    handlers = {
      done = function(event)
        S.ssh.form = nil
        S.ssh.replaceFor = nil
        S.ssh.created = { name = event.name, publicKey = event.publicKey or "", host = event.host or "" }
        return nil
      end,
      error = function(event)
        if event.code == "ssh-exists" then
          S.ssh.replaceFor = options
          return noctalia.tr("error.ssh-exists", { detail = event.detail })
        elseif event.code == "ssh-invalid" and S.ssh.form ~= nil then
          S.ssh.form.problem = "ssh.invalid-" .. (event.detail or "")
        end
        return nil
      end,
    },
  })
end

function M.submitForm()
  local form = S.ssh.form
  if form == nil or S.isBusy() then
    return
  end
  form.problem = problem(form)
  if form.problem ~= "" then
    S.render()
    return
  end
  create({
    algorithm = ALGORITHMS[form.algorithm],
    application = form.application,
    user = form.user,
    comment = form.comment,
    verify = form.verify,
    touch = form.touch,
    replace = false,
  })
end

local function host(entry, enable)
  S.run(TAB, "ssh.host", { "ssh", "host", entry.name, if enable then "on" else "off" }, {
    done = function(event)
      return noctalia.tr(if event.enabled then "ssh.host-enabled" else "ssh.host-disabled", { host = event.host })
    end,
  })
end

local function persist(entry, minutes)
  S.run(TAB, "ssh.persist", { "ssh", "persist", entry.name, tostring(minutes) }, {
    done = function(event)
      S.ssh.persistFor = ""
      if event.minutes == 0 then
        return noctalia.tr("ssh.persist-none", { host = event.host })
      end
      return noctalia.tr("ssh.persist-set", { host = event.host, minutes = event.minutes })
    end,
  })
end

local function removeCopy(entry)
  S.run(TAB, "ssh.remove", { "ssh", "remove", entry.name }, {
    done = function(event)
      return noctalia.tr("ssh.removed", { name = "~/.ssh/" .. event.name })
    end,
  })
end

local function deleteKey(entry)
  -- Deleting a credential always asks for the PIN (fido2-token reads it on stdin).
  S.askPin({
    tab = TAB,
    op = "ssh.delete",
    title = noctalia.tr("ssh.delete"),
    detail = noctalia.tr("ssh.delete-warning"),
    args = function(pinPath)
      return { "ssh", "delete", "--pin-file", pinPath, entry.name }
    end,
    handlers = {
      done = function(event)
        return noctalia.tr("ssh.deleted", { name = "~/.ssh/" .. event.name })
      end,
    },
  })
end

local function copy(text)
  noctalia.copyToClipboard(text, "text/plain")
  S.setMessage(TAB, noctalia.tr("ssh.copied"), false)
  S.render()
end

local function formNode()
  local form = S.ssh.form
  local k = tostring(S.ssh.formKey or 0)
  local rows = {
    ui.label({ text = noctalia.tr("ssh.create-title"), fontWeight = "bold" }),
    ui.row({ gap = 8, align = "center" }, {
      ui.label({ text = noctalia.tr("ssh.algorithm"), width = 130 }),
      ui.select({ options = ALGORITHMS, selectedIndex = form.algorithm - 1, flexGrow = 1, onChange = function(i)
        form.algorithm = (tonumber(i) or 0) + 1
        S.render()
      end }),
    }),
    W.hint(noctalia.tr("ssh.algorithm-hint")),
  }
  local function field(id, label, value, hint, placeholder)
    table.insert(rows, ui.row({ gap = 8, align = "center" }, {
      ui.label({ text = label, width = 130 }),
      ui.input({ key = "ssh-" .. id .. "-" .. k, value = value, placeholder = placeholder, flexGrow = 1,
        focus = id == "application",
        onChange = function(text)
          form[id] = text or ""
        end,
        onSubmit = function()
          M.submitForm()
        end }),
    }))
    if hint ~= nil then
      table.insert(rows, W.hint(hint))
    end
  end
  field("application", noctalia.tr("ssh.application"), form.application, noctalia.tr("ssh.application-hint"),
    "github.com")
  field("user", noctalia.tr("ssh.user"), form.user, noctalia.tr("ssh.user-hint"), nil)
  field("comment", noctalia.tr("ssh.comment"), form.comment, nil, "user@host")
  for _, flag in ipairs({ "verify", "touch" }) do
    table.insert(rows, ui.row({ gap = 8, align = "center" }, {
      ui.label({ text = noctalia.tr("ssh." .. flag), flexGrow = 1 }),
      ui.toggle({ checked = form[flag], onChange = function(value)
        form[flag] = value == "true"
        S.render()
      end }),
    }))
  end
  if not form.touch then
    table.insert(rows, W.hint(noctalia.tr("ssh.touch-off")))
  end
  if form.problem ~= "" then
    table.insert(rows, W.text(noctalia.tr(form.problem), "error"))
  end
  table.insert(rows, W.buttons({
    W.button("ssh-form-cancel", noctalia.tr("cancel"), { onClick = function()
      S.ssh.form = nil
      S.render()
    end }),
    W.button("ssh-form-create", noctalia.tr("ssh.create-key"), { glyph = "plus", variant = "primary",
      onClick = M.submitForm }),
  }))
  return W.card("ssh-form", rows)
end

local function createdNode()
  local created = S.ssh.created
  local rows = {
    W.text(noctalia.tr("ssh.created", { name = "~/.ssh/" .. created.name })),
    ui.label({ text = created.publicKey, fontFamily = "monospace", fontSize = 11, maxLines = 4 }),
  }
  local buttons = {
    W.button("ssh-created-close", noctalia.tr("close"), { onClick = function()
      S.ssh.created = nil
      S.render()
    end }),
    W.button("ssh-created-copy", noctalia.tr("ssh.copy"), { glyph = "copy", variant = "primary", onClick = function()
      copy(created.publicKey)
    end }),
  }
  if created.host ~= "" then
    table.insert(rows, W.hint(noctalia.tr("ssh.host-suggest", { host = created.host })))
  end
  table.insert(rows, W.buttons(buttons))
  return W.card("ssh-created", rows)
end

local function keyNode(entry, index)
  local id = entry.name
  local title = if entry.application ~= "" then entry.application else "ssh:"
  local rows = {
    ui.row({ gap = 8, align = "center" }, {
      ui.glyph({ name = "key", size = 18, color = "primary" }),
      ui.label({ text = title, fontWeight = "bold", flexGrow = 1, maxLines = 2 }),
      ui.label({ text = entry.type, color = "on_surface_variant", fontSize = 12 }),
    }),
  }
  if entry.user ~= "" then
    table.insert(rows, W.infoRow(noctalia.tr("ssh.user"), model.short(entry.user, 24)))
  end
  if entry.fingerprint ~= "" then
    table.insert(rows, ui.label({ text = entry.fingerprint, fontFamily = "monospace", fontSize = 11,
      color = "on_surface_variant", maxLines = 2 }))
  end
  table.insert(rows, W.hint("~/.ssh/" .. model.short(entry.name, 60)))
  if entry.host ~= "" then
    local state = entry.hostState
    if state == "on" then
      table.insert(rows, W.hint(noctalia.tr("ssh.host-on", { host = entry.host })))
    elseif state == "edited" or state == "foreign" then
      table.insert(rows, W.hint(noctalia.tr("error.ssh-config-edited",
        { detail = "~/.ssh/config.d/" .. entry.host .. ".conf" })))
    end
  end

  if S.armed == "ssh-delete-" .. id then
    table.insert(rows, W.text(noctalia.tr("ssh.delete-warning"), "error"))
  end

  if S.ssh.persistFor == id then
    table.insert(rows, W.text(noctalia.tr("ssh.persist-label", { host = entry.host })))
    table.insert(rows, ui.row({ gap = 8, align = "center" }, {
      ui.slider({ min = 0, max = 1440, step = 5, value = S.ssh.persistValue, flexGrow = 1, onChange = function(v)
        S.ssh.persistValue = math.floor(tonumber(v) or 0)
        S.render()
      end }),
      ui.label({ text = noctalia.tr("ssh.minutes", { minutes = S.ssh.persistValue }), width = 70 }),
    }))
    table.insert(rows, W.hint(noctalia.tr("ssh.persist-hint")))
    table.insert(rows, W.buttons({
      W.button("ssh-persist-cancel-" .. id, noctalia.tr("cancel"), { size = "sm", onClick = function()
        S.ssh.persistFor = ""
        S.render()
      end }),
      W.button("ssh-persist-apply-" .. id, noctalia.tr("ssh.apply"), { size = "sm", variant = "primary",
        onClick = function()
          persist(entry, S.ssh.persistValue)
        end }),
    }))
  end

  local buttons = {}
  if entry.publicKey ~= "" then
    table.insert(buttons, ui.button({ key = "ssh-copy-" .. id, glyph = "copy", variant = "ghost", controlSize = "sm",
      tooltip = noctalia.tr("ssh.copy"), onClick = function()
        copy(entry.publicKey)
      end }))
  end
  if entry.host ~= "" and (entry.hostState == "on" or entry.hostState == "off") then
    local on = entry.hostState == "on"
    table.insert(buttons, W.button("ssh-host-" .. id,
      noctalia.tr(if on then "ssh.host-disable" else "ssh.host-enable", { host = entry.host }),
      { size = "sm", variant = if on then "ghost" else "secondary", onClick = function()
        host(entry, not on)
      end }))
    if on and S.ssh.persistFor ~= id then
      table.insert(buttons, W.button("ssh-persist-" .. id,
        if (entry.persistMinutes or 0) > 0 then noctalia.tr("ssh.persist-on", { minutes = entry.persistMinutes })
          else noctalia.tr("ssh.persist-off"),
        { size = "sm", variant = "ghost", onClick = function()
          S.ssh.persistFor = id
          S.ssh.persistValue = entry.persistMinutes or 0
          S.render()
        end }))
    end
  end
  table.insert(buttons, ui.spacer({ flexGrow = 1 }))
  table.insert(buttons, W.confirmButton("ssh-remove-" .. id, noctalia.tr("ssh.remove-copy"),
    noctalia.tr("confirm-remove"), function()
      removeCopy(entry)
    end, { glyph = "x" }))
  if model.device(S.state) ~= nil and not entry.encrypted then
    table.insert(buttons, W.confirmButton("ssh-delete-" .. id, noctalia.tr("ssh.delete"),
      noctalia.tr("ssh.confirm-delete"), function()
        deleteKey(entry)
      end, { destructive = true }))
  end
  table.insert(rows, ui.row({ gap = 6, align = "center" }, buttons))
  return W.card("ssh-key-" .. id, rows, if S.armed == "ssh-delete-" .. id then "error" else nil)
end

function M.build()
  local state = S.state
  local device = model.device(state)
  local items = { W.heading(noctalia.tr("ssh.title"), noctalia.tr("ssh.subtitle")) }
  if state.sshInclude == "link" then
    table.insert(items, W.card("ssh-include", { W.text(noctalia.tr("error.ssh-config-link"), "error") }, "error"))
  end
  W.append(items, W.status(TAB))
  if S.ssh.replaceFor ~= nil and S.busy == nil then
    local options = S.ssh.replaceFor
    table.insert(items, W.buttons({
      W.button("ssh-replace-cancel", noctalia.tr("cancel"), { onClick = function()
        S.ssh.replaceFor = nil
        S.setMessage(TAB, nil)
        S.render()
      end }),
      W.button("ssh-replace", noctalia.tr("ssh.replace"), { variant = "destructive", onClick = function()
        local again = table.clone(options)
        again.replace = true
        create(again)
      end }),
    }))
  end
  if S.ssh.created ~= nil then
    table.insert(items, createdNode())
  end
  if S.ssh.form ~= nil then
    table.insert(items, formNode())
  elseif device ~= nil and device.rk then
    table.insert(items, W.buttons({
      W.button("ssh-new", noctalia.tr("ssh.create"), { glyph = "plus", shortcut = "Alt+N", onClick = M.openForm }),
      W.button("ssh-import", noctalia.tr("ssh.import"), { glyph = "download", variant = "primary", shortcut = "Alt+S",
        onClick = M.import }),
    }))
  end
  local keys = state.sshKeys or {}
  if #keys == 0 then
    table.insert(items, W.text(noctalia.tr("ssh.none-copied"), "on_surface_variant"))
  end
  for i, entry in ipairs(keys) do
    table.insert(items, keyNode(entry, i))
  end
  if #keys > 0 then
    table.insert(items, W.hint(noctalia.tr("ssh.touch-note")))
  end
  return items
end

function M.key(chord)
  if S.isBusy() then
    return
  end
  if chord == "alt+s" then
    M.import()
  elseif chord == "alt+n" then
    M.openForm()
  end
end

return M
