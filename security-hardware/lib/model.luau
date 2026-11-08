--!nonstrict
-- Pure helpers for the panel: which tabs show, what an error code says, formatting.

local M = {}

M.TABS = { "fingerprint", "fido", "gpg", "ssh" }

M.FINGERS = {
  "right-thumb", "right-index-finger", "right-middle-finger", "right-ring-finger", "right-little-finger",
  "left-thumb", "left-index-finger", "left-middle-finger", "left-ring-finger", "left-little-finger",
}

-- The first FIDO device the helper reported, or nil.
function M.device(state)
  return if state ~= nil and state.devices ~= nil then state.devices[1] else nil
end

function M.hasResidentKeys(state)
  for _, device in ipairs(state.devices or {}) do
    if device.rk then
      return true
    end
  end
  return false
end

-- One tab per thing the hardware here can do, in this order:
--   fingerprint  a reader fprintd knows
--   fido         a key plugged in, or keys registered
--   gpg          an OpenPGP card
--   ssh          a key that keeps resident credentials, or resident copies in ~/.ssh
function M.tabs(state)
  local out = {}
  if state == nil then
    return out
  end
  local fp = state.fingerprint or {}
  if fp.available and #(fp.devices or {}) > 0 then
    table.insert(out, "fingerprint")
  end
  if M.device(state) ~= nil or #(state.credentials or {}) > 0 then
    table.insert(out, "fido")
  end
  if state.card ~= nil then
    table.insert(out, "gpg")
  end
  if M.hasResidentKeys(state) or #(state.sshKeys or {}) > 0 then
    table.insert(out, "ssh")
  end
  return out
end

function M.contains(list, value)
  for _, item in ipairs(list or {}) do
    if item == value then
      return true
    end
  end
  return false
end

-- The tab shown: the one picked while it still exists, else the first.
function M.currentTab(tabs, chosen)
  if M.contains(tabs, chosen) then
    return chosen
  end
  return tabs[1] or ""
end

function M.nextTab(tabs, current, by)
  if #tabs == 0 then
    return ""
  end
  local index = 1
  for i, tab in ipairs(tabs) do
    if tab == current then
      index = i
    end
  end
  return tabs[((index - 1 + by) % #tabs) + 1]
end

-- The helper's error codes that have their own text; the rest say "error.generic".
local KNOWN_ERRORS = {
  ["pin-required"] = true, ["pin-invalid"] = true, ["pin-blocked"] = true, ["timeout"] = true,
  ["no-device"] = true, ["no-card"] = true, ["no-pin"] = true, ["already-registered"] = true,
  ["not-target"] = true, ["write-failed"] = true, ["no-test-service"] = true, ["test-failed"] = true,
  ["import-failed"] = true, ["no-file"] = true, ["trust-failed"] = true, ["remove-failed"] = true,
  ["secret-on-disk"] = true, ["ssh-none"] = true, ["ssh-exists"] = true, ["ssh-file-exists"] = true,
  ["ssh-not-on-key"] = true, ["ssh-encrypted"] = true, ["ssh-damaged"] = true, ["ssh-invalid"] = true,
  ["ssh-config-edited"] = true, ["ssh-config-foreign"] = true, ["ssh-config-link"] = true,
  ["ssh-config-conflict"] = true, ["fp-in-use"] = true, ["fp-permission-denied"] = true,
  ["fp-no-device"] = true, ["fp-no-prints"] = true, ["fp-not-deleted"] = true, ["helper"] = true,
}

function M.errorText(code, detail)
  local key = if KNOWN_ERRORS[code] then code else "generic"
  return noctalia.tr("error." .. key, { detail = detail or "" })
end

-- gpg's own grouping: ten blocks of four, an extra space in the middle.
function M.formatFingerprint(fpr)
  local hex = string.upper(fpr or "")
  if #hex ~= 40 then
    return hex
  end
  local blocks = {}
  for i = 1, 40, 4 do
    table.insert(blocks, string.sub(hex, i, i + 3))
  end
  return table.concat(blocks, " ", 1, 5) .. "  " .. table.concat(blocks, " ", 6, 10)
end

function M.fingerLabel(finger)
  local short = string.gsub(finger or "", "%-finger$", "")
  return noctalia.tr("fingerprint.finger." .. short)
end

-- Long user IDs (64 hex digits from a random ID) shortened for a row.
function M.short(text, size)
  text = text or ""
  if #text <= size then
    return text
  end
  return string.sub(text, 1, size - 1) .. "…"
end

-- A button label with its keyboard shortcut after it.
function M.withKey(label, key)
  return label .. "  ·  " .. key
end

return M
