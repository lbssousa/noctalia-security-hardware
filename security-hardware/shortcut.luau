--!nonstrict
-- Control-center tile that opens the security hardware panel.

shortcut.setLabel(noctalia.tr("title"))
shortcut.setIcon("fingerprint")
shortcut.setActive(false)
shortcut.setEnabled(true)

function onClick()
  noctalia.togglePanel("lbssousa/security-hardware:panel")
end
