# vendor/wireshark/

A **stripped portable Wireshark** bundled so TShark2MCP runs out of the box —
no Wireshark install, no `TSHARK_PATH`, no first-run download.

## Contents

Only what `tshark` + `capinfos` need to read and dissect pcap/pcapng files:

- `tshark.exe`, `capinfos.exe` — the two CLI tools this project calls
- `libwireshark.dll`, `libwiretap.dll`, `libwsutil.dll` — core libraries
- All remaining runtime DLLs (TLS, Kerberos, codecs, Lua, glib, zstd, …)
- `plugins/4.6/*.dll` — protocol dissectors
- Dissection data dirs: `diameter/`, `radius/`, `snmp/`, `tls/`, `wimaxasncp/`,
  `dtds/`, `protobuf/`, `tpncp/`, `generic/`
- `COPYING.txt`, `README.txt` — Wireshark's own license & attribution

**Pruned** (not needed for CLI file analysis): `wireshark.exe` (GUI), all
`Qt6*.dll` + Qt plugin dirs (`platforms/`, `styles/`, `imageformats/`,
`iconengines/`, `multimedia/`, `networkinformation/`), `opengl32sw.dll`,
`dxcompiler.dll`, `d3dcompiler_47.dll`, `WinSparkle.dll`, `translations/`,
`Wireshark User's Guide/`, `extcap/`, and standalone tools not used here
(`editcap`, `mergecap`, `rawshark`, `sharkd`, `dumpcap`, …).

Source: official **Wireshark 4.6.0** Windows build, unmodified binaries.

## License (important)

Wireshark is **GPL-2.0-or-later** (`wireshark/COPYING.txt`). The binaries here
are redistributed verbatim from an official build, with Wireshark's own
`COPYING.txt` and `README.txt` retained alongside.

TShark2MCP itself is **MIT** (`/LICENSE`). It does **not** link to Wireshark
code — it invokes `tshark` / `capinfos` as separate subprocesses. That is
"mere aggregation", so bundling these GPL binaries does **not** change
TShark2MCP's license. Source for Wireshark is available at
<https://www.wireshark.org/>.

## Used by

`src/tshark_mcp/config.py::_find_bundled_dir()` locates this directory relative
to the package and `resolve_tshark_paths()` prefers it (after an explicit
`TSHARK_PATH` override, before any system Wireshark).

## Regenerating / updating

From a standard Wireshark install (here `C:\Program Files\Wireshark`):

```powershell
$src = "C:\Program Files\Wireshark"
$dst = "<repo>\TShark2MCP\vendor\wireshark"
robocopy $src $dst /E /NFL /NDL /NJH `
  /XF Qt6*.dll opengl32sw.dll dxcompiler.dll dxil.dll d3dcompiler_47.dll WinSparkle.dll `
       Wireshark.exe captype.exe dumpcap.exe editcap.exe mergecap.exe mmdbresolve.exe `
       randpkt.exe rawshark.exe reordercap.exe sharkd.exe text2pcap.exe uninstall-wireshark.exe `
  /XD platforms styles imageformats iconengines multimedia networkinformation `
       translations extcap "Wireshark User's Guide" profiles
```

Resulting tree is ~155 MB. Validate with `tshark.exe --version` and a real pcap
before committing.
