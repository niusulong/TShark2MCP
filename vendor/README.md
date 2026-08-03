# vendor/wireshark/

A **stripped portable Wireshark** bundled so TShark2MCP runs out of the box —
no Wireshark install, no `TSHARK_PATH`, no first-run download.

## Contents

Only what `tshark` + `capinfos` need to read and dissect pcap/pcapng files:

- `tshark.exe`, `capinfos.exe` — the two CLI tools this project calls
- `libwireshark.dll`, `libwiretap.dll`, `libwsutil.dll` — core libraries
- All remaining runtime DLLs (TLS, Kerberos, Lua, glib, zstd, …)
- `plugins/4.6/*.dll` — protocol dissectors
- Dissection data dirs: `diameter/`, `radius/`, `tls/`, `wimaxasncp/`, `dtds/`,
  `protobuf/`, `tpncp/`, `generic/`
- `COPYING.txt`, `README.txt` — Wireshark's own license & attribution

**Pruned** (not needed for CLI file analysis): `wireshark.exe` (GUI), all
`Qt6*.dll` + Qt plugin dirs (`platforms/`, `styles/`, `imageformats/`,
`iconengines/`, `multimedia/`, `networkinformation/`), `opengl32sw.dll`,
`dxcompiler.dll`, `d3dcompiler_47.dll`, `WinSparkle.dll`, `translations/`,
`Wireshark User's Guide/`, `extcap/`, and standalone tools not used here
(`editcap`, `mergecap`, `rawshark`, `sharkd`, `dumpcap`, …). Also pruned:
media voice/FFmpeg codecs — `avcodec`/`avformat`/`avutil`/`swscale`/`swresample`,
`opus`, `libilbc`, `libspandsp`, `libspeexdsp`, `libsbc`, `libopencore-amrnb`,
`libbcg729`, plus the codec plugins under `plugins/4.6/codecs/` (`g722`, `g726`,
`g729`, `ilbc`, `opus_dec`, `sbc`). These only *decode* RTP/media payloads,
which the 5 MCP tools never do; protocol **dissection** is unaffected (verified
against 4 pcaps incl. a 15 MB multi-protocol capture). Also pruned `snmp/`
(MIB files, 18 MB): SNMP *name resolution* needs these, but the tools never
enable name resolution (`-N`), so SNMP still dissects as raw OIDs — dissector
registration verified intact via `tshark -G protocols`.

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
       avcodec-61.dll avformat-61.dll avutil-59.dll swscale-8.dll swresample-5.dll `
       opus.dll libilbc-2.dll libspandsp-2.dll libspeexdsp.dll libsbc-1.dll libopencore-amrnb-0.dll libbcg729.dll `
       Wireshark.exe captype.exe dumpcap.exe editcap.exe mergecap.exe mmdbresolve.exe `
       randpkt.exe rawshark.exe reordercap.exe sharkd.exe text2pcap.exe uninstall-wireshark.exe `
  /XD platforms styles imageformats iconengines multimedia networkinformation `
       translations extcap "Wireshark User's Guide" profiles codecs snmp
```

The `/XD codecs` drops `plugins/4.6/codecs/` (the voice-codec dissectors that
depend on the pruned codec DLLs); `/XD snmp` drops the MIB files. Resulting
tree is ~118 MB. Validate with `tshark.exe --version` and a real pcap before
committing.
