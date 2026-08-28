# MIT-389 A.1: bare multi-digit immediate static scan for Keystone asm text.
#
# Background (MIT-371 root cause, fixed in MIT-373 8ed50b0):
#   Keystone Intel syntax parses BARE multi-digit numeric literals as HEX
#   ("sub T9, 24" assembles to sub r?, 0x24 = 36, not 24). Every immediate
#   emitted into Keystone asm text must go through the imm()/hex() helpers
#   (explicit 0x prefix) or be a single-digit decimal (0-9, hex == decimal).
#   An idle SSE handler class bug ships silently when the offset formula
#   constants are wrong -- this scan is the regression gate.
#
# What it does:
#   Scan 1 (literal): the exact Select-String pattern from the dispatch
#     sheet -- informational; each hit classified against the unsafe set.
#   Scan 2 (semantic, decision): finds Keystone asm immediates that are
#     bare multi-digit decimals NOT routed through imm()/hex() and without
#     an explicit 0x prefix. Two bug shapes covered:
#       A) fully-inline asm instruction inside one string literal:
#            "    sub T9, 24\n"
#       B) operand tail emitted via concatenation:
#            o += ... + r64(t_[9]) + ", 24\n";      (comma+number fragment)
#            o += ... + ", " + 24 + "\n";           (numeric C++ literal)
#     Any unsafe hit = FAIL.
#     Single-digit decimals (0-9: hex == decimal) and explicit 0x forms are
#     SAFE per the dispatch sheet.
#
# Exit codes: 0 = clean (no unsafe hits); 1 = unsafe hit(s) found; 2 = tooling error.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\verifier\static_scan_bare_immediates.ps1
#   powershell ... -TargetFile <path>   # default: vm\regvm\runtime\src\asmgen.cpp

param(
    [string]$TargetFile = ""
)

$ErrorActionPreference = "Stop"

$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)   # scripts\verifier -> repo root
if ($TargetFile -eq "") { $TargetFile = Join-Path $repo "vm\regvm\runtime\src\asmgen.cpp" }
if (-not (Test-Path $TargetFile)) {
    Write-Output "[static-scan] FAIL tooling: target file not found: $TargetFile"
    exit 2
}
$fname = Split-Path -Leaf $TargetFile

# ---- Scan 2 (decision): semantic unsafe-immediate detection ---------------
# op start of an emitted asm instruction (leading whitespace inside literal).
$opStart = '^\s*(sub|shl|add|and|or|xor|cmp|mov|rol|ror|sar|shr)\s+'
# trailing escape sequences commonly appended to asm lines (\n, \t, ...).
$tailEsc = '(?:\\[nrt0"''])*'

$lines = Get-Content -Path $TargetFile
$unsafe = New-Object System.Collections.Generic.List[string]
$safeInline = New-Object System.Collections.Generic.List[string]

# per-line fragment cache: literal contents within one C++ line
function Get-Literals([string]$line) {
    $out = @()
    foreach ($m in [regex]::Matches($line, '"([^"]*)"')) { $out += $m.Groups[1].Value }
    return ,$out
}

for ($i = 0; $i -lt $lines.Count; $i++) {
    $line = $lines[$i]
    $frags = Get-Literals $line

    # Shape A: fully-inline "<op> <reg>, <bare 2+ digit decimal>" in one literal
    foreach ($frag in $frags) {
        $m = [regex]::Match($frag, ($opStart + '([A-Za-z][A-Za-z0-9]*)\s*,\s*([0-9]+)\s*' + $tailEsc + '\s*$'))
        if ($m.Success) {
            # groups: 1 = op (from $opStart), 2 = reg, 3 = immediate
            $immText = $m.Groups[3].Value
            $val = [int64]$immText
            $desc = ("{0}:{1}: emitted asm ''...{2} {3}, {4}''" -f $fname, ($i + 1), $m.Groups[1].Value, $m.Groups[2].Value, $m.Groups[3].Value)
            if ($val -lt 10) {
                $safeInline.Add($desc + "  [SAFE: single-digit decimal, hex==decimal]")
            } else {
                $unsafe.Add($desc + ("  [UNSAFE shape A: bare decimal, keystone reads hex 0x{0:X} = {1}]" -f $val, $val))
            }
        }
    }

    # Shape B1: operand-tail fragment ", <bare 2+ digit decimal>" on a line that
    # also starts an asm op (realistic concat regression: op in one fragment,
    # immediate in the next)
    $lineHasOpStart = $false
    foreach ($frag in $frags) {
        if ([regex]::IsMatch($frag, $opStart)) { $lineHasOpStart = $true; break }
    }
    if ($lineHasOpStart) {
        foreach ($frag in $frags) {
            $m = [regex]::Match($frag, ('^\s*,\s*([0-9]+)\s*' + $tailEsc + '\s*$'))
            if ($m.Success) {
                $val = [int64]$m.Groups[1].Value
                $desc = ("{0}:{1}: operand-tail fragment '',{2}'' after asm op on same line" -f $fname, ($i + 1), $m.Groups[1].Value)
                if ($val -lt 10) {
                    $safeInline.Add($desc + "  [SAFE: single-digit decimal, hex==decimal]")
                } else {
                    $unsafe.Add($desc + ("  [UNSAFE shape B1: bare decimal operand, keystone reads hex 0x{0:X} = {1}]" -f $val, $val))
                }
            }
        }
        # Shape B2: numeric C++ literal concatenated into asm emission:
        #   ... + ", " + 24 + "\n"  ->  regex "+ 24 +" style on the raw line
        if ([regex]::IsMatch($line, '\+\s*[0-9]{2,}\s*\+') -and $line -match '"') {
            $unsafe.Add(("{0}:{1}: numeric C++ literal concatenated into asm emission (shape B2): {2}" -f $fname, ($i + 1), $line.Trim()))
        }
    }
}

$unsafeLines = @{}
foreach ($u in $unsafe) {
    if ($u -match ":(\d+):") { $unsafeLines[[int]$Matches[1]] = $true }
}

# ---- Scan 1 (literal dispatch-sheet pattern, informational + classified) --
$literalPattern = 'sub [^,]+, [0-9]{2,}|shl [^,]+, [0-9]{2,}|add [^,]+, 0x[0-9a-fA-F]+'
$literalHits = @(Select-String -Path $TargetFile -Pattern $literalPattern)
Write-Output ("[static-scan] Scan 1 (literal dispatch pattern) hits: {0}" -f $literalHits.Count)
foreach ($h in $literalHits) {
    $cls = "benign (no unsafe semantic match on this line)"
    if ($unsafeLines.ContainsKey($h.LineNumber)) { $cls = "UNSAFE (semantic match on same line)" }
    Write-Output ("  literal-hit {0}:{1} [{2}]: {3}" -f $fname, $h.LineNumber, $cls, $h.Line.Trim())
}

Write-Output ("[static-scan] Scan 2 (semantic) unsafe hits: {0}" -f $unsafe.Count)
foreach ($u in $unsafe) { Write-Output ("  UNSAFE {0}" -f $u) }
Write-Output ("[static-scan] Scan 2 safe inline immediates (0x-prefixed via imm()/hex() never appear; single-digit shown): {0}" -f $safeInline.Count)
foreach ($s in $safeInline) { Write-Output ("  safe {0}" -f $s) }

if ($unsafe.Count -gt 0) {
    Write-Output "[static-scan] RESULT: FAIL - bare multi-digit immediate(s) routed around imm()/hex() found"
    exit 1
}
Write-Output "[static-scan] RESULT: PASS - no bare multi-digit decimal immediates in emitted asm text"
exit 0
