$ErrorActionPreference = 'Stop'
$reviewRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$reviewOut = Join-Path $reviewRoot 'build\code_review_20260918'
$reviewVcvars = 'C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path -LiteralPath $reviewVcvars)) {
    throw "VS toolchain missing: $reviewVcvars (same requirement as scripts/build.bat)"
}
if (-not (Test-Path -LiteralPath (Join-Path $reviewRoot 'build\vm\regvm\wvmp_regvm.lib'))) {
    throw 'Run scripts/build.bat with the default Debug configuration first.'
}
New-Item -ItemType Directory -Force -Path $reviewOut | Out-Null

function Invoke-ReviewProbe {
    param([string]$Name, [string[]]$Includes, [string[]]$Sources, [string[]]$Libraries = @())
    $reviewArgs = @('/nologo', '/std:c++20', '/EHsc', '/MDd', '/utf-8', ('/Fe:' + $Name + '.exe'))
    $reviewArgs += $Includes | ForEach-Object { '/I"' + (Join-Path $reviewRoot $_) + '"' }
    $reviewArgs += $Sources | ForEach-Object { '"' + (Join-Path $reviewRoot $_) + '"' }
    $reviewArgs += $Libraries | ForEach-Object { '"' + (Join-Path $reviewRoot $_) + '"' }
    $reviewArgs += @('shell32.lib', 'ole32.lib')
    $reviewBatch = Join-Path $reviewOut ($Name + '_build.cmd')
    @('@echo off', ('call "' + $reviewVcvars + '" >nul'),
      ('cl ' + ($reviewArgs -join ' ')), 'exit /b %errorlevel%') |
        Set-Content -LiteralPath $reviewBatch -Encoding ascii
    & $reviewBatch
    if ($LASTEXITCODE -ne 0) { throw "$Name build failed: $LASTEXITCODE" }
    & (Join-Path $reviewOut ($Name + '.exe'))
    if ($LASTEXITCODE -ne 0) { throw "$Name execution failed: $LASTEXITCODE" }
}

Push-Location $reviewOut
try {
    $reviewCommonInc = @('common/include', 'framework/include', 'ir/include', 'vm/include',
                         'vm/regvm/isa/include')
    Invoke-ReviewProbe -Name review_probe -Includes ($reviewCommonInc + @(
        'passes/pe_loader/include', 'passes/pe_writer/src', 'passes/virtualize/include',
        'passes/crypt/include', 'vm/regvm/codecs/include', 'cli/include',
        '.deps/tomlplusplus-src/include')) -Sources @(
        'docs/code-review-2026-09-18/review_probe.cpp', 'common/src/bytes.cpp',
        'framework/src/registry.cpp', 'passes/pe_loader/src/pe_image.cpp',
        'passes/pe_writer/src/section_builder.cpp', 'passes/crypt/src/crypt_pass.cpp',
        'vm/regvm/codecs/src/xor_chain.cpp', 'vm/regvm/isa/src/blob.cpp', 'cli/src/config.cpp')
    Invoke-ReviewProbe -Name flags_probe -Includes ($reviewCommonInc + @(
        'vm/regvm/translator/include', 'vm/regvm/runtime/include')) -Sources @(
        'docs/code-review-2026-09-18/flags_probe.cpp') -Libraries @(
        'build/vm/regvm/wvmp_regvm.lib', 'build/vm/wvmp_vm.lib', 'build/ir/wvmp_ir.lib',
        'build/common/wvmp_common.lib', 'build/framework/wvmp_framework.lib',
        '.deps/keystone-build/llvm/lib/keystone.lib')
} finally {
    Pop-Location
}
