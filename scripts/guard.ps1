#requires -Version 5.1
<#
  dsh-system-guard · Windows 系统层唯一入口（脚本 helper）

  协议（见 CONTRACT.md §5）：
    powershell.exe -NoProfile -ExecutionPolicy Bypass -File guard.ps1 `
      -Action <action> -OutFile <result.json> [-Params <params.json>] [-TimeoutSec <n>]

  规则：
    - 业务数据只写 -OutFile（UTF-8 无 BOM，{ok,action,value} / {ok,action,error}）；
    - stdout 只留日志，不塞业务数据；
    - 退出码 0 = 结果文件已写（无论 ok 真假）；非 0 = helper 自身没写出结果；
    - 只做「用户显式触发」的写操作（备份/还原/删除垃圾/修复/还原点），
      其余动作严格只读；不删除系统文件本身。

  重要：本文件必须保存为 UTF-8 **with BOM**。Windows PowerShell 5.1 对无 BOM 的 .ps1
  会按系统 ANSI（本机 GBK）解析，中文注释会乱码甚至直接语法错误。
#>
[CmdletBinding()]
param(
  [string]$Action = '',
  [string]$OutFile = '',
  [string]$Params = '',
  [int]$TimeoutSec = 0
)

# ---------------------------------------------------------------------------
# 全局状态
# ---------------------------------------------------------------------------
$script:GuardVersion = '1.0.0'
$script:Warnings = New-Object 'System.Collections.Generic.List[string]'
$script:StartedAt = Get-Date
$script:Epoch = New-Object -TypeName System.DateTime -ArgumentList @(1970, 1, 1, 0, 0, 0, [System.DateTimeKind]::Utc)
$script:SystemRoot = $env:SystemRoot
$script:SystemDrive = $env:SystemDrive
$script:GuardParams = $null
$script:ExitCode = 0
$script:MaxOutputChars = 4000
$script:DefaultJunkMaxItems = 3000
$script:DefaultScanBudgetMs = 45000
if ([string]::IsNullOrWhiteSpace($script:SystemRoot)) { $script:SystemRoot = 'C:\Windows' }
if ([string]::IsNullOrWhiteSpace($script:SystemDrive)) { $script:SystemDrive = 'C:' }
$script:SystemRoot = $script:SystemRoot.TrimEnd('\')
$script:SystemDrive = $script:SystemDrive.TrimEnd('\').TrimEnd(':')

# 资源自律：把自己降到低优先级，避免分析与扫描时抢占用户机器的 CPU/IO
# （PS 5.1 的 Start-Process 没有 -Priority 参数，等价做法是在 helper 内部自降优先级）
try {
  $selfProcess = [System.Diagnostics.Process]::GetCurrentProcess()
  $selfProcess.PriorityClass = [System.Diagnostics.ProcessPriorityClass]::BelowNormal
} catch { }

# ---------------------------------------------------------------------------
# 基础工具
# ---------------------------------------------------------------------------

function Add-Warning {
  param([string]$Message)
  if ([string]::IsNullOrWhiteSpace($Message)) { return }
  if ($script:Warnings.Count -ge 200) { return }
  $script:Warnings.Add($Message)
}

# 抛出带 code 的受控错误；Node 侧会把它转成 Error.code
function Stop-GuardError {
  param([string]$Code, [string]$Message)
  $ex = New-Object System.Exception($Message)
  $ex.Data['guardCode'] = $Code
  throw $ex
}

function Get-GuardErrorCode {
  param($ErrorRecord)
  try {
    $ex = $null
    if ($null -ne $ErrorRecord) { $ex = $ErrorRecord.Exception }
    if ($null -ne $ex -and $null -ne $ex.Data -and $ex.Data.Contains('guardCode')) {
      return [string]$ex.Data['guardCode']
    }
  } catch { }
  return 'guard-error'
}

function Test-FileExists {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
  try { return [System.IO.File]::Exists($Path) } catch { return $false }
}

function Test-DirExists {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
  try { return [System.IO.Directory]::Exists($Path) } catch { return $false }
}

function Get-NormalizedPathKey {
  param([string]$Path)
  if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
  $p = $Path.Trim()
  try { $p = [System.IO.Path]::GetFullPath($p) } catch { }
  return $p.TrimEnd('\').ToLowerInvariant()
}

function Get-FileSizeSafe {
  param([string]$Path)
  try { return [long]([System.IO.FileInfo]::new($Path)).Length } catch { return [long]-1 }
}

function Get-FileLastWriteUtc {
  param([string]$Path)
  try { return [System.IO.File]::GetLastWriteTimeUtc($Path) } catch { return $null }
}

function Get-FileVersionText {
  param([string]$Path)
  try {
    $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($Path)
    if ($null -ne $vi) {
      if (-not [string]::IsNullOrWhiteSpace($vi.FileVersion)) { return ([string]$vi.FileVersion).Trim() }
      if (-not [string]::IsNullOrWhiteSpace($vi.ProductVersion)) { return ([string]$vi.ProductVersion).Trim() }
    }
  } catch { }
  return $null
}

function Get-FileSha256 {
  param([string]$Path)
  $sha = $null
  $fs = $null
  try {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    $hash = $sha.ComputeHash($fs)
    $sb = New-Object System.Text.StringBuilder
    foreach ($b in $hash) { [void]$sb.Append($b.ToString('x2')) }
    return $sb.ToString()
  } catch {
    return $null
  } finally {
    if ($null -ne $fs) { try { $fs.Dispose() } catch { } }
    if ($null -ne $sha) { try { $sha.Dispose() } catch { } }
  }
}

function ConvertTo-EpochMs {
  param($Value)
  if ($null -eq $Value) { return $null }
  try {
    $dt = $Value
    if ($dt -isnot [System.DateTime]) { $dt = [System.DateTime]$Value }
    if ($dt.Kind -ne [System.DateTimeKind]::Utc) { $dt = $dt.ToUniversalTime() }
    return [long](($dt - $script:Epoch).TotalMilliseconds)
  } catch { return $null }
}

function ConvertTo-IsoUtc {
  param($Value)
  if ($null -eq $Value) { return $null }
  try {
    $dt = $Value
    if ($dt -isnot [System.DateTime]) { $dt = [System.DateTime]$Value }
    return $dt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
  } catch { return $null }
}

function ConvertFrom-IsoToUtc {
  param($Value)
  if ($null -eq $Value) { return $null }
  $text = [string]$Value
  if ([string]::IsNullOrWhiteSpace($text)) { return $null }
  try {
    $dto = [System.DateTimeOffset]::Parse($text, [System.Globalization.CultureInfo]::InvariantCulture)
    return $dto.UtcDateTime
  } catch { return $null }
}

function Get-GuardParam {
  param([string]$Name, $Default = $null)
  if ($null -eq $script:GuardParams) { return $Default }
  try {
    $prop = $script:GuardParams.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $Default }
    if ($null -eq $prop.Value) { return $Default }
    return $prop.Value
  } catch { return $Default }
}

function Get-ObjectProp {
  param($Object, [string]$Name, $Default = $null)
  if ($null -eq $Object) { return $Default }
  try {
    $prop = $Object.PSObject.Properties[$Name]
    if ($null -eq $prop) { return $Default }
    if ($null -eq $prop.Value) { return $Default }
    return $prop.Value
  } catch { return $Default }
}

function ConvertTo-StringArray {
  param($Value)
  $list = New-Object 'System.Collections.Generic.List[string]'
  if ($null -eq $Value) { return $list.ToArray() }
  if ($Value -is [string]) {
    if (-not [string]::IsNullOrWhiteSpace($Value)) { $list.Add($Value) }
    return $list.ToArray()
  }
  try {
    foreach ($item in @($Value)) {
      if ($null -eq $item) { continue }
      $text = [string]$item
      if (-not [string]::IsNullOrWhiteSpace($text)) { $list.Add($text) }
    }
  } catch { }
  return $list.ToArray()
}

function Read-GuardParams {
  if ([string]::IsNullOrWhiteSpace($Params)) { return $null }
  if (-not (Test-FileExists $Params)) { Stop-GuardError -Code 'invalid-params' -Message ("参数文件不存在：" + $Params) }
  try {
    $text = [System.IO.File]::ReadAllText($Params)
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return ($text | ConvertFrom-Json)
  } catch {
    Stop-GuardError -Code 'invalid-params' -Message ("参数文件解析失败：" + $_.Exception.Message)
  }
}

# 写 UTF-8 无 BOM 的 JSON 结果文件（覆盖写，避免 BOM）
function Write-JsonFileNoBom {
  param([string]$Path, [string]$JsonText)
  $enc = New-Object System.Text.UTF8Encoding($false)
  $bytes = $enc.GetBytes($JsonText)
  $dir = $null
  try { $dir = [System.IO.Path]::GetDirectoryName($Path) } catch { $dir = $null }
  if (-not [string]::IsNullOrWhiteSpace($dir) -and -not (Test-DirExists $dir)) {
    [void][System.IO.Directory]::CreateDirectory($dir)
  }
  if ([System.IO.File]::Exists($Path)) {
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::Read)
    try {
      $fs.SetLength(0)
      $fs.Write($bytes, 0, $bytes.Length)
      $fs.Flush()
    } finally { $fs.Dispose() }
  } else {
    [System.IO.File]::WriteAllBytes($Path, $bytes)
  }
}

function Write-GuardResult {
  param([bool]$Ok, [string]$ActionName, $Value, [string]$Code, [string]$Message)
  if ($Ok) {
    $payload = [pscustomobject][ordered]@{ ok = $true; action = $ActionName; value = $Value }
  } else {
    $payload = [pscustomobject][ordered]@{
      ok = $false
      action = $ActionName
      error = [pscustomobject][ordered]@{ code = $Code; message = $Message }
    }
  }
  # 结果文件用 -Compress：Node 侧只做 JSON.parse，压缩能显著减少体积与序列化耗时
  $json = ConvertTo-Json -InputObject $payload -Depth 20 -Compress
  Write-JsonFileNoBom -Path $OutFile -JsonText $json
}

function Test-IsAdmin {
  try {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object System.Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
  } catch {
    Add-Warning ("检测管理员身份失败：" + $_.Exception.Message)
    return $false
  }
}

function Confirm-Admin {
  if (-not (Test-IsAdmin)) {
    Stop-GuardError -Code 'need-elevation' -Message '需要管理员权限，请在面板点「授予守护权限」'
  }
}

function Test-CommandAvailable {
  param([string]$Name)
  try {
    $cmd = Get-Command -Name $Name -ErrorAction Stop
    return ($null -ne $cmd)
  } catch { return $false }
}

# ---------------------------------------------------------------------------
# 固定磁盘 / 卷
# ---------------------------------------------------------------------------

function Get-FixedVolumes {
  $list = New-Object 'System.Collections.Generic.List[object]'
  try {
    $disks = @(Get-CimInstance -ClassName Win32_LogicalDisk -Filter 'DriveType=3' -ErrorAction Stop)
    foreach ($disk in $disks) {
      $total = [long]0
      $free = [long]0
      try { if ($null -ne $disk.Size) { $total = [long]$disk.Size } } catch { }
      try { if ($null -ne $disk.FreeSpace) { $free = [long]$disk.FreeSpace } } catch { }
      if ($total -le 0) { Add-Warning ("磁盘 " + $disk.DeviceID + " 容量读取失败，已跳过") ; continue }
      $list.Add([pscustomobject][ordered]@{
          id         = [string]$disk.DeviceID
          label      = [string]$disk.VolumeName
          fs         = [string]$disk.FileSystem
          totalBytes = $total
          freeBytes  = $free
          isSystem   = ([string]$disk.DeviceID).TrimEnd(':').ToLowerInvariant() -eq $script:SystemDrive.ToLowerInvariant()
        })
    }
  } catch {
    Add-Warning ("枚举固定磁盘失败：" + $_.Exception.Message)
  }
  return $list
}

function Get-UpdateWindowInfo {
  param([int]$Minutes = 1440)
  if ($Minutes -le 0) { $Minutes = 1440 }
  $latest = $null
  $latestHotfix = $null
  try {
    $items = @(Get-CimInstance -ClassName Win32_QuickFixEngineering -ErrorAction Stop)
    foreach ($item in $items) {
      $installed = Get-ObjectProp -Object $item -Name 'InstalledOn' -Default $null
      if ($null -eq $installed) { continue }
      $dt = $null
      try {
        if ($installed -is [System.DateTime]) { $dt = $installed }
        else { $dt = [System.DateTime]$installed }
      } catch { $dt = $null }
      if ($null -eq $dt) { continue }
      if ($dt.Year -lt 2000) { continue }
      if ($null -eq $latest -or $dt -gt $latest) {
        $latest = $dt
        $latestHotfix = [string](Get-ObjectProp -Object $item -Name 'HotFixID' -Default '')
      }
    }
  } catch {
    Add-Warning ("读取 Windows 更新记录失败：" + $_.Exception.Message)
  }
  if ($null -eq $latest) { return $null }
  $toUtc = $latest.ToUniversalTime()
  $fromUtc = $toUtc.AddMinutes(-1 * $Minutes)
  return [pscustomobject][ordered]@{
    fromUtc   = $fromUtc
    toUtc     = $toUtc
    fromIso   = (ConvertTo-IsoUtc $fromUtc)
    toIso     = (ConvertTo-IsoUtc $toUtc)
    fromMs    = (ConvertTo-EpochMs $fromUtc)
    toMs      = (ConvertTo-EpochMs $toUtc)
    latestMs  = (ConvertTo-EpochMs $toUtc)
    minutes   = $Minutes
    hotfixId  = $latestHotfix
  }
}

# ---------------------------------------------------------------------------
# 受保护文件清单（内置基线，写死在脚本里）
# 说明：路径按本机 SystemRoot 拼接；不存在的文件在解析时跳过并记 warning
#       （memory 类缺失属正常，例如本机未启用休眠）。
# ---------------------------------------------------------------------------

function Get-ProtectedManifestEntries {
  $entries = New-Object 'System.Collections.Generic.List[object]'
  $add = {
    param([string]$Id, [string]$Rel, [string]$Role, [string]$Group, [bool]$Critical)
    $entries.Add([pscustomobject][ordered]@{
        id = $Id; rel = $Rel; role = $Role; group = $Group; critical = $Critical
        path = (Join-Path $script:SystemRoot $Rel)
      })
  }
  $addAbs = {
    param([string]$Id, [string]$AbsPath, [string]$Role, [string]$Group, [bool]$Critical)
    $entries.Add([pscustomobject][ordered]@{
        id = $Id; rel = $null; role = $Role; group = $Group; critical = $Critical
        path = $AbsPath
      })
  }

  # —— 内核与图形内核 ——
  & $add 'kernel-ntoskrnl'      'System32\ntoskrnl.exe'      'core' 'kernel' $true
  & $add 'kernel-ntdll'         'System32\ntdll.dll'         'core' 'kernel' $true
  & $add 'kernel-kernel32'      'System32\kernel32.dll'      'core' 'kernel' $true
  & $add 'kernel-kernelbase'    'System32\kernelbase.dll'    'core' 'kernel' $true
  & $add 'kernel-hal'           'System32\hal.dll'           'core' 'kernel' $true
  & $add 'kernel-ci'            'System32\ci.dll'            'core' 'kernel' $true
  & $add 'kernel-win32k'        'System32\win32k.sys'        'core' 'kernel' $true
  & $add 'kernel-win32kbase'    'System32\win32kbase.sys'    'core' 'kernel' $true
  & $add 'kernel-win32kfull'    'System32\win32kfull.sys'    'core' 'kernel' $true

  # —— 引导 ——
  & $add 'boot-winload-efi'     'System32\winload.efi'       'core' 'boot' $true
  & $add 'boot-winload-exe'     'System32\winload.exe'       'core' 'boot' $true
  & $add 'boot-winresume-efi'   'System32\winresume.efi'     'core' 'boot' $true
  & $add 'boot-bootmgfw'        'boot\EFI\bootmgfw.efi'      'core' 'boot' $true
  & $add 'boot-bcd'             'boot\DVD\EFI\BCD'           'core' 'boot' $true
  & $add 'boot-sdi'             'boot\DVD\EFI\boot.sdi'      'core' 'boot' $true

  # —— 用户态关键进程与系统 DLL ——
  & $add 'shell-explorer'       'explorer.exe'               'core' 'shell' $true
  & $add 'sys-csrss'            'System32\csrss.exe'         'core' 'usermode' $true
  & $add 'sys-lsass'            'System32\lsass.exe'         'core' 'usermode' $true
  & $add 'sys-services'         'System32\services.exe'      'core' 'usermode' $true
  & $add 'sys-winlogon'         'System32\winlogon.exe'      'core' 'usermode' $true
  & $add 'sys-wininit'          'System32\wininit.exe'       'core' 'usermode' $true
  & $add 'sys-smss'             'System32\smss.exe'          'core' 'usermode' $true
  & $add 'sys-svchost'          'System32\svchost.exe'       'core' 'usermode' $true
  & $add 'sys-dwm'              'System32\dwm.exe'           'core' 'usermode' $true
  & $add 'sys-fontdrvhost'      'System32\fontdrvhost.exe'   'core' 'usermode' $true
  & $add 'sys-logonui'          'System32\LogonUI.exe'       'core' 'usermode' $true
  & $add 'sys-smartscreen'      'System32\smartscreen.exe'   'core' 'usermode' $true
  & $add 'user-advapi32'        'System32\advapi32.dll'      'core' 'usermode' $true
  & $add 'user-ole32'           'System32\ole32.dll'         'core' 'usermode' $true
  & $add 'user-combase'         'System32\combase.dll'       'core' 'usermode' $true
  & $add 'user-user32'          'System32\user32.dll'        'core' 'usermode' $true
  & $add 'user-gdi32'           'System32\gdi32.dll'         'core' 'usermode' $true
  & $add 'user-gdi32full'       'System32\gdi32full.dll'     'core' 'usermode' $true
  & $add 'user-shell32'         'System32\shell32.dll'       'core' 'usermode' $true
  & $add 'user-rpcrt4'          'System32\rpcrt4.dll'        'core' 'usermode' $true
  & $add 'user-rpcss'           'System32\RpcSs.dll'         'core' 'usermode' $true
  & $add 'user-sechost'         'System32\sechost.dll'       'core' 'usermode' $true
  & $add 'user-bcrypt'          'System32\bcrypt.dll'        'core' 'usermode' $true
  & $add 'user-crypt32'         'System32\crypt32.dll'       'core' 'usermode' $true
  & $add 'user-imm32'           'System32\imm32.dll'         'core' 'usermode' $true
  & $add 'user-msctf'           'System32\msctf.dll'         'core' 'usermode' $true
  & $add 'user-profapi'         'System32\profapi.dll'       'core' 'usermode' $true
  & $add 'user-setupapi'        'System32\setupapi.dll'      'core' 'usermode' $true
  & $add 'user-shcore'          'System32\shcore.dll'        'core' 'usermode' $true
  & $add 'user-shlwapi'         'System32\shlwapi.dll'       'core' 'usermode' $true
  & $add 'user-sspicli'         'System32\sspicli.dll'       'core' 'usermode' $true
  & $add 'user-ucrtbase'        'System32\ucrtbase.dll'      'core' 'usermode' $true
  & $add 'user-wintrust'        'System32\wintrust.dll'      'core' 'usermode' $true
  & $add 'user-ws2_32'          'System32\ws2_32.dll'        'core' 'usermode' $true
  & $add 'user-msvcrt'          'System32\msvcrt.dll'        'core' 'usermode' $true
  & $add 'user-comctl32'        'System32\comctl32.dll'      'core' 'usermode' $true
  & $add 'user-oleaut32'        'System32\oleaut32.dll'      'core' 'usermode' $true
  & $add 'user-windows-codecs'  'System32\WindowsCodecs.dll' 'core' 'usermode' $true
  & $add 'user-ntmarta'         'System32\ntmarta.dll'       'core' 'usermode' $true
  & $add 'user-powrprof'        'System32\powrprof.dll'      'core' 'usermode' $true
  & $add 'user-userenv'         'System32\userenv.dll'       'core' 'usermode' $true
  & $add 'user-wldp'            'System32\wldp.dll'          'core' 'usermode' $true

  # —— 关键驱动 ——
  & $add 'drv-disk'             'System32\drivers\disk.sys'      'core' 'driver' $true
  & $add 'drv-ntfs'             'System32\drivers\ntfs.sys'      'core' 'driver' $true
  & $add 'drv-volsnap'          'System32\drivers\volsnap.sys'   'core' 'driver' $true
  & $add 'drv-storport'         'System32\drivers\storport.sys'  'core' 'driver' $true
  & $add 'drv-storahci'         'System32\drivers\storahci.sys'  'core' 'driver' $true
  & $add 'drv-stornvme'         'System32\drivers\stornvme.sys'  'core' 'driver' $true
  & $add 'drv-spaceport'        'System32\drivers\spaceport.sys' 'core' 'driver' $true
  & $add 'drv-acpi'             'System32\drivers\acpi.sys'      'core' 'driver' $true
  & $add 'drv-pci'              'System32\drivers\pci.sys'       'core' 'driver' $true
  & $add 'drv-volmgr'           'System32\drivers\volmgr.sys'    'core' 'driver' $true
  & $add 'drv-partmgr'          'System32\drivers\partmgr.sys'   'core' 'driver' $true
  & $add 'drv-mountmgr'         'System32\drivers\mountmgr.sys'  'core' 'driver' $true
  & $add 'drv-fvevol'           'System32\drivers\fvevol.sys'    'core' 'driver' $true
  & $add 'drv-usbhub'           'System32\drivers\usbhub.sys'    'core' 'driver' $true
  & $add 'drv-usbxhci'          'System32\drivers\usbxhci.sys'   'core' 'driver' $true
  & $add 'drv-wdf01000'         'System32\drivers\wdf01000.sys'  'core' 'driver' $true
  & $add 'drv-afd'              'System32\drivers\afd.sys'       'core' 'driver' $true
  & $add 'drv-netio'            'System32\drivers\netio.sys'     'core' 'driver' $true
  & $add 'drv-ndis'             'System32\drivers\ndis.sys'      'core' 'driver' $true
  & $add 'drv-tcpip'            'System32\drivers\tcpip.sys'     'core' 'driver' $true
  & $add 'drv-tcpipreg'         'System32\drivers\tcpipreg.sys'  'core' 'driver' $true
  & $add 'drv-http'             'System32\drivers\http.sys'      'core' 'driver' $true
  & $add 'drv-cng'              'System32\drivers\cng.sys'       'core' 'driver' $true
  & $add 'drv-ksecdd'           'System32\drivers\ksecdd.sys'    'core' 'driver' $true
  & $add 'drv-clfs'             'System32\drivers\clfs.sys'      'core' 'driver' $true
  & $add 'drv-mup'              'System32\drivers\mup.sys'       'core' 'driver' $true
  & $add 'drv-wdfilter'         'System32\drivers\WdFilter.sys'  'core' 'driver' $true

  # —— 系统记忆类（role=memory，只展示不删除）——
  & $add 'mem-crash-dump'       'MEMORY.DMP'                     'memory' 'memory' $false
  & $addAbs 'mem-swapfile'      ($script:SystemDrive + ':\swapfile.sys') 'memory' 'memory' $false
  & $addAbs 'mem-hiberfil'      ($script:SystemDrive + ':\hiberfil.sys') 'memory' 'memory' $false
  & $addAbs 'mem-pagefile'      ($script:SystemDrive + ':\pagefile.sys') 'memory' 'memory' $false

  return $entries
}

# 解析受保护文件清单：返回真实存在性 / 大小 / 版本 / 可选哈希
function Resolve-ProtectedFiles {
  param(
    [switch]$ComputeHash,
    [switch]$IncludeMissing
  )
  $result = New-Object 'System.Collections.Generic.List[object]'
  foreach ($entry in (Get-ProtectedManifestEntries)) {
    $exists = Test-FileExists $entry.path
    $size = [long]0
    $sha = $null
    $version = $null
    if ($exists) {
      $size = Get-FileSizeSafe $entry.path
      if ($size -lt 0) {
        if ($entry.role -eq 'core') { Add-Warning ("核心文件大小读取失败：" + $entry.path) }
        $exists = $false
        $size = [long]0
      }
      if ($exists) {
        $version = Get-FileVersionText $entry.path
        if ($ComputeHash) {
          $sha = Get-FileSha256 $entry.path
          if ($null -eq $sha) { Add-Warning ("核心文件哈希读取失败：" + $entry.path) }
        }
      }
    } else {
      if ($entry.role -eq 'core') {
        Add-Warning ("内置核心清单文件不存在，已跳过：" + $entry.path)
      }
    }
    if (-not $exists -and -not $IncludeMissing) { continue }
    $result.Add([pscustomobject][ordered]@{
        id       = $entry.id
        path     = $entry.path
        role     = $entry.role
        group    = $entry.group
        size     = $size
        sha256   = $sha
        version  = $version
        critical = [bool]$entry.critical
        exists   = [bool]$exists
      })
  }
  return $result
}

# System32 顶层 *.dll/*.exe 抽样（role=support），并统计真实数量与体积
function Get-SupportStats {
  param(
    [int]$SampleCount = 60,
    [hashtable]$Baseline = $null,
    [switch]$ComputeHash
  )
  $stats = [pscustomobject][ordered]@{
    count   = [long]0
    bytes   = [long]0
    scope   = 'System32 顶层 *.dll / *.exe'
    samples = (New-Object 'System.Collections.Generic.List[object]')
  }
  $sys32 = Join-Path $script:SystemRoot 'System32'
  if (-not (Test-DirExists $sys32)) {
    Add-Warning ("System32 目录不存在：" + $sys32)
    return $stats
  }
  $files = @()
  try {
    $files = @([System.IO.Directory]::GetFiles($sys32, '*.dll')) + @([System.IO.Directory]::GetFiles($sys32, '*.exe'))
  } catch {
    Add-Warning ("枚举 System32 失败：" + $_.Exception.Message)
    return $stats
  }
  $count = [long]0
  $bytes = [long]0
  $records = New-Object 'System.Collections.Generic.List[object]'
  foreach ($file in $files) {
    $size = Get-FileSizeSafe $file
    if ($size -lt 0) { continue }
    $count++
    $bytes += $size
    $records.Add([pscustomobject][ordered]@{ path = $file; size = $size })
  }
  $stats.count = $count
  $stats.bytes = $bytes
  if ($records.Count -eq 0) { return $stats }
  $sorted = @($records | Sort-Object -Property path)
  $wanted = $SampleCount
  if ($wanted -lt 1) { $wanted = 1 }
  if ($wanted -gt $sorted.Count) { $wanted = $sorted.Count }
  $step = [int][Math]::Floor($sorted.Count / $wanted)
  if ($step -lt 1) { $step = 1 }
  $index = 0
  $n = 0
  while ($index -lt $sorted.Count -and $n -lt $wanted) {
    $rec = $sorted[$index]
    $sha = $null
    $reused = $false
    if ($null -ne $Baseline) {
      $key = Get-NormalizedPathKey $rec.path
      if ($Baseline.ContainsKey($key)) {
        $prev = $Baseline[$key]
        $prevSize = Get-ObjectProp -Object $prev -Name 'size' -Default $null
        $prevSha = Get-ObjectProp -Object $prev -Name 'sha256' -Default $null
        if ($null -ne $prevSize -and [long]$prevSize -eq [long]$rec.size -and -not [string]::IsNullOrWhiteSpace([string]$prevSha)) {
          $sha = [string]$prevSha
          $reused = $true
        }
      }
    }
    if ($ComputeHash -and -not $reused) { $sha = Get-FileSha256 $rec.path }
    $n++
    $stats.samples.Add([pscustomobject][ordered]@{
        id       = ('support-{0:d4}' -f $n)
        path     = $rec.path
        role     = 'support'
        group    = 'system32'
        size     = [long]$rec.size
        sha256   = $sha
        version  = (Get-FileVersionText $rec.path)
        critical = $false
        exists   = $true
      })
    $index += $step
  }
  return $stats
}

# ---------------------------------------------------------------------------
# 垃圾与系统记忆扫描
# ---------------------------------------------------------------------------

function New-JunkGroup {
  param([string]$Id, [string]$Title, [string]$Kind, [string]$Note, [bool]$SafeToDelete)
  return [pscustomobject][ordered]@{
    id           = $Id
    title        = $Title
    kind         = $Kind
    note         = $Note
    safeToDelete = $SafeToDelete
    items        = (New-Object 'System.Collections.Generic.List[object]')
    totalBytes   = [long]0
    itemCount    = [long]0
  }
}

function Add-GroupNote {
  param($Group, [string]$Text)
  if ([string]::IsNullOrWhiteSpace($Text)) { return }
  $Group.note = ([string]$Group.note) + '；' + $Text
}

function Add-GroupFileItem {
  param($Group, [string]$Path, [long]$Size, [int]$MaxItems)
  $Group.itemCount = [long]$Group.itemCount + 1
  $Group.totalBytes = [long]$Group.totalBytes + $Size
  if ($Group.items.Count -lt $MaxItems) {
    $Group.items.Add([pscustomobject][ordered]@{
        id     = ('{0}-{1:d4}' -f $Group.id, $Group.itemCount)
        path   = $Path
        size   = $Size
        exists = $true
      })
    return $true
  }
  return $false
}

# 带深度/数量/时间预算的目录扫描；只统计真实文件大小
function Add-ScanResults {
  param(
    $Group,
    [string[]]$Roots,
    [string]$Filter = '*',
    [int]$MaxDepth = 6,
    [int]$MaxItems = 3000,
    [datetime]$Deadline,
    [string[]]$SkipDirNames = @()
  )
  $skip = @{}
  foreach ($name in $SkipDirNames) {
    if (-not [string]::IsNullOrWhiteSpace($name)) { $skip[$name.ToLowerInvariant()] = $true }
  }
  $truncated = $false
  $timedOut = $false
  $denied = 0
  $statErrors = 0
  $rootScanned = 0

  foreach ($root in $Roots) {
    if ([string]::IsNullOrWhiteSpace($root)) { continue }
    if (-not (Test-DirExists $root)) { continue }
    $rootScanned++
    $stack = New-Object 'System.Collections.Stack'
    $stack.Push(@($root, 0))
    while ($stack.Count -gt 0) {
      if ((Get-Date) -gt $Deadline) { $timedOut = $true; break }
      $current = $stack.Pop()
      $dir = [string]$current[0]
      $depth = [int]$current[1]
      $fileList = $null
      try {
        $fileList = [System.IO.Directory]::GetFiles($dir, $Filter)
      } catch {
        $denied++
        continue
      }
      foreach ($file in $fileList) {
        $size = Get-FileSizeSafe $file
        if ($size -lt 0) { $statErrors++; continue }
        $ok = Add-GroupFileItem -Group $Group -Path $file -Size $size -MaxItems $MaxItems
        if (-not $ok) { $truncated = $true }
      }
      if ($depth -lt $MaxDepth) {
        $dirList = $null
        try {
          $dirList = [System.IO.Directory]::GetDirectories($dir)
        } catch {
          $denied++
          continue
        }
        foreach ($sub in $dirList) {
          $leaf = ''
          try { $leaf = [System.IO.Path]::GetFileName($sub) } catch { $leaf = '' }
          if ($skip.ContainsKey($leaf.ToLowerInvariant())) { continue }
          try {
            $attrs = [System.IO.File]::GetAttributes($sub)
            if (($attrs -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
          } catch {
            $denied++
            continue
          }
          $stack.Push(@($sub, ($depth + 1)))
        }
      }
    }
    if ($timedOut) { break }
  }

  if ($truncated) { Add-GroupNote $Group ("单项列表已截断为前 " + $MaxItems + " 条，总大小按真实全量统计") }
  if ($timedOut) {
    Add-GroupNote $Group '扫描超出时间预算，结果可能不完整'
    Add-Warning ("扫描超时，结果可能不完整：" + $Group.id)
  }
  if ($denied -gt 0) {
    Add-Warning ("部分目录无法访问（" + $denied + " 处，可能需要管理员）：" + $Group.id)
  }
  if ($statErrors -gt 0) {
    Add-Warning ("部分文件大小读取失败（" + $statErrors + " 个，可能被占用）：" + $Group.id)
  }
  if ($rootScanned -eq 0) {
    Add-GroupNote $Group '目标目录在本机不存在，已跳过'
  }
}

function Add-SingleFileToGroup {
  param($Group, [string]$Path, [int]$MaxItems)
  if (-not (Test-FileExists $Path)) { return $false }
  $size = Get-FileSizeSafe $Path
  if ($size -lt 0) { return $false }
  [void](Add-GroupFileItem -Group $Group -Path $Path -Size $size -MaxItems $MaxItems)
  return $true
}

function Get-JunkReport {
  param([int]$MaxItems = 3000, [int]$MaxDurationMs = 45000)
  if ($MaxItems -lt 1) { $MaxItems = 3000 }
  if ($MaxDurationMs -lt 5000) { $MaxDurationMs = 5000 }
  if ($MaxDurationMs -gt 120000) { $MaxDurationMs = 120000 }
  $deadline = (Get-Date).AddMilliseconds($MaxDurationMs)
  $groups = New-Object 'System.Collections.Generic.List[object]'

  # 1) 用户临时文件（$env:TEMP 与 %LOCALAPPDATA%\Temp 可能是同一路径，去重）
  $tempRoots = New-Object 'System.Collections.Generic.List[string]'
  $seen = @{}
  foreach ($candidate in @($env:TEMP, (Join-Path $env:LOCALAPPDATA 'Temp'))) {
    if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
    $key = Get-NormalizedPathKey $candidate
    if ($seen.ContainsKey($key)) { continue }
    $seen[$key] = $true
    $tempRoots.Add($candidate)
  }
  $g = New-JunkGroup -Id 'temp-user' -Title '用户临时文件' -Kind 'junk' -Note '删掉不影响系统运行；正在被程序占用的文件会失败跳过' -SafeToDelete $true
  Add-ScanResults -Group $g -Roots $tempRoots.ToArray() -MaxDepth 6 -MaxItems $MaxItems -Deadline $deadline -SkipDirNames @('System Volume Information')
  $groups.Add($g)

  # 2) Windows 临时目录
  $g = New-JunkGroup -Id 'temp-windows' -Title 'Windows 临时文件' -Kind 'junk' -Note '系统临时目录，部分文件需要管理员权限才能删除' -SafeToDelete $true
  Add-ScanResults -Group $g -Roots @((Join-Path $script:SystemRoot 'Temp')) -MaxDepth 4 -MaxItems $MaxItems -Deadline $deadline -SkipDirNames @('System Volume Information')
  $groups.Add($g)

  # 3) Windows 更新下载缓存
  $g = New-JunkGroup -Id 'update-cache' -Title 'Windows 更新缓存' -Kind 'junk' -Note '已下载的更新包，删除后需要时会重新下载；删除前建议停止 Windows Update 服务（需管理员）' -SafeToDelete $true
  Add-ScanResults -Group $g -Roots @((Join-Path $script:SystemRoot 'SoftwareDistribution\Download')) -MaxDepth 6 -MaxItems $MaxItems -Deadline $deadline
  $groups.Add($g)

  # 4) 系统日志与安装日志
  $g = New-JunkGroup -Id 'logs-windows' -Title '系统日志（CBS/DISM/安装日志）' -Kind 'junk' -Note '组件安装与更新日志，删除可释放空间；部分文件需要管理员权限' -SafeToDelete $true
  Add-ScanResults -Group $g -Roots @((Join-Path $script:SystemRoot 'Logs'), (Join-Path $script:SystemRoot 'Panther')) -MaxDepth 5 -MaxItems $MaxItems -Deadline $deadline
  $groups.Add($g)

  # 5) 缩略图缓存
  $explorerDir = Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Explorer'
  $g = New-JunkGroup -Id 'thumbs' -Title '缩略图缓存' -Kind 'junk' -Note '资源管理器缩略图数据库，删除后系统会自动重建' -SafeToDelete $true
  Add-ScanResults -Group $g -Roots @($explorerDir) -Filter 'thumbcache_*.db' -MaxDepth 0 -MaxItems $MaxItems -Deadline $deadline
  Add-ScanResults -Group $g -Roots @($explorerDir) -Filter 'iconcache_*.db' -MaxDepth 0 -MaxItems $MaxItems -Deadline $deadline
  $groups.Add($g)

  # 6) 错误报告（WER）
  $g = New-JunkGroup -Id 'wer' -Title '错误报告（WER）' -Kind 'junk' -Note '程序崩溃错误报告归档，可安全删除' -SafeToDelete $true
  Add-ScanResults -Group $g -Roots @((Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\WER'), (Join-Path $env:ProgramData 'Microsoft\Windows\WER')) -MaxDepth 5 -MaxItems $MaxItems -Deadline $deadline
  $groups.Add($g)

  # 7) 回收站（只统计；直接删 $R 文件会残留 $I 索引，交给系统「清空回收站」）
  $g = New-JunkGroup -Id 'recycle-bin' -Title '回收站' -Kind 'junk' -Note '只统计不直接删除，避免残留 $I 索引；请在资源管理器里「清空回收站」' -SafeToDelete $false
  $recycleRoot = $script:SystemDrive + ':\$Recycle.Bin'
  $recycleSids = New-Object 'System.Collections.Generic.List[string]'
  if (Test-DirExists $recycleRoot) {
    try {
      foreach ($sidDir in [System.IO.Directory]::GetDirectories($recycleRoot)) { $recycleSids.Add($sidDir) }
    } catch { Add-Warning ("枚举回收站失败（可能缺少权限）：" + $_.Exception.Message) }
  }
  if ($recycleSids.Count -gt 0) {
    Add-ScanResults -Group $g -Roots $recycleSids.ToArray() -MaxDepth 2 -MaxItems $MaxItems -Deadline $deadline
  } else {
    Add-GroupNote $g '回收站路径不存在或不可访问'
  }
  $groups.Add($g)

  # 8) 预取文件（默认不删：删除只影响启动速度，且需要管理员）
  $g = New-JunkGroup -Id 'prefetch' -Title '预取文件（Prefetch）' -Kind 'junk' -Note '用于加快程序启动；删除后短期变慢且需要管理员，插件默认不删除' -SafeToDelete $false
  Add-ScanResults -Group $g -Roots @((Join-Path $script:SystemRoot 'Prefetch')) -Filter '*.pf' -MaxDepth 0 -MaxItems $MaxItems -Deadline $deadline
  $groups.Add($g)

  # 9) 系统记忆类：内存转储
  $memoryNote = '系统记忆类，单独存放，删除会影响排障且不建议，插件不删除'
  $g = New-JunkGroup -Id 'memory-dump' -Title '内存转储（蓝屏/崩溃）' -Kind 'memory' -Note $memoryNote -SafeToDelete $false
  [void](Add-SingleFileToGroup -Group $g -Path (Join-Path $script:SystemRoot 'MEMORY.DMP') -MaxItems $MaxItems)
  Add-ScanResults -Group $g -Roots @((Join-Path $script:SystemRoot 'Minidump')) -Filter '*.dmp' -MaxDepth 1 -MaxItems $MaxItems -Deadline $deadline
  Add-ScanResults -Group $g -Roots @((Join-Path $script:SystemRoot 'LiveKernelReports')) -Filter '*.dmp' -MaxDepth 3 -MaxItems $MaxItems -Deadline $deadline
  Add-ScanResults -Group $g -Roots @((Join-Path $env:LOCALAPPDATA 'CrashDumps')) -Filter '*.dmp' -MaxDepth 1 -MaxItems $MaxItems -Deadline $deadline
  if ($g.itemCount -eq 0) { Add-GroupNote $g '本机当前没有内存转储文件' }
  $groups.Add($g)

  # 10) 系统记忆类：页文件 / 休眠文件 / 交换文件
  $g = New-JunkGroup -Id 'memory-pagefile' -Title '页文件与休眠文件' -Kind 'memory' -Note $memoryNote -SafeToDelete $false
  $pageCandidates = New-Object 'System.Collections.Generic.List[string]'
  try {
    foreach ($pf in @(Get-CimInstance -ClassName Win32_PageFileUsage -ErrorAction Stop)) {
      $name = [string](Get-ObjectProp -Object $pf -Name 'Name' -Default '')
      if (-not [string]::IsNullOrWhiteSpace($name)) { $pageCandidates.Add($name) }
    }
  } catch { }
  foreach ($vol in (Get-FixedVolumes)) {
    $drive = [string]$vol.id
    if ([string]::IsNullOrWhiteSpace($drive)) { continue }
    $pageCandidates.Add($drive + '\pagefile.sys')
    $pageCandidates.Add($drive + '\hiberfil.sys')
    $pageCandidates.Add($drive + '\swapfile.sys')
  }
  $pageSeen = @{}
  $pageFound = 0
  foreach ($candidate in $pageCandidates) {
    $key = Get-NormalizedPathKey $candidate
    if ([string]::IsNullOrWhiteSpace($key) -or $pageSeen.ContainsKey($key)) { continue }
    $pageSeen[$key] = $true
    if (Add-SingleFileToGroup -Group $g -Path $candidate -MaxItems $MaxItems) { $pageFound++ }
  }
  if ($pageFound -eq 0) { Add-GroupNote $g '本机未发现页文件/休眠文件（休眠可能未启用）' }
  if (-not (Test-FileExists (Join-Path $script:SystemRoot 'MEMORY.DMP')) -and -not (Test-DirExists (Join-Path $script:SystemRoot 'Minidump'))) {
    Add-GroupNote $g '本机未发现内存转储'
  }
  $groups.Add($g)

  # 11) 系统记忆类：事件日志归档（只读统计）
  $g = New-JunkGroup -Id 'memory-eventlog' -Title '事件日志（.evtx）' -Kind 'memory' -Note $memoryNote -SafeToDelete $false
  Add-ScanResults -Group $g -Roots @((Join-Path $script:SystemRoot 'System32\winevt\Logs')) -Filter '*.evtx' -MaxDepth 0 -MaxItems $MaxItems -Deadline $deadline
  $groups.Add($g)

  $junkBytes = [long]0
  $memoryBytes = [long]0
  foreach ($group in $groups) {
    if ($group.kind -eq 'memory') { $memoryBytes += [long]$group.totalBytes } else { $junkBytes += [long]$group.totalBytes }
  }

  return [pscustomobject][ordered]@{
    scannedAt   = (ConvertTo-EpochMs (Get-Date))
    durationMs  = [int]((Get-Date) - $script:StartedAt).TotalMilliseconds
    groups      = $groups
    totalBytes  = $junkBytes          # 只算可清理垃圾，系统记忆类单独给 memoryBytes
    junkBytes   = $junkBytes
    memoryBytes = $memoryBytes
    warnings    = @($script:Warnings)
  }
}

# ---------------------------------------------------------------------------
# 动作：probe
# ---------------------------------------------------------------------------

function Invoke-Probe {
  $osName = $null
  $osVersion = $null
  $osBuild = $null
  $arch = $env:PROCESSOR_ARCHITECTURE
  try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $osName = [string](Get-ObjectProp -Object $os -Name 'Caption' -Default '')
    $osVersion = [string](Get-ObjectProp -Object $os -Name 'Version' -Default '')
    $osBuild = [string](Get-ObjectProp -Object $os -Name 'BuildNumber' -Default '')
    $osArch = [string](Get-ObjectProp -Object $os -Name 'OSArchitecture' -Default '')
    if ([string]::IsNullOrWhiteSpace($arch) -and -not [string]::IsNullOrWhiteSpace($osArch)) { $arch = $osArch }
  } catch {
    Add-Warning ("读取操作系统信息失败：" + $_.Exception.Message)
  }
  if ([string]::IsNullOrWhiteSpace($osName)) { $osName = 'Microsoft Windows' }
  if ([string]::IsNullOrWhiteSpace($osVersion)) { $osVersion = [System.Environment]::OSVersion.Version.ToString() }
  if ([string]::IsNullOrWhiteSpace($osBuild)) { $osBuild = [System.Environment]::OSVersion.Version.Build.ToString() }
  if ([string]::IsNullOrWhiteSpace($arch)) { $arch = 'unknown' }

  $minutes = 1440
  try { $minutes = [int](Get-GuardParam -Name 'excludeUpdateWindowMinutes' -Default 1440) } catch { $minutes = 1440 }
  $window = Get-UpdateWindowInfo -Minutes $minutes

  $volumes = New-Object 'System.Collections.Generic.List[object]'
  foreach ($vol in (Get-FixedVolumes)) {
    $volumes.Add([pscustomobject][ordered]@{
        id         = $vol.id
        label      = $vol.label
        fs         = $vol.fs
        totalBytes = $vol.totalBytes
        freeBytes  = $vol.freeBytes
        isSystem   = $vol.isSystem
      })
  }
  if ($volumes.Count -eq 0) { Add-Warning '没有检测到任何固定磁盘' }

  $tools = [pscustomobject][ordered]@{
    sfc        = (Test-CommandAvailable 'sfc')
    dism       = (Test-CommandAvailable 'dism')
    wbadmin    = (Test-CommandAvailable 'wbadmin')
    vssadmin   = (Test-CommandAvailable 'vssadmin')
    bcdedit    = (Test-CommandAvailable 'bcdedit')
    checkpoint = (Test-CommandAvailable 'Checkpoint-Computer')
    takeown    = (Test-CommandAvailable 'takeown')
    icacls     = (Test-CommandAvailable 'icacls')
  }

  $updateWindow = $null
  if ($null -ne $window) {
    $updateWindow = [pscustomobject][ordered]@{ from = $window.fromIso; to = $window.toIso }
  }

  $value = [pscustomobject][ordered]@{
    platform     = 'windows'
    osName       = $osName.Trim()
    osVersion    = $osVersion.Trim()
    osBuild      = $osBuild.Trim()
    arch         = $arch
    admin        = (Test-IsAdmin)
    systemRoot   = $script:SystemRoot
    systemDrive  = ($script:SystemDrive + ':')
    volumes      = $volumes
    tools        = $tools
    updateWindow = $updateWindow
    warnings     = @($script:Warnings)
  }
  return $value
}

# ---------------------------------------------------------------------------
# 动作：junk-scan / junk-delete
# ---------------------------------------------------------------------------

function Invoke-JunkScan {
  $maxItems = 3000
  try { $maxItems = [int](Get-GuardParam -Name 'junkMaxItems' -Default 3000) } catch { $maxItems = 3000 }
  if ($maxItems -lt 1) { $maxItems = 3000 }
  if ($maxItems -gt 3000) { $maxItems = 3000 }
  $budget = $script:DefaultScanBudgetMs
  try { $budget = [int](Get-GuardParam -Name 'maxDurationMs' -Default $script:DefaultScanBudgetMs) } catch { $budget = $script:DefaultScanBudgetMs }
  return (Get-JunkReport -MaxItems $maxItems -MaxDurationMs $budget)
}

# 只允许删除明确属于垃圾分类目录里的、用户点名的路径
function Get-JunkAllowRoots {
  $roots = New-Object 'System.Collections.Generic.List[string]'
  foreach ($candidate in @(
      $env:TEMP,
      (Join-Path $env:LOCALAPPDATA 'Temp'),
      (Join-Path $script:SystemRoot 'Temp'),
      (Join-Path $script:SystemRoot 'SoftwareDistribution\Download'),
      (Join-Path $script:SystemRoot 'Logs'),
      (Join-Path $script:SystemRoot 'Panther'),
      (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\WER'),
      (Join-Path $env:ProgramData 'Microsoft\Windows\WER')
    )) {
    if ([string]::IsNullOrWhiteSpace($candidate)) { continue }
    $roots.Add($candidate.TrimEnd('\'))
  }
  $thumbsDir = (Join-Path $env:LOCALAPPDATA 'Microsoft\Windows\Explorer').TrimEnd('\')
  return [pscustomobject][ordered]@{ roots = $roots.ToArray(); thumbsDir = $thumbsDir }
}

function Test-PathUnderRoot {
  param([string]$Path, [string]$Root)
  if ([string]::IsNullOrWhiteSpace($Path) -or [string]::IsNullOrWhiteSpace($Root)) { return $false }
  $p = $Path.TrimEnd('\')
  $r = $Root.TrimEnd('\')
  if ($p.Equals($r, [System.StringComparison]::OrdinalIgnoreCase)) { return $true }
  return $p.StartsWith(($r + '\'), [System.StringComparison]::OrdinalIgnoreCase)
}

function Get-JunkDeleteDenyReason {
  param([string]$Path)
  $allow = Get-JunkAllowRoots
  foreach ($root in $allow.roots) {
    if (Test-PathUnderRoot -Path $Path -Root $root) { return $null }
  }
  if (Test-PathUnderRoot -Path $Path -Root $allow.thumbsDir) {
    $leaf = ''
    try { $leaf = [System.IO.Path]::GetFileName($Path) } catch { $leaf = '' }
    if ($leaf -match '^(thumbcache|iconcache)_.*\.db$') { return $null }
    return 'not-allowed'
  }
  return 'not-allowed'
}

function Invoke-JunkDelete {
  $rawItems = Get-GuardParam -Name 'items' -Default $null
  if ($null -eq $rawItems) { Stop-GuardError -Code 'invalid-params' -Message '未指定要删除的垃圾项' }
  $paths = New-Object 'System.Collections.Generic.List[string]'
  foreach ($item in @($rawItems)) {
    if ($null -eq $item) { continue }
    if ($item -is [string]) {
      if (-not [string]::IsNullOrWhiteSpace($item)) { $paths.Add($item) }
    } else {
      $p = [string](Get-ObjectProp -Object $item -Name 'path' -Default '')
      if (-not [string]::IsNullOrWhiteSpace($p)) { $paths.Add($p) }
    }
  }
  if ($paths.Count -eq 0) { Stop-GuardError -Code 'invalid-params' -Message '未指定要删除的垃圾项（缺少 items[].path）' }
  if ($paths.Count -gt 5000) { Stop-GuardError -Code 'invalid-params' -Message '一次最多删除 5000 项' }

  $deleted = New-Object 'System.Collections.Generic.List[string]'
  $failed = New-Object 'System.Collections.Generic.List[object]'
  $freedBytes = [long]0

  foreach ($path in $paths) {
    $denyReason = Get-JunkDeleteDenyReason -Path $path
    if ($null -ne $denyReason) {
      $failed.Add([pscustomobject][ordered]@{ path = $path; error = $denyReason })
      continue
    }
    if (Test-DirExists $path) {
      try {
        [System.IO.Directory]::Delete($path, $false)
        $deleted.Add($path)
      } catch {
        $failed.Add([pscustomobject][ordered]@{ path = $path; error = 'directory-not-empty-or-denied' })
      }
      continue
    }
    if (-not (Test-FileExists $path)) {
      $failed.Add([pscustomobject][ordered]@{ path = $path; error = 'not-found' })
      continue
    }
    $size = Get-FileSizeSafe $path
    if ($size -lt 0) { $size = [long]0 }
    try {
      # 清掉只读/隐藏/系统属性后再删，避免误判失败
      try { [System.IO.File]::SetAttributes($path, [System.IO.FileAttributes]::Normal) } catch { }
      [System.IO.File]::Delete($path)
      $deleted.Add($path)
      $freedBytes += $size
    } catch {
      $message = ''
      try { $message = $_.Exception.Message } catch { }
      $errorCode = 'delete-failed'
      if ($message -match 'denied|拒绝访问|Access is denied') { $errorCode = 'access-denied' }
      elseif ($message -match 'being used|正由另一进程使用|in use') { $errorCode = 'in-use' }
      $failed.Add([pscustomobject][ordered]@{ path = $path; error = $errorCode })
    }
  }

  $value = [pscustomobject][ordered]@{
    requested  = $paths.Count
    deleted    = $deleted
    failed     = $failed
    freedBytes = $freedBytes
    elevated   = (Test-IsAdmin)
    warnings   = @($script:Warnings)
  }
  return $value
}

# ---------------------------------------------------------------------------
# 动作：analyze
# ---------------------------------------------------------------------------

function Get-BaselineMap {
  param($FilesParam)
  $map = @{}
  if ($null -eq $FilesParam) { return $map }
  try {
    foreach ($item in @($FilesParam)) {
      if ($null -eq $item) { continue }
      $path = [string](Get-ObjectProp -Object $item -Name 'path' -Default '')
      $sha = [string](Get-ObjectProp -Object $item -Name 'sha256' -Default '')
      if ([string]::IsNullOrWhiteSpace($path) -or [string]::IsNullOrWhiteSpace($sha)) { continue }
      $map[(Get-NormalizedPathKey $path)] = $item
    }
  } catch { }
  return $map
}

function Invoke-Analyze {
  $baseline = Get-BaselineMap -FilesParam (Get-GuardParam -Name 'files' -Default $null)
  $maxItems = 3000
  try { $maxItems = [int](Get-GuardParam -Name 'junkMaxItems' -Default 3000) } catch { $maxItems = 3000 }
  $budget = $script:DefaultScanBudgetMs
  try { $budget = [int](Get-GuardParam -Name 'maxDurationMs' -Default $script:DefaultScanBudgetMs) } catch { $budget = $script:DefaultScanBudgetMs }

  # 核心/记忆文件（复用上次基线里同大小文件的 sha256，避免每次重算）
  $coreFiles = New-Object 'System.Collections.Generic.List[object]'
  $coreCount = [long]0
  $coreBytes = [long]0
  $memoryCount = 0
  $memoryBytes = [long]0

  foreach ($entry in (Get-ProtectedManifestEntries)) {
    $exists = Test-FileExists $entry.path
    $size = [long]0
    $sha = $null
    $version = $null
    if ($exists) {
      $size = Get-FileSizeSafe $entry.path
      if ($size -lt 0) { $exists = $false }
    }
    if ($exists) {
      $version = Get-FileVersionText $entry.path
      # 系统记忆类（转储 / 页文件）体积大且常被系统独占，不做哈希，只统计大小
      if ($entry.role -ne 'memory') {
        $key = Get-NormalizedPathKey $entry.path
        $reused = $false
        if ($baseline.ContainsKey($key)) {
          $prev = $baseline[$key]
          $prevSize = Get-ObjectProp -Object $prev -Name 'size' -Default $null
          $prevSha = Get-ObjectProp -Object $prev -Name 'sha256' -Default $null
          if ($null -ne $prevSize -and [long]$prevSize -eq $size -and -not [string]::IsNullOrWhiteSpace([string]$prevSha)) {
            $sha = [string]$prevSha
            $reused = $true
          }
        }
        if (-not $reused) {
          $sha = Get-FileSha256 $entry.path
          if ($null -eq $sha) { Add-Warning ("读取文件哈希失败：" + $entry.path) }
        }
      }
      if ($entry.role -eq 'memory') { $memoryCount++; $memoryBytes += $size }
      else { $coreCount++; $coreBytes += $size }
    } else {
      if ($entry.role -eq 'core') { Add-Warning ("核心清单文件不存在：" + $entry.path) }
    }
    if ($exists -or $entry.role -eq 'core') {
      $coreFiles.Add([pscustomobject][ordered]@{
          id       = $entry.id
          path     = $entry.path
          role     = $entry.role
          group    = $entry.group
          size     = $size
          sha256   = $sha
          version  = $version
          critical = [bool]$entry.critical
          exists   = [bool]$exists
        })
    }
  }

  # System32 普通系统文件抽样（role=support）
  $support = Get-SupportStats -SampleCount 60 -Baseline $baseline -ComputeHash

  # 垃圾与系统记忆分类
  $junk = Get-JunkReport -MaxItems $maxItems -MaxDurationMs $budget

  $files = New-Object 'System.Collections.Generic.List[object]'
  foreach ($ref in $coreFiles) { $files.Add($ref) }
  foreach ($ref in $support.samples) { $files.Add($ref) }
  if ($files.Count -gt 800) {
    while ($files.Count -gt 800) { $files.RemoveAt($files.Count - 1) }
    Add-Warning '分析文件列表超过 800 条，已截断'
  }

  $value = [pscustomobject][ordered]@{
    analyzedAt           = (ConvertTo-EpochMs (Get-Date))
    durationMs           = [int]((Get-Date) - $script:StartedAt).TotalMilliseconds
    coreCount            = $coreCount
    coreBytes            = $coreBytes
    supportCount         = $support.count
    supportBytes         = $support.bytes
    supportSampleCount   = $support.samples.Count
    supportScope         = $support.scope
    memoryCount          = $memoryCount
    memoryBytes          = $memoryBytes
    files                = $files
    groups               = $junk.groups
    totalJunkBytes       = $junk.totalBytes
    memoryGroupBytes     = $junk.memoryBytes
    baselineSource       = 'builtin'
    calibratedAt         = $null
    warnings             = @($script:Warnings)
  }
  return $value
}

# ---------------------------------------------------------------------------
# 动作：backup / backup-status
# ---------------------------------------------------------------------------

function Get-RelativeBackupPath {
  param([string]$Path)
  $root = ''
  try { $root = [System.IO.Path]::GetPathRoot($Path) } catch { $root = '' }
  if ([string]::IsNullOrWhiteSpace($root)) { return (Join-Path 'files' ([System.IO.Path]::GetFileName($Path))) }
  $letter = $root.TrimEnd('\').TrimEnd(':')
  if ([string]::IsNullOrWhiteSpace($letter)) { $letter = 'X' }
  $rest = ''
  try { $rest = $Path.Substring($root.Length) } catch { $rest = [System.IO.Path]::GetFileName($Path) }
  return (Join-Path 'files' (Join-Path $letter $rest))
}

function Get-BackupRoots {
  $list = New-Object 'System.Collections.Generic.List[object]'
  $hint = [string](Get-GuardParam -Name 'backupRoot' -Default '')
  if (-not [string]::IsNullOrWhiteSpace($hint)) {
    $list.Add([pscustomobject][ordered]@{ root = $hint; volume = ([System.IO.Path]::GetPathRoot($hint)); manifest = (Join-Path $hint 'manifest.json') })
  }
  foreach ($vol in (Get-FixedVolumes)) {
    $root = [string]$vol.id + '\SystemGuardBackup\.system-guard'
    if (-not (Test-DirExists $root)) { continue }
    $already = $false
    foreach ($existing in $list) {
      if ((Get-NormalizedPathKey $existing.root) -eq (Get-NormalizedPathKey $root)) { $already = $true }
    }
    if ($already) { continue }
    $list.Add([pscustomobject][ordered]@{ root = $root; volume = [string]$vol.id; manifest = (Join-Path $root 'manifest.json') })
  }
  return $list
}

function Read-JsonFileSafe {
  param([string]$Path)
  if (-not (Test-FileExists $Path)) { return $null }
  try {
    $text = [System.IO.File]::ReadAllText($Path)
    if ([string]::IsNullOrWhiteSpace($text)) { return $null }
    return ($text | ConvertFrom-Json)
  } catch { return $null }
}

function Select-BackupVolume {
  param([long]$NeedBytes)
  $volumes = @(Get-FixedVolumes)
  if ($volumes.Count -eq 0) { Stop-GuardError -Code 'no-volume' -Message '没有检测到可用的固定磁盘，无法创建备份' }
  $hint = [string](Get-GuardParam -Name 'backupVolume' -Default '')
  if (-not [string]::IsNullOrWhiteSpace($hint)) {
    $want = $hint.Trim().TrimEnd('\')
    if ($want.Length -eq 1) { $want = $want + ':' }
    foreach ($vol in $volumes) {
      if (([string]$vol.id).Equals($want, [System.StringComparison]::OrdinalIgnoreCase)) {
        if ($vol.freeBytes -ge ($NeedBytes + 268435456)) { return $vol }
        Add-Warning ('指定的备份盘 ' + $vol.id + ' 剩余空间不足，改为自动选择剩余最大的盘')
      }
    }
  }
  $best = $null
  foreach ($vol in $volumes) {
    if ($null -eq $best -or $vol.freeBytes -gt $best.freeBytes) { $best = $vol }
  }
  if ($null -eq $best) { Stop-GuardError -Code 'no-volume' -Message '没有可用的固定磁盘，无法创建备份' }
  if ($best.freeBytes -lt ($NeedBytes + 268435456)) {
    Add-Warning ('剩余空间最大的盘 ' + $best.id + ' 也不足（需要约 ' + [int]($NeedBytes / 1MB) + ' MB）')
  }
  return $best
}

function Invoke-Backup {
  $targets = New-Object 'System.Collections.Generic.List[object]'
  $needBytes = [long]0
  $skipped = New-Object 'System.Collections.Generic.List[object]'
  foreach ($entry in (Get-ProtectedManifestEntries)) {
    if ($entry.role -ne 'core') { continue }
    if (-not (Test-FileExists $entry.path)) {
      $skipped.Add([pscustomobject][ordered]@{ path = $entry.path; reason = 'missing' })
      continue
    }
    $size = Get-FileSizeSafe $entry.path
    if ($size -lt 0) {
      $skipped.Add([pscustomobject][ordered]@{ path = $entry.path; reason = 'unreadable' })
      continue
    }
    $needBytes += $size
    $targets.Add([pscustomobject][ordered]@{
        id = $entry.id; path = $entry.path; role = $entry.role; group = $entry.group
        critical = [bool]$entry.critical; size = [long]$size
      })
  }
  foreach ($item in $skipped) { Add-Warning ("备份跳过：" + $item.path + "（" + $item.reason + "）") }
  if ($targets.Count -eq 0) { Stop-GuardError -Code 'backup-failed' -Message '没有可备份的核心文件（内置清单未命中任何现有文件）' }

  $volume = Select-BackupVolume -NeedBytes $needBytes
  $root = [string]$volume.id + '\SystemGuardBackup\.system-guard'
  $filesRoot = Join-Path $root 'files'
  try {
    [void][System.IO.Directory]::CreateDirectory($filesRoot)
  } catch {
    Stop-GuardError -Code 'backup-failed' -Message ('无法创建备份目录：' + $root + '（' + $_.Exception.Message + '）')
  }

  $manifestFiles = New-Object 'System.Collections.Generic.List[object]'
  $missingFiles = New-Object 'System.Collections.Generic.List[string]'
  $corruptFiles = New-Object 'System.Collections.Generic.List[string]'
  $copiedCount = 0
  $copiedBytes = [long]0

  foreach ($target in $targets) {
    $rel = Get-RelativeBackupPath -Path $target.path
    $dest = Join-Path $root $rel
    try {
      $destDir = [System.IO.Path]::GetDirectoryName($dest)
      if (-not [string]::IsNullOrWhiteSpace($destDir) -and -not (Test-DirExists $destDir)) {
        [void][System.IO.Directory]::CreateDirectory($destDir)
      }
      [System.IO.File]::Copy($target.path, $dest, $true)
      try { [System.IO.File]::SetAttributes($dest, [System.IO.FileAttributes]::Normal) } catch { }
      $destSize = Get-FileSizeSafe $dest
      if ($destSize -ne $target.size) {
        $corruptFiles.Add($target.path)
        Add-Warning ('备份后大小不一致：' + $target.path)
        continue
      }
      $sha = Get-FileSha256 $dest
      if ($null -eq $sha) {
        $corruptFiles.Add($target.path)
        Add-Warning ('备份文件哈希读取失败：' + $dest)
        continue
      }
      $copiedCount++
      $copiedBytes += $destSize
      $manifestFiles.Add([pscustomobject][ordered]@{
          id       = $target.id
          path     = $target.path
          rel      = $rel
          size     = [long]$destSize
          sha256   = $sha
          version  = (Get-FileVersionText $target.path)
          role     = $target.role
          critical = [bool]$target.critical
        })
    } catch {
      $corruptFiles.Add($target.path)
      Add-Warning ('复制失败：' + $target.path + '（' + $_.Exception.Message + '）')
    }
  }

  if ($manifestFiles.Count -eq 0) { Stop-GuardError -Code 'backup-failed' -Message '备份没有成功复制任何核心文件' }

  $createdAt = ConvertTo-EpochMs (Get-Date)
  $manifestPath = Join-Path $root 'manifest.json'
  $manifest = [pscustomobject][ordered]@{
    version       = 1
    guardVersion  = $script:GuardVersion
    createdAt     = $createdAt
    createdAtIso  = (ConvertTo-IsoUtc (Get-Date))
    volume        = [string]$volume.id
    systemRoot    = $script:SystemRoot
    systemDrive   = ($script:SystemDrive + ':')
    root          = $root
    fileCount     = $manifestFiles.Count
    totalBytes    = $copiedBytes
    files         = $manifestFiles
    skipped       = $skipped
  }
  try {
    $json = ConvertTo-Json -InputObject $manifest -Depth 12
    Write-JsonFileNoBom -Path $manifestPath -JsonText $json
  } catch {
    Stop-GuardError -Code 'backup-failed' -Message ('写入备份清单失败：' + $_.Exception.Message)
  }

  # 隐藏备份目录（+h +s）
  $hidden = $false
  try {
    & attrib.exe @('+h', '+s', $root) 2>&1 | Out-Null
    $attrs = [System.IO.File]::GetAttributes($root)
    $hidden = (($attrs -band [System.IO.FileAttributes]::Hidden) -ne 0)
  } catch {
    Add-Warning ('设置隐藏属性失败：' + $_.Exception.Message)
  }

  # 尽力加保护 ACL：拒绝普通用户删除该目录子项（CONTRACT §1：不能物理阻止，只做尽力而为）
  $aclProtected = $false
  try {
    $out = (& icacls.exe $root /deny '*S-1-5-32-545:(DE,DC)' 2>&1 | Out-String)
    if ($out -match 'Successfully processed|已成功处理') { $aclProtected = $true }
    else { Add-Warning '备份目录 ACL 保护未生效（icacls 返回未成功）' }
  } catch {
    Add-Warning ('备份目录 ACL 保护失败：' + $_.Exception.Message)
  }

  $value = [pscustomobject][ordered]@{
    root         = $root
    hidden       = $hidden
    aclProtected = $aclProtected
    volume       = [string]$volume.id
    createdAt    = $createdAt
    fileCount    = $manifestFiles.Count
    totalBytes   = $copiedBytes
    manifestPath = $manifestPath
    state        = 'ok'
    verifiedAt   = (ConvertTo-EpochMs (Get-Date))
    missingFiles = @($missingFiles)
    corruptFiles = @($corruptFiles)
    skippedCount = $skipped.Count
    durationMs   = [int]((Get-Date) - $script:StartedAt).TotalMilliseconds
    warnings     = @($script:Warnings)
  }
  return $value
}

function Invoke-BackupStatus {
  $roots = Get-BackupRoots
  $found = $null
  foreach ($candidate in $roots) {
    if (Test-FileExists $candidate.manifest) { $found = $candidate; break }
  }
  if ($null -eq $found) {
    # 目录存在但清单丢失 → missing；完全不存在 → none
    $dirExists = $false
    foreach ($candidate in $roots) { if (Test-DirExists $candidate.root) { $dirExists = $true; break } }
    $value = [pscustomobject][ordered]@{
      root         = $null
      hidden       = $false
      aclProtected = $false
      volume       = $null
      createdAt    = $null
      fileCount    = 0
      totalBytes   = 0
      manifestPath = $null
      state        = $(if ($dirExists) { 'missing' } else { 'none' })
      verifiedAt   = (ConvertTo-EpochMs (Get-Date))
      missingFiles = @()
      corruptFiles = @()
      warnings     = @($script:Warnings)
    }
    return $value
  }

  $manifest = Read-JsonFileSafe -Path $found.manifest
  if ($null -eq $manifest) {
    return [pscustomobject][ordered]@{
      root         = $found.root
      hidden       = ((Test-DirExists $found.root) -and ((([System.IO.File]::GetAttributes($found.root)) -band [System.IO.FileAttributes]::Hidden) -ne 0))
      aclProtected = $false
      volume       = $found.volume
      createdAt    = $null
      fileCount    = 0
      totalBytes    = 0
      manifestPath = $found.manifest
      state        = 'missing'
      verifiedAt   = (ConvertTo-EpochMs (Get-Date))
      missingFiles = @()
      corruptFiles = @()
      warnings     = @($script:Warnings)
    }
  }

  $manifestFiles = @(Get-ObjectProp -Object $manifest -Name 'files' -Default @())
  $missingFiles = New-Object 'System.Collections.Generic.List[string]'
  $corruptFiles = New-Object 'System.Collections.Generic.List[string]'
  $totalBytes = [long]0
  $hashBudget = 300
  $hashChecked = 0
  foreach ($fileEntry in $manifestFiles) {
    if ($null -eq $fileEntry) { continue }
    $originalPath = [string](Get-ObjectProp -Object $fileEntry -Name 'path' -Default '')
    $rel = [string](Get-ObjectProp -Object $fileEntry -Name 'rel' -Default '')
    $expectedSize = Get-ObjectProp -Object $fileEntry -Name 'size' -Default $null
    $expectedSha = [string](Get-ObjectProp -Object $fileEntry -Name 'sha256' -Default '')
    $backupPath = if (-not [string]::IsNullOrWhiteSpace($rel)) { Join-Path $found.root $rel } else { $null }
    $totalBytes += [long]$expectedSize
    if ($null -eq $backupPath -or -not (Test-FileExists $backupPath)) {
      $missingFiles.Add($originalPath)
      continue
    }
    $actualSize = Get-FileSizeSafe $backupPath
    if ($null -ne $expectedSize -and $actualSize -ne [long]$expectedSize) {
      $corruptFiles.Add($originalPath)
      continue
    }
    if (-not [string]::IsNullOrWhiteSpace($expectedSha) -and $hashChecked -lt $hashBudget) {
      $actualSha = Get-FileSha256 $backupPath
      $hashChecked++
      if ($null -ne $actualSha -and $actualSha -ne $expectedSha) { $corruptFiles.Add($originalPath) }
    }
  }

  $state = 'ok'
  if ($missingFiles.Count -gt 0 -or $corruptFiles.Count -gt 0) { $state = 'partial' }
  if ($manifestFiles.Count -eq 0) { $state = 'partial' }

  $hidden = $false
  try { $hidden = ((([System.IO.File]::GetAttributes($found.root)) -band [System.IO.FileAttributes]::Hidden) -ne 0) } catch { $hidden = $false }
  # manifest 里的 createdAt 已经是 epoch 毫秒，不能再走 ConvertTo-EpochMs（否则会变成负数年份）。
  $createdAt = $null
  $createdRaw = Get-ObjectProp -Object $manifest -Name 'createdAt' -Default $null
  if ($null -ne $createdRaw) {
    $numeric = 0.0
    if ([double]::TryParse([string]$createdRaw, [ref]$numeric)) {
      if ($numeric -gt 0) { $createdAt = [long]$numeric }
    }
  }
  $aclProtected = $false
  try {
    $acl = Get-Acl -LiteralPath $found.root -ErrorAction Stop
    foreach ($rule in $acl.Access) {
      if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) { $aclProtected = $true; break }
    }
  } catch { $aclProtected = $false }

  return [pscustomobject][ordered]@{
    root         = $found.root
    hidden       = $hidden
    aclProtected = $aclProtected
    volume       = $found.volume
    createdAt    = $createdAt
    fileCount    = $manifestFiles.Count
    totalBytes   = $totalBytes
    manifestPath = $found.manifest
    state        = $state
    verifiedAt   = (ConvertTo-EpochMs (Get-Date))
    missingFiles = @($missingFiles)
    corruptFiles = @($corruptFiles)
    hashChecked  = $hashChecked
    warnings     = @($script:Warnings)
  }
}

# ---------------------------------------------------------------------------
# 动作：restore（从备份还原）/ repair（sfc / dism / 还原点）
# ---------------------------------------------------------------------------

function Get-QuarantineBase {
  $dataDir = [string](Get-GuardParam -Name 'dataDir' -Default '')
  if ([string]::IsNullOrWhiteSpace($dataDir)) {
    $dataDir = Join-Path ([System.IO.Path]::GetTempPath()) 'dsh-system-guard'
  }
  return (Join-Path $dataDir 'quarantine')
}

function Remove-OldQuarantineDirs {
  param([string]$BaseDir, [int]$KeepDays)
  if ($KeepDays -le 0) { $KeepDays = 7 }
  if (-not (Test-DirExists $BaseDir)) { return }
  $limit = (Get-Date).AddDays(-1 * $KeepDays)
  try {
    foreach ($dir in [System.IO.Directory]::GetDirectories($BaseDir)) {
      try {
        $written = [System.IO.Directory]::GetLastWriteTime($dir)
        if ($written -lt $limit) { [System.IO.Directory]::Delete($dir, $true) }
      } catch { }
    }
  } catch { }
}

function Find-BackupManifestRoot {
  $roots = Get-BackupRoots
  foreach ($candidate in $roots) {
    if (Test-FileExists $candidate.manifest) {
      $manifest = Read-JsonFileSafe -Path $candidate.manifest
      if ($null -ne $manifest) { return [pscustomobject][ordered]@{ root = $candidate.root; manifestPath = $candidate.manifest; manifest = $manifest } }
    }
  }
  return $null
}

function Invoke-Restore {
  $paths = ConvertTo-StringArray (Get-GuardParam -Name 'paths' -Default @())
  if ($paths.Count -eq 0) { Stop-GuardError -Code 'invalid-params' -Message '未指定要还原的文件路径' }
  Confirm-Admin

  $found = Find-BackupManifestRoot
  if ($null -eq $found) { Stop-GuardError -Code 'backup-missing' -Message '没有找到可用的隐藏备份（备份清单不存在），无法还原' }
  $manifestFiles = @(Get-ObjectProp -Object $found.manifest -Name 'files' -Default @())
  $index = @{}
  foreach ($fileEntry in $manifestFiles) {
    if ($null -eq $fileEntry) { continue }
    $originalPath = [string](Get-ObjectProp -Object $fileEntry -Name 'path' -Default '')
    $key = Get-NormalizedPathKey $originalPath
    if (-not [string]::IsNullOrWhiteSpace($key)) { $index[$key] = $fileEntry }
  }

  $quarantineBase = Get-QuarantineBase
  $stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
  $quarantineDir = Join-Path $quarantineBase $stamp
  $keepDays = 7
  try { $keepDays = [int](Get-GuardParam -Name 'keepQuarantineDays' -Default 7) } catch { $keepDays = 7 }

  $actions = New-Object 'System.Collections.Generic.List[object]'
  $failed = 0
  foreach ($path in $paths) {
    $key = Get-NormalizedPathKey $path
    $entry = $null
    if ($index.ContainsKey($key)) { $entry = $index[$key] }
    if ($null -eq $entry) {
      $failed++
      $actions.Add([pscustomobject][ordered]@{ step = ('restore:' + $path); ok = $false; detail = '备份清单里没有该文件' })
      continue
    }
    $rel = [string](Get-ObjectProp -Object $entry -Name 'rel' -Default '')
    $expectedSha = [string](Get-ObjectProp -Object $entry -Name 'sha256' -Default '')
    $backupPath = Join-Path $found.root $rel
    if (-not (Test-FileExists $backupPath)) {
      $failed++
      $actions.Add([pscustomobject][ordered]@{ step = ('restore:' + $path); ok = $false; detail = '备份文件缺失' })
      continue
    }
    try {
      if (Test-FileExists $path) {
        if (-not (Test-DirExists $quarantineDir)) { [void][System.IO.Directory]::CreateDirectory($quarantineDir) }
        $flat = $path.Replace(':', '_').Replace('\', '_')
        if ($flat.Length -gt 180) { $flat = $flat.Substring($flat.Length - 180) }
        $quarantinePath = Join-Path $quarantineDir $flat
        [System.IO.File]::Copy($path, $quarantinePath, $true)
      }
      $targetDir = [System.IO.Path]::GetDirectoryName($path)
      if (-not [string]::IsNullOrWhiteSpace($targetDir) -and -not (Test-DirExists $targetDir)) {
        [void][System.IO.Directory]::CreateDirectory($targetDir)
      }
      [System.IO.File]::Copy($backupPath, $path, $true)
      $actualSha = Get-FileSha256 $path
      if (-not [string]::IsNullOrWhiteSpace($expectedSha) -and $null -ne $actualSha -and $actualSha -ne $expectedSha) {
        $failed++
        $actions.Add([pscustomobject][ordered]@{ step = ('restore:' + $path); ok = $false; detail = '还原后哈希与清单不一致' })
      } else {
        $actions.Add([pscustomobject][ordered]@{ step = ('restore:' + $path); ok = $true; detail = '' })
      }
    } catch {
      $failed++
      $actions.Add([pscustomobject][ordered]@{ step = ('restore:' + $path); ok = $false; detail = $_.Exception.Message })
    }
  }
  Remove-OldQuarantineDirs -BaseDir $quarantineBase -KeepDays $keepDays

  $value = [pscustomobject][ordered]@{
    ok       = ($failed -eq 0)
    mode     = 'restore'
    actions  = $actions
    output   = ('还原 ' + $paths.Count + ' 个文件，失败 ' + $failed + ' 个；隔离目录：' + $quarantineDir)
    warnings = @($script:Warnings)
  }
  return $value
}

function Invoke-NativeCommand {
  param([string]$FilePath, [string[]]$Arguments, [int]$CommandTimeoutSec = 0, [string]$Description = '')
  $oem = 936
  try { $oem = [System.Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage } catch { $oem = 936 }
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $FilePath
  $argList = New-Object 'System.Collections.Generic.List[string]'
  foreach ($arg in $Arguments) { $argList.Add([string]$arg) }
  $psi.Arguments = ($argList -join ' ')
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.CreateNoWindow = $true
  try { $psi.StandardOutputEncoding = [System.Text.Encoding]::GetEncoding($oem) } catch { }
  try { $psi.StandardErrorEncoding = [System.Text.Encoding]::GetEncoding($oem) } catch { }

  $process = New-Object System.Diagnostics.Process
  $process.StartInfo = $psi
  $timedOut = $false
  $exitCode = -1
  $stdout = ''
  $stderr = ''
  try {
    [void]$process.Start()
    $outTask = $process.StandardOutput.ReadToEndAsync()
    $errTask = $process.StandardError.ReadToEndAsync()
    if ($CommandTimeoutSec -gt 0) {
      if (-not $process.WaitForExit($CommandTimeoutSec * 1000)) {
        $timedOut = $true
        try { $process.Kill() } catch { }
        [void]$process.WaitForExit(10000)
      }
    } else {
      $process.WaitForExit()
    }
    try { if ($outTask.Wait(10000)) { $stdout = $outTask.Result } } catch { }
    try { if ($errTask.Wait(10000)) { $stderr = $errTask.Result } } catch { }
    try { $exitCode = $process.ExitCode } catch { $exitCode = -1 }
  } finally {
    try { $process.Dispose() } catch { }
  }
  $text = ([string]$stdout) + [Environment]::NewLine + ([string]$stderr)
  $truncated = $text.Trim()
  if ($truncated.Length -gt $script:MaxOutputChars) { $truncated = $truncated.Substring(0, $script:MaxOutputChars) + '…（输出已截断）' }
  return [pscustomobject][ordered]@{
    exitCode = $exitCode
    timedOut = $timedOut
    output   = $truncated
    title    = $Description
  }
}

function Invoke-Repair {
  $mode = [string](Get-GuardParam -Name 'mode' -Default '')
  if ([string]::IsNullOrWhiteSpace($mode)) { Stop-GuardError -Code 'invalid-params' -Message '修复需要指定 mode（restore | sfc | dism | restore-point）' }
  $mode = $mode.ToLowerInvariant()
  switch ($mode) {
    'restore' {
      return (Invoke-Restore)
    }
    'restore-point' {
      $point = Invoke-RestorePoint
      if ($point.ok -eq $true) {
        return [pscustomobject][ordered]@{
          ok = $true; mode = 'restore-point'
          actions = @([pscustomobject][ordered]@{ step = 'checkpoint-computer'; ok = $true; detail = $point.message })
          output = [string]$point.message; warnings = @($script:Warnings)
        }
      }
      return [pscustomobject][ordered]@{
        ok = $false; mode = 'restore-point'
        actions = @([pscustomobject][ordered]@{ step = 'checkpoint-computer'; ok = $false; detail = $point.message })
        output = [string]$point.message; warnings = @($script:Warnings)
        error = $point.error
      }
    }
    'sfc' {
      Confirm-Admin
      $wanted = 1800
      try { $wanted = [int](Get-GuardParam -Name 'timeoutSec' -Default $wanted) } catch { }
      if ($wanted -lt 300) { $wanted = 300 }
      $result = Invoke-NativeCommand -FilePath (Join-Path $script:SystemRoot 'System32\sfc.exe') -Arguments @('/scannow') -CommandTimeoutSec $wanted -Description 'sfc /scannow'
      $passed = $null
      $lower = ([string]$result.output).ToLowerInvariant()
      if ($lower -match 'did not find any integrity violations|未找到任何完整性冲突') { $passed = $true }
      elseif ($lower -match 'found corrupt files|发现损坏') { $passed = $false }
      if ($result.timedOut) { Add-Warning ('sfc 超时（' + $wanted + ' 秒）已终止，结果可能不完整') }
      return [pscustomobject][ordered]@{
        ok       = ($result.exitCode -eq 0 -and -not $result.timedOut)
        mode     = 'sfc'
        actions  = @([pscustomobject][ordered]@{ step = 'sfc /scannow'; ok = ($result.exitCode -eq 0); detail = ('exit=' + $result.exitCode + ' passed=' + $passed) })
        output   = [string]$result.output
        passed   = $passed
        warnings = @($script:Warnings)
      }
    }
    'dism' {
      Confirm-Admin
      $wanted = 1800
      try { $wanted = [int](Get-GuardParam -Name 'timeoutSec' -Default $wanted) } catch { }
      if ($wanted -lt 300) { $wanted = 300 }
      $dismPath = Join-Path $script:SystemRoot 'System32\Dism.exe'
      $result = Invoke-NativeCommand -FilePath $dismPath -Arguments @('/Online', '/Cleanup-Image', '/RestoreHealth') -CommandTimeoutSec $wanted -Description 'DISM /Online /Cleanup-Image /RestoreHealth'
      if ($result.timedOut) { Add-Warning ('DISM 超时（' + $wanted + ' 秒）已终止，结果可能不完整') }
      return [pscustomobject][ordered]@{
        ok       = ($result.exitCode -eq 0 -and -not $result.timedOut)
        mode     = 'dism'
        actions  = @([pscustomobject][ordered]@{ step = 'DISM /Online /Cleanup-Image /RestoreHealth'; ok = ($result.exitCode -eq 0); detail = ('exit=' + $result.exitCode) })
        output   = [string]$result.output
        warnings = @($script:Warnings)
      }
    }
    'backup' {
      $info = Invoke-Backup
      return [pscustomobject][ordered]@{
        ok       = ($info.state -eq 'ok')
        mode     = 'backup'
        actions  = @([pscustomobject][ordered]@{ step = 'backup'; ok = ($info.state -eq 'ok'); detail = [string]$info.root })
        output   = ('备份目录：' + $info.root + '；文件数：' + $info.fileCount)
        warnings = @($script:Warnings)
      }
    }
    default {
      Stop-GuardError -Code 'invalid-params' -Message ('未知修复模式：' + $mode)
    }
  }
}

# ---------------------------------------------------------------------------
# 动作：restore-point
# ---------------------------------------------------------------------------

function Get-NewestRestorePointTime {
  try {
    $points = @(Get-ComputerRestorePoint -ErrorAction Stop)
    $newest = $null
    foreach ($point in $points) {
      $raw = Get-ObjectProp -Object $point -Name 'CreationTime' -Default $null
      if ($null -eq $raw) { continue }
      $dt = $null
      try { $dt = [System.Management.ManagementDateTimeConverter]::ToDateTime([string]$raw) } catch { try { $dt = [System.DateTime]$raw } catch { $dt = $null } }
      if ($null -eq $dt) { continue }
      if ($null -eq $newest -or $dt -gt $newest) { $newest = $dt }
    }
    return $newest
  } catch { return $null }
}

function Invoke-RestorePoint {
  Confirm-Admin
  $before = Get-NewestRestorePointTime
  $errorMessage = $null
  try {
    Checkpoint-Computer -Description 'dsh-system-guard' -RestorePointType 'MODIFY_SETTINGS' -ErrorAction Stop
  } catch {
    $errorMessage = $_.Exception.Message
  }
  $after = Get-NewestRestorePointTime
  $createdAt = $null
  $created = $false
  if ($null -ne $after) {
    if ($null -eq $before) { $created = $true }
    elseif ($after -gt $before) { $created = $true }
    if ($created) { $createdAt = $after }
  }

  if ($null -ne $errorMessage) {
    $hint = '创建系统还原点失败：' + $errorMessage
    $lower = $errorMessage.ToLowerInvariant()
    if ($lower -match 'disabled|未启用|被禁用|组策略') {
      $hint = '系统保护未启用，无法创建还原点。请在「系统属性 → 系统保护」为系统盘开启系统保护后重试。原始错误：' + $errorMessage
    }
    return [pscustomobject][ordered]@{
      ok             = $false
      message        = $hint
      restorePointAt = $null
      output         = $errorMessage
      warnings       = @($script:Warnings)
    }
  }

  if ($created) {
    return [pscustomobject][ordered]@{
      ok             = $true
      message        = '已创建系统还原点「dsh-system-guard」'
      restorePointAt = (ConvertTo-EpochMs $createdAt)
      output         = ''
      warnings       = @($script:Warnings)
    }
  }

  $latestText = ''
  if ($null -ne $after) { $latestText = '；最新还原点：' + (ConvertTo-IsoUtc $after) }
  return [pscustomobject][ordered]@{
    ok             = $false
    message        = ('未创建新的系统还原点（Windows 默认每 24 小时最多创建一次，本次可能被频率限制跳过）' + $latestText)
    restorePointAt = $null
    output         = ''
    warnings       = @($script:Warnings)
  }
}

# ---------------------------------------------------------------------------
# 动作：patrol
# ---------------------------------------------------------------------------

function Get-PatrolWindow {
  $explicit = Get-GuardParam -Name 'updateWindow' -Default $null
  if ($null -ne $explicit) {
    $fromIso = [string](Get-ObjectProp -Object $explicit -Name 'from' -Default '')
    $toIso = [string](Get-ObjectProp -Object $explicit -Name 'to' -Default '')
    $fromUtc = ConvertFrom-IsoToUtc $fromIso
    $toUtc = ConvertFrom-IsoToUtc $toIso
    if ($null -ne $fromUtc -and $null -ne $toUtc) {
      return [pscustomobject][ordered]@{ fromUtc = $fromUtc; toUtc = $toUtc; fromMs = (ConvertTo-EpochMs $fromUtc); toMs = (ConvertTo-EpochMs $toUtc) }
    }
  }
  $minutes = 1440
  try { $minutes = [int](Get-GuardParam -Name 'excludeUpdateWindowMinutes' -Default 1440) } catch { $minutes = 1440 }
  $window = Get-UpdateWindowInfo -Minutes $minutes
  if ($null -eq $window) { return $null }
  return [pscustomobject][ordered]@{ fromUtc = $window.fromUtc; toUtc = $window.toUtc; fromMs = $window.fromMs; toMs = $window.toMs }
}

function Test-ExemptedByUpdateWindow {
  param($Window, $LastWriteUtc)
  if ($null -eq $Window) { return $false }
  if ($null -eq $LastWriteUtc) { return $false }
  $slackSeconds = 600
  try {
    $mtime = $LastWriteUtc
    if ($mtime -isnot [System.DateTime]) { $mtime = [System.DateTime]$LastWriteUtc }
    if ($mtime.Kind -ne [System.DateTimeKind]::Utc) { $mtime = $mtime.ToUniversalTime() }
    if ($mtime -lt $Window.fromUtc) { return $false }
    if ($mtime -gt $Window.toUtc.AddSeconds($slackSeconds)) { return $false }
    return $true
  } catch { return $false }
}

function Get-BackupStateQuick {
  $roots = Get-BackupRoots
  if ($roots.Count -eq 0) { return 'none' }
  $hasManifest = $false
  $hasDir = $false
  foreach ($candidate in $roots) {
    if (Test-DirExists $candidate.root) { $hasDir = $true }
    if (Test-FileExists $candidate.manifest) { $hasManifest = $true; break }
  }
  if (-not $hasDir) { return 'none' }
  if (-not $hasManifest) { return 'missing' }
  $found = Find-BackupManifestRoot
  if ($null -eq $found) { return 'missing' }
  $manifestFiles = @(Get-ObjectProp -Object $found.manifest -Name 'files' -Default @())
  if ($manifestFiles.Count -eq 0) { return 'partial' }
  foreach ($fileEntry in $manifestFiles) {
    if ($null -eq $fileEntry) { continue }
    $rel = [string](Get-ObjectProp -Object $fileEntry -Name 'rel' -Default '')
    if ([string]::IsNullOrWhiteSpace($rel)) { continue }
    if (-not (Test-FileExists (Join-Path $found.root $rel))) { return 'partial' }
  }
  return 'ok'
}

function Invoke-Patrol {
  $filesParam = Get-GuardParam -Name 'files' -Default $null
  $window = Get-PatrolWindow
  $sfcRequested = $false
  try { $sfcRequested = [bool](Get-GuardParam -Name 'sfc' -Default $false) } catch { $sfcRequested = $false }

  # 目标清单：优先用调用方给的基线，否则用内置核心清单
  $targets = New-Object 'System.Collections.Generic.List[object]'
  if ($null -ne $filesParam -and @($filesParam).Count -gt 0) {
    foreach ($item in @($filesParam)) {
      if ($null -eq $item) { continue }
      $path = [string](Get-ObjectProp -Object $item -Name 'path' -Default '')
      if ([string]::IsNullOrWhiteSpace($path)) { continue }
      $targets.Add([pscustomobject][ordered]@{
          path     = $path
          expectedSha  = [string](Get-ObjectProp -Object $item -Name 'sha256' -Default '')
          expectedSize = (Get-ObjectProp -Object $item -Name 'size' -Default $null)
          role     = [string](Get-ObjectProp -Object $item -Name 'role' -Default 'core')
        })
      if ($targets.Count -ge 600) { break }
    }
    if (@($filesParam).Count -gt 600) { Add-Warning '巡查清单超过 600 条，已只检查前 600 条' }
  } else {
    foreach ($entry in (Get-ProtectedManifestEntries)) {
      if ($entry.role -ne 'core') { continue }
      $targets.Add([pscustomobject][ordered]@{
          path = $entry.path
          expectedSha = ''
          expectedSize = $null
          role = 'core'
        })
    }
    Add-Warning '调用方未提供基线清单，本次巡查使用内置核心清单（无期望哈希，仅做存在性检查）'
  }

  $changed = New-Object 'System.Collections.Generic.List[object]'
  $missing = New-Object 'System.Collections.Generic.List[string]'
  $unchanged = 0
  $hashErrors = 0
  $nonExemptChanged = 0
  $sizeMismatch = 0

  foreach ($target in $targets) {
    if (-not (Test-FileExists $target.path)) {
      $missing.Add([string]$target.path)
      continue
    }
    $actualSize = Get-FileSizeSafe $target.path
    if ($actualSize -lt 0) {
      $missing.Add([string]$target.path)
      continue
    }
    $expectedSha = [string]$target.expectedSha
    $actualSha = $null
    if (-not [string]::IsNullOrWhiteSpace($expectedSha)) {
      $actualSha = Get-FileSha256 $target.path
      if ($null -eq $actualSha) { $hashErrors++ }
    }
    $sizeChanged = $false
    if ($null -ne $target.expectedSize) {
      try { if ([long]$target.expectedSize -ne $actualSize) { $sizeChanged = $true } } catch { }
    }
    $isChanged = $false
    if ($sizeChanged) { $isChanged = $true; $sizeMismatch++ }
    elseif (-not [string]::IsNullOrWhiteSpace($expectedSha) -and $null -ne $actualSha -and $actualSha -ne $expectedSha) { $isChanged = $true }

    if (-not $isChanged) { $unchanged++; continue }

    $lastWrite = Get-FileLastWriteUtc $target.path
    $exempted = Test-ExemptedByUpdateWindow -Window $window -LastWriteUtc $lastWrite
    if (-not $exempted) { $nonExemptChanged++ }
    $changed.Add([pscustomobject][ordered]@{
        path         = [string]$target.path
        expectedSha  = $expectedSha
        actualSha    = $actualSha
        expectedSize = $target.expectedSize
        actualSize   = $actualSize
        exempted     = [bool]$exempted
        reason       = $(if ($exempted) { 'windows-update-window' } else { 'changed' })
      })
  }

  # SFC：默认不跑（太慢），只有调用方显式要求才跑
  $sfcResult = [pscustomobject][ordered]@{ ran = $false; passed = $null; detail = '' }
  if ($sfcRequested) {
    if (-not (Test-IsAdmin)) {
      Add-Warning '请求了 SFC 巡查，但当前不是管理员，已跳过（sfc 需要管理员权限）'
      $sfcResult = [pscustomobject][ordered]@{ ran = $false; passed = $null; detail = '需要管理员权限，请在面板点「授予守护权限」' }
    } else {
      $wanted = 1800
      try { $wanted = [int](Get-GuardParam -Name 'sfcTimeoutSec' -Default 1800) } catch { }
      $run = Invoke-NativeCommand -FilePath (Join-Path $script:SystemRoot 'System32\sfc.exe') -Arguments @('/scannow') -CommandTimeoutSec $wanted -Description 'sfc /scannow'
      $passed = $null
      $lower = ([string]$run.output).ToLowerInvariant()
      if ($lower -match 'did not find any integrity violations|未找到任何完整性冲突') { $passed = $true }
      elseif ($lower -match 'found corrupt files|发现损坏') { $passed = $false }
      if ($run.timedOut) { Add-Warning '巡查中的 sfc 超时已终止' }
      $sfcResult = [pscustomobject][ordered]@{ ran = $true; passed = $passed; detail = ([string]$run.output) }
    }
  }

  # 备份状态（只看存在性，不做全量哈希，保证巡查速度）
  $backupState = 'none'
  try { $backupState = Get-BackupStateQuick } catch { $backupState = 'unknown' }

  $total = $targets.Count
  $verdict = 'unknown'
  if ($total -gt 0) {
    if ($missing.Count -gt 0) { $verdict = 'damaged' }
    elseif ($nonExemptChanged -gt 0) {
      if ($sizeMismatch -gt 0) { $verdict = 'damaged' } else { $verdict = 'changed' }
    }
    elseif ($hashErrors -gt 0 -and $hashErrors -ge [int]($total / 2)) { $verdict = 'unknown' }
    else { $verdict = 'healthy' }
  }
  if ($hashErrors -gt 0) { Add-Warning ('有 ' + $hashErrors + ' 个文件哈希读取失败，结果可能不完整') }

  return [pscustomobject][ordered]@{
    checkedAt = (ConvertTo-EpochMs (Get-Date))
    durationMs = [int]((Get-Date) - $script:StartedAt).TotalMilliseconds
    total      = $total
    unchanged  = $unchanged
    changed    = $changed
    missing    = $missing
    verdict    = $verdict
    sfc        = $sfcResult
    backup     = [pscustomobject][ordered]@{ state = $backupState }
    updateWindow = $(if ($null -ne $window) { [pscustomobject][ordered]@{ from = (ConvertTo-IsoUtc $window.fromUtc); to = (ConvertTo-IsoUtc $window.toUtc) } } else { $null })
    warnings   = @($script:Warnings)
  }
}

# ---------------------------------------------------------------------------
# 动作：calibrate-facts
# ---------------------------------------------------------------------------

function Invoke-CalibrateFacts {
  $osName = 'Microsoft Windows'
  $osVersion = [System.Environment]::OSVersion.Version.ToString()
  $osBuild = [System.Environment]::OSVersion.Version.Build.ToString()
  $arch = $env:PROCESSOR_ARCHITECTURE
  try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $caption = [string](Get-ObjectProp -Object $os -Name 'Caption' -Default '')
    $version = [string](Get-ObjectProp -Object $os -Name 'Version' -Default '')
    $build = [string](Get-ObjectProp -Object $os -Name 'BuildNumber' -Default '')
    if (-not [string]::IsNullOrWhiteSpace($caption)) { $osName = $caption.Trim() }
    if (-not [string]::IsNullOrWhiteSpace($version)) { $osVersion = $version.Trim() }
    if (-not [string]::IsNullOrWhiteSpace($build)) { $osBuild = $build.Trim() }
  } catch {
    Add-Warning ('读取操作系统信息失败：' + $_.Exception.Message)
  }
  if ([string]::IsNullOrWhiteSpace($arch)) { $arch = 'unknown' }

  $files = New-Object 'System.Collections.Generic.List[object]'
  foreach ($entry in (Get-ProtectedManifestEntries)) {
    if ($files.Count -ge 80) { break }
    if ($entry.role -ne 'core') { continue }
    if (-not (Test-FileExists $entry.path)) { continue }
    $sha = Get-FileSha256 $entry.path
    if ($null -eq $sha) {
      Add-Warning ('哈希读取失败，已跳过：' + $entry.path)
      continue
    }
    $files.Add([pscustomobject][ordered]@{
        path    = $entry.path
        version = (Get-FileVersionText $entry.path)
        sha256  = $sha
      })
  }
  if ($files.Count -eq 0) { Add-Warning '没有任何核心文件可用于校准（清单全部未命中）' }

  return [pscustomobject][ordered]@{
    platform  = 'windows'
    osName    = $osName
    osVersion = $osVersion
    osBuild   = $osBuild
    arch      = $arch
    files     = $files
    warnings  = @($script:Warnings)
  }
}

# ---------------------------------------------------------------------------
# 动作分发
# ---------------------------------------------------------------------------

function Invoke-GuardAction {
  param([string]$ActionName)
  $normalized = $ActionName.Trim().ToLowerInvariant()
  switch ($normalized) {
    'probe' { return (Invoke-Probe) }
    'analyze' { return (Invoke-Analyze) }
    'patrol' { return (Invoke-Patrol) }
    'junk-scan' { return (Invoke-JunkScan) }
    'junk-delete' { return (Invoke-JunkDelete) }
    'backup' { return (Invoke-Backup) }
    'backup-status' { return (Invoke-BackupStatus) }
    'restore' { return (Invoke-Restore) }
    'repair' { return (Invoke-Repair) }
    'calibrate-facts' { return (Invoke-CalibrateFacts) }
    'restore-point' { return (Invoke-RestorePoint) }
    default {
      Stop-GuardError -Code 'invalid-action' -Message ('未知动作：' + $ActionName)
    }
  }
}

# ---------------------------------------------------------------------------
# 主入口
# ---------------------------------------------------------------------------
try {
  if ([string]::IsNullOrWhiteSpace($Action)) { throw '缺少 -Action 参数' }
  if ([string]::IsNullOrWhiteSpace($OutFile)) { throw '缺少 -OutFile 参数' }
  $script:GuardParams = Read-GuardParams
  $value = Invoke-GuardAction -ActionName $Action
  Write-GuardResult -Ok $true -ActionName $Action -Value $value
  Write-Output ('[dsh-system-guard] ' + $Action + ' ok in ' + [int](((Get-Date) - $script:StartedAt).TotalMilliseconds) + ' ms')
} catch {
  $code = Get-GuardErrorCode $_
  $message = ''
  try { $message = $_.Exception.Message } catch { $message = '未知错误' }
  try {
    Write-GuardResult -Ok $false -ActionName $Action -Code $code -Message $message
    Write-Output ('[dsh-system-guard] ' + $Action + ' failed: ' + $code + ' ' + $message)
  } catch {
    Write-Output ('[dsh-system-guard] 结果文件写入失败：' + $_.Exception.Message)
    $script:ExitCode = 1
  }
}
exit $script:ExitCode
