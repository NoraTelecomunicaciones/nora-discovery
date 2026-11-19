<#
 Nora Discovery - buscador de equipos de red compatibles con el protocolo de descubrimiento UDP 10001
 (airMAX, airFiber, LTU, EdgeMAX, UniFi y otros que lo implementan).
 Software libre y gratuito. No requiere Java ni instalacion: Windows PowerShell 5.1 o superior.
 Proyecto independiente de Nora Telecomunicaciones; no esta afiliado a Ubiquiti Inc.
#>
param([switch]$Consola, [int]$Segundos = 4)

$ErrorActionPreference = 'Stop'
$Version = '1.0.0'
$Puerto = 10001

# ---------- protocolo ----------
function Get-Interfaces {
    $r = @()
    foreach ($nic in [Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces()) {
        if ($nic.OperationalStatus -ne 'Up' -or $nic.NetworkInterfaceType -eq 'Loopback') { continue }
        foreach ($ua in $nic.GetIPProperties().UnicastAddresses) {
            if ($ua.Address.AddressFamily -ne 'InterNetwork') { continue }
            $ip = $ua.Address.GetAddressBytes(); $mask = $ua.IPv4Mask.GetAddressBytes()
            if ($ip[0] -eq 169 -and $ip[1] -eq 254) { continue }
            $bc = New-Object byte[] 4
            for ($i = 0; $i -lt 4; $i++) { $bc[$i] = $ip[$i] -bor (-bnot $mask[$i] -band 0xFF) }
            $r += [pscustomobject]@{ Nombre = $nic.Name; IP = $ua.Address; Broadcast = (New-Object Net.IPAddress (, $bc)) }
        }
    }
    return $r
}

function Open-Sockets {
    $socks = @()
    foreach ($if in (Get-Interfaces)) {
        try {
            $u = New-Object Net.Sockets.UdpClient (New-Object Net.IPEndPoint ($if.IP, 0))
            $u.EnableBroadcast = $true
            $socks += [pscustomobject]@{ Udp = $u; If = $if }
        } catch { }
    }
    return $socks
}

function Send-Consulta($socks) {
    [byte[]]$v1 = 1, 0, 0, 0
    [byte[]]$v2 = 2, 8, 0, 0
    foreach ($s in $socks) {
        foreach ($dst in @('255.255.255.255', $s.If.Broadcast.ToString(), '233.89.188.1')) {
            foreach ($pl in @(, $v1) + @(, $v2)) { try { [void]$s.Udp.Send($pl, 4, $dst, $Puerto) } catch { } }
        }
    }
}

function Format-Mac([byte[]]$b, [int]$o) { return (($b[$o..($o + 5)] | ForEach-Object { $_.ToString('X2') }) -join ':') }
function Format-Uptime([long]$s) {
    $d = [math]::Floor($s / 86400); $h = [math]::Floor(($s % 86400) / 3600); $m = [math]::Floor(($s % 3600) / 60)
    if ($d -gt 0) { return ('{0}d {1}h {2}m' -f $d, $h, $m) }
    if ($h -gt 0) { return ('{0}h {1}m' -f $h, $m) }
    return ('{0}m' -f $m)
}

# Convierte una respuesta en un objeto. Formato: cabecera de 4 bytes y campos tipo(1) largo(2) valor.
function ConvertFrom-Respuesta([byte[]]$b, [string]$origen) {
    if ($b.Length -lt 8) { return $null }
    $e = [ordered]@{ MAC = ''; IP = $origen; IPs = @(); Nombre = ''; Modelo = ''; ModeloCorto = ''; Firmware = ''; FirmwareCompleto = ''; ESSID = ''; Modo = ''; Uptime = ''; UptimeSeg = [long]0 }
    $o = 4
    while ($o + 3 -le $b.Length) {
        $t = $b[$o]; $l = ([int]$b[$o + 1] -shl 8) -bor [int]$b[$o + 2]; $v = $o + 3
        if ($v + $l -gt $b.Length) { break }
        switch ($t) {
            0x01 { if ($l -ge 6) { $e.MAC = Format-Mac $b $v } }
            0x02 { if ($l -ge 10) { if (-not $e.MAC) { $e.MAC = Format-Mac $b $v }; $e.IPs += ('{0}.{1}.{2}.{3}' -f $b[$v + 6], $b[$v + 7], $b[$v + 8], $b[$v + 9]) } }
            0x03 { $e.FirmwareCompleto = [Text.Encoding]::UTF8.GetString($b, $v, $l).Trim([char]0) }
            0x0A { if ($l -ge 4) { $e.UptimeSeg = ([long]$b[$v] -shl 24) -bor ([long]$b[$v + 1] -shl 16) -bor ([long]$b[$v + 2] -shl 8) -bor [long]$b[$v + 3]; $e.Uptime = Format-Uptime $e.UptimeSeg } }
            0x0B { $e.Nombre = [Text.Encoding]::UTF8.GetString($b, $v, $l).Trim([char]0) }
            0x0C { $e.ModeloCorto = [Text.Encoding]::UTF8.GetString($b, $v, $l).Trim([char]0) }
            0x0D { $e.ESSID = [Text.Encoding]::UTF8.GetString($b, $v, $l).Trim([char]0) }
            0x0E { if ($l -ge 1) { $e.Modo = switch ($b[$v]) { 0 { '' } 2 { 'Estación' } 3 { 'AP' } default { "$($b[$v])" } } } }
            0x13 { if (-not $e.MAC -and $l -ge 6) { $e.MAC = Format-Mac $b $v } }
            0x14 { $e.Modelo = [Text.Encoding]::UTF8.GetString($b, $v, $l).Trim([char]0) }
            0x15 { if (-not $e.ModeloCorto) { $e.ModeloCorto = [Text.Encoding]::UTF8.GetString($b, $v, $l).Trim([char]0) } }
            0x16 { if (-not $e.FirmwareCompleto) { $e.FirmwareCompleto = [Text.Encoding]::UTF8.GetString($b, $v, $l).Trim([char]0) } }
        }
        $o = $v + $l
    }
    if (-not $e.MAC) { return $null }
    if (-not $e.Modelo) { $e.Modelo = $e.ModeloCorto }
    $e.Firmware = if ($e.FirmwareCompleto -match 'v\d+\.\d+(\.\d+)?') { $Matches[0] } elseif ($e.FirmwareCompleto -match '\d+\.\d+(\.\d+)?') { $Matches[0] } else { $e.FirmwareCompleto }
    if (-not $e.IP -and $e.IPs.Count) { $e.IP = $e.IPs[0] }
    return [pscustomobject]$e
}

function Receive-Pendientes($socks, [hashtable]$equipos) {
    $nuevos = 0
    foreach ($s in $socks) {
        try {
            while ($s.Udp.Available -gt 0) {
                $ep = New-Object Net.IPEndPoint ([Net.IPAddress]::Any, 0)
                $b = $s.Udp.Receive([ref]$ep)
                $e = ConvertFrom-Respuesta $b $ep.Address.ToString()
                if ($e) { if (-not $equipos.ContainsKey($e.MAC)) { $nuevos++ }; $equipos[$e.MAC] = $e }
            }
        } catch { }
    }
    return $nuevos
}

function IpANumero([string]$ip) { $p = $ip.Split('.'); if ($p.Count -ne 4) { return [long]0 }; return ([long]$p[0] -shl 24) + ([long]$p[1] -shl 16) + ([long]$p[2] -shl 8) + [long]$p[3] }

# ---------- modo consola ----------
if ($Consola) {
    $socks = @(Open-Sockets); $eq = @{}
    Send-Consulta $socks
    $fin = (Get-Date).AddSeconds($Segundos); $re = (Get-Date).AddSeconds(1)
    while ((Get-Date) -lt $fin) {
        [void](Receive-Pendientes $socks $eq)
        if ($re -and (Get-Date) -gt $re) { Send-Consulta $socks; $re = $null }
        Start-Sleep -Milliseconds 50
    }
    $socks | ForEach-Object { $_.Udp.Close() }
    $eq.Values | Sort-Object { IpANumero $_.IP } | Select-Object Modelo, Nombre, IP, MAC, Firmware, ESSID, Modo, Uptime
    return
}

# ---------- interfaz ----------
Add-Type -AssemblyName System.Windows.Forms, System.Drawing
Add-Type -Namespace NoraDisc -Name Dpi -MemberDefinition '[DllImport("user32.dll")] public static extern bool SetProcessDPIAware();'
[void][NoraDisc.Dpi]::SetProcessDPIAware()
[Windows.Forms.Application]::EnableVisualStyles()

$script:Equipos = @{}
$script:Socks = @()
$script:Fin = Get-Date
$script:Reenvio = $null

$tabla = New-Object Data.DataTable
foreach ($c in 'Modelo', 'Nombre', 'IP', 'MAC', 'Firmware', 'ESSID', 'Modo', 'Uptime') { [void]$tabla.Columns.Add($c, [string]) }
[void]$tabla.Columns.Add('IPNum', [long]); [void]$tabla.Columns.Add('UptimeSeg', [long]); [void]$tabla.Columns.Add('Detalle', [string])
$tabla.PrimaryKey = @($tabla.Columns['MAC'])
$vista = New-Object Data.DataView $tabla
$vista.Sort = 'IPNum ASC'

$form = New-Object Windows.Forms.Form
$form.Text = "Nora Discovery $Version"
$form.Size = New-Object Drawing.Size 1180, 680
$form.MinimumSize = New-Object Drawing.Size 760, 380
$form.StartPosition = 'CenterScreen'
$form.Font = New-Object Drawing.Font 'Segoe UI', 9

$barra = New-Object Windows.Forms.Panel; $barra.Dock = 'Top'; $barra.Height = 46; $barra.Padding = New-Object Windows.Forms.Padding 8
$btnScan = New-Object Windows.Forms.Button; $btnScan.Text = 'Buscar equipos'; $btnScan.SetBounds(8, 8, 130, 30)
$lblF = New-Object Windows.Forms.Label; $lblF.Text = 'Filtrar:'; $lblF.SetBounds(154, 14, 50, 20)
$txtF = New-Object Windows.Forms.TextBox; $txtF.SetBounds(206, 11, 260, 24)
$btnCsv = New-Object Windows.Forms.Button; $btnCsv.Text = 'Exportar CSV'; $btnCsv.SetBounds(480, 8, 110, 30)
$lblEstado = New-Object Windows.Forms.Label; $lblEstado.SetBounds(606, 14, 540, 20); $lblEstado.Anchor = 'Top, Left, Right'
$barra.Controls.AddRange(@($btnScan, $lblF, $txtF, $btnCsv, $lblEstado))

$grid = New-Object Windows.Forms.DataGridView
$grid.Dock = 'Fill'; $grid.ReadOnly = $true; $grid.AllowUserToAddRows = $false; $grid.AllowUserToDeleteRows = $false
$grid.AllowUserToResizeRows = $false; $grid.RowHeadersVisible = $false; $grid.SelectionMode = 'FullRowSelect'; $grid.MultiSelect = $true
$grid.AutoSizeColumnsMode = 'Fill'; $grid.BackgroundColor = [Drawing.Color]::White; $grid.BorderStyle = 'None'
$grid.AlternatingRowsDefaultCellStyle.BackColor = [Drawing.Color]::FromArgb(245, 248, 251)
$grid.ClipboardCopyMode = 'EnableWithoutHeaderText'
$grid.DataSource = $vista
$form.Controls.Add($grid); $form.Controls.Add($barra)

$form.Add_Shown({
    foreach ($h in 'IPNum', 'UptimeSeg', 'Detalle') { $grid.Columns[$h].Visible = $false }
    $pesos = @{ Modelo = 16; Nombre = 22; IP = 11; MAC = 14; Firmware = 9; ESSID = 16; Modo = 6; Uptime = 8 }
    foreach ($k in $pesos.Keys) { $grid.Columns[$k].FillWeight = $pesos[$k] }
    Start-Busqueda
})

function Actualizar-Tabla {
    foreach ($e in $script:Equipos.Values) {
        $r = $tabla.Rows.Find($e.MAC)
        if (-not $r) { $r = $tabla.NewRow(); $r['MAC'] = $e.MAC; $tabla.Rows.Add($r) }
        foreach ($c in 'Modelo', 'Nombre', 'IP', 'Firmware', 'ESSID', 'Modo', 'Uptime') { if ("$($r[$c])" -ne "$($e.$c)") { $r[$c] = "$($e.$c)" } }
        $r['IPNum'] = IpANumero $e.IP; $r['UptimeSeg'] = $e.UptimeSeg
        $r['Detalle'] = "Firmware: $($e.FirmwareCompleto)`nDirecciones: $(($e.IPs | Sort-Object -Unique) -join ', ')"
    }
}
function Actualizar-Estado([string]$extra) {
    $t = "$($tabla.Rows.Count) equipos"
    if ($vista.Count -ne $tabla.Rows.Count) { $t += " ($($vista.Count) visibles)" }
    if ($extra) { $t += " - $extra" }
    $lblEstado.Text = $t
}

$timer = New-Object Windows.Forms.Timer; $timer.Interval = 120
$timer.Add_Tick({
    $n = Receive-Pendientes $script:Socks $script:Equipos
    if ($n -gt 0) { Actualizar-Tabla; Actualizar-Estado 'buscando...' }
    if ($script:Reenvio -and (Get-Date) -gt $script:Reenvio) { Send-Consulta $script:Socks; $script:Reenvio = $null }
    if ((Get-Date) -gt $script:Fin) {
        $timer.Stop(); [void](Receive-Pendientes $script:Socks $script:Equipos); Actualizar-Tabla
        $script:Socks | ForEach-Object { $_.Udp.Close() }; $script:Socks = @()
        $btnScan.Enabled = $true; Actualizar-Estado ("última búsqueda " + (Get-Date -Format 'HH:mm:ss'))
    }
})

function Start-Busqueda {
    if (-not $btnScan.Enabled) { return }
    $btnScan.Enabled = $false
    $script:Equipos = @{}; $tabla.Rows.Clear()
    $script:Socks = @(Open-Sockets)   # @(): con una sola red, PowerShell 5.1 devuelve un objeto suelto sin .Count
    if ($script:Socks.Count -eq 0) { $btnScan.Enabled = $true; $lblEstado.Text = 'No hay ninguna red activa en este equipo.'; return }
    Send-Consulta $script:Socks
    $script:Fin = (Get-Date).AddSeconds($Segundos); $script:Reenvio = (Get-Date).AddSeconds(1)
    Actualizar-Estado 'buscando...'
    $timer.Start()
}

function Seleccion([string]$col) { @($grid.SelectedRows | ForEach-Object { "$($_.Cells[$col].Value)" } | Where-Object { $_ }) }
function Abrir([string]$esquema) { foreach ($ip in (Seleccion 'IP' | Select-Object -First 8)) { Start-Process "${esquema}://$ip" } }
function Copiar([string]$col) { $v = Seleccion $col; if ($v.Count) { [Windows.Forms.Clipboard]::SetText(($v -join "`r`n")) } }

$menu = New-Object Windows.Forms.ContextMenuStrip
[void]$menu.Items.Add('Abrir en el navegador (https)', $null, { Abrir 'https' })
[void]$menu.Items.Add('Abrir en el navegador (http)', $null, { Abrir 'http' })
[void]$menu.Items.Add('Conectar por SSH', $null, { foreach ($ip in (Seleccion 'IP' | Select-Object -First 4)) { Start-Process cmd.exe -ArgumentList '/k', "ssh ubnt@$ip" } })
[void]$menu.Items.Add('-')
[void]$menu.Items.Add('Copiar IP', $null, { Copiar 'IP' })
[void]$menu.Items.Add('Copiar MAC', $null, { Copiar 'MAC' })
[void]$menu.Items.Add('Copiar nombre', $null, { Copiar 'Nombre' })
$grid.ContextMenuStrip = $menu
$grid.Add_CellMouseDown({ param($s, $e) if ($e.Button -eq 'Right' -and $e.RowIndex -ge 0 -and -not $grid.Rows[$e.RowIndex].Selected) { $grid.ClearSelection(); $grid.Rows[$e.RowIndex].Selected = $true } })
$grid.Add_CellDoubleClick({ param($s, $e) if ($e.RowIndex -ge 0) { Abrir 'https' } })
$grid.Add_CellFormatting({ param($s, $e) if ($e.RowIndex -ge 0 -and $e.ColumnIndex -ge 0) { $grid.Rows[$e.RowIndex].Cells[$e.ColumnIndex].ToolTipText = "$($grid.Rows[$e.RowIndex].Cells['Detalle'].Value)" } })
# Orden correcto de IP y Uptime (por su valor numerico, no como texto)
$grid.Add_ColumnHeaderMouseClick({ param($s, $e)
    $col = $grid.Columns[$e.ColumnIndex].Name
    $clave = switch ($col) { 'IP' { 'IPNum' } 'Uptime' { 'UptimeSeg' } default { "[$col]" } }
    $dir = if ($vista.Sort -eq "$clave ASC") { 'DESC' } else { 'ASC' }
    $vista.Sort = "$clave $dir"
})

$txtF.Add_TextChanged({
    $q = $txtF.Text.Trim().Replace("'", "''").Replace('[', '[[]').Replace('%', '[%]').Replace('*', '[*]')
    if ($q) { $vista.RowFilter = (('Modelo', 'Nombre', 'IP', 'MAC', 'Firmware', 'ESSID', 'Modo') | ForEach-Object { "[$_] LIKE '%$q%'" }) -join ' OR ' } else { $vista.RowFilter = '' }
    Actualizar-Estado ''
})
$btnScan.Add_Click({ Start-Busqueda })
$btnCsv.Add_Click({
    $dlg = New-Object Windows.Forms.SaveFileDialog; $dlg.Filter = 'CSV (*.csv)|*.csv'; $dlg.FileName = 'equipos-' + (Get-Date -Format 'yyyyMMdd-HHmm') + '.csv'
    if ($dlg.ShowDialog() -eq 'OK') {
        $vista | ForEach-Object { [pscustomobject]@{ Modelo = $_['Modelo']; Nombre = $_['Nombre']; IP = $_['IP']; MAC = $_['MAC']; Firmware = $_['Firmware']; ESSID = $_['ESSID']; Modo = $_['Modo']; Uptime = $_['Uptime'] } } |
            Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding UTF8
    }
})
$form.Add_KeyDown({ param($s, $e) if ($e.KeyCode -eq 'F5') { Start-Busqueda } })
$form.KeyPreview = $true
$form.Add_FormClosed({ $timer.Stop(); $script:Socks | ForEach-Object { try { $_.Udp.Close() } catch { } } })

[void]$form.ShowDialog()
