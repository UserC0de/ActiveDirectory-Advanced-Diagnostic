# Analisis avanzado del estado del Active Directory y diagnostico ajustado para pedir dominio

function Mostrar-Resumen {
    # Ruta archivo resumen en Escritorio con timestamp para evitar sobreescritura
    $rutaResumen = "$env:USERPROFILE\Desktop\Resumen_AD_$(Get-Date -Format 'yyyyMMdd_HHmm').txt"

    $output = @()
    $output += "Analizando estado general del AD..."

    # Obtención de métricas clave del AD
    $usuariosTotales = (Get-ADUser -Filter *).Count
    $usuariosDeshabilitados = (Get-ADUser -Filter 'Enabled -eq $false').Count
    $usuariosPwdNeverExpires = (Get-ADUser -Filter 'PasswordNeverExpires -eq $true').Count
    $usuariosSinLogin = (Get-ADUser -Filter * -Properties LastLogonDate | Where-Object { -not $_.LastLogonDate }).Count
    $usuariosInactivos = (Get-ADUser -Filter * -Properties LastLogonDate | Where-Object { $_.LastLogonDate -lt (Get-Date).AddDays(-90) }).Count

    $equiposTotales = (Get-ADComputer -Filter *).Count
    $equiposInactivos = (Get-ADComputer -Filter * -Properties LastLogonDate | Where-Object { $_.LastLogonDate -lt (Get-Date).AddDays(-90) }).Count

    $gruposTotales = (Get-ADGroup -Filter *).Count
    $gruposVacios = (Get-ADGroup -Filter * | Where-Object { (Get-ADGroupMember $_ -ErrorAction SilentlyContinue).Count -eq 0 }).Count

    $cuentasCaducadas = (Search-ADAccount -AccountExpired).Count
    $cuentasBloqueadas = (Search-ADAccount -LockedOut).Count

    # Obtener miembros del grupo "Administradores del dominio"
    $adminGroup = Get-ADGroup -Filter { Name -like '*Administradores del dominio*' } -ErrorAction SilentlyContinue
    $adminsDominio = if ($adminGroup) { (Get-ADGroupMember -Identity $adminGroup -Recursive).Count } else { 'N/A' }

    # Construcción del reporte
    $output += @(
        "======================================"
        "        ESTADO GENERAL DEL AD"
        "======================================"
        "Usuarios totales:                   $usuariosTotales"
        "Usuarios deshabilitados:            $usuariosDeshabilitados"
        "Usuarios con pwd never expires:     $usuariosPwdNeverExpires"
        "Usuarios sin logon registrado:      $usuariosSinLogin"
        "Usuarios inactivos (+90d):          $usuariosInactivos"
        "Cuentas expiradas:                  $cuentasCaducadas"
        "Cuentas bloqueadas:                 $cuentasBloqueadas"
        "--------------------------------------"
        "Equipos totales:                    $equiposTotales"
        "Equipos inactivos (+90d):           $equiposInactivos"
        "--------------------------------------"
        "Grupos totales:                     $gruposTotales"
        "Grupos vacios:                      $gruposVacios"
        "--------------------------------------"
        "Miembros del grupo 'Administradores del dominio': $adminsDominio"
        "======================================"
    )

    # Exportar a archivo UTF8
    $output | Out-File -FilePath $rutaResumen -Encoding UTF8

    # Mostrar en pantalla
    Write-Host ($output -join "`n")

    return $rutaResumen
}

function Diagnostico-ServiciosAD {
    $diag = @()
    $diag += "============= DIAGNOSTICO DEL AD ============="

    do {
        $domainName = Read-Host -Prompt "Ingrese el nombre del dominio (FQDN) para el diagnóstico"
        if ([string]::IsNullOrWhiteSpace($domainName)) {
            Write-Host "El nombre del dominio no puede estar vacío. Intente nuevamente." -ForegroundColor Yellow
        }
    } while ([string]::IsNullOrWhiteSpace($domainName))

    Write-Host "DEBUG: Dominio recibido: '$domainName'" -ForegroundColor Cyan

    try {
        # Usar -Discover con -Domain para obtener DC válido
        $dc = Get-ADDomainController -Discover -Domain $domainName -ErrorAction Stop
        $diag += "Controlador de dominio: OK [$($dc.HostName)]"
    } catch {
        $diag += "Controlador de dominio: ERROR - No se pudo encontrar controlador para el dominio '$domainName'. Error: $_"
        Write-Host ($diag -join "`n")
        return
    }

    try {
        $ping = Test-Connection -ComputerName $dc.HostName -Count 2 -Quiet
        if ($ping) {
            $diag += "Conexion al DC: OK"
        } else {
            $diag += "Conexion al DC: ERROR - No se pudo contactar al controlador mediante ping"
        }
    } catch {
        $diag += "Conexion al DC: ERROR - Excepción durante el ping: $_"
    }

    try {
        repadmin /replsummary | Out-Null
        $diag += "Replicacion: OK"
    } catch {
        $diag += "Replicacion: ERROR - Fallo al ejecutar repadmin"
    }

    try {
        $netlogon = Get-Service -Name Netlogon -ErrorAction Stop
        if ($netlogon.Status -eq 'Running') {
            $diag += "Servicio Netlogon: OK"
        } else {
            $diag += "Servicio Netlogon: ERROR - Servicio no está en estado 'Running' (Estado actual: $($netlogon.Status))"
        }
    } catch {
        $diag += "Servicio Netlogon: ERROR - Servicio no encontrado o no accesible"
    }

    try {
        $dns = Get-Service -Name DNS -ErrorAction Stop
        if ($dns.Status -eq 'Running') {
            $diag += "Servicio DNS: OK"
        } else {
            $diag += "Servicio DNS: ERROR - Servicio no está en estado 'Running' (Estado actual: $($dns.Status))"
        }
    } catch {
        $diag += "Servicio DNS: ERROR - Servicio no encontrado o no accesible"
    }

    try {
        w32tm /query /status 2>$null | Out-Null
        $diag += "Sincronizacion horaria (NTP): OK"
    } catch {
        $diag += "Sincronizacion horaria (NTP): ERROR - Fallo al consultar estado NTP"
    }

    $diag += "==============================================="

    Write-Host ($diag -join "`n")

    $rutaResumen = "$env:USERPROFILE\Desktop\Resumen_AD_$(Get-Date -Format 'yyyyMMdd_HHmm').txt"
    $diag | Out-File -Append -FilePath $rutaResumen -Encoding UTF8
}
function Diagnostico-ServiciosAD {
    $diag = @()
    $diag += "============= DIAGNOSTICO DEL AD ============="

    do {
        $domainName = Read-Host -Prompt "Ingrese el nombre del dominio (FQDN) para el diagnóstico"
        if ([string]::IsNullOrWhiteSpace($domainName)) {
            Write-Host "El nombre del dominio no puede estar vacío. Intente nuevamente." -ForegroundColor Yellow
        }
    } while ([string]::IsNullOrWhiteSpace($domainName))

    Write-Host "DEBUG: Dominio recibido: '$domainName'" -ForegroundColor Cyan

    try {
        # Usar -Discover con -Domain para obtener DC válido
        $dc = Get-ADDomainController -Discover -Domain $domainName -ErrorAction Stop
        $diag += "Controlador de dominio: OK [$($dc.HostName)]"
    } catch {
        $diag += "Controlador de dominio: ERROR - No se pudo encontrar controlador para el dominio '$domainName'. Error: $_"
        Write-Host ($diag -join "`n")
        return
    }

    try {
        $ping = Test-Connection -ComputerName $dc.HostName -Count 2 -Quiet
        if ($ping) {
            $diag += "Conexion al DC: OK"
        } else {
            $diag += "Conexion al DC: ERROR - No se pudo contactar al controlador mediante ping"
        }
    } catch {
        $diag += "Conexion al DC: ERROR - Excepción durante el ping: $_"
    }

    try {
        repadmin /replsummary | Out-Null
        $diag += "Replicacion: OK"
    } catch {
        $diag += "Replicacion: ERROR - Fallo al ejecutar repadmin"
    }

    try {
        $netlogon = Get-Service -Name Netlogon -ErrorAction Stop
        if ($netlogon.Status -eq 'Running') {
            $diag += "Servicio Netlogon: OK"
        } else {
            $diag += "Servicio Netlogon: ERROR - Servicio no está en estado 'Running' (Estado actual: $($netlogon.Status))"
        }
    } catch {
        $diag += "Servicio Netlogon: ERROR - Servicio no encontrado o no accesible"
    }

    try {
        $dns = Get-Service -Name DNS -ErrorAction Stop
        if ($dns.Status -eq 'Running') {
            $diag += "Servicio DNS: OK"
        } else {
            $diag += "Servicio DNS: ERROR - Servicio no está en estado 'Running' (Estado actual: $($dns.Status))"
        }
    } catch {
        $diag += "Servicio DNS: ERROR - Servicio no encontrado o no accesible"
    }

    try {
        w32tm /query /status 2>$null | Out-Null
        $diag += "Sincronizacion horaria (NTP): OK"
    } catch {
        $diag += "Sincronizacion horaria (NTP): ERROR - Fallo al consultar estado NTP"
    }

    $diag += "==============================================="

    Write-Host ($diag -join "`n")

    $rutaResumen = "$env:USERPROFILE\Desktop\Resumen_AD_$(Get-Date -Format 'yyyyMMdd_HHmm').txt"
    $diag | Out-File -Append -FilePath $rutaResumen -Encoding UTF8
}



# Ejecución principal
$rutaResumen = Mostrar-Resumen
Diagnostico-ServiciosAD

Write-Host "`nAnálisis completo. El resumen se guardó en: $rutaResumen`n"
Pause
