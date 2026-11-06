param(
    [string]$Password = 'changeit',
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$serverRoot = Split-Path -Parent $PSScriptRoot
$repoRoot = Split-Path -Parent $serverRoot
$config = Join-Path $serverRoot 'config'
$keyStore = Join-Path $config 'dev-server.p12'
New-Item -ItemType Directory -Force $config | Out-Null

if ((Test-Path $keyStore) -and -not $Force) {
    Write-Host "Using existing certificate: $keyStore"
} else {
    if (Test-Path $keyStore) { Remove-Item -LiteralPath $keyStore -Force }
    $keytool = (Get-Command keytool.exe -ErrorAction Stop).Source
    & $keytool `
        -genkeypair `
        -alias secret-auth `
        -keyalg EC `
        -groupname secp256r1 `
        -sigalg SHA256withECDSA `
        -storetype PKCS12 `
        -keystore $keyStore `
        -storepass $Password `
        -keypass $Password `
        -validity 3650 `
        -dname 'CN=localhost, OU=Secret, O=Himitsu, C=CN' `
        -ext 'SAN=dns:localhost,ip:127.0.0.1' `
        -noprompt
    if ($LASTEXITCODE -ne 0) { throw "keytool exited with $LASTEXITCODE" }
}

Add-Type -AssemblyName System.Security
$certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(
    $keyStore,
    $Password
)
$sha256 = [System.Security.Cryptography.SHA256]::Create()
try {
    $digest = $sha256.ComputeHash($certificate.RawData)
} finally {
    $sha256.Dispose()
}
$fingerprint = ($digest | ForEach-Object { '{0:X2}' -f $_ }) -join ':'
Write-Host "Keystore: $keyStore"
Write-Host "Certificate SHA-256: $fingerprint"
Write-Host ""
Write-Host "The client reads its endpoint, build id and certificate pin from"
Write-Host "native/src/validation/auth_config.cpp. Before building the DLL, update"
Write-Host "that file and re-encode the tables with its XOR stream:"
Write-Host "  certificate pin : $fingerprint"
