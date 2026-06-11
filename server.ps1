# ==========================================================================
# Aura Vault Backend Server (PowerShell Core / Desktop Native)
# Runs a local REST API web server on port 5000 with database persistence.
# ==========================================================================

$port = 5000
$serverSecret = "AuraVaultServerSuperSecretKey123!"

# Sticking to standard .NET UTF-8 encoding
$utf8 = [System.Text.Encoding]::UTF8

# Stretch the serverSecret using SHA-256 to a 32-byte (256-bit) AES key
$secretBytes = $utf8.GetBytes($serverSecret)
$sha = [System.Security.Cryptography.SHA256Managed]::new()
$serverKey = $sha.ComputeHash($secretBytes)
$serverKeyHex = [System.BitConverter]::ToString($serverKey).Replace("-", "").ToLower()
$sha.Dispose()

# Database setup
$dbDir = Join-Path $PSScriptRoot "database"
if (!(Test-Path $dbDir)) {
    New-Item -ItemType Directory -Path $dbDir | Out-Null
}
$usersFile = Join-Path $dbDir "users.json"
$credsFile = Join-Path $dbDir "credentials.json"

if (!(Test-Path $usersFile)) { Set-Content $usersFile "[]" }
if (!(Test-Path $credsFile)) { Set-Content $credsFile "[]" }

# In-memory Session Store (Token -> User ID)
$sessions = @{}

# --- Helper Cryptographic Functions ---

# Computes SHA-256 hash of a password concatenated with a salt.
function Get-PasswordHash($password, $salt) {
    $combined = $password + $salt
    $bytes = $utf8.GetBytes($combined)
    $shaInstance = [System.Security.Cryptography.SHA256Managed]::new()
    $hashBytes = $shaInstance.ComputeHash($bytes)
    $shaInstance.Dispose()
    return [System.Convert]::ToBase64String($hashBytes)
}

# Generates a random GUID-based hexadecimal string for salts, tokens, and IDs.
function Get-RandomString {
    return [System.Guid]::NewGuid().ToString("N")
}

# Encrypts a string using AES-256 with the server-wide key and a custom IV.
function Encrypt-Password($plaintext, $iv) {
    if ([string]::IsNullOrEmpty($plaintext)) { return "" }
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $serverKey
    $aes.IV = $iv
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    
    $encryptor = $aes.CreateEncryptor()
    $plainBytes = $utf8.GetBytes($plaintext)
    $encBytes = $encryptor.TransformFinalBlock($plainBytes, 0, $plainBytes.Length)
    
    $aes.Dispose()
    return [System.Convert]::ToBase64String($encBytes)
}

# Decrypts a base64 ciphertext using AES-256.
function Decrypt-Password($ciphertext, $ivBase64) {
    if ([string]::IsNullOrEmpty($ciphertext)) { return "" }
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $serverKey
    $aes.IV = [System.Convert]::FromBase64String($ivBase64)
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    
    $decryptor = $aes.CreateDecryptor()
    $encBytes = [System.Convert]::FromBase64String($ciphertext)
    $plainBytes = $decryptor.TransformFinalBlock($encBytes, 0, $encBytes.Length)
    
    $aes.Dispose()
    return $utf8.GetString($plainBytes)
}

# --- Server Startup ---

$listener = New-Object System.Net.HttpListener
$listener.Prefixes.Add("http://localhost:$port/")

try {
    $listener.Start()
    Write-Host "==========================================================================" -ForegroundColor Cyan
    Write-Host "  AURA VAULT BACKEND SERVER STARTED SUCCESSFULLY" -ForegroundColor Green
    Write-Host "  Listening at: http://localhost:$port/" -ForegroundColor White
    Write-Host "  Press Ctrl+C in this terminal to stop the server." -ForegroundColor Yellow
    Write-Host "==========================================================================" -ForegroundColor Cyan
} catch {
    Write-Host "Error starting server: $_" -ForegroundColor Red
    Exit 1
}

# --- Event Loop ---

while ($listener.IsListening) {
    try {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response
        
        $url = $request.Url.LocalPath
        $method = $request.HttpMethod
        
        # Add CORS Headers for development flexibility
        $response.Headers.Add("Access-Control-Allow-Origin", "*")
        $response.Headers.Add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        $response.Headers.Add("Access-Control-Allow-Headers", "Content-Type, Authorization")
        
        # Handle Preflight OPTIONS request
        if ($method -eq "OPTIONS") {
            $response.StatusCode = 200
            $response.Close()
            continue
        }
        
        # Route API Queries
        if ($url.StartsWith("/api/")) {
            # Read request stream
            $reader = New-Object System.IO.StreamReader($request.InputStream)
            $body = $reader.ReadToEnd()
            $reader.Close()
            
            $response.ContentType = "application/json"
            $resPayload = ""
            
            # ROUTE: GET /api/status
            if ($url -eq "/api/status" -and $method -eq "GET") {
                $users = Get-Content $usersFile | ConvertFrom-Json
                $usersExist = $false
                if ($null -ne $users -and $users.Count -gt 0) { $usersExist = $true }
                $response.StatusCode = 200
                $resPayload = @{ success = $true; usersExist = $usersExist } | ConvertTo-Json
            }
            # ROUTE: POST /api/register
            elseif ($url -eq "/api/register" -and $method -eq "POST") {
                $data = $body | ConvertFrom-Json
                $users = Get-Content $usersFile | ConvertFrom-Json
                if ($null -eq $users) { $users = @() }
                
                # Check for existing profile
                $exists = $users | Where-Object { $_.username -eq $data.username }
                if ($exists) {
                    $response.StatusCode = 400
                    $resPayload = @{ error = "Username already exists." } | ConvertTo-Json
                } else {
                    $salt = Get-RandomString
                    $hash = Get-PasswordHash $data.password $salt
                    $newUser = @{
                        id = Get-RandomString
                        username = $data.username
                        salt = $salt
                        passwordHash = $hash
                    }
                    $users += $newUser
                    $users | ConvertTo-Json -Depth 5 | Set-Content $usersFile
                    $response.StatusCode = 201
                    $resPayload = @{ success = $true; message = "User account created." } | ConvertTo-Json
                }
            }
            # ROUTE: POST /api/login
            elseif ($url -eq "/api/login" -and $method -eq "POST") {
                $data = $body | ConvertFrom-Json
                $users = Get-Content $usersFile | ConvertFrom-Json
                if ($null -eq $users) { $users = @() }
                
                $user = $users | Where-Object { $_.username -eq $data.username }
                if ($user -and (Get-PasswordHash $data.password $user.salt) -eq $user.passwordHash) {
                    $token = Get-RandomString
                    $sessions[$token] = $user.id
                    $response.StatusCode = 200
                    $resPayload = @{ success = $true; token = $token; username = $user.username } | ConvertTo-Json
                } else {
                    $response.StatusCode = 401
                    $resPayload = @{ error = "Invalid credentials." } | ConvertTo-Json
                }
            }
            # ROUTE: GET /api/credentials
            elseif ($url -eq "/api/credentials" -and $method -eq "GET") {
                $token = $request.Headers["Authorization"]
                if ($token -and $sessions.ContainsKey($token)) {
                    $userId = $sessions[$token]
                    $creds = Get-Content $credsFile | ConvertFrom-Json
                    if ($null -eq $creds) { $creds = @() }
                    
                    # Filter and decrypt items belonging to the active user
                    $userCreds = $creds | Where-Object { $_.userId -eq $userId }
                    if ($null -eq $userCreds) { $userCreds = @() }
                    
                    $decryptedList = foreach ($c in $userCreds) {
                        $decPw = Decrypt-Password $c.encryptedPassword $c.iv
                        $decNotes = Decrypt-Password $c.encryptedNotes $c.notesIv
                        @{
                            id = $c.id
                            category = $c.category
                            title = $c.title
                            username = $c.username
                            password = $decPw
                            website = $c.website
                            notes = $decNotes
                            lastModified = $c.lastModified
                        }
                    }
                    
                    $response.StatusCode = 200
                    $resPayload = $decryptedList | ConvertTo-Json -Depth 5
                } else {
                    $response.StatusCode = 401
                    $resPayload = @{ error = "Unauthorized session." } | ConvertTo-Json
                }
            }
            # ROUTE: POST /api/credentials
            elseif ($url -eq "/api/credentials" -and $method -eq "POST") {
                $token = $request.Headers["Authorization"]
                if ($token -and $sessions.ContainsKey($token)) {
                    $userId = $sessions[$token]
                    $data = $body | ConvertFrom-Json
                    $creds = Get-Content $credsFile | ConvertFrom-Json
                    if ($null -eq $creds) { $creds = @() }
                    
                    # Generate distinct IVs for password and notes
                    $iv = New-Object Byte[] 16
                    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($iv)
                    $notesIv = New-Object Byte[] 16
                    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($notesIv)
                    
                    $encPw = Encrypt-Password $data.password $iv
                    $encNotes = Encrypt-Password $data.notes $notesIv
                    
                    $newRecord = @{
                        id = Get-RandomString
                        userId = $userId
                        category = $data.category
                        title = $data.title
                        username = $data.username
                        encryptedPassword = $encPw
                        iv = [System.Convert]::ToBase64String($iv)
                        website = $data.website
                        encryptedNotes = $encNotes
                        notesIv = [System.Convert]::ToBase64String($notesIv)
                        lastModified = (Get-Date -Format "o")
                    }
                    
                    $creds += $newRecord
                    $creds | ConvertTo-Json -Depth 5 | Set-Content $credsFile
                    
                    $response.StatusCode = 201
                    $resPayload = @{ success = $true; id = $newRecord.id } | ConvertTo-Json
                } else {
                    $response.StatusCode = 401
                    $resPayload = @{ error = "Unauthorized session." } | ConvertTo-Json
                }
            }
            # ROUTE: PUT /api/credentials/<id>
            elseif ($url.StartsWith("/api/credentials/") -and $method -eq "PUT") {
                $token = $request.Headers["Authorization"]
                if ($token -and $sessions.ContainsKey($token)) {
                    $userId = $sessions[$token]
                    $credId = $url.Substring(17) # Extract ID from path
                    $data = $body | ConvertFrom-Json
                    $creds = Get-Content $credsFile | ConvertFrom-Json
                    if ($null -eq $creds) { $creds = @() }
                    
                    # Locate user record
                    $index = -1
                    for ($i = 0; $i -lt $creds.Count; $i++) {
                        if ($creds[$i].id -eq $credId -and $creds[$i].userId -eq $userId) {
                            $index = $i
                            break
                        }
                    }
                    
                    if ($index -ne -1) {
                        $iv = New-Object Byte[] 16
                        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($iv)
                        $notesIv = New-Object Byte[] 16
                        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($notesIv)
                        
                        $encPw = Encrypt-Password $data.password $iv
                        $encNotes = Encrypt-Password $data.notes $notesIv
                        
                        $creds[$index].category = $data.category
                        $creds[$index].title = $data.title
                        $creds[$index].username = $data.username
                        $creds[$index].encryptedPassword = $encPw
                        $creds[$index].iv = [System.Convert]::ToBase64String($iv)
                        $creds[$index].website = $data.website
                        $creds[$index].encryptedNotes = $encNotes
                        $creds[$index].notesIv = [System.Convert]::ToBase64String($notesIv)
                        $creds[$index].lastModified = (Get-Date -Format "o")
                        
                        $creds | ConvertTo-Json -Depth 5 | Set-Content $credsFile
                        $response.StatusCode = 200
                        $resPayload = @{ success = $true } | ConvertTo-Json
                    } else {
                        $response.StatusCode = 404
                        $resPayload = @{ error = "Credential record not found." } | ConvertTo-Json
                    }
                } else {
                    $response.StatusCode = 401
                    $resPayload = @{ error = "Unauthorized session." } | ConvertTo-Json
                }
            }
            # ROUTE: DELETE /api/credentials/<id>
            elseif ($url.StartsWith("/api/credentials/") -and $method -eq "DELETE") {
                $token = $request.Headers["Authorization"]
                if ($token -and $sessions.ContainsKey($token)) {
                    $userId = $sessions[$token]
                    $credId = $url.Substring(17)
                    $creds = Get-Content $credsFile | ConvertFrom-Json
                    if ($null -eq $creds) { $creds = @() }
                    
                    $newCreds = $creds | Where-Object { $_.id -ne $credId -or $_.userId -ne $userId }
                    if ($null -eq $newCreds) { $newCreds = @() }
                    
                    $newCreds | ConvertTo-Json -Depth 5 | Set-Content $credsFile
                    $response.StatusCode = 200
                    $resPayload = @{ success = $true } | ConvertTo-Json
                } else {
                    $response.StatusCode = 401
                    $resPayload = @{ error = "Unauthorized session." } | ConvertTo-Json
                }
            }
            # ROUTE: POST /api/visualize (Playground visualizer support)
            elseif ($url -eq "/api/visualize" -and $method -eq "POST") {
                $data = $body | ConvertFrom-Json
                $plaintextPayload = $data.plaintext
                
                # Mock a salt and hashing for password input
                $salt = Get-RandomString
                $passwordHash = Get-PasswordHash $data.password $salt
                
                # Encrypt payload using Server Key
                $iv = New-Object Byte[] 16
                [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($iv)
                $encBytes = Encrypt-Password $plaintextPayload $iv
                
                $response.StatusCode = 200
                $resPayload = @{
                    masterPasswordLength = "●".repeat($data.password.Length)
                    saltHex = [System.BitConverter]::ToString($utf8.GetBytes($salt)).Replace("-", "").ToLower()
                    derivedKeyHex = $serverKeyHex
                    plaintext = $plaintextPayload
                    plaintextBytes = [System.BitConverter]::ToString($utf8.GetBytes($plaintextPayload)).Replace("-", "").ToLower()
                    ivHex = [System.BitConverter]::ToString($iv).Replace("-", "").ToLower()
                    ciphertextBase64 = $encBytes
                    ciphertextHex = [System.BitConverter]::ToString([System.Convert]::FromBase64String($encBytes)).Replace("-", "").ToLower()
                } | ConvertTo-Json
            }
            else {
                $response.StatusCode = 404
                $resPayload = @{ error = "Endpoint not supported." } | ConvertTo-Json
            }
            
            $resBytes = $utf8.GetBytes($resPayload)
            $response.OutputStream.Write($resBytes, 0, $resBytes.Length)
        } else {
            # Serve Static UI Files
            $filePath = Join-Path $PSScriptRoot $url
            
            # If folder requested, default to index.html
            if (Test-Path $filePath -PathType Container) {
                $filePath = Join-Path $filePath "index.html"
            }
            
            if (Test-Path $filePath) {
                $extension = [System.IO.Path]::GetExtension($filePath)
                switch ($extension) {
                    ".html" { $response.ContentType = "text/html; charset=utf-8" }
                    ".css"  { $response.ContentType = "text/css; charset=utf-8" }
                    ".js"   { $response.ContentType = "application/javascript; charset=utf-8" }
                    default { $response.ContentType = "application/octet-stream" }
                }
                
                $fileBytes = [System.IO.File]::ReadAllBytes($filePath)
                $response.OutputStream.Write($fileBytes, 0, $fileBytes.Length)
            } else {
                $response.StatusCode = 404
                $response.ContentType = "text/plain; charset=utf-8"
                $resBytes = $utf8.GetBytes("404 Not Found")
                $response.OutputStream.Write($resBytes, 0, $resBytes.Length)
            }
        }
    } catch {
        # Global Error Handling
        Write-Host "Request handling error: $_" -ForegroundColor Red
        if ($response) {
            $response.StatusCode = 500
            $response.ContentType = "application/json"
            $errJson = @{ error = $_.Exception.Message } | ConvertTo-Json
            $resBytes = $utf8.GetBytes($errJson)
            try {
                $response.OutputStream.Write($resBytes, 0, $resBytes.Length)
            } catch {}
        }
    } finally {
        if ($response) {
            $response.Close()
        }
    }
}
