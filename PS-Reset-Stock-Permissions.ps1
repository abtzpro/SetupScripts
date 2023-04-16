$root = "C:\"
$Acl = Get-Acl $root
$Ar = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","Allow")
$Acl.SetAccessRule($Ar)
Set-Acl $root $Acl

function Reset-Permissions {
    Param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
        [Alias('FullName')]
        [string]$Path
    )
    $Acl = Get-Acl $Path
    $Ar = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","Allow")
    $Acl.SetAccessRule($Ar)
    Set-Acl $Path $Acl
    Write-Host "Resetting permissions for $Path"
    $items = Get-ChildItem -Path $Path -ErrorAction SilentlyContinue -Force
    foreach ($item in $items) {
        try {
            $Acl = Get-Acl $item.FullName
            $Ar = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","Allow")
            $Acl.SetAccessRule($Ar)
            Set-Acl $item.FullName $Acl
            Write-Host "Resetting permissions for $($item.FullName)"
        }
        catch {
            Write-Warning "Error resetting permissions for $($item.FullName): $_"
        }
        if ($item.PSIsContainer) {
            Reset-Permissions -Path $item.FullName
        }
    }
}

Reset-Permissions -Path $root
