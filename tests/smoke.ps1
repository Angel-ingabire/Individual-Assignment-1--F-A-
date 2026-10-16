param(
    [string]$Executable = (Join-Path $PSScriptRoot '..\library_tracker.exe')
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
$executablePath = (Resolve-Path $Executable).Path
$testRoot = Join-Path $env:TEMP ('library-tracker-smoke-' + [guid]::NewGuid().ToString('N'))

function Assert-OutputContains([string]$Output, [string]$Expected, [string]$Scenario) {
    if ($Output -notmatch [regex]::Escape($Expected)) {
        throw "$Scenario did not contain expected output: $Expected"
    }
}

New-Item -ItemType Directory -Path $testRoot | Out-Null

try {
    Copy-Item (Join-Path $projectRoot 'books.txt'),
        (Join-Path $projectRoot 'copies.txt'),
        (Join-Path $projectRoot 'members.txt'),
        (Join-Path $projectRoot 'users.txt') -Destination $testRoot

    $legacyMetadata = [System.Text.Encoding]::ASCII.GetBytes('LIBMETA1') +
        [BitConverter]::GetBytes([int]2) +
        [BitConverter]::GetBytes([int]2)
    [System.IO.File]::WriteAllBytes((Join-Path $testRoot 'chain_metadata.dat'),
        $legacyMetadata)

    Push-Location $testRoot
    try {
        $utxoOutput = @(
            'librarian',
            'library2026',
            'difficulty_status',
            'set_renewal_days 0',
            'set_renewal_days 21',
            'difficulty_status',
            'borrow BK001 ALU001 BK001-C01',
            'mine solo ALU001',
            'return BK001 ALU001 BK001-C01',
            'mine solo ALU001',
            'transfer ALU001 ALU002 2 0',
            'mine solo ALU003',
            'borrow BK002 ALU001 BK002-C01',
            'mine pool ALU001 ALU002',
            'borrow BK003 ALU001 BK003-C01',
            'mine cloud 1 ALU001',
            'balances',
            'history ALU001',
            'utxos',
            'validate',
            'quit'
        ) | & $executablePath --model utxo --difficulty 1 2>&1
        $utxoExit = $LASTEXITCODE
        $utxoText = $utxoOutput -join "`n"
        if ($utxoExit -ne 0) {
            throw "UTXO smoke scenario exited with code $utxoExit."
        }
        Assert-OutputContains $utxoText 'renewal period=14 day(s)' 'Legacy metadata migration'
        Assert-OutputContains $utxoText 'ERROR: renewal period must be an integer from 1 to 3650 days.' 'Renewal validation'
        Assert-OutputContains $utxoText 'Renewal period set to 21 day(s).' 'Renewal configuration'
        Assert-OutputContains $utxoText 'Mined block 1' 'Borrow mining'
        Assert-OutputContains $utxoText 'Mined block 2' 'Return mining'
        Assert-OutputContains $utxoText 'Mined block 3' 'Explicit UTXO transfer mining'
        Assert-OutputContains $utxoText 'Mined block 4' 'Pool payout mining'
        Assert-OutputContains $utxoText 'Mined block 5' 'Cloud charge mining'
        Assert-OutputContains $utxoText 'ALU001 -> CLOUD amount=3' 'Committed cloud fee debit'
        Assert-OutputContains $utxoText 'Chain validation: VALID' 'UTXO ledger validation'
        $utxoBalanceLine = [regex]::Matches($utxoText, '(?m)^\s+ALU001:.*$') |
            Select-Object -Last 1
        $chainHashBeforeTamper = (Get-FileHash '.\blockchain.dat' -Algorithm SHA256).Hash

        $previousErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $tamperOutput = @(
                'librarian',
                'library2026',
                'difficulty_status',
                'tamper',
                'validate',
                'quit'
            ) | & $executablePath --model utxo --difficulty 1 2>&1
        }
        finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
        $tamperExit = $LASTEXITCODE
        $tamperText = $tamperOutput -join "`n"
        if ($tamperExit -ne 0) {
            throw "Tamper scenario exited with code $tamperExit."
        }
        Assert-OutputContains $tamperText 'renewal period=21 day(s)' 'Persisted renewal configuration'
        Assert-OutputContains $tamperText 'Chain validation: INVALID' 'Tampered in-memory copy'
        Assert-OutputContains $tamperText 'Chain validation: VALID' 'Original saved chain'
        $chainHashAfterTamper = (Get-FileHash '.\blockchain.dat' -Algorithm SHA256).Hash
        if ($chainHashBeforeTamper -ne $chainHashAfterTamper) {
            throw 'Tamper command changed the saved blockchain.dat file.'
        }

        $accountOutput = @(
            'librarian',
            'library2026',
            'transfer ALU001 ALU002 2 0',
            'pending',
            'balances',
            'mine solo ALU003',
            'balances',
            'history ALU001',
            'validate',
            'quit'
        ) | & $executablePath --model account --difficulty 1 2>&1
        $accountExit = $LASTEXITCODE
        $accountText = $accountOutput -join "`n"
        if ($accountExit -ne 0) {
            throw "Account-model smoke scenario exited with code $accountExit."
        }
        Assert-OutputContains $accountText 'TRANSFER' 'Account transfer queue'
        Assert-OutputContains $accountText 'Mined block 6' 'Account transfer mining'
        Assert-OutputContains $accountText 'Chain validation: VALID' 'Account ledger validation'
        $accountBalanceLine = [regex]::Matches($accountText, '(?m)^\s+ALU001:.*$') |
            Select-Object -Last 1

        Remove-Item '.\token_state_utxo.dat', '.\token_state_account.dat' `
            -ErrorAction SilentlyContinue
        $utxoReplayOutput = @(
            'librarian',
            'library2026',
            'balances',
            'validate',
            'quit'
        ) | & $executablePath --model utxo --difficulty 1 2>&1
        $utxoReplayText = $utxoReplayOutput -join "`n"
        if ($LASTEXITCODE -ne 0) {
            throw 'UTXO chain-only replay scenario failed.'
        }
        Assert-OutputContains $utxoReplayText 'Chain validation: VALID' 'UTXO payout replay'
        $utxoReplayBalanceLine = [regex]::Matches($utxoReplayText, '(?m)^\s+ALU001:.*$') |
            Select-Object -Last 1
        if ($utxoReplayBalanceLine.Value -ne $utxoBalanceLine.Value) {
            throw 'UTXO balance changed when rebuilding from committed chain data.'
        }

        $accountReplayOutput = @(
            'librarian',
            'library2026',
            'balances',
            'validate',
            'quit'
        ) | & $executablePath --model account --difficulty 1 2>&1
        $accountReplayText = $accountReplayOutput -join "`n"
        if ($LASTEXITCODE -ne 0) {
            throw 'Account chain-only replay scenario failed.'
        }
        Assert-OutputContains $accountReplayText 'Chain validation: VALID' 'Account payout replay'
        $accountReplayBalanceLine = [regex]::Matches($accountReplayText, '(?m)^\s+ALU001:.*$') |
            Select-Object -Last 1
        if ($accountReplayBalanceLine.Value -ne $accountBalanceLine.Value) {
            throw 'Account balance changed when rebuilding from committed chain data.'
        }

        Write-Output 'Smoke tests passed: metadata migration, explicit UTXO proofs, committed mining/cloud economics, replay, and tamper isolation.'
    }
    finally {
        Pop-Location
    }
}
finally {
    if (Test-Path -LiteralPath $testRoot) {
        Remove-Item -LiteralPath $testRoot -Recurse -Force
    }
}
