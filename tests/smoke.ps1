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
        $overlongInput = 'x' * 300
        $overlongCommand = 'x' * 32
        $previousErrorActionPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $utxoOutput = @(
                'librarian',
                'library2026',
                'balances unexpected',
                $overlongCommand,
                $overlongInput,
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
        }
        finally {
            $ErrorActionPreference = $previousErrorActionPreference
        }
        $utxoExit = $LASTEXITCODE
        $utxoText = $utxoOutput -join "`n"
        if ($utxoExit -ne 0) {
            throw "UTXO smoke scenario exited with code $utxoExit."
        }
        Assert-OutputContains $utxoText 'renewal period=14 day(s)' 'Legacy metadata migration'
        Assert-OutputContains $utxoText 'ERROR: invalid command or arguments.' 'Extra CLI arguments'
        Assert-OutputContains $utxoText 'ERROR: command has too many arguments or a token exceeds its length limit.' 'Overlong command token'
        Assert-OutputContains $utxoText 'ERROR: command line is too long; the entire line was discarded.' 'Overlong CLI input'
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

        $rollbackRoot = Join-Path $testRoot 'rollback'
        New-Item -ItemType Directory -Path $rollbackRoot | Out-Null
        Copy-Item (Join-Path $projectRoot 'books.txt'),
            (Join-Path $projectRoot 'copies.txt'),
            (Join-Path $projectRoot 'members.txt'),
            (Join-Path $projectRoot 'users.txt') -Destination $rollbackRoot
        Push-Location $rollbackRoot
        try {
            @('librarian', 'library2026', 'quit') |
                & $executablePath --model utxo --difficulty 1 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw 'Could not initialize rollback-failure test fixture.'
            }
            $stateHashBeforeFailure = (Get-FileHash '.\library_state.dat' -Algorithm SHA256).Hash
            $process = New-Object System.Diagnostics.Process
            $process.StartInfo.FileName = $executablePath
            $process.StartInfo.Arguments = '--model utxo --difficulty 1'
            $process.StartInfo.WorkingDirectory = $rollbackRoot
            $process.StartInfo.UseShellExecute = $false
            $process.StartInfo.CreateNoWindow = $true
            $process.StartInfo.RedirectStandardInput = $true
            $process.StartInfo.RedirectStandardOutput = $true
            $process.StartInfo.RedirectStandardError = $true
            if (-not $process.Start()) {
                throw 'Could not start rollback-failure test process.'
            }
            $startupOutput = [System.Collections.Generic.List[string]]::new()
            try {
                $process.StandardInput.WriteLine('librarian')
                $process.StandardInput.WriteLine('library2026')
                $process.StandardInput.Flush()
                while (-not $process.HasExited) {
                    $startupLine = $process.StandardOutput.ReadLine()
                    if ($null -eq $startupLine) {
                        break
                    }
                    $startupOutput.Add($startupLine)
                    if ($startupLine -match 'Authenticated as librarian') {
                        break
                    }
                }
                if ($process.HasExited) {
                    throw 'Rollback-failure test application exited before command input.'
                }
                New-Item -ItemType Directory -Path '.\library_state.dat.tmp' | Out-Null
                $process.StandardInput.WriteLine('borrow BK001 ALU001 BK001-C01')
                $process.StandardInput.WriteLine('pending')
                $process.StandardInput.WriteLine('copy BK001-C01')
                $process.StandardInput.WriteLine('quit')
                $process.StandardInput.Close()
                $process.WaitForExit()
                $rollbackText = (@($startupOutput) +
                    @($process.StandardOutput.ReadToEnd()) +
                    @($process.StandardError.ReadToEnd())) -join "`n"
            }
            finally {
                if (-not $process.HasExited) {
                    $process.StandardInput.Close()
                    if (-not $process.WaitForExit(10000)) {
                        Stop-Process -Id $process.Id -Force
                    }
                    $process.WaitForExit()
                }
                $process.Dispose()
            }
            Assert-OutputContains $rollbackText 'could not persist borrow request; no state was changed.' 'Failed borrow persistence rollback'
            Assert-OutputContains $rollbackText 'Pending pool: 0 unconfirmed request(s)' 'Failed borrow pending rollback'
            Assert-OutputContains $rollbackText 'AVAILABLE' 'Failed borrow inventory rollback'
            $stateHashAfterFailure = (Get-FileHash '.\library_state.dat' -Algorithm SHA256).Hash
            if ($stateHashBeforeFailure -ne $stateHashAfterFailure) {
                throw 'Failed borrow persistence changed the saved library_state.dat.'
            }
            Remove-Item -LiteralPath '.\library_state.dat.tmp' -Force -Recurse

            $chainHashBeforeMiningFailure = (Get-FileHash '.\blockchain.dat' -Algorithm SHA256).Hash
            $process = New-Object System.Diagnostics.Process
            $process.StartInfo.FileName = $executablePath
            $process.StartInfo.Arguments = '--model utxo --difficulty 1'
            $process.StartInfo.WorkingDirectory = $rollbackRoot
            $process.StartInfo.UseShellExecute = $false
            $process.StartInfo.CreateNoWindow = $true
            $process.StartInfo.RedirectStandardInput = $true
            $process.StartInfo.RedirectStandardOutput = $true
            $process.StartInfo.RedirectStandardError = $true
            if (-not $process.Start()) {
                throw 'Could not start mining-rollback test process.'
            }
            $miningOutput = [System.Collections.Generic.List[string]]::new()
            try {
                $process.StandardInput.WriteLine('librarian')
                $process.StandardInput.WriteLine('library2026')
                $process.StandardInput.Flush()
                while (-not $process.HasExited) {
                    $startupLine = $process.StandardOutput.ReadLine()
                    if ($null -eq $startupLine) {
                        break
                    }
                    $miningOutput.Add($startupLine)
                    if ($startupLine -match 'Authenticated as librarian') {
                        break
                    }
                }
                if ($process.HasExited) {
                    throw 'Mining-rollback process exited before commands were accepted.'
                }
                $process.StandardInput.WriteLine('borrow BK001 ALU001 BK001-C01')
                $process.StandardInput.Flush()
                while (-not $process.HasExited) {
                    $borrowLine = $process.StandardOutput.ReadLine()
                    if ($null -eq $borrowLine) {
                        break
                    }
                    $miningOutput.Add($borrowLine)
                    if ($borrowLine -match 'Pending pool: 1 unconfirmed request') {
                        break
                    }
                }
                if ($process.HasExited) {
                    throw 'Mining-rollback process exited before borrow was queued.'
                }
                New-Item -ItemType Directory -Path '.\token_state_utxo.dat.tmp' | Out-Null
                $process.StandardInput.WriteLine('mine solo ALU001')
                $process.StandardInput.WriteLine('pending')
                $process.StandardInput.WriteLine('validate')
                $process.StandardInput.WriteLine('quit')
                $process.StandardInput.Close()
                $process.WaitForExit()
                $miningRollbackText = (@($miningOutput) +
                    @($process.StandardOutput.ReadToEnd()) +
                    @($process.StandardError.ReadToEnd())) -join "`n"
            }
            finally {
                if (-not $process.HasExited) {
                    $process.StandardInput.Close()
                    if (-not $process.WaitForExit(10000)) {
                        Stop-Process -Id $process.Id -Force
                    }
                    $process.WaitForExit()
                }
                $process.Dispose()
            }
            Assert-OutputContains $miningRollbackText 'rolling back mining commit' 'Failed mining snapshot rollback'
            Assert-OutputContains $miningRollbackText 'Chain validation: VALID (1 blocks)' 'Failed mining chain rollback'
            $chainHashAfterMiningFailure = (Get-FileHash '.\blockchain.dat' -Algorithm SHA256).Hash
            if ($chainHashBeforeMiningFailure -ne $chainHashAfterMiningFailure) {
                throw 'Failed mining snapshot persistence changed blockchain.dat.'
            }
            Remove-Item -LiteralPath '.\token_state_utxo.dat.tmp' -Force -Recurse
            $pendingAfterRollback = @(
                'librarian',
                'library2026',
                'pending',
                'validate',
                'quit'
            ) | & $executablePath --model utxo --difficulty 1 2>&1
            $pendingAfterRollbackText = $pendingAfterRollback -join "`n"
            Assert-OutputContains $pendingAfterRollbackText 'Pending pool: 1 unconfirmed request(s)' 'Mining rollback pending preservation'
            Assert-OutputContains $pendingAfterRollbackText 'Chain validation: VALID (1 blocks)' 'Mining rollback restart validation'

            $booksHashBeforeFailure = (Get-FileHash '.\books.txt' -Algorithm SHA256).Hash
            New-Item -ItemType Directory -Path '.\books.txt.tmp' | Out-Null
            $bookRegistrationFailure = @(
                'librarian',
                'library2026',
                'register_book BK004 New_Title New_Author',
                'view_book BK004',
                'quit'
            ) | & $executablePath --model utxo --difficulty 1 2>&1
            $bookRegistrationText = $bookRegistrationFailure -join "`n"
            Assert-OutputContains $bookRegistrationText 'could not be persisted' 'Failed book registration persistence'
            Assert-OutputContains $bookRegistrationText 'ERROR: book not found.' 'Failed book registration memory rollback'
            if ((Get-FileHash '.\books.txt' -Algorithm SHA256).Hash -ne $booksHashBeforeFailure) {
                throw 'Failed book registration changed books.txt.'
            }
            Remove-Item -LiteralPath '.\books.txt.tmp' -Force -Recurse

            $membersHashBeforeFailure = (Get-FileHash '.\members.txt' -Algorithm SHA256).Hash
            New-Item -ItemType Directory -Path '.\members.txt.tmp' | Out-Null
            $previousErrorActionPreference = $ErrorActionPreference
            $ErrorActionPreference = 'Continue'
            try {
                $memberRegistrationFailure = @(
                    'librarian',
                    'library2026',
                    'register_member ALU004 New_Member CS1',
                    'view_member ALU004',
                    'quit'
                ) | & $executablePath --model utxo --difficulty 1 2>&1
            }
            finally {
                $ErrorActionPreference = $previousErrorActionPreference
            }
            $memberRegistrationText = $memberRegistrationFailure -join "`n"
            Assert-OutputContains $memberRegistrationText 'member registry could not be persisted' 'Failed member registration persistence'
            Assert-OutputContains $memberRegistrationText 'ERROR: Member not found.' 'Failed member registration memory rollback'
            if ((Get-FileHash '.\members.txt' -Algorithm SHA256).Hash -ne $membersHashBeforeFailure) {
                throw 'Failed member registration changed members.txt.'
            }
        }
        finally {
            Pop-Location
        }

        Write-Output 'Smoke tests passed: metadata migration, strict CLI input, transactional persistence rollback, committed mining/cloud economics, chain replay, and tamper isolation.'
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
