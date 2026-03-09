# Debug Session: x64 ELF Worker — Histórico de Fixes

## Contexto
Binário: `vvm` (HTB challenge, PIE ELF x64, base `0x555555554000`)
Comando: `emulateFullHeadless`

---

## Fix 1: Worker Process Crash (0xC0000005 — STATUS_ACCESS_VIOLATION)
**Causa raiz**: `child_process.fork()` usava `process.execPath` (binário Electron).
O Electron tem ACG (Arbitrary Code Guard) no PE header do Windows, que bloqueia
`VirtualAlloc(PAGE_EXECUTE_READWRITE)`. O Unicorn QEMU TCG JIT precisa de memória RWX.

**Solução**: `findSystemNode()` em `x64ElfWorkerClient.ts` — busca Node.js do sistema
(NVM_HOME, NVM_SYMLINK, Program Files, PATH) que NÃO tem ACG no PE header.
Fallback: Electron + `ELECTRON_RUN_AS_NODE=1`.

**Arquivos**: `extensions/hexcore-debugger/src/x64ElfWorkerClient.ts`
**Status**: ✅ RESOLVIDO

---

## Fix 2: Stack Não Mapeada no Worker (instructionsExecuted: 0)
**Causa raiz**: `memRegions()` do Unicorn retorna `end` como INCLUSIVE (último byte válido).
O cálculo de size era `end - begin` (faltava +1). Resultado: stack não migrava corretamente.

**Solução**:
1. `size = end - begin + 1` no loop de migração em `setElfSyncMode`
2. try/catch no `memMap` do loop — loga warning mas continua
3. `FS_BASE` e `GS_BASE` adicionados à lista de registros migrados
4. Verificação pós-migração: se RSP não está em nenhuma região do worker, mapeia stack explicitamente

**Arquivos**: `extensions/hexcore-debugger/src/unicornWrapper.ts` (método `setElfSyncMode`)
**Status**: ✅ RESOLVIDO

---

## Fix 3: UC_ERR_FETCH_PROT — __libc_start_main não redireciona pra main
**Sintoma**: 19 instruções executadas, depois `UC_ERR_FETCH_PROT (code: 14)` em `0x800eef68` (stack).
Todos os registros zerados. RSP em `0x800eef70`.

**Causa raiz**: No worker mode, os code hooks (API interception) chamam `linuxApiHooks.handleCall()`
que usa `getRegistersX64()` (sync) — lê do Unicorn IN-PROCESS. Mas após `setElfSyncMode(true)`,
os registros estão no WORKER. O in-process tem registros stale/zerados.
Resultado: `args[0]` (RDI = ponteiro pra main) = `0n` → `_redirectAddress = null` → sem redirect → RET pra stack.

**Solução (parte 1 — register sync)**: Em `startX64ElfWorker()`, antes de chamar code hooks:
1. Pull: ler registros do worker → escrever no Unicorn in-process
2. Chamar code hooks (que agora veem registros corretos)
3. Push (se houve redirect): ler registros do in-process → enviar pro worker
4. Sync stack: copiar 256 bytes ao redor de RSP do in-process → worker
5. Apply deferred register writes ao in-process, re-sync pro worker

**Solução (parte 2 — stub range terminal)**: O `executeBatch()` do worker rodava até 1000
instruções internamente. Quando o PC chegava no stub (`0x70000000`), o worker NÃO parava —
executava o `RET` do stub, que popava o return address da stack (non-executable) → crash.
Fix: adicionado `terminalRanges` ao `executeBatch()` — range check `[0x70000000, 0x70100000)`
que faz o worker parar ANTES de executar o stub. O host-side code hook então dispara,
`__libc_start_main` handler lê RDI (main pointer), seta `_redirectAddress`, e o interceptor
redireciona RIP pra main.

**Arquivos**:
- `extensions/hexcore-debugger/src/unicornWrapper.ts` (método `startX64ElfWorker` — register sync + terminalRanges)
- `extensions/hexcore-debugger/src/x64ElfWorker.js` (método `executeBatch` — range-based terminal check)
- `extensions/hexcore-debugger/src/x64ElfWorkerClient.ts` (assinatura `executeBatch` — novo param `terminalRanges`)
**Status**: ✅ COMPILADO — aguardando teste

---

## Arquitetura do Worker Mode (referência rápida)

```
debugEngine.ts
  └─ loadELF()
       ├─ setupStack(0x7FFF0000)          ← Unicorn in-process
       ├─ initializeElfProcessStack()      ← Unicorn in-process (RSP ajustado)
       ├─ setupLinuxTLS()                  ← Unicorn in-process (FS_BASE)
       ├─ installELFApiInterceptor()       ← code hooks registrados
       ├─ installSyscallHandler()          ← interrupt handler registrado
       ├─ setElfSyncMode(true)             ← MIGRA tudo pro worker
       │    ├─ remove native hooks
       │    ├─ start X64ElfWorkerClient (com findSystemNode)
       │    ├─ migrate memory regions (size = end - begin + 1)
       │    ├─ migrate registers (incl FS_BASE, GS_BASE)
       │    └─ verify RSP mapped (fallback: map stack explicitly)
       └─ setRegister('rip', entryPoint)   ← seta RIP no worker

unicornWrapper.ts → startX64ElfWorker()
  └─ executeBatch() loop
       ├─ READ PC from worker
       ├─ BREAKPOINT check
       ├─ PULL: worker regs → in-process (antes dos code hooks)
       ├─ code hooks (API interception) — host side, sync reads/writes
       │    └─ isStubAddress(pc)? → handleCall() → _redirectAddress = main
       ├─ IF redirected:
       │    ├─ PUSH: in-process regs → worker (RIP = main, RSP adjusted)
       │    ├─ SYNC STACK: in-process stack → worker (256 bytes ao redor de RSP)
       │    └─ continue (re-read PC from worker)
       ├─ executeBatch() no worker
       │    ├─ terminal address check (exact: 0, 0xDEAD...)
       │    ├─ terminal RANGE check ([0x70000000, 0x70100000) = stub region)
       │    ├─ SYSCALL/INT80 opcode detection
       │    └─ execute 1 instruction via emuStart
       ├─ SYSCALL dispatch — host side (async)
       └─ stopped/error handling
```

## Registros no Worker Mode (após Fix 3)
- `getRegistersX64()` → lê do Unicorn IN-PROCESS (atualizado pelo PULL antes dos hooks)
- `getRegistersX64Async()` → lê do WORKER via IPC
- `readMemorySync()` → lê do IN-PROCESS (stack copiada durante migração)
- `writeMemorySync()` → escreve no IN-PROCESS (sincronizado pro worker pelo PUSH)
- `setRegisterSync()` → escreve no IN-PROCESS (sincronizado pro worker pelo PUSH)

## Arquivos Chave
- `x64ElfWorkerClient.ts` — IPC client, findSystemNode(), start()
- `x64ElfWorker.js` — standalone worker process (NÃO compilado por tsc)
- `unicornWrapper.ts` — setElfSyncMode(), startX64ElfWorker(), register sync
- `debugEngine.ts` — loadELF(), installELFApiInterceptor(), installSyscallHandler()
- `linuxApiHooks.ts` — __libc_start_main handler, readArguments() (sync)
