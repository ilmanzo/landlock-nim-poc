## Idiomatic Nim wrapper for the Linux Landlock LSM (Linux Security Module).
## Provides high-level, safe, and portable filesystem and network sandboxing for Nim applications.

import os, posix, macros

when not defined(linux):
  {.error: "Landlock is only supported on Linux.".}

# --- Low-Level Constants & Syscalls ---

const
  # Syscall numbers (standardized across amd64, arm64, riscv64)
  SYS_landlock_create_ruleset = 444
  SYS_landlock_add_rule       = 445
  SYS_landlock_restrict_self  = 446

when defined(amd64):
  const SYS_prctl = 157
elif defined(arm64) or defined(riscv64):
  const SYS_prctl = 167
else:
  {.error: "Unsupported architecture for Landlock syscalls.".}

const
  PR_SET_NO_NEW_PRIVS = 38
  
  # Rule types
  LANDLOCK_RULE_PATH_BENEATH* = 1
  LANDLOCK_RULE_NET_PORT*     = 2

  # Create ruleset flags
  LANDLOCK_CREATE_RULESET_VERSION* = 1'u32 shl 0

  # Filesystem Access Flags
  LANDLOCK_ACCESS_FS_EXECUTE*    = 1'u64 shl 0
  LANDLOCK_ACCESS_FS_WRITE_FILE* = 1'u64 shl 1
  LANDLOCK_ACCESS_FS_READ_FILE*  = 1'u64 shl 2
  LANDLOCK_ACCESS_FS_READ_DIR*   = 1'u64 shl 3
  LANDLOCK_ACCESS_FS_REMOVE_DIR* = 1'u64 shl 4
  LANDLOCK_ACCESS_FS_REMOVE_FILE* = 1'u64 shl 5
  LANDLOCK_ACCESS_FS_MAKE_CHAR*  = 1'u64 shl 6
  LANDLOCK_ACCESS_FS_MAKE_DIR*   = 1'u64 shl 7
  LANDLOCK_ACCESS_FS_MAKE_REG*   = 1'u64 shl 8
  LANDLOCK_ACCESS_FS_MAKE_SOCK*  = 1'u64 shl 9
  LANDLOCK_ACCESS_FS_MAKE_FIFO*  = 1'u64 shl 10
  LANDLOCK_ACCESS_FS_MAKE_BLOCK* = 1'u64 shl 11
  LANDLOCK_ACCESS_FS_MAKE_SYM*   = 1'u64 shl 12
  LANDLOCK_ACCESS_FS_REFER*      = 1'u64 shl 13 # ABI v2
  LANDLOCK_ACCESS_FS_TRUNCATE*   = 1'u64 shl 14 # ABI v3
  LANDLOCK_ACCESS_FS_IOCTL_DEV*  = 1'u64 shl 15 # ABI v5

  # Network Access Flags (ABI v4)
  LANDLOCK_ACCESS_NET_BIND_TCP*    = 1'u64 shl 0
  LANDLOCK_ACCESS_NET_CONNECT_TCP* = 1'u64 shl 1

  # Scoping Flags (ABI v6)
  LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET* = 1'u64 shl 0
  LANDLOCK_SCOPE_SIGNAL*               = 1'u64 shl 1

  # Restrict self flags (ABI v7, v8)
  LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF*    = 1'u32 shl 0
  LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON*      = 1'u32 shl 1
  LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF*   = 1'u32 shl 2
  LANDLOCK_RESTRICT_SELF_TSYNC*                = 1'u32 shl 3

type
  LandlockRulesetAttr {.pure, final.} = object
    handled_access_fs: uint64
    handled_access_net: uint64 # Added in ABI v4
    handled_scope: uint64      # Added in ABI v6

  LandlockPathBeneathAttr {.pure, final, packed.} = object
    allowed_access: uint64
    parent_fd: int32

  LandlockNetPortAttr {.pure, final, packed.} = object
    allowed_access: uint64
    port: uint64

  RulesetFd = distinct int32

proc syscall(number: int): int {.importc, header: "<unistd.h>", varargs.}

proc landlock_create_ruleset(attr: ptr LandlockRulesetAttr, size: int, flags: uint32): RulesetFd =
  RulesetFd(syscall(SYS_landlock_create_ruleset, attr, size, flags))

proc landlock_add_rule(ruleset_fd: RulesetFd, rule_type: int, rule_attr: pointer, flags: uint32): int =
  syscall(SYS_landlock_add_rule, ruleset_fd.int, rule_type, rule_attr, flags)

proc landlock_restrict_self(ruleset_fd: RulesetFd, flags: uint32): int =
  syscall(SYS_landlock_restrict_self, ruleset_fd.int, flags)

proc setNoNewPrivs(): int =
  syscall(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)

# --- High-Level API ---

type
  LandlockError* = object of OSError
    ## Base exception for Landlock-specific failures.

  FsAccess* = enum
    ## Available filesystem operations to restrict or allow.
    Execute, WriteFile, ReadFile, ReadDir, RemoveDir, RemoveFile,
    MakeChar, MakeDir, MakeReg, MakeSock, MakeFifo, MakeBlock,
    MakeSym, Refer, Truncate, IoctlDev

  NetAccess* = enum
    ## Available network operations (TCP).
    BindTcp, ConnectTcp

  Scope* = enum
    ## Scoping restrictions for IPC and sockets.
    AbstractUnixSocket, Signal

const
  FsAccessMap: array[FsAccess, uint64] = [
    Execute:    LANDLOCK_ACCESS_FS_EXECUTE,
    WriteFile:  LANDLOCK_ACCESS_FS_WRITE_FILE,
    ReadFile:   LANDLOCK_ACCESS_FS_READ_FILE,
    ReadDir:    LANDLOCK_ACCESS_FS_READ_DIR,
    RemoveDir:  LANDLOCK_ACCESS_FS_REMOVE_DIR,
    RemoveFile: LANDLOCK_ACCESS_FS_REMOVE_FILE,
    MakeChar:   LANDLOCK_ACCESS_FS_MAKE_CHAR,
    MakeDir:    LANDLOCK_ACCESS_FS_MAKE_DIR,
    MakeReg:    LANDLOCK_ACCESS_FS_MAKE_REG,
    MakeSock:   LANDLOCK_ACCESS_FS_MAKE_SOCK,
    MakeFifo:   LANDLOCK_ACCESS_FS_MAKE_FIFO,
    MakeBlock:  LANDLOCK_ACCESS_FS_MAKE_BLOCK,
    MakeSym:    LANDLOCK_ACCESS_FS_MAKE_SYM,
    Refer:      LANDLOCK_ACCESS_FS_REFER,
    Truncate:   LANDLOCK_ACCESS_FS_TRUNCATE,
    IoctlDev:   LANDLOCK_ACCESS_FS_IOCTL_DEV
  ]

  NetAccessMap: array[NetAccess, uint64] = [
    BindTcp:    LANDLOCK_ACCESS_NET_BIND_TCP,
    ConnectTcp: LANDLOCK_ACCESS_NET_CONNECT_TCP
  ]

  ScopeMap: array[Scope, uint64] = [
    AbstractUnixSocket: LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET,
    Signal:             LANDLOCK_SCOPE_SIGNAL
  ]

type Access* = FsAccess # Legacy alias

template toLandlock[T: enum](s: set[T], mask: uint64, mapping: array[T, uint64]): uint64 =
  var res: uint64 = 0
  for a in s:
    res = res or (mapping[a] and mask)
  res

macro sandbox*(body: untyped): untyped =
  ## Declarative DSL for sandboxing.
  ## Transforms a block of 'allow', 'allowNet', and 'scope' statements into a Landlock ruleset.
  let 
    allowedPaths = genSym(nskVar, "allowedPaths")
    allowedPorts = genSym(nskVar, "allowedPorts")
    scopeSet = genSym(nskVar, "scopeSet")
  
  result = newStmtList()
  result.add quote do:
    var `allowedPaths`: seq[tuple[path: string, flags: set[FsAccess]]] = @[]
    var `allowedPorts`: seq[tuple[port: uint64, flags: set[NetAccess]]] = @[]
    var `scopeSet`: set[Scope] = {}
  
  for node in body:
    case node.kind:
    of nnkCall, nnkCommand:
      let cmd = node[0].repr
      case cmd:
      of "allow":
        if node.len != 3: error("allow command expects 2 arguments: path and access set", node)
        let (path, access) = (node[1], node[2])
        result.add quote do: `allowedPaths`.add((`path`, `access`))
      of "allowNet":
        if node.len != 3: error("allowNet command expects 2 arguments: port and access set", node)
        let (port, access) = (node[1], node[2])
        result.add quote do: `allowedPorts`.add((`port`.uint64, `access`))
      of "scope":
        if node.len != 2: error("scope command expects 1 argument: scope set", node)
        let s = node[1]
        result.add quote do: `scopeSet` = `scopeSet` + `s`
      else:
        error("Unknown sandbox command: " & cmd, node)
    of nnkEmpty: discard
    else: error("Unexpected node in sandbox block: " & node.repr, node)
      
  result.add quote do:
    restrictTo(`allowedPaths`, `allowedPorts`, `scopeSet`)

macro toStaticLandlock*(s: static set[FsAccess]): uint64 =
  ## Computes the Landlock bitmask at compile-time.
  var mask: uint64 = 0
  for a in s:
    mask = mask or FsAccessMap[a]
  result = newLit(mask)

type 
  Sandboxed* = object
    ## A capability type representing a sandboxed state.

proc getAbiVersion*(): int =
  ## Returns the Landlock ABI version supported by the kernel.
  let res = landlock_create_ruleset(nil, 0, LANDLOCK_CREATE_RULESET_VERSION).int
  if res < 0: return 0
  return res

proc getBestEffortFsMask*(abi: int): uint64 =
  result = LANDLOCK_ACCESS_FS_EXECUTE or LANDLOCK_ACCESS_FS_WRITE_FILE or
           LANDLOCK_ACCESS_FS_READ_FILE or LANDLOCK_ACCESS_FS_READ_DIR or
           LANDLOCK_ACCESS_FS_REMOVE_DIR or LANDLOCK_ACCESS_FS_REMOVE_FILE or
           LANDLOCK_ACCESS_FS_MAKE_CHAR or LANDLOCK_ACCESS_FS_MAKE_DIR or
           LANDLOCK_ACCESS_FS_MAKE_REG or LANDLOCK_ACCESS_FS_MAKE_SOCK or
           LANDLOCK_ACCESS_FS_MAKE_FIFO or LANDLOCK_ACCESS_FS_MAKE_BLOCK or
           LANDLOCK_ACCESS_FS_MAKE_SYM
  if abi >= 2: result = result or LANDLOCK_ACCESS_FS_REFER
  if abi >= 3: result = result or LANDLOCK_ACCESS_FS_TRUNCATE
  if abi >= 5: result = result or LANDLOCK_ACCESS_FS_IOCTL_DEV

proc getBestEffortNetMask*(abi: int): uint64 =
  if abi >= 4:
    result = LANDLOCK_ACCESS_NET_BIND_TCP or LANDLOCK_ACCESS_NET_CONNECT_TCP

proc getBestEffortScopeMask*(abi: int): uint64 =
  if abi >= 6:
    result = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET or LANDLOCK_SCOPE_SIGNAL

proc restrictTo*(allowedPaths: seq[tuple[path: string, flags: set[FsAccess]]] = @[],
                allowedPorts: seq[tuple[port: uint64, flags: set[NetAccess]]] = @[],
                scopes: set[Scope] = {},
                flags: uint32 = 0) =
  ## Restricts the current process to ONLY the provided paths, ports, and scopes.
  
  let abi = getAbiVersion()
  if abi == 0:
    raise newException(LandlockError, "Landlock is not supported or enabled on this kernel.")

  let 
    fsMask = getBestEffortFsMask(abi)
    netMask = getBestEffortNetMask(abi)
    scopeMask = getBestEffortScopeMask(abi)

  # 1. Create Ruleset
  var attr = LandlockRulesetAttr(
    handled_access_fs: fsMask,
    handled_access_net: netMask,
    handled_scope: scopes.toLandlock(scopeMask, ScopeMap)
  )
  
  var attrSize = sizeof(attr)
  if abi < 4: attrSize = sizeof(uint64)
  elif abi < 6: attrSize = sizeof(uint64) * 2
  
  let rfd = landlock_create_ruleset(addr attr, attrSize, 0)
  if rfd.int < 0:
    raise newException(LandlockError, "Failed to create ruleset: " & $osErrorMsg(osLastError()))

  try:
    # 2. Add FS Rules
    for item in allowedPaths:
      const O_PATH = 0x200000 
      let fd = posix.open(item.path.cstring, O_PATH or O_CLOEXEC)
      if fd < 0:
        raise newException(LandlockError, "Failed to open path for rule: " & item.path)
      try:
        var pathBeneath = LandlockPathBeneathAttr(
          allowed_access: item.flags.toLandlock(fsMask, FsAccessMap),
          parent_fd: fd.int32
        )
        if landlock_add_rule(rfd, LANDLOCK_RULE_PATH_BENEATH, addr pathBeneath, 0) < 0:
          raise newException(LandlockError, "Failed to add rule for: " & item.path)
      finally:
        discard posix.close(fd.int32)

    # 3. Add Network Rules
    if abi >= 4:
      for item in allowedPorts:
        var netPort = LandlockNetPortAttr(
          allowed_access: item.flags.toLandlock(netMask, NetAccessMap),
          port: item.port
        )
        if landlock_add_rule(rfd, LANDLOCK_RULE_NET_PORT, addr netPort, 0) < 0:
          raise newException(LandlockError, "Failed to add rule for port: " & $item.port)

    # 4. Apply the Sandbox
    if setNoNewPrivs() < 0:
      raise newException(LandlockError, "Failed to set PR_SET_NO_NEW_PRIVS")

    var restrictFlags = flags
    if abi < 8: restrictFlags = restrictFlags and (not LANDLOCK_RESTRICT_SELF_TSYNC)
    
    if landlock_restrict_self(rfd, restrictFlags) < 0:
      raise newException(LandlockError, "Failed to restrict self")

  finally:
    discard posix.close(rfd.int.int32)

template withSandbox*(allowed: seq[tuple[path: string, flags: set[FsAccess]]], body: untyped) =
  ## Applies a filesystem sandbox and executes the body with a 'Sandboxed' capability.
  restrictTo(allowedPaths = allowed)
  block:
    let sb {.inject.}: Sandboxed = Sandboxed()
    body

proc restrictToRead*(paths: seq[string]) =
  ## High-level helper for the most common use-case: read-only access.
  var config: seq[tuple[path: string, flags: set[FsAccess]]]
  for p in paths:
    config.add((p, {ReadFile, ReadDir}))
  restrictTo(allowedPaths = config)
