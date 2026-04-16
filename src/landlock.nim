## Idiomatic Nim wrapper for the Linux Landlock LSM (Linux Security Module).
## Provides high-level, safe, and portable filesystem and network sandboxing for Nim applications.

import os, posix, macros, options

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
    ## Internal file descriptor wrapper for landlock rulesets.
    ## NOT exported - must be managed internally to prevent FD leaks.
    ## Users should use the high-level restrictTo/sandbox APIs instead.

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

const
  LandlockWrapperVersion* = "0.1.0"
    ## Version of this Nim wrapper library.
    ## This is distinct from the kernel's Landlock ABI version.

type
  LandlockError* = object of OSError
    ## Base exception for Landlock-specific failures.

  FsAccess* = enum
    ## Available filesystem operations to restrict or allow.
    ##
    ## Use these flags in sets to specify what filesystem operations
    ## are permitted on a given path. For example:
    ##   {ReadFile, ReadDir} for read-only access
    ##   {WriteFile, MakeReg} for creating and writing files
    Execute         ## Execute files (requires read access to directory)
    WriteFile       ## Modify existing files
    ReadFile        ## Read file contents
    ReadDir         ## List directory contents
    RemoveDir       ## Delete directories
    RemoveFile      ## Delete files
    MakeChar        ## Create character devices
    MakeDir         ## Create directories
    MakeReg         ## Create regular files
    MakeSock        ## Create Unix sockets
    MakeFifo        ## Create named pipes
    MakeBlock       ## Create block devices
    MakeSym         ## Create symbolic links
    Refer           ## Link/rename across directories (ABI v2+)
    Truncate        ## Truncate files (ABI v3+)
    IoctlDev        ## IOCTL on devices (ABI v5+)

  NetAccess* = enum
    ## Available network operations (TCP).
    ##
    ## Network sandboxing requires ABI v4+.
    ## Use these flags to control TCP networking:
    ##   {BindTcp} to allow binding server sockets
    ##   {ConnectTcp} to allow outbound connections
    BindTcp         ## Bind TCP sockets to ports (server operation)
    ConnectTcp      ## Connect TCP sockets (client operation)

  Scope* = enum
    ## Scoping restrictions for IPC and sockets.
    ##
    ## Scoping requires ABI v6+.
    ## Controls inter-process communication restrictions:
    ##   AbstractUnixSocket - restrict abstract Unix socket access
    ##   Signal - restrict signal sending to other processes
    AbstractUnixSocket  ## Restrict abstract Unix socket namespace access (ABI v6+)
    Signal              ## Restrict sending signals to other processes (ABI v6+)

  RestrictFlag* = enum
    ## Flags for landlock_restrict_self() behavior.
    ## ABI v7+: LogSameExecOff, LogNewExecOn, LogSubdomainsOff
    ## ABI v8+: TSync
    LogSameExecOff    ## Disable logging for same-exec transitions
    LogNewExecOn      ## Enable logging for new-exec transitions
    LogSubdomainsOff  ## Disable logging for subdomain transitions
    TSync             ## Sync restrictions across all threads (ABI v8+)

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

  RestrictFlagMap: array[RestrictFlag, uint32] = [
    LogSameExecOff:   LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF,
    LogNewExecOn:     LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON,
    LogSubdomainsOff: LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF,
    TSync:            LANDLOCK_RESTRICT_SELF_TSYNC
  ]

template toLandlock[T: enum](s: set[T], mask: uint64, mapping: array[T, uint64]): uint64 =
  var res: uint64 = 0
  for a in s:
    res = res or (mapping[a] and mask)
  res

func toRestrictFlags(s: set[RestrictFlag], abi: int): uint32 =
  ## Convert RestrictFlag set to uint32, filtering by ABI version.
  ## Pure function with no side effects.
  result = 0'u32
  for flag in s:
    # TSync is only available in ABI v8+
    if flag == TSync and abi < 8:
      continue
    result = result or RestrictFlagMap[flag]

macro sandbox*(body: untyped): untyped =
  ## Declarative DSL for sandboxing.
  ##
  ## Transforms a block of 'allow', 'allowNet', and 'scope' statements
  ## into a Landlock ruleset. This is the recommended high-level API.
  ##
  ## Returns a Sandboxed capability that must be captured or explicitly discarded.
  ##
  ## Commands:
  ##   allow <path>, {<FsAccess flags>}      - Allow filesystem operations
  ##   allowNet <port>, {<NetAccess flags>}  - Allow network operations (ABI v4+)
  ##   scope {<Scope flags>}                 - Add IPC restrictions (ABI v6+)
  ##
  ## Example:
  ##   discard sandbox:
  ##     allow "/tmp", {ReadFile, WriteFile, MakeReg}
  ##     allow "/home/user/data", {ReadFile, ReadDir}
  ##     allowNet 443, {ConnectTcp}
  ##     scope {Signal}
  ##
  ##   # Process is now restricted
  ##   writeFile("/tmp/safe.txt", "OK")  # Works
  ##   writeFile("/etc/bad", "NO")       # Denied by kernel
  let
    allowedPaths = genSym(nskVar, "allowedPaths")
    allowedPorts = genSym(nskVar, "allowedPorts")
    scopeSet = genSym(nskVar, "scopeSet")

  var stmts = newStmtList()
  stmts.add quote do:
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
        stmts.add quote do: `allowedPaths`.add((`path`, `access`))
      of "allowNet":
        if node.len != 3: error("allowNet command expects 2 arguments: port and access set", node)
        let (port, access) = (node[1], node[2])
        stmts.add quote do: `allowedPorts`.add((`port`.uint64, `access`))
      of "scope":
        if node.len != 2: error("scope command expects 1 argument: scope set", node)
        let s = node[1]
        stmts.add quote do: `scopeSet` = `scopeSet` + `s`
      else:
        error("Unknown sandbox command: " & cmd, node)
    of nnkEmpty: discard
    else: error("Unexpected node in sandbox block: " & node.repr, node)

  # Return the Sandboxed capability from restrictTo
  result = quote do:
    block:
      `stmts`
      restrictTo(`allowedPaths`, `allowedPorts`, `scopeSet`)

macro toStaticLandlock*(s: static set[FsAccess]): uint64 =
  ## Computes the Landlock bitmask at compile-time.
  ##
  ## Useful for verifying flag combinations or testing.
  ## Normal usage should prefer the high-level APIs.
  ##
  ## Example:
  ##   const ReadMask = toStaticLandlock({ReadFile, ReadDir})
  ##   # ReadMask == 12'u64
  var mask: uint64 = 0
  for a in s:
    mask = mask or FsAccessMap[a]
  result = newLit(mask)

type
  Sandboxed* = object
    ## A capability type representing a sandboxed state.
    ##
    ## This is returned by restrictTo(), sandbox:, and helper functions
    ## when sandboxing succeeds. Functions can require this type as a parameter
    ## to ensure they only run within a sandbox.
    ##
    ## Example:
    ##   proc dangerousOp(proof: Sandboxed) =
    ##     # Can only be called when sandboxed
    ##     ...
    ##
    ##   let sb = restrictToRead(@["/tmp"])
    ##   dangerousOp(sb)  # OK - we have proof
    ##   # dangerousOp(???)  # Compiler error - no proof

  SandboxPolicy* = object
    ## Builder type for constructing Landlock policies.
    ##
    ## Provides a fluent API for configuring sandbox restrictions
    ## before applying them. Recommended for complex policies.
    ##
    ## Example:
    ##   var policy = newSandboxPolicy()
    ##   policy.allowPath("/tmp", {ReadFile, WriteFile})
    ##         .allowPath("/home/user", {ReadFile})
    ##         .allowPort(443, {ConnectTcp})
    ##
    ##   let errors = policy.validate()
    ##   if errors.len == 0:
    ##     discard policy.apply()
    paths: seq[tuple[path: string, flags: set[FsAccess]]]
    ports: seq[tuple[port: uint64, flags: set[NetAccess]]]
    scopes: set[Scope]
    restrictFlags: set[RestrictFlag]

var
  gSandboxApplied {.threadvar.}: bool
    ## Thread-local flag tracking whether sandboxing has been applied.
    ## Used by isSandboxed() for introspection.

proc isSandboxed*(): bool =
  ## Returns true if this thread has applied Landlock restrictions.
  ##
  ## Note: This tracks only restrictions applied via this library.
  ## It does not detect restrictions inherited from parent processes
  ## or applied through other means.
  return gSandboxApplied

proc getSandboxedCapability*(): Option[Sandboxed] =
  ## Returns a Sandboxed capability if this thread has been sandboxed.
  ##
  ## This allows obtaining a capability token after sandboxing,
  ## useful when the original token was discarded.
  if gSandboxApplied:
    return some(Sandboxed())
  else:
    return none(Sandboxed)

proc getAbiVersion*(): int =
  ## Returns the Landlock ABI version supported by the kernel.
  let res = landlock_create_ruleset(nil, 0, LANDLOCK_CREATE_RULESET_VERSION).int
  if res < 0: return 0
  return res

func getBestEffortFsMask*(abi: int): uint64 =
  ## Returns filesystem access flags supported by the given ABI version.
  ## Pure function with no side effects.
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

func getBestEffortNetMask*(abi: int): uint64 =
  ## Returns network access flags supported by the given ABI version.
  ## Pure function with no side effects.
  if abi >= 4:
    result = LANDLOCK_ACCESS_NET_BIND_TCP or LANDLOCK_ACCESS_NET_CONNECT_TCP

func getBestEffortScopeMask*(abi: int): uint64 =
  ## Returns scoping flags supported by the given ABI version.
  ## Pure function with no side effects.
  if abi >= 6:
    result = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET or LANDLOCK_SCOPE_SIGNAL

# Forward declaration for builder pattern
proc restrictTo*(allowedPaths: seq[tuple[path: string, flags: set[FsAccess]]] = @[],
                allowedPorts: seq[tuple[port: uint64, flags: set[NetAccess]]] = @[],
                scopes: set[Scope] = {},
                restrictFlags: set[RestrictFlag] = {}): Sandboxed

# --- Builder Pattern API ---

proc newSandboxPolicy*(): SandboxPolicy =
  ## Creates a new empty sandbox policy.
  ##
  ## Use the builder methods to configure the policy, then call apply() to enforce it.
  ##
  ## Example:
  ##   let sb = newSandboxPolicy()
  ##     .allowPath("/tmp", {ReadFile, WriteFile})
  ##     .allowPort(443, {ConnectTcp})
  ##     .apply()
  result = SandboxPolicy(
    paths: @[],
    ports: @[],
    scopes: {},
    restrictFlags: {}
  )

proc allowPath*(policy: var SandboxPolicy, path: string, flags: set[FsAccess]): var SandboxPolicy {.discardable.} =
  ## Add a filesystem path with the given access permissions.
  ## Returns the policy for method chaining.
  policy.paths.add((path, flags))
  return policy

proc allowPort*(policy: var SandboxPolicy, port: uint64, flags: set[NetAccess]): var SandboxPolicy {.discardable.} =
  ## Add a network port with the given access permissions.
  ## Returns the policy for method chaining.
  policy.ports.add((port, flags))
  return policy

proc addScope*(policy: var SandboxPolicy, scope: Scope): var SandboxPolicy {.discardable.} =
  ## Add a single scoping restriction.
  ## Returns the policy for method chaining.
  policy.scopes.incl(scope)
  return policy

proc addScopes*(policy: var SandboxPolicy, scopes: set[Scope]): var SandboxPolicy {.discardable.} =
  ## Add multiple scoping restrictions.
  ## Returns the policy for method chaining.
  policy.scopes = policy.scopes + scopes
  return policy

proc setRestrictFlags*(policy: var SandboxPolicy, flags: set[RestrictFlag]): var SandboxPolicy {.discardable.} =
  ## Set landlock_restrict_self() behavior flags.
  ## Returns the policy for method chaining.
  policy.restrictFlags = flags
  return policy

proc validate*(policy: SandboxPolicy): seq[string] =
  ## Validates the policy without applying it.
  ## Returns a sequence of error messages. Empty sequence means the policy is valid.
  ##
  ## Checks:
  ## - Paths are absolute
  ## - Paths exist and are accessible
  ## - Ports are in valid range (1-65535)
  ##
  ## Example:
  ##   let errors = policy.validate()
  ##   if errors.len > 0:
  ##     for err in errors: echo "Validation error: ", err
  result = @[]

  # Validate filesystem paths
  for item in policy.paths:
    # Check if path is absolute
    if not isAbsolute(item.path):
      result.add("Path must be absolute: " & item.path)
      continue  # Skip existence check if path is not absolute

    # Check if path exists
    if not fileExists(item.path) and not dirExists(item.path):
      result.add("Path does not exist: " & item.path)

  # Validate network ports
  for item in policy.ports:
    if item.port == 0 or item.port > 65535:
      result.add("Port must be in range 1-65535: " & $item.port)

proc apply*(policy: SandboxPolicy): Sandboxed =
  ## Apply the configured sandbox policy to the current process.
  ## Returns a Sandboxed capability on success.
  return restrictTo(
    allowedPaths = policy.paths,
    allowedPorts = policy.ports,
    scopes = policy.scopes,
    restrictFlags = policy.restrictFlags
  )

proc restrictTo*(allowedPaths: seq[tuple[path: string, flags: set[FsAccess]]] = @[],
                allowedPorts: seq[tuple[port: uint64, flags: set[NetAccess]]] = @[],
                scopes: set[Scope] = {},
                restrictFlags: set[RestrictFlag] = {}): Sandboxed =
  ## Restricts the current process to ONLY the provided paths, ports, and scopes.
  ## Returns a 'Sandboxed' capability on success.
  ##
  ## All paths must be absolute. Relative paths will be rejected.
  ## Paths are canonicalized (symlinks resolved, '..' normalized) before use.
  ##
  ## The restrictFlags parameter controls landlock_restrict_self() behavior.
  ## Unsupported flags for the current ABI version are automatically filtered.
  ##
  ## Note: The return value must be captured or explicitly discarded.
  ## This enforces awareness that sandboxing has been applied.

  # Validate and canonicalize paths
  var canonicalPaths: seq[tuple[path: string, flags: set[FsAccess]]]
  for item in allowedPaths:
    if not isAbsolute(item.path):
      raise newException(LandlockError, "Path must be absolute: " & item.path)
    let canonical = absolutePath(item.path)
    canonicalPaths.add((canonical, item.flags))

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
    for item in canonicalPaths:
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

    let flags = toRestrictFlags(restrictFlags, abi)

    if landlock_restrict_self(rfd, flags) < 0:
      raise newException(LandlockError, "Failed to restrict self")

    # Mark this thread as sandboxed for introspection
    gSandboxApplied = true
    result = Sandboxed()

  finally:
    discard posix.close(rfd.int.int32)

template withSandbox*(allowed: seq[tuple[path: string, flags: set[FsAccess]]], body: untyped) =
  ## Applies a filesystem sandbox and executes the body with a 'Sandboxed' capability.
  ##
  ## The sandboxed capability is injected as `sb` for use in the body.
  ## This template is useful for scoping sandbox restrictions to a code block.
  ##
  ## Example:
  ##   withSandbox @[("/tmp", {ReadFile, WriteFile})]:
  ##     # sb is available here as the Sandboxed proof
  ##     writeFile("/tmp/test.txt", "data")
  ##     # Restricted to /tmp only
  let sb {.inject.}: Sandboxed = restrictTo(allowedPaths = allowed)
  block:
    body

proc restrictToRead*(paths: seq[string]): Sandboxed =
  ## High-level helper for the most common use-case: read-only access to multiple paths.
  ##
  ## Note: The return value must be captured or explicitly discarded.
  ## This enforces awareness that sandboxing has been applied.
  var config: seq[tuple[path: string, flags: set[FsAccess]]]
  for p in paths:
    config.add((p, {ReadFile, ReadDir}))
  return restrictTo(allowedPaths = config)

proc restrictToDir*(dir: string, flags: set[FsAccess]): Sandboxed =
  ## Restrict to a single directory tree with specified permissions.
  ##
  ## Common use case: sandbox a process to work within one directory.
  ## All subdirectories inherit the same permissions.
  ##
  ## Note: The return value must be captured or explicitly discarded.
  ## This enforces awareness that sandboxing has been applied.
  return restrictTo(allowedPaths = @[(dir, flags)])

proc restrictToNetworkOnly*(ports: seq[tuple[port: uint64, flags: set[NetAccess]]]): Sandboxed =
  ## Restrict to network-only access with no filesystem permissions.
  ##
  ## Common use case: network proxies, API clients, services that only need network.
  ##
  ## Note: The return value must be captured or explicitly discarded.
  ## This enforces awareness that sandboxing has been applied.
  return restrictTo(allowedPaths = @[], allowedPorts = ports)
