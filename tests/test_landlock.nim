import unittest, os, osproc, strutils, net
import landlock

## Senior Review: Refactored test suite with reusable helpers for process isolation.

proc runTestHelper(name: string, source: string, args: seq[string] = @[]): string =
  ## Compiles and runs a small Nim script in a separate process to test sandboxing.
  let
    srcFile = getTempDir() / (name & ".nim")
    binFile = getTempDir() / name

  writeFile(srcFile, "import os, landlock, strutils, net, posix\n" & source)

  let (outp, exit) = execCmdEx("nim c -d:release --hints:off --path:./src -o:" & binFile & " " & srcFile)
  if exit != 0:
    echo "Compilation output:\n", outp
    quit("Compilation failed for helper: " & name)

  defer:
    # Clean up temporary files - ignore errors for non-existent files
    try:
      removeFile(srcFile)
    except OSError as e:
      if not e.msg.contains("No such file"):
        echo "Warning: Failed to remove ", srcFile, ": ", e.msg

    try:
      removeFile(binFile)
    except OSError as e:
      if not e.msg.contains("No such file"):
        echo "Warning: Failed to remove ", binFile, ": ", e.msg

  return execProcess(binFile, args = args, options = {poStdErrToStdOut}).strip()

suite "Landlock Security Module":
  var testDir, secretFile: string

  setup:
    testDir = absolutePath(getTempDir() / "landlock_test_suite")
    if not dirExists(testDir): createDir(testDir)
    writeFile(testDir / "allowed.txt", "inside sandbox")
    secretFile = absolutePath(getTempDir() / "landlock_secret_test.txt")
    writeFile(secretFile, "outside sandbox")

  teardown:
    # Clean up test fixtures - warn on unexpected errors
    try:
      removeDir(testDir)
    except OSError as e:
      if not e.msg.contains("No such file"):
        echo "Warning: Failed to remove test directory ", testDir, ": ", e.msg

    try:
      removeFile(secretFile)
    except OSError as e:
      if not e.msg.contains("No such file"):
        echo "Warning: Failed to remove secret file ", secretFile, ": ", e.msg

  test "ABI Versioning":
    check getAbiVersion() >= 1

  test "Filesystem Access: Enforcement":
    let code = """
try:
  discard restrictToRead(@[paramStr(2)])
  echo readFile(paramStr(1)).strip()
except:
  echo "PERMISSION_DENIED"
"""
    check runTestHelper("fs_ok", code, @[testDir / "allowed.txt", testDir]) == "inside sandbox"
    check runTestHelper("fs_denied", code, @[secretFile, testDir]) == "PERMISSION_DENIED"

  test "Network Sandbox (ABI v4+)":
    if getAbiVersion() < 4: skip()
    let code = """
try:
  discard sandbox: allowNet 8080, {BindTcp}
  var s = newSocket()
  s.bindAddr(Port(8080))
  echo "OK"
  try:
    var s2 = newSocket()
    s2.bindAddr(Port(9090))
    echo "FAIL"
  except: echo "DENIED"
except LandlockError: echo "UNSUPPORTED"
"""
    check runTestHelper("net_test", code) == "OK\nDENIED"

  test "Scoping (ABI v6+)":
    if getAbiVersion() < 6: skip()
    let code = """
try:
  discard sandbox: scope {Signal}
  if kill(getpid(), 0) == 0: echo "SELF_OK"
  if kill(1, 0) == -1: echo "INIT_DENIED"
except LandlockError: echo "UNSUPPORTED"
"""
    check runTestHelper("scope_test", code) == "SELF_OK\nINIT_DENIED"

  test "Advanced FS Access (ABI v3+)":
    if getAbiVersion() < 3: skip()
    let code = """
let target = paramStr(1)
try:
  discard sandbox: allow target, {ReadFile, WriteFile, Truncate}
  let f = open(target, fmWrite)
  f.setFilePos(0)
  f.write("truncated")
  f.close()
  echo "OK"
except: echo "ERROR"
"""
    check runTestHelper("truncate_test", code, @[testDir / "allowed.txt"]) == "OK"

  test "Path validation: rejects relative paths":
    let code = """
try:
  discard restrictToRead(@["relative/path"])
  echo "FAIL"
except LandlockError as e:
  if "must be absolute" in e.msg: echo "OK"
  else: echo "WRONG_ERROR"
"""
    check runTestHelper("relative_path_test", code) == "OK"

  test "Path validation: canonicalizes paths with ..":
    let code = """
let testPath = paramStr(1)
let parent = parentDir(testPath)
let withDots = testPath / ".." / testPath.splitPath.tail
try:
  # Should work - path gets canonicalized
  discard restrictToRead(@[withDots])
  echo readFile(testPath / "allowed.txt").strip()
except: echo "ERROR"
"""
    check runTestHelper("canonicalize_test", code, @[testDir]) == "inside sandbox"

  test "Path validation: resolves symlinks":
    # Create a symlink to testDir
    let linkPath = getTempDir() / "landlock_symlink_test"
    try: removeFile(linkPath) except: discard
    createSymlink(testDir, linkPath)

    let code = """
let linkPath = paramStr(1)
let targetFile = paramStr(2)
try:
  # Allow access via symlink - should be resolved to real path
  discard restrictToRead(@[linkPath])
  echo readFile(targetFile).strip()
except: echo "ERROR"
"""
    let result = runTestHelper("symlink_test", code, @[linkPath, testDir / "allowed.txt"])
    removeFile(linkPath)
    check result == "inside sandbox"

  test "Capability type enforcement":
    # This test verifies that Sandboxed is a proper capability type
    # Functions can require proof of sandboxing via the Sandboxed parameter
    let code = """
try:
  proc secureOp(proof: Sandboxed): string = "ok"
  let sb = restrictToRead(@[paramStr(1)])
  echo secureOp(sb)
except: echo "ERROR"
"""
    check runTestHelper("capability_test", code, @[testDir]) == "ok"

  test "Type-safe restrict flags":
    # Test that RestrictFlag set works correctly
    let code = """
try:
  # Using type-safe flags instead of raw uint32
  let sb = restrictTo(
    allowedPaths = @[(paramStr(1), {ReadFile, ReadDir})],
    restrictFlags = {}  # empty set is valid
  )
  echo readFile(paramStr(1) / "allowed.txt").strip()
except: echo "ERROR"
"""
    check runTestHelper("restrict_flags_test", code, @[testDir]) == "inside sandbox"

  test "Helper: restrictToDir":
    let code = """
try:
  discard restrictToDir(paramStr(1), {ReadFile, ReadDir, WriteFile, MakeReg})
  let content = readFile(paramStr(1) / "allowed.txt").strip()
  writeFile(paramStr(1) / "newfile.txt", "created")
  echo content
except: echo "ERROR"
"""
    check runTestHelper("restrict_dir_test", code, @[testDir]) == "inside sandbox"

  test "Helper: restrictToNetworkOnly":
    if getAbiVersion() < 4: skip()
    let code = """
try:
  discard restrictToNetworkOnly(@[(8080'u64, {BindTcp})])
  # Should be able to bind network
  var s = newSocket()
  s.bindAddr(Port(8080))
  # Should NOT be able to read files
  try:
    discard readFile("/etc/hostname")
    echo "FAIL_FS_ALLOWED"
  except:
    echo "OK"
except: echo "ERROR"
"""
    check runTestHelper("network_only_test", code) == "OK"

  test "Wrapper version constant":
    check LandlockWrapperVersion == "0.1.0"
    check LandlockWrapperVersion.len > 0

  test "Policy introspection: isSandboxed":
    let code = """
import options
# Before sandboxing
if not isSandboxed(): echo "NOT_SANDBOXED_BEFORE"
if getSandboxedCapability().isNone: echo "NO_CAPABILITY_BEFORE"

# Apply sandboxing
discard restrictToRead(@[paramStr(1)])

# After sandboxing
if isSandboxed(): echo "SANDBOXED_AFTER"
let cap = getSandboxedCapability()
if cap.isSome: echo "HAS_CAPABILITY_AFTER"
"""
    let result = runTestHelper("introspection_test", code, @[testDir])
    check result.contains("NOT_SANDBOXED_BEFORE")
    check result.contains("NO_CAPABILITY_BEFORE")
    check result.contains("SANDBOXED_AFTER")
    check result.contains("HAS_CAPABILITY_AFTER")

  test "Policy introspection: getSandboxedCapability usage":
    let code = """
import options
proc requiresSandbox(proof: Sandboxed): string = "secure_op_ok"

discard restrictToRead(@[paramStr(1)])
let cap = getSandboxedCapability()
if cap.isSome:
  echo requiresSandbox(cap.get)
else:
  echo "ERROR"
"""
    check runTestHelper("capability_retrieval_test", code, @[testDir]) == "secure_op_ok"

  test "Builder pattern: fluent API":
    let code = """
var policy = newSandboxPolicy()
policy.allowPath(paramStr(1), {ReadFile, ReadDir})
      .allowPath(paramStr(2), {WriteFile, MakeReg})
discard policy.apply()

# Should be able to read from first path
echo readFile(paramStr(1) / "allowed.txt").strip()

# Should be able to write to second path
writeFile(paramStr(2) / "written.txt", "data")
echo "WRITE_OK"
"""
    let writePath = getTempDir() / "landlock_write_test"
    if not dirExists(writePath): createDir(writePath)
    let result = runTestHelper("builder_test", code, @[testDir, writePath])
    check result.contains("inside sandbox")
    check result.contains("WRITE_OK")
    removeDir(writePath)

  test "Builder pattern: with network and scopes":
    if getAbiVersion() < 4: skip()
    let code = """
var policy = newSandboxPolicy()
discard policy.allowPort(8080, {BindTcp})
              .addScope(Signal)
              .apply()

var s = newSocket()
s.bindAddr(Port(8080))
echo "BIND_OK"

# Verify scoping works
if kill(getpid(), 0) == 0: echo "SELF_OK"
"""
    let result = runTestHelper("builder_network_test", code)
    check result.contains("BIND_OK")
    check result.contains("SELF_OK")

  test "Policy validation: valid policy":
    var policy = newSandboxPolicy()
    policy.allowPath(testDir, {ReadFile, ReadDir})
    let errors = policy.validate()
    check errors.len == 0

  test "Policy validation: detects non-existent paths":
    var policy = newSandboxPolicy()
    policy.allowPath("/nonexistent/path/12345", {ReadFile})
    let errors = policy.validate()
    check errors.len > 0
    check errors[0].contains("does not exist")

  test "Policy validation: detects relative paths":
    var policy = newSandboxPolicy()
    policy.allowPath("relative/path", {ReadFile})
    let errors = policy.validate()
    check errors.len > 0
    check errors[0].contains("must be absolute")

  test "Policy validation: detects invalid ports":
    var policy = newSandboxPolicy()
    policy.allowPort(0, {BindTcp})
    policy.allowPort(70000, {BindTcp})
    let errors = policy.validate()
    check errors.len >= 2
    var foundRangeError = false
    for e in errors:
      if e.contains("range 1-65535"):
        foundRangeError = true
        break
    check foundRangeError

  test "Policy validation: multiple errors":
    var policy = newSandboxPolicy()
    policy.allowPath("relative", {ReadFile})
    policy.allowPath("/nonexistent/path", {ReadFile})
    policy.allowPort(0, {BindTcp})
    let errors = policy.validate()
    check errors.len >= 3

  test "Compile-time bitmask calculation":
    check toStaticLandlock({ReadFile, ReadDir}) == 12'u64
