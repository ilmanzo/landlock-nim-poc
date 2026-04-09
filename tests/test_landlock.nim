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
    echo outp
    quit("Compilation failed for helper: " & name)
    
  defer:
    try: removeFile(srcFile) except: discard
    try: removeFile(binFile) except: discard
    
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
    try: removeDir(testDir) except: discard
    try: removeFile(secretFile) except: discard

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

  test "Compile-time bitmask calculation":
    check toStaticLandlock({ReadFile, ReadDir}) == 12'u64
