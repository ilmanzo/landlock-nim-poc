# Package
version       = "0.1.0"
author        = "Andrea Manzini"
description   = "Idiomatic Nim wrapper for the Linux Landlock LSM"
license       = "MIT"
srcDir        = "src"
bin           = @["landlock_example"]
binDir        = "bin"

# Dependencies
requires "nim >= 2.0.0"

task test, "Run the test suite":
  exec "nim c -r --path:./src tests/test_landlock.nim"

task example, "Run the example tool":
  exec "nim c -r --path:./src src/landlock_example.nim /tmp/landlock_demo"
