import landlock, os, strutils

proc main() =
  if paramCount() < 1:
    echo "Usage: landlock_example <allowed_dir>"
    echo "This example will perform various file operations in the specified directory."
    return

  let allowedDir = absolutePath(paramStr(1))
  let testFile = allowedDir / "example_test.txt"
  let testSubDir = allowedDir / "subdir"
  let testSubFile = testSubDir / "subfile.txt"

  # Ensure the sandbox directory exists
  if not dirExists(allowedDir):
    createDir(allowedDir)

  echo "--- Sandbox Target: ", allowedDir, " ---"

  echo "\n--- Applying Sandbox (FS + Net + Scope) ---"
  try:
    sandbox:
      allow allowedDir, {ReadFile, ReadDir, WriteFile, MakeReg, MakeDir, RemoveFile, RemoveDir}
      allowNet 443, {ConnectTcp}
      scope {Signal}
    
    echo "Sandbox applied successfully!"
  except LandlockError as e:
    echo "Failed to apply sandbox: ", e.msg
    quit(1)

  echo "\n--- Performing Allowed Operations ---"

  # 1. Create and Write to a File
  try:
    echo "Creating and writing to: ", testFile
    writeFile(testFile, "Hello from the Landlock sandbox!\n")
    echo "SUCCESS: File created and written."
  except:
    echo "FAILURE: Could not write file: ", getCurrentExceptionMsg()

  # 2. Read the File
  try:
    echo "Reading back the file contents..."
    let content = readFile(testFile).strip()
    echo "Read back: '", content, "'"
    echo "SUCCESS: File read back."
  except:
    echo "FAILURE: Could not read file: ", getCurrentExceptionMsg()

  # 3. Create a Subdirectory
  try:
    echo "Creating subdirectory: ", testSubDir
    createDir(testSubDir)
    echo "SUCCESS: Subdirectory created."
  except:
    echo "FAILURE: Could not create directory: ", getCurrentExceptionMsg()

  # 4. Create and Write a File inside the Subdirectory
  try:
    echo "Creating and writing to: ", testSubFile
    writeFile(testSubFile, "Nested data inside a sandbox.\n")
    echo "SUCCESS: Nested file created and written."
  except:
    echo "FAILURE: Could not write nested file: ", getCurrentExceptionMsg()

  # 5. List the Subdirectory
  try:
    echo "Listing subdirectory contents..."
    for kind, path in walkDir(testSubDir):
      echo "  - ", kind, ": ", path
    echo "SUCCESS: Subdirectory listed."
  except:
    echo "FAILURE: Could not list directory: ", getCurrentExceptionMsg()

  # 6. Delete the Files
  try:
    echo "Deleting files..."
    removeFile(testSubFile)
    removeFile(testFile)
    echo "SUCCESS: Files deleted."
  except:
    echo "FAILURE: Could not delete files: ", getCurrentExceptionMsg()

  # 7. Delete the Subdirectory
  try:
    echo "Deleting subdirectory..."
    removeDir(testSubDir)
    echo "SUCCESS: Subdirectory deleted."
  except:
    echo "FAILURE: Could not delete directory: ", getCurrentExceptionMsg()

  echo "\n--- Performing Forbidden Operations ---"

  # 8. Try to write outside the sandbox
  let forbiddenFile = "/tmp/landlock_escape.txt"
  echo "Trying to write to forbidden path: ", forbiddenFile
  try:
    writeFile(forbiddenFile, "If you see this, the sandbox failed!\n")
    echo "FAILURE: Wrote to forbidden file (SHOULD HAVE BEEN DENIED)!"
  except:
    echo "SUCCESS: Access to /tmp denied (Expected behavior)"

  # 9. Try to read a sensitive file
  let secret = "/etc/hostname"
  echo "Trying to read sensitive file: ", secret
  try:
    let data = readFile(secret).strip()
    echo "FAILURE: Read sensitive file: ", data, " (SHOULD HAVE BEEN DENIED)!"
  except:
    echo "SUCCESS: Access to /etc/hostname denied (Expected behavior)"

if isMainModule:
  main()
