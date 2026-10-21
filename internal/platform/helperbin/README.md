`go generate ./...` builds hoststray-helper.exe here, and the Windows app
embeds it (see internal/platform/helper_windows.go). The exe isn't committed.
