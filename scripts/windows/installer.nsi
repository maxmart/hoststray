; Per-user installer for Hosts Tray. scripts/build-release.sh builds it (on
; the Mac, with `brew install makensis`); by hand:
;
;   makensis -DVERSION=0.11.0 -DEXE=dist/hoststray-0.11.0-windows-amd64.exe \
;            -DOUTFILE=dist/Hosts-Tray-0.11.0-windows-amd64-setup.exe scripts/windows/installer.nsi
;
; It installs into %LOCALAPPDATA%\Programs without asking for admin rights.
; That folder is the user's own, so the app's auto-updater can swap the exe
; in place (it couldn't in Program Files).

!ifndef VERSION | EXE | OUTFILE
  !error "define VERSION, EXE and OUTFILE (see the top of this file)"
!endif

Unicode true
ManifestDPIAware true
RequestExecutionLevel user
SetCompressor /SOLID lzma

!define NAME "Hosts Tray"
!define UNINST_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\HostsTray"
!define RUN_KEY "Software\Microsoft\Windows\CurrentVersion\Run"

Name "${NAME}"
OutFile "${OUTFILE}"
InstallDir "$LOCALAPPDATA\Programs\${NAME}"
InstallDirRegKey HKCU "${UNINST_KEY}" "InstallLocation"
BrandingText " "

VIProductVersion "${VERSION}.0"
VIAddVersionKey "ProductName" "${NAME}"
VIAddVersionKey "FileDescription" "${NAME} installer"
VIAddVersionKey "ProductVersion" "${VERSION}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "LegalCopyright" "Copyright (c) 2023 Max Martinsson"

!include "MUI2.nsh"
!include "FileFunc.nsh"
!include "LogicLib.nsh"

!define MUI_ICON "icon.ico"
!define MUI_UNICON "icon.ico"
!define MUI_FINISHPAGE_RUN "$INSTDIR\hoststray.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Start ${NAME}"

!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"

; Stops a running Hosts Tray started from $INSTDIR (and only that one), so its
; exe can be replaced or removed. The installer is 32-bit, and a 32-bit process
; can't read a 64-bit process's path with Get-Process, so ask WMI.
!macro StopApp
  nsExec::Exec `powershell.exe -NoProfile -NonInteractive -Command "Get-CimInstance Win32_Process | Where-Object { $$_.ExecutablePath -eq '$INSTDIR\hoststray.exe' } | ForEach-Object { Stop-Process -Id $$_.ProcessId -Force }"`
  Pop $0
  Sleep 500
!macroend

Section
  !insertmacro StopApp
  SetOutPath "$INSTDIR"
  ClearErrors
  File "/oname=hoststray.exe" "${EXE}"
  ${If} ${Errors}
    MessageBox MB_OK|MB_ICONSTOP "Could not replace $INSTDIR\hoststray.exe. Quit Hosts Tray and run the installer again." /SD IDOK
    SetErrorLevel 2
    Quit
  ${EndIf}
  Delete "$INSTDIR\hoststray.exe.old"
  WriteUninstaller "$INSTDIR\uninstall.exe"
  CreateShortCut "$SMPROGRAMS\${NAME}.lnk" "$INSTDIR\hoststray.exe"

  WriteRegStr HKCU "${UNINST_KEY}" "DisplayName" "${NAME}"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr HKCU "${UNINST_KEY}" "DisplayIcon" "$INSTDIR\hoststray.exe"
  WriteRegStr HKCU "${UNINST_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr HKCU "${UNINST_KEY}" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegStr HKCU "${UNINST_KEY}" "QuietUninstallString" '"$INSTDIR\uninstall.exe" /S'
  WriteRegStr HKCU "${UNINST_KEY}" "URLInfoAbout" "https://github.com/maxmart/hoststray"
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoModify" 1
  WriteRegDWORD HKCU "${UNINST_KEY}" "NoRepair" 1
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  WriteRegDWORD HKCU "${UNINST_KEY}" "EstimatedSize" $0
SectionEnd

Section "Uninstall"
  !insertmacro StopApp

  ; The helper service runs a copy of the exe from Program Files; removing it
  ; asks for permission, and only if it is installed.
  ExecWait '"$INSTDIR\hoststray.exe" --remove-helper'

  ; Undo what the app set up outside its folder. Hosts file entries are kept.
  MessageBox MB_YESNO|MB_ICONQUESTION "Also remove Hosts Tray's settings and certificates?$\n$\nThis stops Windows trusting its certificate authority and removes password-free access to the hosts file (which asks for permission). Your hosts file entries are kept." /SD IDNO IDNO keepdata
    ExecWait '"$INSTDIR\hoststray.exe" --uninstall'
    RMDir /r "$APPDATA\hoststray"
  keepdata:

  DeleteRegValue HKCU "${RUN_KEY}" "${NAME}"
  Delete "$SMPROGRAMS\${NAME}.lnk"
  Delete "$INSTDIR\hoststray.exe"
  Delete "$INSTDIR\hoststray.exe.old"
  Delete "$INSTDIR\uninstall.exe"
  RMDir "$INSTDIR"
  DeleteRegKey HKCU "${UNINST_KEY}"
SectionEnd
