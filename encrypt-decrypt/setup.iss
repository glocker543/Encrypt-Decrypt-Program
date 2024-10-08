; Script generated by the Inno Setup Script Wizard.
; SEE THE DOCUMENTATION FOR DETAILS ON CREATING INNO SETUP SCRIPT FILES!

[Setup]
; NOTE: The value of AppId uniquely identifies this application.
; Do not use the same AppId value in installers for other applications.
; (To generate a new GUID, click Tools | Generate GUID inside the IDE.)
AppId={{F1E26288-C0D3-4CAF-A127-7D417116CD80}}
AppName=EncryptionDecryptionProgram
AppVersion=1.0
DefaultDirName={autopf}\EncryptionDecryptionProgram
DefaultGroupName=EncryptionDecryptionProgram
AllowNoIcons=yes
OutputDir=.
OutputBaseFilename=EncryptionDecryptionSetup
Compression=lzma
SolidCompression=yes

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
Source: "dist\encryption_gui.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\EncryptionDecryptionProgram"; Filename: "{app}\encryption_gui.exe"
Name: "{commondesktop}\EncryptionDecryptionProgram"; Filename: "{app}\encryption_gui.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\encryption_gui.exe"; Description: "{cm:LaunchProgram,EncryptionDecryptionProgram}"; Flags: nowait postinstall skipifsilent
