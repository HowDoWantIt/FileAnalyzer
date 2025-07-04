[Setup]
AppName=File Analyzer
AppVersion=1.0
DefaultDirName={pf}\FileAnalyzer
DefaultGroupName=File Analyzer
OutputDir=output
OutputBaseFilename=FileAnalyzerInstaller
Compression=lzma
SolidCompression=yes

[Files]
Source: "..\dist\main.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\File Analyzer"; Filename: "{app}\main.exe"
