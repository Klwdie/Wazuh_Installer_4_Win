# Made by Raphael Stoute
#
# https://github.com/Klwdie
# https://www.linkedin.com/in/raphael-stoute/
# raphaelscr@protonmail.com
#
# Please feel free to use fork this and make changes as you see fit for your own uses. I simply ask for credit.
#
# Run as administrator and stays in the current directory
if (-Not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    if ([int](Get-CimInstance -Class Win32_OperatingSystem | Select-Object -ExpandProperty BuildNumber) -ge 6000) {
        Start-Process PowerShell -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -Command `"cd '$pwd'; & '$PSCommandPath';`"";
        Exit;
    }
}

$purin = @"




                             -----
                        ----+###+#+-+-
                      -++##+++####+####+.
                    #####+++#######++++##+
                 ####..#####################
             #####............++++-........####
          +###......-------...........----....####
         ##.........-.....----------------.......####
        ##...-...##.-.##+.--.......--......+#.-....+##
       -#..--...##..-.........###.....##-..##..---...##       Wazuh Agent Installer by Klwd
       -#...-..##..-------.#...#..#-........#+..----..#-
        ##.....#..--------.####.###-.-----..##....-...#-
         #######..--------.............----..###.....##
              ##..-----------..######.....--...#######
            -+#...-----------.##.....###...---.##
          +#+##..------------.##.......+##.---.##+
         -#..#..-------------..##....-.....---..## ###
         ##.##..-------------...+###...--------.-##-.##
        +####..-........-------....###.--------..##...#
       -##.-#.....####...--------......--------..+#..-#
       +#...#...##...+##.-----------------------..#.##+
       +#...##..#........---------------------...####
       -#.......#..--...-----------------........#+
        +##.....#...-------------..............###
          ########.........................#####
                 +##########################




"@
Write-Output $purin

# Navigate to the Temp directory
Set-Location C:\Temp

# Download the Wazuh agent MSI
Write-Output "Downloading Wazuh agent..."
Invoke-WebRequest -Uri "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.9.2-1.msi" -OutFile "wazuh-agent.msi" #Make sure to set the right version.

# Install the Wazuh agent
Write-Output "Installing Wazuh agent..."
Start-Process "msiexec.exe" -ArgumentList "/i wazuh-agent.msi /q WAZUH_MANAGER=<DONT_FORGET_YOUR_MANAGER_IP>" -Wait #Make sure to set the Wazuh Manager IP.

NET START Wazuh

# Download Sysmon.zip
Write-Output "Downloading Sysmon..."
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Sysmon.zip" -OutFile "Sysmon.zip"

# Unzip Sysmon.zip to the specified directory
Expand-Archive -Path "Sysmon.zip" -DestinationPath "C:\Program Files (x86)\ossec-agent\Sysmon\"

# Wait for 2 seconds
Start-Sleep -Seconds 2

# Delete the Sysmon.zip file and MSI file
Write-Output "Cleaning up..."
Remove-Item -Path "wazuh-agent.msi" -Force
Remove-Item -Path "Sysmon.zip" -Force

# Navigate to the Sysmon directory
Write-Output "Implementing Sysmon configuration..."
Set-Location "C:\Program Files (x86)\ossec-agent\Sysmon\"

# Wait for 2 seconds
Start-Sleep -Seconds 2

# Create Sysmon.xml file
$xmlContent = @'
<Sysmon schemaversion="4.10">
   <HashAlgorithms>md5</HashAlgorithms>
   <EventFiltering>
      <!--SYSMON EVENT ID 1 : PROCESS CREATION-->
      <ProcessCreate onmatch="include">
         <!--Powershell-->
         <Image condition="contains">powershell.exe</Image>
         <!--Event Viewer-->
         <CommandLine condition="contains">eventvwr.msc</CommandLine>
      </ProcessCreate>
      <!--SYSMON EVENT ID 2 : FILE CREATION TIME RETROACTIVELY CHANGED IN THE FILESYSTEM-->
      <FileCreateTime onmatch="include" />
      <!--SYSMON EVENT ID 3 : NETWORK CONNECTION INITIATED-->
      <NetworkConnect onmatch="include" />
      <!--SYSMON EVENT ID 4 : RESERVED FOR SYSMON STATUS MESSAGES, THIS LINE IS INCLUDED FOR DOCUMENTATION PURPOSES ONLY-->
      <!--SYSMON EVENT ID 5 : PROCESS ENDED-->
      <ProcessTerminate onmatch="include" />
      <!--SYSMON EVENT ID 6 : DRIVER LOADED INTO KERNEL-->
      <DriverLoad onmatch="include" />
      <!--SYSMON EVENT ID 7 : DLL (IMAGE) LOADED BY PROCESS-->
      <ImageLoad onmatch="include" />
      <!--SYSMON EVENT ID 8 : REMOTE THREAD CREATED-->
      <CreateRemoteThread onmatch="include" />
      <!--SYSMON EVENT ID 9 : RAW DISK ACCESS-->
      <RawAccessRead onmatch="include" />
      <!--SYSMON EVENT ID 10 : INTER-PROCESS ACCESS-->
      <ProcessAccess onmatch="include" />
      <!--SYSMON EVENT ID 11 : FILE CREATED-->
      <FileCreate onmatch="include" />
      <!--SYSMON EVENT ID 12 & 13 & 14 : REGISTRY MODIFICATION-->
      <RegistryEvent onmatch="include" />
      <!--SYSMON EVENT ID 15 : ALTERNATE DATA STREAM CREATED-->
      <FileCreateStreamHash onmatch="include" />
      <PipeEvent onmatch="include" />
   </EventFiltering>
</Sysmon>
'@
$xmlContent | Out-File -FilePath "Sysconfig.xml"

# Install Sysmon with the specified configuration
Write-Output "Starting Sysmon..."
Start-Process -FilePath ".\Sysmon64.exe" -ArgumentList "-accepteula -i Sysconfig.xml" -Wait

# Navigate back to the ossec-agent directory
Set-Location "C:\Program Files (x86)\ossec-agent\"

# Read the existing content of ossec.conf
Write-Output "Implementing Wazuh configuration..."
$configPath = "ossec.conf"
$configContent = Get-Content -Path $configPath

# Configuration to be added at line 34
$newConfig = @'
  <!-- Sysmon analysis -->
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- PrintService analysis -->
  <localfile>
    <location>Microsoft-Windows-PrintService/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Windows Defender analysis -->
  <localfile>
    <location>Microsoft-Windows-Windows Defender/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <!-- Powershell analysis -->
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>Microsoft-Windows-TerminalServices-RemoteConnectionManager</location>
    <log_format>eventchannel</log_format>
  </localfile>

  <localfile>
    <location>File Replication Service</location>
    <log_format>eventchannel</log_format>
  </localfile>

'@

# Insert the new configuration at line 34
$newConfigContent = $configContent[0..33] + $newConfig + $configContent[34..$configContent.Length]

# Write the updated content back to ossec.conf
$newConfigContent | Set-Content -Path $configPath

Write-Output "Getting the Wazuh agent ready..."
Restart-Service -Name wazuh

$notice = @"
All done! Please read the following:

...................................................................................................................
Pressing Enter will open Event Viewer, so you can quickly double check Sysmon's functionality. Navigate as follows:

Application and Services > Microsoft > Windows > Sysmon > Operational

Ensure that Sysmon is monitoring what you have set it to.
...................................................................................................................

"@
Write-Output $notice
pause
& "eventvwr"
exit