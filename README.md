# Wazuh Installer for Windows

Getting Wazuh agents quickly especially with Sysmon can be tedious, so I made this script to simply it.

## How to use:

1. ```Download the file.```
2. ```cd "C:\path\to\wherever\it\is\"```
3. Edit the file to include the specific Agent version, Manager IP, and whatever other changes you'd like. ```powershell -noexit -ExecutionPolicy Bypass ise -File .\Wazuh-Installer.ps1```
4. ```powershell -ExecutionPolicy Bypass -File .\Wazuh-Installer.ps1```

---

Obviously all environments are different, so I encourage you to edit this as you need for you OWN environment. You MAY also need to edit the version Agent being downloaded.

You can use the resources below as a guide:

https://tryhackme.com/r/room/wazuhct (OUTDATED - Do not use the ```local_rules.xml``` it mentions, here is why: https://groups.google.com/g/wazuh/c/7lBYzNHdjX4)

https://wazuh.com/blog/learn-to-detect-threats-on-windows-by-monitoring-sysmon-events/

### Manual Wazuh Agent Set-up
https://documentation.wazuh.com/current/installation-guide/wazuh-agent/wazuh-agent-package-windows.html
https://documentation.wazuh.com/current/user-manual/agent/agent-enrollment/deployment-variables/deployment-variables-windows.html

### How Log Collection for Agents works in Wazuh
https://documentation.wazuh.com/current/user-manual/capabilities/log-data-collection/configuration.html
https://documentation.wazuh.com/current/user-manual/manager/event-logging.html

### How to remove a Wazuh Agent from the Wazuh Manager
https://documentation.wazuh.com/current/user-manual/agent/agent-management/remove-agents/remove.html

### Wazuh Rule Syntax
https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html

# Templates
You can edit this stuff within the script before deployment.
## Sysconfig.xml
```
<Sysmon schemaversion="4.10">
   <HashAlgorithms>md5</HashAlgorithms>
   <EventFiltering>
      <!--SYSMON EVENT ID 1 : PROCESS CREATION-->
      <ProcessCreate onmatch="include">
         <!--Powershell-->
         <Image condition="contains">powershell.exe</Image>
         <!--Mimikatz-->
         <Image condition="contains">mimikatz.exe</Image>
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
```

Element ProcessCreate content expects (Rule | RuleName | UtcTime | ProcessGuid | ProcessId | Image | FileVersion | Description | Product | Company | CommandLine | CurrentDirectory | User | LogonGuid | LogonId | TerminalSessionId | IntegrityLevel | Hashes | ParentProcessGuid | ParentProcessId | ParentImage | ParentCommandLine)

Now, note the Event ID numbers ABOVE. 

Those are connected to your ```local_rules.xml``` and what the Wazuh Manager will be checking for. 

The following is an example for your ```local_rules.xml``` found at ```/var/ossec/etc/rules/local_rules.xml``` which also includes the example from Wazuh's article mentioned above:

```
<group name="windows, sysmon, sysmon_process-anomalies,">
   <rule id="100002" level="12">
     <if_group>sysmon_event1</if_group>
     <field name="win.eventdata.image">mimikatz.exe</field>
     <description>Sysmon - Suspicious Process - mimikatz.exe</description>
   </rule>

   <rule id="100003" level="12">
     <if_group>sysmon_event8</if_group>
     <field name="win.eventdata.sourceImage">mimikatz.exe</field>
     <description>Sysmon - Suspicious Process mimikatz.exe created a remote thread</description>
   </rule>

   <rule id="100004" level="12">
     <if_group>sysmon_event_10</if_group>
     <field name="win.eventdata.sourceImage">mimikatz.exe</field>
     <description>Sysmon - Suspicious Process mimikatz.exe accessed $(win.eventdata.targetImage)</description>
   </rule>
</group>

<group name="sus-activities,">
   <rule id="100005" level="12">
     <if_group>sysmon_event1</if_group>
     <field name="win.system.channel">Microsoft-Windows-Sysmon</field>
     <description>Sysmon - Suspicious Process</description>
   </rule>
</group>
```

So, quick overview of Rule 100005, my default script sets up Sysmon on an Endpoint to monitor if Powershell or Event Viewer is opened. Because my scope is so small Rule 100005 is set up to trigger a warning if any event in Sysmon is triggered.
