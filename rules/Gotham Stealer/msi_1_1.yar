/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2023-10-05
   Identifier: 
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule potential_gotham_stealer {
   meta:
      description = " - file potential_gotham_stealer.msi"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2023-10-05"
      hash1 = "05d60e098aa8e62108cd641125fcf2105688e484454bb7c0ccbcf8c5cefc1070"
   strings:
      $x1 = "The integers do not have to be consecutive.A named property to be tied to this item. All the items tied to the same property bec" ascii
      $x2 = "uninstall$C__D8257888821323B21C692E85134060C3=2/installtype=notransaction /action=uninstall /LogFile= \"[#_D8257888821323B21C692" ascii
      $x3 = "RMCCPSearchValidateProductIDCostInitializeFileCostRedirectedDllSupportIsolateComponentsCostFinalizeSetODBCFoldersInstallValidate" ascii
      $s4 = "u have chosen to remove [ProductName] from your computer. Are you sure you want to remove it?VolumeCostList1{\\VSI_MS_Sans_Serif" ascii
      $s5 = "To install in this folder, click \"Next\". To install to a different folder, enter it below or click \"Browse\".{\\VSI_MS_Shell_" ascii
      $s6 = "<assemblyIdentity name=\"Microsoft.Vsa.Vb.CodeDOMProcessor\" publicKeyToken=\"b03f5f7f11d50a3a\" culture=\"neutral\"/>" fullword ascii
      $s7 = "MsiGetTargetPathW - Getting Target Path for '%s'." fullword wide
      $s8 = "nent.ExpTypeComPlus component attributes.Remote execution option, one of irsEnumPrimary key used to identify a particular compon" ascii
      $s9 = "cuted.  Leave blank to suppress action.AdminUISequenceAdvtExecuteSequenceAdvtUISequenceAppIdActivateAtStorageGuidDllSurrogateLoc" ascii
      $s10 = "ure1.0.0.0MSILProcessorArchitecture{E7F174F4-FDAA-0D70-7FEE-1942CAA18EE9}0SETUPL~1.DLL|SetupLibrary_a4915c04583287e71f63eddadfbe" ascii
      $s11 = "all must abort.http://go.microsoft.com/fwlink/?LinkId=863262[VSDNETURLMSG]VSDFXAvailableMSVBDPCADLLCheckFXDIRCA_CheckFXv4.7.2VSD" ascii
      $s12 = "n displayed in progress dialog and log when action is executing.TemplateOptional localized format template used to format action" ascii
      $s13 = "CustomActions.dll" fullword ascii
      $s14 = "Found a version of MSCOREE.DLL" fullword wide
      $s15 = "11075631c974.dll.:USER'S~1|User's DesktopDesktopFolder.:USER'S~2|User's Programs MenuProgramMenuFolderSourceDir[ProgramFilesFold" ascii
      $s16 = "ET Framework version [1].  Please install the .NET Framework and run this setup again.  The .NET Framework can be obtained from " ascii
      $s17 = " name.Binary stream. The binary icon data in PE (.DLL or .EXE) or icon (.ICO) format.Primary key. Name of the icon file.IniFile0" ascii
      $s18 = " run service asStartTypeCatalogSFP CatalogDependencyParent catalog - only used by SFPFile name for the catalog.ShortcutThe comma" ascii
      $s19 = "o interpretation.InstallExecuteSequenceInstallUISequenceIsolatedComponentComponent_ApplicationKey to Component table item for ap" ascii
      $s20 = "Space=1ExitNo[WelcomeForm_ConfirmRemove]YesRetryIgnore[SelectFolderDialog_Property]SetTargetPath{}ResetDirectoryListNewDirectory" ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 2000KB and
      1 of ($x*) and 4 of them
}