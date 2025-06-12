// SidStrings.h

namespace SidString
{
	extern const wchar_t* const Everyone                   ; // L"S-1-1-0";
	extern const wchar_t* const AppContainerSid_Unknown1   ; // L"S-1-15-2-1430448594-2639229838-973813799-439329657-1197984847-4069167804-1277922394";               // App container SID for... (don't remember)
	extern const wchar_t* const AppContainerSid_Unknown2   ; // L"S-1-15-2-95739096-486727260-2033287795-3853587803-1685597119-444378811-2746676523";                 // App container SID for... (don't remember)
	extern const wchar_t* const VmWorkerProcessCapability  ; // L"S-1-15-3-1024-2268835264-3721307629-241982045-173645152-1490879176-104643441-2915960892-1612460704";// sidVmWorkerProcessCapability
	extern const wchar_t* const CreatorOwner               ; // L"S-1-3-0";             // CREATOR OWNER
	extern const wchar_t* const OwnerRights                ; // L"S-1-3-4";
	extern const wchar_t* const NtAuthSystem               ; // L"S-1-5-18";            // NT AUTHORITY\SYSTEM
	extern const wchar_t* const NtAuthLocalService         ; // L"S-1-5-19";            // NT AUTHORITY\LOCAL SERVICE
	extern const wchar_t* const NtAuthNetworkService       ; // L"S-1-5-20";            // NT AUTHORITY\NETWORK SERVICE
	extern const wchar_t* const NtAuthBatch                ; // L"S-1-5-3";             // NT AUTHORITY\BATCH
	extern const wchar_t* const BuiltinAdministrators      ; // L"S-1-5-32-544";        // BUILTIN\Administrators
	extern const wchar_t* const BuiltinUsers               ; // L"S-1-5-32-545");
	extern const wchar_t* const BuiltinAccountOperators    ; // L"S-1-5-32-548";        // BUILTIN\Account Operators
	extern const wchar_t* const BuiltinServerOperators     ; // L"S-1-5-32-549";        // BUILTIN\Server Operators
	extern const wchar_t* const BuiltinPrintOperators      ; // L"S-1-5-32-550";        // BUILTIN\Print Operators
	extern const wchar_t* const BuiltinBackupOperators     ; // L"S-1-5-32-551";        // BUILTIN\Backup Operators
	extern const wchar_t* const BuiltinNetworkCfgOperators ; // L"S-1-5-32-556";
	extern const wchar_t* const BuiltinPerfLogUsers        ; // L"S-1-5-32-559";        // BUILTIN\Performance Log Users
	extern const wchar_t* const BuiltinIISIUsers           ; // L"S-1-5-32-568";        // BUILTIN\IIS_IUSRS
	extern const wchar_t* const BuiltinRdsMgtServers       ; // L"S-1-5-32-577";        // BUILTIN\RDS Management Servers
	extern const wchar_t* const NtAuthService              ; // L"S-1-5-6";             // NT AUTHORITY\SERVICE
	extern const wchar_t* const NtSvcTrustedInstaller      ; // L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";  // NT SERVICE\TrustedInstaller
	extern const wchar_t* const NtVMVirtualMachines        ; // L"S-1-5-83-0";          // NT VIRTUAL MACHINE\Virtual Machines
	extern const wchar_t* const NtAuthUserModeDrivers      ; // L"S-1-5-84-0-0-0-0-0";  // NT AUTHORITY\USER MODE DRIVERS
};