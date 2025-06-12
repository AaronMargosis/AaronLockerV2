#pragma once

/// <summary>
/// Indicates whether the current computer is a domain controller.
/// Reports "false" if the machine has been booted into Directory Services Repair Mode (DSRM).
/// </summary>
/// <returns>true if the computer is a DC that is not in Directory Services Repair Mode; false otherwise.</returns>
bool IsDomainController();
