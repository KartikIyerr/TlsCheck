rule NOP_Instructions {
    meta:
        description = "Detects various NOP instructions and NOP sleds"
        author = "Kartik Iyer"
        severity = "medium"
        date = "2024-12-25"

    strings:
        // Traditional NOP instruction
        $nop1 = { 90 }                    // Single NOP (0x90)
        
        // Multi-byte NOP equivalents
        $nop2 = { 66 90 }                 // 2-byte NOP (DATA16 NOP)
        $nop3 = { 0F 1F 00 }              // 3-byte NOP
        $nop4 = { 0F 1F 40 00 }           // 4-byte NOP
        $nop5 = { 0F 1F 44 00 00 }        // 5-byte NOP
        $nop6 = { 66 0F 1F 44 00 00 }     // 6-byte NOP
        $nop7 = { 0F 1F 80 00 00 00 00 }  // 7-byte NOP
        $nop8 = { 0F 1F 84 00 00 00 00 00 } // 8-byte NOP
        
        // NOP equivalent instructions
        $nop_alt1 = { 89 C0 }             // mov eax, eax
        $nop_alt2 = { 8D 00 }             // lea eax, [eax]
        $nop_alt3 = { 87 DB }             // xchg ebx, ebx
        
        // Common NOP sled patterns
        $nop_sled1 = /\x90{10,}/          // 10 or more consecutive NOPs
        $nop_sled2 = { 90 90 90 90 90 }   // 5 consecutive NOPs

    condition:
        // Alert if:
        // 1. Found a NOP sled pattern
        // 2. High concentration of single NOPs
        // 3. Multiple different types of NOP instructions
        any of ($nop_sled*) or
        #nop1 > 15 or
        (3 of them and #nop1 > 5)
}

rule Suspicious_NOP_Pattern {
    meta:
        description = "Detects suspicious patterns of NOP instructions that might indicate shellcode"
        author = "Kartik Iyer"
        severity = "high"
        date = "2024-12-25"

    strings:
        // NOP instruction
        $nop = { 90 }
        
        // Common instructions found after NOP sleds
        $after_nop1 = { 90 90 90 90 90 E8 }  // NOPs followed by CALL
        $after_nop2 = { 90 90 90 90 90 EB }  // NOPs followed by JMP
        $after_nop3 = { 90 90 90 90 90 E9 }  // NOPs followed by JMP FAR
        $after_nop4 = { 90 90 90 90 90 FF }  // NOPs followed by indirect CALL/JMP

    condition:
        // Alert if:
        // 1. Found NOP sled followed by control flow instruction
        // 2. Large number of NOPs in small space
        any of ($after_nop*) or
        (#nop > 20 and @nop[1] - @nop[0] < 30)  // Many NOPs close together
}