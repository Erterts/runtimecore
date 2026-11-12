//==============================================================
//  detect_intrusion.hpp
//==============================================================
#pragma once
#include "graph_struct.hpp"

/*  PURPOSE
    Набор из 9 правил обнаружения атак.
    Каждое правило чисто: возвращает bool, НЕ меняет глобальный стейт.
*/

/*  ==== TODO ====
    1. enum RuleId { ReverseShell, Orphan, DownloadExec, K8sToken,
                     IpFanout, SysFileRewrite, TmpDirExec,
                     Mass777, SuitRoot };
    2. using DetectFn = bool(const Packet&, const Context&) noexcept;
    3. inline bool rule_reverse_shell (…);
       …
       inline bool rule_suit_root    (…);
    4. constexpr std::array<DetectFn*,9> DETECTORS = { … };
    5. helper: apply_risk_flag(Pid, RuleId) – выставляет InRisk/Compromised
*/
