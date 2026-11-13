
#pragma once
#include "graph_struct.h"

/*  PURPOSE
    Набор из 10 правил обнаружения атак:
    1. Reverse shell - имеет доступ к командной строке, при этом соединенный с внешним не системным ip , либо создает дочерние bin/bash
2. Процесс сирота - не базовый системный процесс и не временно ожидающий родителя по причине задержки логов(их привязываем к суперкорню) 
3. Download - exec . Запуск скачанного извне файла
4. Попытка чтения системных токенов kubernetes,кроме самого первого процесса (обычно pid=1) - детект через kprobe 
5. Аномальное расширение подключенных ip адресов (считаем уникальные ip и сравниваем число за период времени , точные значения будем подбирать)
6. Попытка перезаписи системных файлов linux - определяется через kprobe
7. Temp-dir exec - запуск бинарников из временных папок - process.binary/argv[0] начинается с /tmp/ и это не системный build процесс
8. Массовое повышение прав и раздача привилегий - за время T секунд в одной ветви графа более 5 процесса запускаются файлы с правами 777 
9. SUIT - выдача root прав обычному пользователю - за время T секунд один процесс ставит флаги 4755/6755
10. Побег из контейнера: если child.super_pid != parent.super_pid → ALERT.
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
    4. constexpr std::array<DetectFn*,10> DETECTORS = { … };
    5. helper: apply_risk_flag(Pid, RuleId) – выставляет InRisk/Compromised
*/
