import json
from typing import Any, Dict, List

from openai import OpenAI

SYSTEM_INSTRUCTIONS = """You are an expert Security Operations Center (SOC) Analyst and Threat Hunter.
Your goal is to analyze network traffic summaries and security artifacts to detect potential threats, malware,
and anomalous behavior.
You are provided with data derived from PCAP analysis, including:
- Traffic flow statistics and volume.
- Zeek logs (connections, DNS, HTTP, SSL).
- Potential C2 beaconing candidates.
- OSINT enrichment for IPs and domains.
- Carved file metadata.

Your analysis must be:
1. **Objective**: Base findings strictly on the provided evidence.
2. **Prioritized**: Highlight critical threats first (High/Critical severity).
3. **Contextual**: Correlate different data points (e.g., a suspicious domain in DNS logs + beaconing behavior).
4. **Actionable**: Provide concrete recommendations for containment and remediation.

Avoid generic advice. Focus on specific indicators found in the data. If no significant threats are found,
state that clearly but note any interesting anomalies."""


def generate_report(
    base_url: str, api_key: str, model: str, context: Dict[str, Any], language: str = "US English"
) -> str:
    """
    Generate an LLM report using a summarized context.
    """

    # --- Summaries ---
    feats = context.get("features") or {}
    osint = context.get("osint") or {}
    zeek = context.get("zeek") or {}
    beacon = context.get("beaconing") or []
    carved = context.get("carved") or []

    # Calculate protocol distribution for summary
    flows = feats.get("flows") or []
    proto_counts = {}
    for f in flows:
        p = f.get("proto", "Unknown")
        proto_counts[p] = proto_counts.get(p, 0) + 1
    top_protos = dict(sorted(proto_counts.items(), key=lambda x: x[1], reverse=True)[:5])

    summary = {
        "packet_count": context.get("packet_count"),
        "flow_count": len(flows),
        "top_protocols": top_protos,
        "artifact_counts": {k: len(v or []) for k, v in (feats.get("artifacts") or {}).items() if isinstance(v, list)},
        "zeek_tables": {k: len(v or []) for k, v in zeek.items()},
        "osint": {
            "ip_count": len(osint.get("ips") or {}),
            "domain_count": len(osint.get("domains") or {}),
            "ja3_count": len(osint.get("ja3") or {}),
        },
        "beacon_candidates": len(beacon or []),
        "carved_files": len(carved or []),
        "config": context.get("config") or {},
    }

    # --- Highlight samples ---
    highlights = {
        "top_flows": flows[:5],
        "sample_zeek": {k: (rows[:3] if isinstance(rows, list) else []) for k, rows in zeek.items()},
        "sample_osint_ips": list((osint.get("ips") or {}).keys())[:10],
        "sample_osint_domains": list((osint.get("domains") or {}).keys())[:10],
        "sample_carved": carved[:5],
        "sample_beacon": beacon[:5] if isinstance(beacon, list) else [],
    }

    # Language instruction logic
    lang_instruction = ""
    if language == "Tradition Chinese (zh-tw)":
        lang_instruction = (
            "IMPORTANT: You MUST write the entire report in Traditional Chinese "
            "(using Taiwan usage/wording/vocabulary)."
        )
    elif language == "Simplified Chinese (zh-cn)":
        lang_instruction = (
            "IMPORTANT: You MUST write the entire report in Simplified Chinese "
            "(using Mainland China usage/wording/vocabulary)."
        )
    elif language != "US English":
        lang_instruction = f"IMPORTANT: You MUST write the entire report in {language}."

    # Define sections to generate separately
    sections = [
        (
            "Executive Summary",
            "Write the 'Executive Summary' section. Focus on high-level impact and critical findings.",
        ),
        (
            "Key Findings",
            "Write the 'Key Findings' section. List the most important observations.",
        ),
        (
            "Indicators & Evidence",
            "Write the 'Indicators & Evidence' section. Include IPs, domains, hashes, and notable Zeek records.",
        ),
        (
            "OSINT Corroboration",
            "Write the 'OSINT Corroboration' section. Cite data from VT/GreyNoise/Shodan if available.",
        ),
        (
            "Potential Beaconing / C2 Rationale",
            "Write the 'Potential Beaconing / C2 Rationale' section. Explain detailed reasoning for suspect flows.",
        ),
        (
            "Risk Assessment",
            "Write the 'Risk Assessment (Low/Med/High) and Likely Impact' section.",
        ),
        (
            "Recommended Actions",
            "Write the 'Recommended Actions' section. "
            "Provide a concise, prioritized list of the top 5-7 concrete steps.",
        ),
    ]

    # Translate section titles and instructions if not English
    translations = {
        "Tradition Chinese (zh-tw)": {
            "Executive Summary": {
                "title": "執行摘要",
                "instruction": "撰寫「執行摘要」章節。重點在於高階影響分析與關鍵發現。",
            },
            "Key Findings": {"title": "主要發現", "instruction": "撰寫「主要發現」章節。列出最重要的觀察結果。"},
            "Indicators & Evidence": {
                "title": "指標與證據",
                "instruction": "撰寫「指標與證據」章節。包含 IP、網域、雜湊值及值得注意的 Zeek 紀錄。",
            },
            "OSINT Corroboration": {
                "title": "OSINT 偵察驗證",
                "instruction": "撰寫「OSINT 偵察驗證」章節。引用 VT/GreyNoise/Shodan 的資料（如有）。",
            },
            "Potential Beaconing / C2 Rationale": {
                "title": "潛在信標 / C2 原理說明",
                "instruction": "撰寫「潛在信標 / C2 原理說明」章節。詳細解釋可疑流量的推理過程。",
            },
            "Risk Assessment": {"title": "風險評估", "instruction": "撰寫「風險評估（低/中/高）與可能影響」章節。"},
            "Recommended Actions": {
                "title": "建議處置行動",
                "instruction": "撰寫「建議處置行動」章節。提供一份簡潔、依優先順序排列的前 5-7 個具體步驟。",
            },
        },
        "Simplified Chinese (zh-cn)": {
            "Executive Summary": {
                "title": "执行摘要",
                "instruction": "撰写“执行摘要”章节。重点在于高阶影响分析与关键发现。",
            },
            "Key Findings": {"title": "主要发现", "instruction": "撰写“主要发现”章节。列出最重要的观察结果。"},
            "Indicators & Evidence": {
                "title": "指标与证据",
                "instruction": "撰写“指标与证据”章节。包含 IP、域名、哈希值及值得注意的 Zeek 记录。",
            },
            "OSINT Corroboration": {
                "title": "OSINT 侦察验证",
                "instruction": "撰写“OSINT 侦察验证”章节。引用 VT/GreyNoise/Shodan 的数据（如有）。",
            },
            "Potential Beaconing / C2 Rationale": {
                "title": "潜在信标 / C2 原理说明",
                "instruction": "撰写“潜在信标 / C2 原理说明”章节。详细解释可疑流量的推理过程。",
            },
            "Risk Assessment": {"title": "风险评估", "instruction": "撰写“风险评估（低/中/高）与可能影响”章节。"},
            "Recommended Actions": {
                "title": "建议处置行动",
                "instruction": "撰写“建议处置行动”章节。提供一份简洁、按优先级排列的前 5-7 个具体步骤。",
            },
        },
        "Japanese": {
            "Executive Summary": {
                "title": "エグゼクティブサマリー",
                "instruction": "「エグゼクティブサマリー」セクションを記述してください。ハイレベルな影響と重要な発見事項に焦点を当ててください。",
            },
            "Key Findings": {
                "title": "主な発見事項",
                "instruction": "「主な発見事項」セクションを記述してください。最も重要な観察事項をリストアップしてください。",
            },
            "Indicators & Evidence": {
                "title": "指標と証拠",
                "instruction": "「指標と証拠」セクションを記述してください。IP、ドメイン、ハッシュ、および注目すべきZeekレコードを含めてください。",
            },
            "OSINT Corroboration": {
                "title": "OSINTによる裏付け",
                "instruction": "「OSINTによる裏付け」セクションを記述してください。利用可能な場合は、VT/GreyNoise/Shodanのデータを引用してください。",
            },
            "Potential Beaconing / C2 Rationale": {
                "title": "潜在的なビーコニング / C2の根拠",
                "instruction": "「潜在的なビーコニング / C2の根拠」セクションを記述してください。不審なフローに関する詳細な理由を説明してください。",
            },
            "Risk Assessment": {
                "title": "リスク評価",
                "instruction": "「リスク評価（低/中/高）と予想される影響」セクションを記述してください。",
            },
            "Recommended Actions": {
                "title": "推奨されるアクション",
                "instruction": "「推奨されるアクション」セクションを記述してください。優先順位付けされた、上位5〜7つの具体的なステップを簡潔に示してください。",
            },
        },
        "Korean": {
            "Executive Summary": {
                "title": "요약 보고서",
                "instruction": "「요약 보고서」 섹션을 작성하십시오. 고수준의 영향과 핵심 발견 사항에 집중하십시오.",
            },
            "Key Findings": {
                "title": "주요 결과",
                "instruction": "「주요 결과」 섹션을 작성하십시오. 가장 중요한 관찰 사항을 나열하십시오.",
            },
            "Indicators & Evidence": {
                "title": "지표 및 증거",
                "instruction": "「지표 및 증거」 섹션을 작성하십시오. IP, 도메인, 해시 및 주목할만한 Zeek 레코드를 포함하십시오.",
            },
            "OSINT Corroboration": {
                "title": "OSINT 교차 검증",
                "instruction": "「OSINT 교차 검증」 섹션을 작성하십시오. 가능한 경우 VT/GreyNoise/Shodan의 데이터를 인용하십시오.",
            },
            "Potential Beaconing / C2 Rationale": {
                "title": "잠재적 비코닝 / C2 근거",
                "instruction": "「잠재적 비코닝 / C2 근거」 섹션을 작성하십시오. 의심스러운 흐름에 대한 상세한 추론 과정을 설명하십시오.",
            },
            "Risk Assessment": {
                "title": "위험 평가",
                "instruction": "「위험 평가(낮음/중간/높음) 및 예상 영향」 섹션을 작성하십시오.",
            },
            "Recommended Actions": {
                "title": "권장 조치 사항",
                "instruction": "「권장 조치 사항」 섹션을 작성하십시오. 간결하고 우선순위가 지정된 상위 5~7개의 구체적인 단계를 제공하십시오.",
            },
        },
        "Italian": {
            "Executive Summary": {
                "title": "Riepilogo Esecutivo",
                "instruction": "Scrivi la sezione 'Riepilogo Esecutivo'. Focalizzati sull'impatto di alto livello e sulle scoperte critiche.",
            },
            "Key Findings": {
                "title": "Risultati Principali",
                "instruction": "Scrivi la sezione 'Risultati Principali'. Elenca le osservazioni più importanti.",
            },
            "Indicators & Evidence": {
                "title": "Indicatori ed Evidenze",
                "instruction": "Scrivi la sezione 'Indicatori ed Evidenze'. Includi IP, domini, hash e record Zeek rilevanti.",
            },
            "OSINT Corroboration": {
                "title": "Corroborazione OSINT",
                "instruction": "Scrivi la sezione 'Corroborazione OSINT'. Cita dati da VT/GreyNoise/Shodan, se disponibili.",
            },
            "Potential Beaconing / C2 Rationale": {
                "title": "Potenziale Beaconing / Analisi C2",
                "instruction": "Scrivi la sezione 'Potenziale Beaconing / Analisi C2'. Spiega il ragionamento dettagliato per i flussi sospetti.",
            },
            "Risk Assessment": {
                "title": "Valutazione del Rischio",
                "instruction": "Scrivi la sezione 'Valutazione del Rischio (Basso/Medio/Alto) e Impatto Probabile'.",
            },
            "Recommended Actions": {
                "title": "Azioni Raccomandate",
                "instruction": "Scrivi la sezione 'Azioni Raccomandate'. Fornisci un elenco conciso e prioritario dei primi 5-7 passaggi concreti.",
            },
        },
        "Spanish": {
            "Executive Summary": {
                "title": "Resumen Ejecutivo",
                "instruction": "Escribe la sección 'Resumen Ejecutivo'. Enfócate en el impacto de alto nivel y los hallazgos críticos.",
            },
            "Key Findings": {
                "title": "Hallazgos Clave",
                "instruction": "Escribe la sección 'Hallazgos Clave'. Enumera las observaciones más importantes.",
            },
            "Indicators & Evidence": {
                "title": "Indicadores y Evidencias",
                "instruction": "Escribe la sección 'Indicadores y Evidencias'. Incluye IPs, dominios, hashes y registros notables de Zeek.",
            },
            "OSINT Corroboration": {
                "title": "Corroboración OSINT",
                "instruction": "Escribe la sección 'Corroboración OSINT'. Cita datos de VT/GreyNoise/Shodan si están disponibles.",
            },
            "Potential Beaconing / C2 Rationale": {
                "title": "Posible Beaconing / Razón de C2",
                "instruction": "Escribe la sección 'Posible Beaconing / Razón de C2'. Explica el razonamiento detallado de los flujos sospechosos.",
            },
            "Risk Assessment": {
                "title": "Evaluación de Riesgos",
                "instruction": "Escribe la sección 'Evaluación de Riesgos (Baja/Media/Alta) e Impacto Probable'.",
            },
            "Recommended Actions": {
                "title": "Acciones Recomendadas",
                "instruction": "Escribe la sección 'Acciones Recomendadas'. Proporciona una lista concisa y priorizada de los 5-7 pasos concretos más importantes.",
            },
        },
        "French": {
            "Executive Summary": {
                "title": "Résumé Exécutif",
                "instruction": "Écrivez la section 'Résumé Exécutif'. Concentrez-vous sur l'impact de haut niveau et les conclusions critiques.",
            },
            "Key Findings": {
                "title": "Principales Constatations",
                "instruction": "Écrivez la section 'Principales Constatations'. Énumérez les observations les plus importantes.",
            },
            "Indicators & Evidence": {
                "title": "Indicateurs et Preuves",
                "instruction": "Écrivez la section 'Indicateurs et Preuves'. Incluez les adresses IP, les domaines, les hachages et les enregistrements Zeek notables.",
            },
            "OSINT Corroboration": {
                "title": "Corroboration OSINT",
                "instruction": "Écrivez la section 'Corroboration OSINT'. Citez les données de VT/GreyNoise/Shodan si disponibles.",
            },
            "Potential Beaconing / C2 Rationale": {
                "title": "Beaconing Potentiel / Analyse C2",
                "instruction": "Écrivez la section 'Beaconing Potentiel / Analyse C2'. Expliquez le raisonnement détaillé pour les flux suspects.",
            },
            "Risk Assessment": {
                "title": "Évaluation des Risques",
                "instruction": "Écrivez la section 'Évaluation des Risques (Faible/Moyen/Élevé) et Impact Probable'.",
            },
            "Recommended Actions": {
                "title": "Actions Recommandées",
                "instruction": "Écrivez la section 'Actions Recommandées'. Fournissez une liste concise et hiérarchisée des 5 à 7 principales étapes concrètes.",
            },
        },
        "German": {
            "Executive Summary": {
                "title": "Zusammenfassung für die Geschäftsführung",
                "instruction": "Schreiben Sie den Abschnitt 'Zusammenfassung für die Geschäftsführung'. Konzentrieren Sie sich auf die Auswirkungen auf hoher Ebene und kritische Erkenntnisse.",
            },
            "Key Findings": {
                "title": "Wichtigste Erkenntnisse",
                "instruction": "Schreiben Sie den Abschnitt 'Wichtigste Erkenntnisse'. Listen Sie die wichtigsten Beobachtungen auf.",
            },
            "Indicators & Evidence": {
                "title": "Indikatoren und Beweise",
                "instruction": "Schreiben Sie den Abschnitt 'Indikatoren und Beweise'. Fügen Sie IPs, Domänen, Hashes und bemerkenswerte Zeek-Datensätze hinzu.",
            },
            "OSINT Corroboration": {
                "title": "OSINT-Bestätigung",
                "instruction": "Schreiben Sie den Abschnitt 'OSINT-Bestätigung'. Zitieren Sie Daten von VT/GreyNoise/Shodan, falls verfügbar.",
            },
            "Potential Beaconing / C2 Rationale": {
                "title": "Potenzielles Beaconing / C2-Begründung",
                "instruction": "Schreiben Sie den Abschnitt 'Potenzielles Beaconing / C2-Begründung'. Erläutern Sie die detaillierte Begründung für verdächtige Datenströme.",
            },
            "Risk Assessment": {
                "title": "Risikobewertung",
                "instruction": "Schreiben Sie den Abschnitt 'Risikobewertung (Niedrig/Mittel/Hoch) und wahrscheinliche Auswirkungen'.",
            },
            "Recommended Actions": {
                "title": "Empfohlene Maßnahmen",
                "instruction": "Schreiben Sie den Abschnitt 'Empfohlene Maßnahmen'. Erstellen Sie eine prägnante, prioritätenorientierte Liste der wichtigsten 5–7 konkreten Schritte.",
            },
        },
    }

    t_map = translations.get(language, {})

    client = OpenAI(base_url=base_url, api_key=api_key)

    # Common system message
    msg_system = SYSTEM_INSTRUCTIONS
    if lang_instruction:
        msg_system += f"\n\n{lang_instruction}"

    full_report_parts = []

    for title, instruction in sections:
        # Translate title and instructions if possible
        lang_data = t_map.get(title, {})
        display_title = lang_data.get("title", title)
        display_instruction = lang_data.get("instruction", instruction)

        # Construct prompt for this specific section
        section_prompt = f"""
{lang_instruction}

You are a senior SOC analyst. Based on summarized PCAP hunting results, write ONLY the following section of the report:

**{display_title}**

Instruction: {display_instruction} (WRITE IN {language.upper()})

=== SUMMARY ===
{json.dumps(summary, ensure_ascii=False)}

=== HIGHLIGHTS (examples only, not full data) ===
{json.dumps(highlights, ensure_ascii=False)}
"""
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": msg_system},
                    {"role": "user", "content": section_prompt},
                ],
                max_tokens=2000,  # Per section
                temperature=0.2,
            )
            content = resp.choices[0].message.content if resp and resp.choices else ""
            if content:
                # Add a translated header for the section
                full_report_parts.append(f"## {display_title}\n\n{content}")
        except Exception as e:
            full_report_parts.append(f"## {display_title}\n\n_Error generating section: {str(e)}_")

    if not full_report_parts:
        return "_No content returned from the model._"

    return "\n\n".join(full_report_parts)


def test_connection(base_url: str, api_key: str, model: str) -> str:
    """
    Test connectivity to the LLM endpoint by performing a minimal API call.
    Returns an empty string on success, or an error message on failure.
    """
    if not base_url:
        return "Missing Base URL."

    try:
        client = OpenAI(base_url=base_url, api_key=api_key or "lm-studio")
        client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=1,
        )
        return ""
    except Exception as e:
        return str(e)


def fetch_models(base_url: str, api_key: str) -> List[str]:
    """
    Fetch available models from the LLM endpoint.
    Returns a list of model IDs. Returns an empty list on failure.
    """
    if not base_url:
        return []

    try:
        client = OpenAI(base_url=base_url, api_key=api_key or "lm-studio")
        models = client.models.list()
        return [m.id for m in models]
    except Exception:
        return []
