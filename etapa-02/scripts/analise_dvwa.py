"""Extensão do artefato SBSeg no commit auditado, com Python 3.10+."""

import argparse
import csv
import hashlib
import importlib.util
import json
import statistics
import subprocess
import sys
from collections import Counter
from dataclasses import asdict, dataclass, replace
from pathlib import Path

COMMIT = "5b18244126350d1a6a4bf39e7a34701af9190563"
RELATORIOS = "reports-0a8e877_"
PROXIES = (5, 6, 7, 7.5, 8, 9, 10)
LIMIARES = (5, 6, 7, 8, 9)
ORIGINAIS = (("P1", 9), ("P2", 7), ("P3", 7))
IDS_DVWA = {
    "SQL Injection": "dvwa-sql-injection",
    "Cross-Site Scripting (XSS)": "dvwa-xss",
    "Command Injection": "dvwa-command-injection",
    "CSRF": "dvwa-csrf",
    "Weak Session IDs": "dvwa-weak-session-ids",
    "Brute Force": "dvwa-brute-force",
    "Open HTTP Redirect": "dvwa-open-http-redirect",
    "JavaScript Attacks": "dvwa-javascript-attacks",
    "Content Security Policy Bypass": "dvwa-csp-bypass",
    "Default Credentials": "dvwa-default-credentials",
    "Exposed MySQL": "dvwa-exposed-mysql",
    "Outdated OS": "dvwa-outdated-os",
    "Outdated Packages": "dvwa-outdated-packages",
}
FONTES = {
    "Semgrep": "semgrep-report.json",
    "Trivy FS (SCA)": "trivy-sca-report.json",
    "OWASP ZAP (Baseline)": "zap-report.json",
    "OWASP ZAP (Active)": "zap-auth-active-report.json",
    "Brute Force": "hydra-bruteforce.json",
    "Trivy Container": "trivy-report.json",
}


@dataclass(frozen=True)
class Unidade:
    id: str
    ferramenta: str
    camada: str
    estagio: str
    classe: str
    score: float | None
    origem_score: str
    severidade_original: str | None
    identificador_scanner: str | None
    cwes: tuple
    vinculos: dict
    referencia: str
    granularidade: str


def conferir(condicao, mensagem):
    if not condicao:
        raise ValueError(mensagem)


def ler_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def gravar_csv(path, linhas):
    with path.open("w", encoding="utf-8-sig", newline="") as arquivo:
        if not linhas:
            raise ValueError(f"Sem linhas para {path.name}")
        writer = csv.DictWriter(arquivo, fieldnames=list(linhas[0]))
        writer.writeheader()
        writer.writerows(linhas)


def carregar_artefato(repo):
    caminho = repo / "src" / "analise_artigo.py"
    spec = importlib.util.spec_from_file_location("sbseg_upstream", caminho)
    modulo = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = modulo
    spec.loader.exec_module(modulo)
    return modulo


def checar_commit(repo):
    cmd = ["git", "-C", str(repo)]
    head = subprocess.check_output(cmd + ["rev-parse", "HEAD"], text=True).strip()
    if head != COMMIT:
        raise ValueError(f"Use o commit auditado {COMMIT}. Encontrado {head}.")
    if subprocess.run(
        cmd + ["diff", "--quiet", COMMIT, "--", "src", "data/raw", "expected"],
        check=False,
    ).returncode != 0:
        raise ValueError("Código, relatórios ou referência dos autores têm alterações locais.")


def classe_global(vinculos):
    if "direta" in vinculos.values():
        return "direta"
    if "indireta" in vinculos.values():
        return "indireta"
    return "sem_matriz"


def referencias_dos_relatorios(artefato):
    """Localizadores dos registros na mesma ordem em que os loaders os leem."""
    refs = {}
    refs["Semgrep"] = [
        f"{RELATORIOS}{FONTES['Semgrep']}#/results/{i}"
        for i, _ in enumerate(artefato.load_semgrep())
    ]
    refs["Trivy FS (SCA)"] = [
        f"{RELATORIOS}{FONTES['Trivy FS (SCA)']}#/Results/{i}/Vulnerabilities/{j}"
        for i, alvo in enumerate(artefato.load_json(
            RELATORIOS + FONTES["Trivy FS (SCA)"]
        ).get("Results", []))
        for j, _ in enumerate(alvo.get("Vulnerabilities") or [])
    ]
    refs["Checkov"] = []
    for variante in ("terraform", "k8s"):
        nome = f"{RELATORIOS}checkov-{variante}.json"
        falhas = artefato.load_json(nome).get("results", {}).get("failed_checks", [])
        refs["Checkov"].extend(
            f"{nome}#/results/failed_checks/{i}" for i, _ in enumerate(falhas)
        )
    nome = RELATORIOS + FONTES["OWASP ZAP (Baseline)"]
    refs["OWASP ZAP (Baseline)"] = [
        f"{nome}#/site/{i}/alerts/{j}"
        for i, site in enumerate(artefato.load_json(nome).get("site", []))
        for j, _ in enumerate(site.get("alerts", []))
    ]
    nome = RELATORIOS + FONTES["OWASP ZAP (Active)"]
    primeiros = {}
    for i, alerta in enumerate(artefato.load_json(nome).get("alerts", [])):
        chave = alerta.get("pluginId"), alerta.get("name")
        primeiros.setdefault(chave, f"{nome}#/alerts/{i}")
    refs["OWASP ZAP (Active)"] = list(primeiros.values())
    nome = RELATORIOS + FONTES["Brute Force"]
    refs["Brute Force"] = [f"{nome}#/vulnerable"] * len(artefato.load_bruteforce())
    return refs


def preparar_trivy(artefato, trivy):
    nome = RELATORIOS + FONTES["Trivy Container"]
    chaves = [
        f"{nome}#/Results/{i}/Vulnerabilities/{j}"
        for i, alvo in enumerate(artefato.load_json(nome).get("Results", []))
        for j, _ in enumerate(alvo.get("Vulnerabilities") or [])
    ]
    conferir(len(chaves) == len(trivy), "Localizadores do Trivy não conferem.")
    bruto = []
    for cve, ref in zip(trivy, chaves):
        coincide = bool(artefato.APP_CWES.intersection(cve["cwes"]))
        bruto.append({
            "referencia": ref,
            "cve": cve["cve"],
            "pacote": cve["pkg"],
            "score": cve["cvss"],
            "cwes": "|".join(cve["cwes"]),
            "contexto_eosl": int(cve["eosl_context"]),
            "individual_app_match": int(coincide),
            # EOSL usa todo o relatório quando existe um contexto EOSL.
            "agg-outdated-os": 1,
            "agg-outdated-packages": int(bool(cve["fixed_version"])),
            "agg-other-os-cves": int(not coincide),
        })
    return bruto


def origem_do_score(finding):
    if finding.tool == "Semgrep":
        return f"semgrep_{finding.severity_label.lower()}"
    if (finding.extra.get("granularity") or "").startswith("aggregate_"):
        return "trivy_max"
    return {
        "Trivy Container": "cvss_v3",
        "Trivy FS (SCA)": "cvss_v3",
        "Checkov": "proxy_checkov",
        "OWASP ZAP (Baseline)": "proxy_zap_baseline",
        "OWASP ZAP (Active)": "proxy_zap_active" if finding.cvss is not None else "sem_score_zap_active",
        "Brute Force": "proxy_teste_credenciais",
    }[finding.tool]


def montar_dados(artefato):
    findings, trivy = artefato.build_findings()
    bruto = preparar_trivy(artefato, trivy)
    refs = referencias_dos_relatorios(artefato)
    refs_trivy = iter(r["referencia"] for r in bruto if r["individual_app_match"])
    ordem = Counter()
    unidades = []
    for finding in findings:
        ordem[finding.tool] += 1
        grao = finding.extra.get("granularity") or "individual"
        if grao.startswith("aggregate_"):
            ref = f"trivy_composicao.csv#{finding.identifier}"
        elif finding.tool == "Trivy Container":
            ref = next(refs_trivy)
        else:
            ref = refs[finding.tool][ordem[finding.tool] - 1]
        vinculos = {}
        for nome, vid in IDS_DVWA.items():
            classe = artefato.classify(finding, nome, artefato.DVWA[nome])
            if classe:
                vinculos[vid] = classe
        classe = classe_global(vinculos)
        conferir(
            artefato.finding_class_overall(finding) == {"sem_matriz": "n_a"}.get(classe, classe),
            f"Classe divergiu na unidade {finding.tool} {ref}.",
        )
        unidades.append(Unidade(
            f"dvwa-{len(unidades) + 1:03d}", finding.tool, finding.layer, finding.stage_hint,
            classe, finding.cvss, origem_do_score(finding), finding.severity_label,
            finding.identifier, tuple(finding.cwes), vinculos, ref, grao,
        ))
    conferir(all(ordem[fonte] == len(referencias) for fonte, referencias in refs.items()),
             "Há localizadores sobrando nos relatórios.")
    conferir(next(refs_trivy, None) is None, "Há localizadores sobrando no Trivy.")
    return unidades, bruto


def avaliar(unidades, politica, limiar, scores=None, *, universo=len(IDS_DVWA)):
    overrides = scores or {}
    progressiva = politica in {"P3", "progressiva"}
    bloqueadas = [
        u for u in unidades
        if (overrides.get(u.id, u.score) or 0.0) >= limiar
        and (not progressiva or u.classe != "indireta")
    ]
    por_classe = Counter(u.classe for u in bloqueadas)
    por_estagio = Counter(u.estagio for u in bloqueadas)
    ids_bloq = sorted({vid for u in bloqueadas for vid in u.vinculos})
    ids_dir = {vid for u in unidades for vid, cls in u.vinculos.items() if cls == "direta"}
    ids_detectados = {vid for u in unidades for vid in u.vinculos}
    return {
        "politica": politica, "limiar": limiar,
        "unidades": len(unidades), "bloqueios": len(bloqueadas),
        "diretos": por_classe["direta"], "indiretos": por_classe["indireta"],
        "sem_matriz": por_classe["sem_matriz"],
        "commit": por_estagio["commit"], "build": por_estagio["build"], "deploy": por_estagio["deploy"],
        "vulnerabilidades_matriz": universo, "detectadas": len(ids_detectados),
        "detectadas_diretas": len(ids_dir), "cobertura_bloqueante": len(ids_bloq),
        "cobertura_bloqueante_pct": round(100 * len(ids_bloq) / universo, 2),
        "ids_bloqueados": "|".join(ids_bloq),
    }


def verificar_baseline(expected, unidades, artefato, base):
    classes_esperadas = {
        {"n_a": "sem_matriz"}.get(k, k): v for k, v in expected["volume_classe"].items()
    }
    conferir(Counter(u.classe for u in unidades) == classes_esperadas,
             "Volume por classe diverge do baseline.")
    matriz = []
    for linha in expected["cobertura"]["rows"]:
        nome = linha["name"]
        vid = IDS_DVWA[nome]
        spec = artefato.DVWA[nome]
        direta = sum(u.vinculos.get(vid) == "direta" for u in unidades)
        indireta = sum(u.vinculos.get(vid) == "indireta" for u in unidades)
        encontrado = spec["cwe"], spec["layer"], direta, indireta
        esperado = linha["cwe"], linha["layer"], linha["n_direta"], linha["n_indireta"]
        conferir(encontrado == esperado, f"Associações divergentes em {nome}.")
        status = "direta" if direta else "apenas indireta" if indireta else "sem detecção"
        conferir(status == linha["status"], f"Status de detecção divergente em {nome}.")
        matriz.append({"vulnerability_id": vid, "nome": nome, "cwe": spec["cwe"],
                       "camada": spec["layer"], "diretas": direta, "indiretas": indireta,
                       "status_deteccao": status})
    for r in base:
        p = r["politica"]
        politica_atual = {
            "total": r["unidades"], "blocks": r["bloqueios"],
            "dir": r["diretos"], "ind": r["indiretos"], "na": r["sem_matriz"],
        }
        conferir(expected["politicas"][p] == politica_atual, f"Bloqueios por classe divergem em {p}.")
        estagios = {e: r[e] for e in ("commit", "build", "deploy")}
        conferir(expected["politicas_por_estagio"][p] == estagios,
                 f"Bloqueios por estágio divergem em {p}.")
        conferir(expected["cobertura_bloqueante"][p] == r["cobertura_bloqueante"],
                 f"Cobertura bloqueante diverge em {p}.")
    return matriz


def variar_proxies(unidades, base):
    saida = []
    for origem, notas in (("semgrep_error", PROXIES), ("semgrep_warning", LIMIARES)):
        alteraveis = [u for u in unidades if u.origem_score == origem]
        for nota in notas:
            valores = {u.id: nota for u in alteraveis}
            for (politica, limiar), original in zip(ORIGINAIS, base):
                r = avaliar(unidades, politica, limiar, valores)
                saida.append({
                    "origem_proxy": origem, "nota": nota, "unidades_do_proxy": len(alteraveis),
                    **r, "delta_bloqueios": r["bloqueios"] - original["bloqueios"],
                    "delta_cobertura": r["cobertura_bloqueante"] - original["cobertura_bloqueante"],
                })
    return saida


def variar_agregacao(unidades, bruto):
    estatisticas = []
    substitutos = {"maximo": {}, "media": {}, "mediana": {}}
    for u in unidades:
        grupo = u.identificador_scanner
        if u.origem_score != "trivy_max":
            continue
        membros = [r for r in bruto if r[grupo]]
        validos = [r["score"] for r in membros if r["score"] is not None]
        conferir(bool(validos) and max(validos) == u.score, f"Máximo divergente em {grupo}.")
        metricas = {"maximo": max(validos), "media": statistics.mean(validos),
                    "mediana": statistics.median(validos)}
        for metodo, score in metricas.items():
            substitutos[metodo][u.id] = score
        estatisticas.append({
            "grupo": grupo, "ocorrencias": len(membros),
            "com_cvss_v3": len(validos), "sem_cvss_v3": len(membros) - len(validos),
            **metricas,
        })
    linhas = [
        {"agregacao": metodo, **avaliar(unidades, p, l, scores)}
        for metodo, scores in substitutos.items()
        for p, l in ORIGINAIS
    ]
    return estatisticas, linhas


def individualizar_trivy(unidades, bruto, matriz):
    """Cenário alternativo sem os três agregados nem correspondência estrutural."""
    outras = [u for u in unidades if u.ferramenta != "Trivy Container"]
    for i, cve in enumerate(bruto, 1):
        cwes = tuple(filter(None, cve["cwes"].split("|")))
        vinculos = {
            v["vulnerability_id"]: "indireta"
            for v in matriz if v["camada"] == "APP" and v["cwe"] in cwes
        }
        outras.append(Unidade(
            f"trivy-raw-{i:04d}", "Trivy Container", "INFRA", "build",
            classe_global(vinculos), cve["score"], "cvss_v3", None, cve["cve"],
            cwes, vinculos, cve["referencia"], "individual",
        ))
    conferir(len(outras) == 1750, "Volume individual do Trivy divergente.")
    return [
        {"granularidade": "todas_ocorrencias_trivy_sem_agregados", **avaliar(outras, p, l)}
        for p, l in ORIGINAIS
    ]


def testar_leitura_zap_active(unidades):
    # Alternativa diagnóstica. Os dados trazem textos e o loader tenta int(risk).
    escala = {"high": 7.5, "medium": 5.0, "low": 3.0, "informational": 0.0}
    scores = {
        u.id: escala[u.severidade_original.casefold()]
        for u in unidades if u.origem_score == "sem_score_zap_active"
        and (u.severidade_original or "").casefold() in escala
    }
    return [
        {"alteracao": "zap_active_risco_textual", "scores_mapeados": len(scores),
         **avaliar(unidades, p, l, scores)} for p, l in ORIGINAIS
    ]


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def executar(repo, destino):
    checar_commit(repo)
    artefato = carregar_artefato(repo)
    unidades, bruto = montar_dados(artefato)
    expected = ler_json(repo / "expected" / "numeros_secao6.json")
    base = [avaliar(unidades, p, l) for p, l in ORIGINAIS]
    matriz = verificar_baseline(expected, unidades, artefato, base)
    conferir(len(bruto) == expected["bruto"]["trivy_container_individual"],
             "Volume bruto do Trivy divergente.")
    conferir(len(unidades) == expected["simulacao"]["total_p_simulacao"],
             "Volume de unidades divergente do baseline.")
    variantes_proxy = variar_proxies(unidades, base)
    limiares = [avaliar(unidades, p, l) for l in LIMIARES for p in ("uniforme", "progressiva")]
    combinados = [
        {"nota_semgrep_error": nota, **avaliar(unidades, p, l, valores)}
        for nota in PROXIES
        for valores in ({u.id: nota for u in unidades if u.origem_score == "semgrep_error"},)
        for l in LIMIARES for p in ("uniforme", "progressiva")
    ]
    estatisticas, agregacao = variar_agregacao(unidades, bruto)
    maximos = [{k: v for k, v in r.items() if k != "agregacao"} for r in agregacao[:3]]
    conferir(maximos == base, "O cenário de máximo Trivy diverge do baseline.")
    individual = individualizar_trivy(unidades, bruto, matriz)
    auditoria_zap = testar_leitura_zap_active(unidades)
    for pasta in ("data/normalized", "data/ground_truth", "results", "evidence"):
        (destino / pasta).mkdir(parents=True, exist_ok=True)
    (destino / "data/normalized/dvwa.json").write_text(
        json.dumps({"aplicacao": "DVWA (coleta SBSeg 2026)", "upstream_commit": COMMIT,
                    "unidades": [asdict(u) for u in unidades]}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    csv_unidades = []
    for u in unidades:
        linha = asdict(u)
        linha["cwes"] = "|".join(u.cwes)
        linha["vinculos"] = "|".join(f"{vid}:{cls}" for vid, cls in u.vinculos.items())
        csv_unidades.append(linha)
    saidas = {
        "data/normalized/dvwa.csv": csv_unidades,
        "data/normalized/trivy_composicao.csv": bruto,
        "data/ground_truth/dvwa.csv": matriz,
        "results/baseline.csv": base,
        "results/sensibilidade_semgrep_error.csv": [
            r for r in variantes_proxy if r["origem_proxy"] == "semgrep_error"
        ],
        "results/sensibilidade_semgrep_warning.csv": [
            r for r in variantes_proxy if r["origem_proxy"] == "semgrep_warning"
        ],
        "results/sensibilidade_limiares.csv": limiares,
        "results/sensibilidade_combinada.csv": combinados,
        "results/trivy_estatisticas_grupos.csv": estatisticas,
        "results/sensibilidade_trivy_agregacao.csv": agregacao,
        "results/trivy_granularidade_individual.csv": individual,
        "results/zap_active_risco_textual.csv": auditoria_zap,
    }
    for path, linhas in saidas.items():
        gravar_csv(destino / path, linhas)
    arquivos = [repo / "src/analise_artigo.py", repo / "expected/numeros_secao6.json"]
    arquivos.extend(sorted((repo / "data/raw").glob("*.json")))
    (destino / "evidence/sha256_autores.txt").write_text(
        "".join(f"{sha256(p)}  {p.relative_to(repo).as_posix()}\n" for p in arquivos),
        encoding="utf-8",
    )
    print(f"Artefato dos autores: {COMMIT}")
    print(f"Baseline validado: {len(bruto)} ocorrências Trivy e {len(unidades)} unidades totais.")
    print(Counter(u.origem_score for u in unidades if u.ferramenta == "Semgrep"))
    for linha in base:
        print(f"{linha['politica']}: {linha['bloqueios']} bloqueios, "
              f"cobertura {linha['cobertura_bloqueante']}/{linha['vulnerabilidades_matriz']}")
    print(f"Resultados e dados normalizados em {destino}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--autores", type=Path, required=True, help="Checkout do artefato original")
    parser.add_argument("--out", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    executar(args.autores.resolve(), args.out.resolve())


if __name__ == "__main__":
    main()
