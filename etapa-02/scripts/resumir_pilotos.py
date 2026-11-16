"""Resume relatórios reais e aplica as políticas a uma matriz piloto de três casos por app."""

import csv
import json
import re
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from analise_dvwa import LIMIARES, ORIGINAIS, Unidade, avaliar, classe_global, gravar_csv, ler_json

ETAPA = Path(__file__).resolve().parent.parent
APPS = {"juice-shop": "19.0.0", "webgoat": "2025.3"}
SEVERIDADE = {"ERROR": 7.5, "WARNING": 5.0, "INFO": 3.0, "HIGH": 7.5, "MEDIUM": 5.0,
              "LOW": 3.0, "CRITICAL": 9.5, "INFORMATIONAL": 0.0}


def cwes_de_semgrep(registro):
    cwes = registro["extra"]["metadata"].get("cwe") or []
    if isinstance(cwes, str):
        cwes = [cwes]
    return tuple(m.group() for item in cwes if (m := re.match(r"CWE-\d+", item)))


def score_trivy(registro):
    origens = registro.get("CVSS") or {}
    prioridades = list(dict.fromkeys(["nvd", "redhat", "ghsa", *origens]))
    for origem in prioridades:
        score = origens.get(origem, {}).get("V3Score")
        if score is not None:
            return float(score)
    return None


def carregar_relatorios(app):
    p = ETAPA / "pilotos"
    fontes = {"sast": f"semgrep/{app}.json", "iac": f"checkov/{app}.json",
              "fs": f"trivy/{app}-fs.json", "container": f"trivy/{app}-image.json",
              "passivo": f"zap/{app}-passivo.json", "ativo": f"zap/{app}-ativo.json"}
    return fontes, {k: ler_json(p / nome) for k, nome in fontes.items()}


def resumir(app, versao, d):
    fs = d["fs"].get("Results") or []
    img = d["container"]["Results"]
    passivos, ativos = d["passivo"]["alerts"], d["ativo"]["alerts"]
    return {
        "aplicacao": app, "versao": versao,
        "semgrep_achados": len(d["sast"]["results"]),
        "semgrep_erros_execucao": len(d["sast"]["errors"]),
        "checkov_reprovacoes_dockerfile": d["iac"]["summary"]["failed"],
        "checkov_verificacoes_dockerfile": (
            d["iac"]["summary"]["passed"] + d["iac"]["summary"]["failed"]
        ),
        "trivy_fs_artefatos": len(fs),
        "trivy_fs_ocorrencias": sum(len(x.get("Vulnerabilities") or []) for x in fs) if fs else "",
        "trivy_imagem_ocorrencias": sum(len(x.get("Vulnerabilities") or []) for x in img),
        "trivy_imagem_ocorrencias_os": sum(len(x.get("Vulnerabilities") or [])
                                          for x in img if x.get("Class") == "os-pkgs"),
        "zap_urls_passivo": len(d["passivo"]["urls"]),
        "zap_instancias_passivo": len(passivos),
        "zap_tipos_passivo": len({a["pluginId"] for a in passivos}),
        "zap_instancias_ativo": len(ativos),
        "zap_tipos_ativo": len({a["pluginId"] for a in ativos}),
    }


def normalizar(app, matriz, fontes, relatorios):
    unidades = []
    score_restante = []
    for i, f in enumerate(relatorios["sast"]["results"]):
        cwes = cwes_de_semgrep(f)
        severidade = f["extra"]["severity"]
        vs = {g["vulnerability_id"]: "direta" for g in matriz
              if f["path"] == g["arquivo_sast"] and g["cwe"] in cwes}
        unidades.append(Unidade(
            f"{app}-sast-{i:03d}", "Semgrep", "APP", "commit", classe_global(vs),
            SEVERIDADE.get(severidade), f"semgrep_{severidade.lower()}", severidade,
            f["check_id"], cwes, vs, f"{fontes['sast']}#/results/{i}", "individual",
        ))
    for i, resultado in enumerate(relatorios["container"]["Results"]):
        for j, f in enumerate(resultado.get("Vulnerabilities") or []):
            cwes = tuple(f.get("CweIDs") or ())
            score = score_trivy(f)
            vs = {g["vulnerability_id"]: "indireta" for g in matriz if g["cwe"] in cwes}
            if not vs:
                score_restante.append(score)
                continue
            unidades.append(Unidade(
                f"{app}-imagem-{i:02d}-{j:04d}", "Trivy Container", "INFRA", "build",
                "indireta", score, "cvss_v3", f.get("Severity"), f["VulnerabilityID"], cwes,
                vs, f"{fontes['container']}#/Results/{i}/Vulnerabilities/{j}", "individual",
            ))
    if score_restante:
        maior = max((s for s in score_restante if s is not None), default=None)
        unidades.append(Unidade(
            f"{app}-imagem-agregado", "Trivy Container", "INFRA", "build", "sem_matriz",
            maior, "trivy_max", None, f"demais-ocorrencias:{len(score_restante)}", (), {},
            fontes["container"], "aggregate_other",
        ))
    vistos = set()
    for i, f in enumerate(relatorios["ativo"]["alerts"]):
        plugin = f["pluginId"], f["alert"]
        if plugin in vistos:
            continue
        vistos.add(plugin)
        cwe = "CWE-" + f["cweid"]
        vs = {g["vulnerability_id"]: "direta" for g in matriz if g["cwe"] == cwe
              and g["rota_dast"] and g["rota_dast"] in f["url"]}
        unidades.append(Unidade(
            f"{app}-zap-{i:03d}", "OWASP ZAP (Active)", "APP", "deploy", classe_global(vs),
            SEVERIDADE.get(f["risk"].upper()), "proxy_zap_active", f["risk"],
            f["pluginId"], (cwe,), vs, f"{fontes['ativo']}#/alerts/{i}", "individual",
        ))
    return unidades


def main():
    with (ETAPA / "data/ground_truth/pilotos.csv").open(encoding="utf-8-sig") as arquivo:
        referencia = list(csv.DictReader(arquivo))
    resumo, politicas, variacoes, cobertura = [], [], [], []
    for app, versao in APPS.items():
        matriz = [linha for linha in referencia if linha["aplicacao"] == app]
        fontes, d = carregar_relatorios(app)
        resumo.append(resumir(app, versao, d))
        us = normalizar(app, matriz, fontes, d)
        ausentes = sum(u.score is None for u in us)
        saida = {"aplicacao": app, "versao": versao, "scores_ausentes": ausentes,
                 "unidades": [asdict(u) for u in us]}
        (ETAPA / "data/normalized" / f"piloto-{app}.json").write_text(
            json.dumps(saida, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        for p, l in ORIGINAIS:
            politicas.append({"aplicacao": app, **avaliar(us, p, l, universo=len(matriz))})
        for l in LIMIARES:
            for p in ("uniforme", "progressiva"):
                variacoes.append({"aplicacao": app, **avaliar(us, p, l, universo=len(matriz))})
        for v in matriz:
            contagens = Counter(u.vinculos.get(v["vulnerability_id"]) for u in us)
            cobertura.append({"aplicacao": app, "caso": v["vulnerability_id"],
                              "diretas": contagens["direta"], "indiretas": contagens["indireta"]})
    for nome, dados in [("pilotos_scanners", resumo), ("pilotos_politicas", politicas),
                        ("pilotos_limiares", variacoes), ("pilotos_cobertura", cobertura)]:
        gravar_csv(ETAPA / "results" / f"{nome}.csv", dados)


if __name__ == "__main__":
    main()
