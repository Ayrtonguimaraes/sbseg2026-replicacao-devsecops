"""Aplica P4 em modo de avaliação local às lacunas de evidência da DVWA."""

import argparse
import csv
import itertools
import json
import math
from dataclasses import dataclass
from pathlib import Path

from analise_dvwa import IDS_DVWA, Unidade, avaliar, gravar_csv, ler_json, sha256

STATUS = {"nao_executada", "inconclusiva", "nao_confirmada", "confirmada"}


@dataclass(frozen=True)
class Validacao:
    status: str = "nao_executada"
    evidencia: str = ""
    score_confirmacao: float | None = None
    configuracao: str = ""


def selecionar_lacunas(unidades, bloqueadas):
    alvos = {}
    for nome, vid in IDS_DVWA.items():
        if vid in bloqueadas or any(u.vinculos.get(vid) == "direta" for u in unidades):
            continue
        sinais = [u.id for u in unidades if u.vinculos.get(vid) == "indireta"]
        if sinais:
            alvos[vid] = (nome, sinais)
    return alvos


def ler_validacoes(caminho, alvos):
    if caminho is None:
        return {}
    dados = {}
    with caminho.open(encoding="utf-8-sig", newline="") as arquivo:
        for row in csv.DictReader(arquivo):
            vid, status = row["vulnerability_id"], row["status"]
            if vid not in alvos or vid in dados or status not in STATUS:
                raise ValueError(f"Linha inválida em {caminho.name} para {vid}: {status}")
            evidencia = row["evidencia"]
            configuracao = row["configuracao"]
            if status != "nao_executada":
                if not evidencia or not configuracao:
                    raise ValueError(f"{vid}: registre a evidência e a configuração do teste.")
                caminho_evidencia = caminho.parent / evidencia
                if sha256(caminho_evidencia) != row["sha256_evidencia"]:
                    raise ValueError(f"{vid}: SHA-256 da evidência diverge.")
            score = float(row["score_confirmacao"]) if row["score_confirmacao"] else None
            if score is not None and (not math.isfinite(score) or not 0 <= score <= 10):
                raise ValueError(f"{vid}: use uma nota entre 0 e 10.")
            dados[vid] = Validacao(status, evidencia, score, configuracao)
    return dados


def bloqueia_confirmacao(validacao, politica, limiar=7):
    if politica not in {"P4-A", "P4-B"}:
        raise ValueError(f"Variante P4 desconhecida: {politica}")
    if validacao.status != "confirmada":
        return False
    if politica == "P4-A":
        return True
    return validacao.score_confirmacao is not None and validacao.score_confirmacao >= limiar


def executar(base, raiz, laudos):
    unidades = [Unidade(**u) for u in ler_json(base)["unidades"]]
    p3 = avaliar(unidades, "P3", 7)
    bloqueadas = set(filter(None, p3["ids_bloqueados"].split("|")))
    alvos = selecionar_lacunas(unidades, bloqueadas)
    validacoes = ler_validacoes(laudos, alvos)
    fila = []
    for vid, (nome, ids) in alvos.items():
        v = validacoes.get(vid, Validacao())
        fila.append({
            "vulnerability_id": vid, "nome": nome, "sinais_indiretos": len(ids),
            "finding_ids": "|".join(ids), "status": v.status,
            "evidencia": v.evidencia, "configuracao": v.configuracao,
            "score_confirmacao": v.score_confirmacao,
            "adiciona_bloqueio_p4_a": int(bloqueia_confirmacao(v, "P4-A")),
            "adiciona_bloqueio_p4_b": int(bloqueia_confirmacao(v, "P4-B")),
        })
    resultados = []
    for p, campo in [("P3", ""), ("P4-A", "adiciona_bloqueio_p4_a"),
                     ("P4-B", "adiciona_bloqueio_p4_b")]:
        novas = {r["vulnerability_id"] for r in fila if campo and r[campo]}
        resultados.append({
            "politica": p,
            "base_bloqueios": p3["bloqueios"], "bloqueios_adicionais_no_deploy": len(novas),
            "decisoes_simuladas": p3["bloqueios"] + len(novas),
            "cobertura_bloqueante": len(bloqueadas | novas),
            "vulnerabilidades_matriz": len(IDS_DVWA), "novos_ids_bloqueados": "|".join(sorted(novas)),
            "fonte_validacoes": (
                "nao_aplicavel" if p == "P3"
                else "evidencias_informadas" if laudos else "sem_laudos"
            ),
        })
    condicionais = []
    for n in range(len(alvos) + 1):
        for combinacao in itertools.combinations(alvos, n):
            condicionais.append({
                "natureza": "condicional_p4_a", "hipotese_ids_confirmados": "|".join(combinacao),
                "confirmacoes": n, "decisoes_simuladas": p3["bloqueios"] + n,
                "cobertura_bloqueante": len(bloqueadas) + n,
                "vulnerabilidades_matriz": len(IDS_DVWA),
            })
    gravar_csv(raiz / "p4_fila.csv", fila)
    gravar_csv(raiz / "p4_resultados.csv", resultados)
    gravar_csv(raiz / "p4_cenarios_condicionais.csv", condicionais)
    print(json.dumps(resultados, ensure_ascii=False, indent=2))


def main():
    etapa = Path(__file__).resolve().parent.parent
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", type=Path, default=etapa / "data/normalized/dvwa.json")
    parser.add_argument("--out", type=Path, default=etapa / "results")
    parser.add_argument("--validacoes", type=Path, help="CSV com laudos da configuração avaliada")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    executar(args.base, args.out, args.validacoes)


if __name__ == "__main__":
    main()
