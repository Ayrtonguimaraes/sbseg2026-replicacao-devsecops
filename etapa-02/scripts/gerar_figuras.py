"""Gera gráficos da análise secundária da DVWA a partir dos CSVs."""

import csv
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ETAPA = Path(__file__).resolve().parent.parent
FIGURAS = ETAPA / "figures"
CORES = {"P1": "#8D4913", "P2": "#1C6475", "P3": "#673D82",
         "uniforme": "#1C6475", "progressiva": "#673D82"}
ROTULOS = {"P1": "P1", "P2": "P2", "P3": "P3",
           "uniforme": "Uniforme", "progressiva": "Progressiva"}


def ler(nome):
    with (ETAPA / "results" / f"{nome}.csv").open(encoding="utf-8-sig") as arquivo:
        return list(csv.DictReader(arquivo))


def salvar(fig, nome):
    for formato in ("pdf", "png"):
        fig.savefig(FIGURAS / f"{nome}.{formato}", dpi=190, bbox_inches="tight")
    plt.close(fig)


def curvas(nome, dados, eixo_x, series, xlabel, titulo):
    fig, axs = plt.subplots(1, 2, figsize=(9.1, 3.55), layout="constrained")
    for politica in series:
        selecionadas = [r for r in dados if r["politica"] == politica]
        x = [float(r[eixo_x]) for r in selecionadas]
        for ax, chave in zip(axs, ["bloqueios", "cobertura_bloqueante"]):
            ax.step(x, [int(r[chave]) for r in selecionadas], "o-", where="post",
                    c=CORES[politica], label=ROTULOS[politica], lw=2, ms=5)
            ax.set_xticks(x, [f"{v:g}".replace(".", ",") for v in x])
            ax.set_xlabel(xlabel)
            ax.set_ylim(bottom=0)
            ax.grid(axis="y", alpha=.21)
            ax.spines[["right", "top"]].set_visible(False)
            ax.set_axisbelow(True)
    axs[0].set_ylabel("Unidades bloqueadas")
    axs[1].set_ylabel("Vulnerabilidades com bloqueio")
    axs[1].set_ylim(0, 13.65)
    axs[1].set_yticks([0, 3, 6, 9, 13])
    if eixo_x == "nota":
        for ax in axs:
            ax.axvline(7.5, lw=1, linestyle=":", color="#3B4D57")
    axs[0].legend(frameon=False)
    fig.suptitle(titulo, x=.03, ha="left", fontweight="bold")
    salvar(fig, nome)


def grade():
    linhas = ler("sensibilidade_combinada")
    medidas = {(float(r["nota_semgrep_error"]), int(r["limiar"]), r["politica"]):
               (int(r["bloqueios"]), int(r["cobertura_bloqueante"])) for r in linhas}
    notas = sorted({k[0] for k in medidas})
    limiares = sorted({k[1] for k in medidas})
    delta = np.array([[medidas[n, l, "uniforme"][1] - medidas[n, l, "progressiva"][1]
                     for l in limiares] for n in notas])
    fig, ax = plt.subplots(figsize=(6.5, 4.4), layout="constrained")
    img = ax.imshow(delta, cmap="Blues", vmin=0, vmax=int(delta.max()), aspect="auto")
    ax.set_xticks(range(len(limiares)), limiares)
    ax.set_yticks(range(len(notas)), [f"{n:g}".replace(".", ",") for n in notas])
    ax.set_xlabel("Limiar comum")
    ax.set_ylabel("Nota proxy do Semgrep ERROR")
    ax.set_title("Perda de cobertura da política progressiva na DVWA", loc="left", pad=12,
                 fontweight="bold")
    for i, row in enumerate(delta):
        for j, valor in enumerate(row):
            ax.text(j, i, str(valor), ha="center", va="center",
                    color="white" if valor > delta.max() / 2 else "#152D46")
    fig.colorbar(img, ax=ax, label="Vulnerabilidades a menos com bloqueio", shrink=.89)
    salvar(fig, "dvwa_grade_perda_cobertura")


def main():
    FIGURAS.mkdir(exist_ok=True)
    plt.rcParams.update({
        "font.family": "DejaVu Sans", "text.color": "#152D46", "axes.labelcolor": "#152D46",
        "axes.edgecolor": "#90A0AA", "xtick.color": "#152D46", "ytick.color": "#152D46",
        "font.size": 10, "pdf.fonttype": 42,
    })
    curvas("dvwa_proxy_semgrep", ler("sensibilidade_semgrep_error"), "nota",
           ["P1", "P2", "P3"], "Nota atribuída aos alertas ERROR",
           "Sensibilidade à nota do Semgrep ERROR na DVWA")
    curvas("dvwa_limiares", ler("sensibilidade_limiares"), "limiar",
           ["uniforme", "progressiva"], "Limiar aplicado às duas regras",
           "Sensibilidade ao limiar na DVWA")
    grade()


if __name__ == "__main__":
    main()
