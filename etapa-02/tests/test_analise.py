import csv
import sys
import unittest
from pathlib import Path

ETAPA = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ETAPA / "scripts"))

from analise_dvwa import (  # noqa: E402
    ORIGINAIS, Unidade, avaliar, ler_json, variar_proxies,
)
from politica_p4 import Validacao, bloqueia_confirmacao, selecionar_lacunas  # noqa: E402


class TesteAnalise(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        caminho = ETAPA / "data/normalized/dvwa.json"
        cls.unidades = [Unidade(**r) for r in ler_json(caminho)["unidades"]]
        cls.base = [avaliar(cls.unidades, p, l) for p, l in ORIGINAIS]

    def test_baseline_por_classe_e_estagio(self):
        atual = [(r["bloqueios"], r["cobertura_bloqueante"], r["diretos"], r["indiretos"],
                  r["sem_matriz"], r["commit"], r["build"], r["deploy"]) for r in self.base]
        self.assertEqual(atual, [
            (5, 3, 2, 2, 1, 0, 5, 0),
            (80, 11, 29, 24, 27, 51, 27, 2),
            (56, 8, 29, 0, 27, 51, 3, 2),
        ])

    def test_limiar_inclusivo_e_proxies_distintos(self):
        cenarios = variar_proxies(self.unidades, self.base)
        error = [r for r in cenarios if r["origem_proxy"] == "semgrep_error"]
        por_nota = {(r["politica"], r["nota"]): r for r in error}
        self.assertEqual(len(error), 21)
        self.assertEqual(por_nota["P3", 7]["unidades_do_proxy"], 51)
        self.assertEqual(por_nota["P3", 6]["bloqueios"], 5)
        self.assertEqual(por_nota["P3", 7]["bloqueios"], 56)
        self.assertEqual(por_nota["P1", 8]["bloqueios"], 5)
        self.assertEqual(por_nota["P1", 9]["bloqueios"], 56)

    def test_lacunas_e_ids_de_infra_distintos(self):
        bloqueadas = set(self.base[2]["ids_bloqueados"].split("|"))
        self.assertTrue({"dvwa-outdated-os", "dvwa-outdated-packages"} <= bloqueadas)
        alvos = selecionar_lacunas(self.unidades, bloqueadas)
        self.assertEqual({vid: len(alvo[1]) for vid, alvo in alvos.items()}, {
            "dvwa-csrf": 1, "dvwa-weak-session-ids": 2, "dvwa-open-http-redirect": 8,
        })

    def test_confirmacao_p4_com_e_sem_nota(self):
        for status in ("nao_executada", "inconclusiva", "nao_confirmada"):
            for p in ("P4-A", "P4-B"):
                self.assertFalse(bloqueia_confirmacao(Validacao(status, score_confirmacao=10), p))
        self.assertTrue(bloqueia_confirmacao(Validacao("confirmada"), "P4-A"))
        self.assertFalse(bloqueia_confirmacao(Validacao("confirmada"), "P4-B"))
        self.assertFalse(bloqueia_confirmacao(Validacao("confirmada", score_confirmacao=6.9), "P4-B"))
        self.assertTrue(bloqueia_confirmacao(Validacao("confirmada", score_confirmacao=7), "P4-B"))

    def test_score_ausente_e_escopo_das_duas_politicas(self):
        self.assertEqual(sum(u.score is None for u in self.unidades if u.ferramenta == "OWASP ZAP (Active)"), 14)
        self.assertEqual(self.base[2]["indiretos"], 0)
        self.assertEqual(self.base[2]["sem_matriz"], 27)

    def test_estagio_e_classe_somam_bloqueios_em_toda_a_grade(self):
        with (ETAPA / "results/sensibilidade_combinada.csv").open(encoding="utf-8-sig") as f:
            registros = list(csv.DictReader(f))
        self.assertEqual(len(registros), 70)
        for r in registros:
            total = int(r["bloqueios"])
            for chaves in [("diretos", "indiretos", "sem_matriz"), ("commit", "build", "deploy")]:
                self.assertEqual(sum(int(r[k]) for k in chaves), total)
            self.assertLessEqual(int(r["cobertura_bloqueante"]), int(r["detectadas"]))


if __name__ == "__main__":
    unittest.main()
