"""Coletor de contexto de execução da P4 (protocolo em docs/p4-contexto.md).

Para cada alvo em execução local, registra o que os processos da aplicação carregaram:
bibliotecas mapeadas em memória, arquivos abertos, linhas de comando e, no Node.js, os
módulos já carregados (hook em ambientes/contexto/hook-modulos.js). Depois decide, para cada
achado indireto do Trivy, se o pacote vulnerável está "em uso" ou "latente".

Duas observações: S1 logo após a aplicação responder e S2 depois de tráfego benigno (GET em
páginas públicas, sem payload). A leitura de /proc é feita por um contêiner auxiliar que
compartilha o espaço de processos do alvo, porque a imagem do Juice Shop não tem shell.
"""

import argparse
import csv
import io
import json
import subprocess
import tarfile
import time
import urllib.parse
import urllib.request
from pathlib import Path, PurePosixPath

ETAPA = Path(__file__).resolve().parent.parent
AUXILIAR = "busybox@sha256:73aaf090f3d85aa34ee199857f03fa3a95c8ede2ffd4cc2cdb5b94e566b11662"
HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))
TEASTORE = ("registry", "db", "persistence", "auth", "image", "recommender", "webui")

ALVOS = {
    "dvwa": {
        "unidades": "data/normalized/dvwa.json",
        "containers": ["dvwa-r"],
        "trafego": ["http://127.0.0.1:18083/login.php", "http://127.0.0.1:18083/setup.php",
                    "http://127.0.0.1:18083/index.php", "http://127.0.0.1:18083/about.php"],
    },
    "teastore": {
        "unidades": "data/normalized/alvo-teastore.json",
        "containers": [f"teastore-{s}-1" for s in TEASTORE],
        "trafego": [f"http://127.0.0.1:18081/tools.descartes.teastore.webui/{p}" for p in
                    ("", "login", "category?category=2&page=1", "product?id=7", "cart",
                     "about", "status", "category?category=3&page=2")],
    },
    "juice-shop": {
        "unidades": "data/normalized/alvo-juice-shop.json",
        "containers": ["juice-r"],
        "trafego": [f"http://127.0.0.1:18082/{p}" for p in
                    ("", "rest/products/search?q=apple", "api/Products", "rest/languages",
                     "api/Challenges", "rest/admin/application-version", "ftp", "metrics")],
    },
}

SCRIPT_PROC = r"""
for p in /proc/[0-9]*; do
  [ -r $p/maps ] || continue
  awk '{print "MAP " $6}' $p/maps 2>/dev/null
  for f in $p/fd/*; do echo "FD $(readlink $f 2>/dev/null)"; done
  echo "CMD $(tr '\0' ' ' < $p/cmdline 2>/dev/null)"
done
"""


def observar(container):
    saida = subprocess.run(
        ["docker", "run", "--rm", f"--pid=container:{container}", "--cap-add", "SYS_PTRACE",
         AUXILIAR, "sh", "-c", SCRIPT_PROC], capture_output=True, text=True, check=True).stdout
    caminhos, comandos = set(), []
    for linha in saida.splitlines():
        tipo, _, valor = linha.partition(" ")
        if tipo in ("MAP", "FD") and valor.startswith("/"):
            caminhos.add(valor.removesuffix(" (deleted)"))
        elif tipo == "CMD" and valor.strip():
            comandos.append(valor.strip())
    modulos = set()
    tar = subprocess.run(["docker", "cp", f"{container}:/tmp/p4-modulos.txt", "-"],
                         capture_output=True)
    if tar.returncode == 0:
        with tarfile.open(fileobj=io.BytesIO(tar.stdout)) as t:
            for m in t.getmembers():
                modulos |= set(t.extractfile(m).read().decode().split())
    return {"caminhos": caminhos, "comandos": comandos, "modulos": modulos}


def dpkg(container):
    """Mapa arquivo -> pacote a partir das listas do dpkg do próprio contêiner."""
    tar = subprocess.run(["docker", "cp", f"{container}:/var/lib/dpkg/info", "-"],
                         capture_output=True)
    mapa = {}
    if tar.returncode != 0:
        return mapa
    with tarfile.open(fileobj=io.BytesIO(tar.stdout)) as t:
        for m in t.getmembers():
            if m.isfile() and m.name.endswith(".list"):
                pacote = PurePosixPath(m.name).stem.split(":")[0]
                for linha in t.extractfile(m).read().decode("utf-8", "replace").splitlines():
                    mapa.setdefault(linha.strip(), set()).add(pacote)
    return mapa


def pacotes_carregados(obs, mapa):
    pacotes = set()
    for c in obs["caminhos"]:
        for alt in {c, c.replace("/usr/lib/", "/lib/", 1), c.replace("/lib/", "/usr/lib/", 1)}:
            pacotes |= mapa.get(alt, set())
    return pacotes


def scripts_de_inicializacao(container):
    """Texto do Entrypoint/Cmd da imagem e dos scripts que eles chamam (processos de vida
    curta que o snapshot não vê, como o gosu no banco do TeaStore)."""
    cfg = json.loads(subprocess.run(
        ["docker", "inspect", "--format", "{{json .Config}}", container],
        capture_output=True, text=True, check=True).stdout)
    texto = " ".join((cfg.get("Entrypoint") or []) + (cfg.get("Cmd") or []))
    candidatos = {t.strip(";&'\"") for t in texto.split() if t.endswith(".sh") or "/" in t}
    for nome in list(candidatos):
        caminhos = [nome] if nome.startswith("/") else [f"/usr/local/bin/{nome}", f"/{nome}"]
        for caminho in caminhos:
            r = subprocess.run(["docker", "cp", f"{container}:{caminho}", "-"], capture_output=True)
            if r.returncode == 0:
                with tarfile.open(fileobj=io.BytesIO(r.stdout)) as t:
                    for m in t.getmembers():
                        if m.isfile() and m.size < 2_000_000:
                            texto += "\n" + t.extractfile(m).read().decode("utf-8", "replace")
                break
    return set(texto.replace("(", " ").replace(")", " ").replace(";", " ").split())


def zap_spider(urls):
    """Tráfego benigno mais amplo: spider passivo do ZAP que já roda no compose do TeaStore."""
    api = "http://127.0.0.1:18090/JSON"
    for url in urls:
        q = urllib.parse.urlencode({"apikey": "piloto-loopback", "url": url, "recurse": "true"})
        try:
            sid = json.load(HTTP.open(f"{api}/spider/action/scan/?{q}", timeout=30))["scan"]
            prazo = time.monotonic() + 150
            while time.monotonic() < prazo:
                st = json.load(HTTP.open(f"{api}/spider/view/status/?apikey=piloto-loopback"
                                         f"&scanId={sid}", timeout=30))["status"]
                if st == "100":
                    break
                time.sleep(3)
        except Exception:  # noqa: BLE001
            pass


def trafegar(urls):
    for url in urls:
        try:
            with HTTP.open(url, timeout=30) as r:
                r.read()
        except Exception:  # noqa: BLE001 - tráfego é só para exercitar rotas públicas
            pass


def resolver(ref, autores):
    caminho, _, ponteiro = ref.partition("#")
    base = autores / "data/raw" / caminho if caminho.startswith("reports-") else ETAPA / caminho
    dados = json.loads(base.read_text(encoding="utf-8"))
    partes = ponteiro.strip("/").split("/")
    resultado = dados["Results"][int(partes[1])]
    return caminho, resultado, resultado["Vulnerabilities"][int(partes[3])]


def container_do_relatorio(app, caminho):
    if app == "teastore":
        nome = PurePosixPath(caminho).name
        if nome.startswith("image-"):
            return [f"teastore-{nome[6:-5]}-1"]
        return ALVOS["teastore"]["containers"]  # Trivy FS: dependência de qualquer serviço
    return ALVOS[app]["containers"]


def executado_na_inicializacao(resultado, vuln, containers, init, mapas):
    tipo, nome = resultado.get("Type"), vuln["PkgName"]
    if tipo == "gobinary":
        alvo = PurePosixPath(resultado["Target"]).name
        return any(alvo in init[c] for c in containers)
    if tipo in ("debian", "ubuntu"):
        for c in containers:
            comandos = {PurePosixPath(p).name for p, pk in mapas[c].items() if nome in pk
                        and PurePosixPath(p).parent.name in ("bin", "sbin")}
            if comandos & init[c]:
                return True
    return False


def em_uso(resultado, vuln, containers, obs, pacotes):
    tipo = resultado.get("Type")
    nome = vuln["PkgName"]
    if tipo in ("debian", "ubuntu"):
        if any(nome in pacotes[c] for c in containers):
            return True
        if nome == "libc6":  # imagem distroless sem listas do dpkg
            return any("libc.so" in p or "libc-" in p for c in containers
                       for p in obs[c]["caminhos"])
        return False
    if tipo == "jar":
        jar = PurePosixPath(vuln.get("PkgPath", "")).name
        return any(PurePosixPath(p).name == jar for c in containers for p in obs[c]["caminhos"])
    if tipo == "pom":
        artefato = nome.split(":")[-1] + "-"
        return any(PurePosixPath(p).name.startswith(artefato) and p.endswith(".jar")
                   for c in containers for p in obs[c]["caminhos"])
    if tipo == "gobinary":
        alvo = "/" + resultado["Target"].lstrip("/")
        return any(alvo in cmd.split() for c in containers for cmd in obs[c]["comandos"])
    if tipo == "node-pkg":
        pasta = "/" + str(PurePosixPath(vuln.get("PkgPath", "")).parent) + "/"
        return any(pasta in m for c in containers for m in obs[c]["modulos"])
    raise ValueError(f"Tipo de pacote sem regra: {tipo}")


def coletar(app, autores, saida_bruta, spider):
    cfg = ALVOS[app]
    mapas = {c: dpkg(c) for c in cfg["containers"]}
    init = {c: scripts_de_inicializacao(c) for c in cfg["containers"]}
    s1 = {c: observar(c) for c in cfg["containers"]}
    trafegar(cfg["trafego"])
    time.sleep(8)
    s2 = {c: observar(c) for c in cfg["containers"]}
    # S3 (pós-registro): spider passivo do ZAP com os endereços vistos de dentro da rede.
    zap_spider(spider.get(app, []))
    time.sleep(8)
    s3 = {c: observar(c) for c in cfg["containers"]}
    for c in cfg["containers"]:
        for rotulo, obs in (("s1", s1[c]), ("s2", s2[c]), ("s3", s3[c])):
            (saida_bruta / f"{app}--{c}--{rotulo}.txt").write_text(
                "\n".join(sorted(obs["caminhos"]) + ["# comandos"] + obs["comandos"]
                          + ["# modulos"] + sorted(obs["modulos"])) + "\n", encoding="utf-8")
    pac1 = {c: pacotes_carregados(s1[c], mapas[c]) for c in cfg["containers"]}
    pac2 = {c: pacotes_carregados(s2[c], mapas[c]) for c in cfg["containers"]}
    pac3 = {c: pacotes_carregados(s3[c], mapas[c]) for c in cfg["containers"]}
    unidades = json.loads((ETAPA / cfg["unidades"]).read_text(encoding="utf-8"))["unidades"]
    linhas = []
    for u in unidades:
        if u["classe"] != "indireta":
            continue
        caminho, resultado, vuln = resolver(u["referencia"], autores)
        cs = container_do_relatorio(app, caminho)
        a = em_uso(resultado, vuln, cs, s1, pac1)
        b = em_uso(resultado, vuln, cs, s2, pac2)
        c3 = em_uso(resultado, vuln, cs, s3, pac3)
        ini = executado_na_inicializacao(resultado, vuln, cs, init, mapas)
        linhas.append({"aplicacao": app, "unidade": u["id"], "ferramenta": u["ferramenta"],
                       "estagio": u["estagio"], "score": u["score"],
                       "tipo_pacote": resultado.get("Type"), "pacote": vuln["PkgName"],
                       "cve": vuln["VulnerabilityID"], "containers": "|".join(cs),
                       "em_uso_s1": int(a), "em_uso_s2": int(b), "em_uso_s3": int(c3),
                       "em_uso": int(a or b),  # definição registrada (S1 ou S2)
                       "executado_na_inicializacao": int(ini),
                       "carregado": int(a or b or c3 or ini),  # pós-registro: + S3 + init
                       "vinculos": "|".join(sorted(u["vinculos"]))})
    return linhas


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--autores", type=Path, required=True,
                   help="Clone do artefato dos autores (para o relatório Trivy da DVWA)")
    p.add_argument("--apps", nargs="+", default=list(ALVOS))
    p.add_argument("--out", type=Path, default=ETAPA / "results/contexto_execucao.csv")
    for app in ALVOS:
        p.add_argument("--spider-" + app, nargs="*",
                       help="URLs iniciais do spider do ZAP, vistas de dentro da rede Docker")
    a = p.parse_args()
    bruto = ETAPA / "pilotos/contexto"
    bruto.mkdir(parents=True, exist_ok=True)
    spider = {app: [u.strip() for u in getattr(a, "spider_" + app.replace("-", "_")) or []]
              for app in ALVOS}
    linhas = []
    for app in a.apps:
        linhas += coletar(app, a.autores, bruto, spider)
    with a.out.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(linhas[0]))
        w.writeheader()
        w.writerows(linhas)
    for app in a.apps:
        ls = [x for x in linhas if x["aplicacao"] == app]
        altos = [x for x in ls if (x["score"] or 0) >= 7]
        estaveis = sum(x["em_uso_s1"] == x["em_uso_s2"] for x in altos)
        print(f"{app}: indiretos {len(ls)}, em uso {sum(x['em_uso'] for x in ls)}; "
              f">=7: {len(altos)}, em uso {sum(x['em_uso'] for x in altos)}, "
              f"S1=S2 em {estaveis}/{len(altos)}")


if __name__ == "__main__":
    main()
