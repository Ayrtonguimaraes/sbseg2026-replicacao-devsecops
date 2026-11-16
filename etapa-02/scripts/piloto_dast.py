"""Piloto local ZAP de duas aplicações versionadas, sem autenticação."""

import argparse
import fcntl
import json
import os
import signal
import socket
import struct
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from contextlib import ExitStack
from pathlib import Path

HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))
ZAP = "http://127.0.0.1:18090"
API_KEY = "piloto-loopback"


def preparar_loopback():
    linhas = Path("/proc/self/net/dev").read_text().splitlines()[2:]
    interfaces = {linha.partition(":")[0].strip() for linha in linhas}
    if interfaces != {"lo"}:
        raise RuntimeError("Execute com unshare --user --map-root-user --net.")
    with socket.socket() as s:
        fcntl.ioctl(s, 0x8914, struct.pack("=16sH14x", b"lo", 1))


def requisitar(url):
    with HTTP.open(url, timeout=12) as r:
        return r.status, r.read()


def zap_api(endpoint, **params):
    query = urllib.parse.urlencode({"apikey": API_KEY, **params})
    try:
        _, dados = requisitar(f"{ZAP}/JSON/{endpoint}/?{query}")
    except urllib.error.HTTPError as err:
        raise RuntimeError(f"ZAP {endpoint}: HTTP {err.code} {err.read(250)!r}") from err
    return json.loads(dados)


def aguardar(funcao, descricao, limite=90, processo=None):
    prazo = time.monotonic() + limite
    while time.monotonic() < prazo:
        if processo is not None and processo.poll() is not None:
            raise RuntimeError(f"{descricao}: processo terminou com código {processo.returncode}")
        try:
            valor = funcao()
            if valor:
                return valor
        except (urllib.error.URLError, TimeoutError, RuntimeError):
            if processo is None:
                raise
        time.sleep(1)
    raise TimeoutError(descricao)


def finalizar(proc):
    if proc.poll() is None:
        os.killpg(proc.pid, signal.SIGTERM)
        try:
            proc.wait(timeout=8)
        except subprocess.TimeoutExpired:
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()


def iniciar(stack, cmd, cwd, log, env=None):
    arquivo = stack.enter_context(log.open("wb"))
    proc = subprocess.Popen(
        cmd, cwd=cwd, stdout=arquivo, stderr=subprocess.STDOUT,
        env=env, start_new_session=True,
    )
    stack.callback(finalizar, proc)
    return proc


def salvar(path, dados):
    path.write_text(json.dumps(dados, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def rodar(args):
    preparar_loopback()
    args.out.mkdir(parents=True, exist_ok=True)
    args.work.mkdir(parents=True, exist_ok=True)
    if args.app == "juice-shop":
        base = "http://127.0.0.1:18080"
        alvo = base + "/"
        ativo = base + "/rest/products/search?q=apple"
        cmd = [args.runtime, str(args.release / "build/app.js")]
        cwd = args.release
        env = {**os.environ, "PORT": "18080", "NODE_ENV": "unsafe"}
    else:
        base = "http://127.0.0.1:18080"
        alvo = base + "/WebGoat/login"
        ativo = alvo + "?error=true"
        cmd = [args.runtime, "-Xmx384m", f"-Duser.home={args.work}", "-jar", str(args.release)]
        cwd = args.work
        env = {**os.environ, "WEBGOAT_HOST": "127.0.0.1", "WEBGOAT_PORT": "18080",
               "WEBWOLF_HOST": "127.0.0.1", "WEBWOLF_PORT": "19091"}
    saida = {"app": args.app, "healthcheck": alvo, "active_target": ativo,
             "autenticado": False, "rede": "namespace_somente_loopback"}
    with ExitStack() as stack:
        app = iniciar(stack, cmd, cwd, args.out / f"{args.app}-app.log", env)
        status = aguardar(lambda: requisitar(alvo)[0], "Inicialização do alvo", processo=app)
        saida["healthcheck_http"] = status
        zap_home = args.work / "zap-home"
        zap_home.mkdir(exist_ok=True)
        zap = iniciar(stack, [str(args.zap / "zap.sh"), "-daemon", "-host", "127.0.0.1",
            "-port", "18090", "-dir", str(zap_home), "-silent", "-config",
            f"api.key={API_KEY}", "-config", "autoupdate.checkOnStart=false"],
            args.work, args.out / f"{args.app}-zap.log")
        saida["zap"] = aguardar(lambda: zap_api("core/view/version"), "Inicialização do ZAP",
                                processo=zap)
        zap_api("core/action/accessUrl", url=alvo, followRedirects="true")
        zap_api("core/action/accessUrl", url=ativo, followRedirects="true")
        zap_api("spider/action/setOptionMaxDuration", Integer="1")
        id_spider = zap_api("spider/action/scan", url=alvo, recurse="true")["scan"]
        aguardar(lambda: zap_api("spider/view/status", scanId=id_spider)["status"] == "100",
                 "Spider ZAP", limite=85)
        aguardar(lambda: zap_api("pscan/view/recordsToScan")["recordsToScan"] == "0",
                 "Fila de análise passiva", limite=80)
        urls = zap_api("core/view/urls", baseurl=base)["urls"]
        passivos = zap_api("core/view/alerts", baseurl=base, start=0, count=10000)["alerts"]
        salvar(args.out / f"{args.app}-passivo.json", {"urls": urls, "alerts": passivos})
        saida.update({"urls_passivas": len(urls), "alertas_passivos": len(passivos)})
        salvar(args.out / f"{args.app}-resumo.json", saida)
        zap_api("ascan/action/setOptionMaxScanDurationInMins", Integer="1")
        zap_api("ascan/action/setOptionMaxRuleDurationInMins", Integer="1")
        # As duas regras têm escopo restrito ao endpoint acima.
        zap_api("ascan/action/disableAllScanners")
        zap_api("ascan/action/enableScanners", ids="40012,40018")
        id_ativo = zap_api("ascan/action/scan", url=ativo, recurse="false",
                           inScopeOnly="false")["scan"]
        aguardar(lambda: zap_api("ascan/view/status", scanId=id_ativo)["status"] == "100",
                 "Escaneamento ativo ZAP", limite=90)
        ids = set(zap_api("ascan/view/alertsIds", scanId=id_ativo)["alertsIds"])
        acumulados = zap_api("core/view/alerts", baseurl=base, start=0, count=10000)["alerts"]
        ativos = [a for a in acumulados if a["id"] in ids]
        salvar(args.out / f"{args.app}-ativo.json", {"url": ativo, "regras": [40012, 40018],
              "ids": sorted(ids), "alerts": ativos})
        saida.update({"alertas_ativos": len(ativos), "regras_ativas": [40012, 40018]})
        salvar(args.out / f"{args.app}-resumo.json", saida)
    print(json.dumps(saida, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app", choices=("juice-shop", "webgoat"))
    parser.add_argument("--release", type=lambda s: Path(s).resolve(), required=True)
    parser.add_argument("--runtime", required=True, help="Node 24 ou Java 23")
    for nome in ("zap", "out", "work"):
        parser.add_argument("--" + nome, type=lambda s: Path(s).resolve(), required=True)
    rodar(parser.parse_args())


if __name__ == "__main__":
    main()
