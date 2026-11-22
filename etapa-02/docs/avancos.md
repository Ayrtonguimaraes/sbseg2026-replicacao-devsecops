# Avanços do projeto — estado em 2026-11-22

Painel de situação da reprodução e extensão do artigo de Machado, Cordeiro e Jandre
(SBSeg 2026). Complementa `protocolo.md` (metodologia e resultados), `pilotos.md`
(evidência dinâmica) e `esquema.md` (proveniência). Para o que ainda falta e **por que**
alguns itens não podem ser automatizados por este assistente, veja
[`limitacoes-assistente.md`](limitacoes-assistente.md).

## Resumo em uma linha

Etapa 01 (reprodução) concluída e conferida. Etapa 02 (extensão) com as três melhorias
combinadas com o professor **prontas e verificadas**. O que resta é confirmação dinâmica
de alguns casos (XSS ativo, RCE) e o push para o GitHub do grupo — detalhado abaixo.

## Etapa 01 — reprodução

| Item | Estado |
|---|---|
| Reprodução das Tabelas 3, 4 e 5 do artigo | ✅ Concluída |
| Números batem com a referência | ✅ P1/P2/P3 = 5/80/56 bloqueios; cobertura 11/13 (P2) → 8/13 (P3) |
| Evidências versionadas | ✅ `etapa-01/evidencias/` |

## Etapa 02 — extensão (três melhorias do checkpoint)

| Melhoria | Estado | Resultado |
|---|---|---|
| (1) Política P4 nova | ✅ Concluída e testada contra alternativas | P4 (= P4-A): DVWA 58 e 10/13, TeaStore 140 e 5/14, Juice Shop 10 e 4/14. Recupera 4 dos 10 casos perdidos pela P3 com 2,4% dos bloqueios extras da P2. Não é dominada por ajustes de limiar na DVWA e no Juice Shop; no TeaStore, a P2 com limiar 8 a domina em cobertura bruta (protocolo registrado antes, `p4-avaliacao.md`). Catálogo benigno confirma 4 de 11 casos da fila. P4-B virou análise de sensibilidade. |
| (2) Mais aplicações | ✅ Análise completa, com Deploy Gate (ZAP passivo) nos dois alvos | TeaStore 1.4.2 e Juice Shop 19.0.0, matriz de 14 casos cada. |
| (3) Sensibilidade das notas arbitrárias | ✅ Concluída | Redução de P3 vs P2 vai de 13% a 89% conforme as notas (Monte Carlo, 10.000 amostras). O resultado qualitativo resiste em todas as amostras. |

### Números dos dois alvos pedidos pelo professor

| Alvo | Unidades | P2 (bloqueios/cobertura) | P3 (bloqueios/cobertura) | Redução P3 vs P2 |
|---|---:|---|---|---:|
| TeaStore 1.4.2 | 729 | 262 / 7-14 | 139 / 4-14 | 47% |
| Juice Shop 19.0.0 | 83 | 28 / 7-14 | 9 / 3-14 | 68% |

**Ponto forte para a apresentação:** o padrão do artigo (P3 bloqueia menos e perde
cobertura) se repete no TeaStore, que **não** foi construído para ser vulnerável — ataca
diretamente a maior ameaça à validade externa do artigo original.

### Verificação automatizada

- 12 testes passam: `uv run --no-project --python 3.12 python -m unittest discover -s etapa-02/tests`.
- **Atenção:** o Python do sistema (3.9) é velho demais; usar 3.10+.

## Avanços desta sessão (2026-11-22)

| Avanço | Estado | Detalhe |
|---|---|---|
| Ponto de recuperação no git | ✅ | Tag `backup/pre-conclusao-2026-11-22`, branch de trabalho `etapa-02-conclusao`, bundle em `../backups/sbseg2026-pre-conclusao-2026-11-22.bundle` (verificado). |
| Docker instalado | ✅ | colima (VM `vz` + Rosetta) + docker 29 + compose, via Homebrew, sem `sudo`. Remoção: `brew uninstall` + `colima delete`. |
| Imagens baixadas | ✅ | 7 serviços `descartesresearch/teastore-*:1.4.2`, `zaproxy/zap-stable`, DVWA fixada por digest. Digests registrados. |
| TeaStore `ts-tls-trust-all` — análise de código | ✅ | O trecho "trust-all certs" (`RESTClient.java`) só roda com `USE_HTTPS=true`, que **não** existe no manifesto de referência (`teastore-clusterip.yaml`) nem no `docker-compose_default.yaml`. Logo, não é exercitado na implantação de referência. |
| TeaStore — Deploy Gate | ✅ | 7 serviços + ZAP 2.17.0 em Docker local, portas só em `127.0.0.1`. ZAP **passivo**: 29 URLs, 532 alertas, 12 tipos. Nenhum acima do limiar, então P1–P3 não mudam; +1 detecção direta (`ts-cookie-flags`). Rotas DAST pré-registradas antes da coleta (`66ba136`). |
| TeaStore `ts-db-reset-unauth` — P4 | ✅ Confirmado | O spider do ZAP, sem autenticação nem payload, submeteu o formulário público `/database` e o banco foi regenerado (log do webui). P4-A: **140 decisões, 5/14**. P4-B igual com o vetor proposto (9,1); com o alternativo (6,5) não bloqueia — **pendente de ratificação do vetor pelo grupo**. Laudo em `pilotos/p4-teastore/`. |
| Política de uso — revalidação | ✅ | Citações conferidas nas páginas oficiais em 22/11; quote da AUP corrigido, Cyber Verification Program incluído, regra 3 do protocolo corrigida. Ver `limitacoes-assistente.md`. |
| TeaStore `ts-output-encoding` — análise de código | ✅ | XSS armazenado real confirmado por leitura de código: campos `firstname/lastname/address1/address2` vêm de parâmetros POST em `CartActionServlet.java:131` e são renderizados sem escape em `profile.jsp` (`${order.address1}` etc.). |

## O que falta para "100%"

Ordenado por quem consegue fazer. A coluna "quem" distingue o que o assistente pode
automatizar do que precisa ser feito manualmente — a razão está em
[`limitacoes-assistente.md`](limitacoes-assistente.md).

| Pendência | Quem | Observação |
|---|---|---|
| **Push dos commits para o GitHub do grupo** | Usuário | `git push` dá 403: a conta não tem escrita no repo do `jldsn`. Resolver com acesso de colaborador ou fork + PR. 3 commits locais + o trabalho desta sessão aguardam. |
| **XSS ativo** (TeaStore `ts-output-encoding`; Juice Shop `js-dom-xss`, `js-reflected-xss`) | Usuário | Confirmar enviando payload num navegador. Evidência estática já existe; a dinâmica envia um exploit, o que o classificador de segurança pode bloquear. Alternativa oficial: o usuário pedir o Cyber Verification Program (Defense Access cobre "vulnerability triage and validation"). |
| **TeaStore — ZAP ativo** | Usuário (opcional) | Só para simetria com o Juice Shop. O escaneamento ativo dispara payloads. |
| **TeaStore `ts-tls-trust-all`** | Ninguém (limite do alvo) | Só existe com `USE_HTTPS=true`, fora da implantação de referência. |
| **Juice Shop `js-rce-b2b`** | Usuário (ou ficar estático) | Decisão do grupo: **não automatizar**. O teste oficial tem efeito de negação de serviço. Apoiado só em evidência estática (Semgrep) + indireta (Trivy). |
| **Decisões do grupo** | Grupo | Ratificar vetores CVSS da P4-B, regra de escopo e ressalva de circularidade da matriz (ver `protocolo.md`). |
| **Slides da Etapa 02** | Grupo/Assistente | Os PDFs na raiz ainda mostram só o piloto de 3 casos. Não há bloqueio de política: o assistente pode preparar o conteúdo. |

Impacto numérico de cada pendência: `limitacoes-assistente.md`, seção 8.

## Como retomar com segurança

1. Trabalho em branch dedicado `etapa-02-conclusao`; `main` intacto.
2. Antes de qualquer `git checkout/reset/clean`, rodar `git status` e `git stash -u`.
3. Recuperar o estado pré-sessão: `git checkout backup/pre-conclusao-2026-11-22` ou
   restaurar do bundle `../backups/sbseg2026-pre-conclusao-2026-11-22.bundle`.
