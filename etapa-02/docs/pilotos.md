# Pilotos e validação dinâmica

## Candidatas e cobertura de ferramentas

| Alvo | Stack e referência técnica | Resultado |
|---|---|---|
| DVWA | PHP e MariaDB. Imagem Debian histórica, matriz com 13 casos em escopo. | Análise histórica reproduzida e três testes dirigidos em instância local descartável. |
| Juice Shop 19.0.0 | Node.js, Express e Angular. Catálogo de desafios e código da versão. | Selecionada. Semgrep, Checkov Dockerfile, Trivy Image, Trivy FS e ZAP executados. |
| WebGoat 2025.3 | Java e Spring Boot. Catálogo de lições e código tagueados. | Selecionada. Mesmas frentes do piloto, com regras SAST para Java. |
| NodeGoat | Node.js e MongoDB. Exercícios OWASP e Docker Compose. | Reserva. O código e os artefatos de contêiner existem. A coleta precisaria de configuração própria. |
| crAPI | Aplicação de treinamento de segurança de APIs, com serviços e Compose. | Reserva. A cobertura envolve vários serviços, inventário de rotas e autenticação. |

Fontes das candidatas. [DVWA](https://github.com/digininja/DVWA), [Juice Shop](https://github.com/juice-shop/juice-shop/releases/tag/v19.0.0), [WebGoat](https://github.com/WebGoat/WebGoat/releases/tag/v2025.3), [NodeGoat](https://github.com/OWASP/NodeGoat), [crAPI](https://owasp.org/projects/crapi).

| Scanner | Juice Shop | WebGoat |
|---|---|---|
| Semgrep 1.185.0 | 58 regras executadas, 457 arquivos, 16 achados | 95 regras executadas, 260 arquivos, 53 achados |
| Checkov 3.4.5 | 2 reprovações em 279 verificações no Dockerfile | 0 reprovações em 31 verificações no Dockerfile |
| Trivy Container 0.69.3 | 448 ocorrências, 104 em pacotes de sistema | 825 ocorrências, 674 em pacotes de sistema |
| Trivy FS 0.69.3 | Execução concluída sem artefato de dependências reconhecido | 41 ocorrências no POM. Há aviso de versões de dependências sem resolução offline |
| ZAP 2.17.0 passivo | 103 URLs, 432 instâncias de alerta, 6 tipos | 19 URLs, 33 instâncias de alerta, 8 tipos |
| ZAP 2.17.0 ativo | 1 indicador de SQL Injection no parâmetro q da busca. Confiança Low, com código da rota inspecionado | 0 alertas na rota de login e nas duas regras ativadas |

Os números usam unidades de saída distintas. As quantidades de Trivy são ocorrências por alvo/pacote, não agregações por CVE única. O Checkov analisou Dockerfile, diferente do Terraform e Kubernetes do histórico da DVWA. Os relatórios `pilotos_scanners.csv`, `pilotos_politicas.csv`, `pilotos_limiares.csv` e `pilotos_cobertura.csv` detalham os resultados. No Juice Shop, o lockfile de dependências da raiz está ausente no checkout; um backup versionado em `ftp/` fica fora do reconhecimento do scanner. A imagem analisada tem componentes identificados.

### Versões que controlam a reprodução

| Componente | Origem fixada |
|---|---|
| Artefato DVWA | `5b18244126350d1a6a4bf39e7a34701af9190563` |
| Imagem DVWA | `vulnerables/web-dvwa@sha256:dae203fe11646a86937bf04db0079adef295f426da68a92b40e3b181f337daa7` |
| Código Juice Shop | v19.0.0, `36870cbbdfe7864698e1adf644c7bf772f67ebb7` |
| Imagem Juice Shop amd64 | `bkimminich/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58` |
| Código WebGoat | v2025.3, `c3ed45a733377bc7313b93f57ff518254d81380f` |
| Imagem WebGoat amd64 | `webgoat/webgoat@sha256:6ebbadd5a440af0970049a8261e1d79914009fb9537b36b8081633913b9684ea` |
| Regras Semgrep | [semgrep/semgrep-rules](https://github.com/semgrep/semgrep-rules), commit `a5ad1714f00c9f7fde980cab0ea1d6dc6d414fd2` |
| Runtimes DAST | Node 24.22.1, Temurin 23.0.2 para WebGoat, OpenJDK 21 para ZAP |
| Banco Trivy | `evidence/trivy-db.json` e `evidence/trivy-java-db.json` com data de atualização e download |

## Reexecução dos scanners

Os relatórios já foram coletados. A reanálise numérica usa os arquivos existentes e roda com `python3 etapa-02/scripts/resumir_pilotos.py`. Recolete apenas se quiser verificar uma configuração específica. Fixe as versões, registre datas, parâmetros, logs e hashes. Use diretórios de saída distintos para guardar a execução de referência.

Exemplos abaixo assumem as variáveis `OUT` (pasta própria para a coleta), `REGRAS` (checkout do conjunto Semgrep), `JUICE` e `GOAT` (checkouts nas versões da tabela). CLI e dependências das ferramentas são instaladas separadamente.

~~~bash
(
  cd "$JUICE"
  semgrep scan --oss-only --metrics=off --disable-version-check --jobs 2 \
    --no-rewrite-rule-ids --json-output "$OUT/juice-shop-semgrep.json" \
    --config "$REGRAS/javascript/express/security" \
    --config "$REGRAS/javascript/browser/security" \
    --config "$REGRAS/typescript/angular/security" \
    routes lib models frontend/src
  BC_SKIP_MAPPING=true checkov --file Dockerfile --framework dockerfile \
    --skip-download --soft-fail --output json > "$OUT/juice-shop-checkov.json"
)
(
  cd "$GOAT"
  semgrep scan --oss-only --metrics=off --disable-version-check --jobs 2 \
    --no-rewrite-rule-ids --json-output "$OUT/webgoat-semgrep.json" \
    --config "$REGRAS/java/lang/security" \
    --config "$REGRAS/java/spring/security" \
    --config "$REGRAS/java/servlets/security" src/main/java
  BC_SKIP_MAPPING=true checkov --file Dockerfile --framework dockerfile \
    --skip-download --soft-fail --output json > "$OUT/webgoat-checkov.json"
)
trivy image --download-db-only
trivy image --download-java-db-only
trivy fs --skip-db-update --skip-java-db-update --offline-scan --scanners vuln \
  --format json --output "$OUT/juice-shop-fs.json" "$JUICE"
trivy fs --skip-db-update --skip-java-db-update --offline-scan --scanners vuln \
  --format json --output "$OUT/webgoat-fs.json" "$GOAT"
trivy image --image-src remote --platform linux/amd64 --skip-db-update \
  --skip-java-db-update --offline-scan --scanners vuln --format json \
  --output "$OUT/juice-shop-image.json" \
  bkimminich/juice-shop@sha256:547bd3fef4a6d7e25e131da68f454e6dc4a59d281f8793df6853e6796c9bbf58
trivy image --image-src remote --platform linux/amd64 --skip-db-update \
  --skip-java-db-update --offline-scan --scanners vuln --format json \
  --output "$OUT/webgoat-image.json" \
  webgoat/webgoat@sha256:6ebbadd5a440af0970049a8261e1d79914009fb9537b36b8081633913b9684ea
~~~

Um banco de CVEs atualizado pode produzir novos números. Os hashes e os relatórios já coletados permitem recalcular os mesmos resultados do pacote.

Para o ZAP local, baixe os releases oficiais para Linux e extraia o Juice Shop Node 24 e o ZAP em pastas próprias. O WebGoat usa o JAR do release com Java 23. Execute cada piloto com namespace de rede somente loopback. Em WSL, a disponibilidade de namespaces depende da configuração de kernel.

~~~bash
unshare --user --map-root-user --mount --pid --fork --net --kill-child \
  python3 etapa-02/scripts/piloto_dast.py juice-shop \
  --release "$JUICE_RELEASE" --runtime "$(command -v node)" \
  --zap "$ZAP_DIR" --out "$OUT/zap" --work "$OUT/runtime-juice"

unshare --user --map-root-user --mount --pid --fork --net --kill-child \
  python3 etapa-02/scripts/piloto_dast.py webgoat \
  --release "$GOAT_JAR" --runtime "$JAVA23" \
  --zap "$ZAP_DIR" --out "$OUT/zap" --work "$OUT/runtime-goat"
~~~

O passivo usa spider de até um minuto e espera a fila de alertas. O ativo limita o teste às regras ZAP 40012 e 40018, com teto de um minuto, no parâmetro da busca do Juice Shop e na rota de login do WebGoat. Os dois aplicativos responderam HTTP 200 no healthcheck. Documentação. [ZAP API](https://www.zaproxy.org/docs/api/).

## DVWA P4 · Evidência dirigida

A avaliação usou o digest histórico da imagem DVWA, com seus arquivos PHP e MariaDB, dentro de um namespace Linux sem acesso externo. O ambiente local serviu o PHP 7.0 com seu servidor de desenvolvimento, após reset do banco descartável. A coleta histórica usava GKE e Apache. No laboratório, o nível de segurança confirmado por cookie era `low`.

| Caso | Observação | Estado |
|---|---|---|
| CSRF | A requisição GET com sessão, Referer distinto e sem token mudou a senha da conta descartável. O controle sem sessão redirecionou para login. A nova senha funcionou, a anterior falhou e foi restaurada. | Confirmada no protocolo HTTP |
| Weak Session IDs | Doze respostas HTTP 200 produziram o cookie de treinamento `dvwaSession` com os valores consecutivos 1 a 12. A evidência delimita-se a esse cookie. | Confirmada |
| Open HTTP Redirect | Duas rotas candidatas retornaram 404 no digest ensaiado. Consultamos a árvore da imagem e não localizamos o módulo nessas rotas. | Inconclusiva |

A P4-A, aplicada aos laudos, simulou 2 decisões novas de Deploy, totalizando 58 decisões e cobertura de 10/13. A P4-B, com a exigência de score independente, ficou em 56 e 8/13. Os dois laudos positivos registram evidência comportamental e a pontuação de confirmação permanece pendente. O resultado de P4-A é uma simulação de portão com entradas obtidas em teste real. Um teste com navegador real pode refinar a verificação de envio de cookies no CSRF. O máximo condicional de 11/13 considera a terceira lacuna confirmada e tem registro próprio.

A versão empacotada contém laudo HTTP com status, indicadores e hash. Para repetir a decisão a partir dessa evidência na raiz que contém `etapa-02/`.

~~~bash
python3 etapa-02/scripts/politica_p4.py \
  --validacoes etapa-02/pilotos/p4-dvwa/validacoes.csv
~~~

Para recriar o teste interativo em WSL com Docker disponível, use uma instância descartável e limite a publicação ao loopback. Em outro terminal, abra `http://127.0.0.1:18080/setup.php`, crie o banco de laboratório e configure o nível Low na interface autenticada.

~~~bash
docker run --rm --name dvwa-etapa02-lab -p 127.0.0.1:18080:80 \
  vulnerables/web-dvwa@sha256:dae203fe11646a86937bf04db0079adef295f426da68a92b40e3b181f337daa7
~~~

Depois execute o teste com a conta descartável. O CLI pede a senha de forma interativa e salva somente o laudo verificável. Use outra pasta para a nova saída.

~~~bash
python3 etapa-02/scripts/validar_dvwa_http.py --base http://127.0.0.1:18080 \
  --configuracao 'DVWA digest dae203fe, Docker local, Apache, low' \
  --out nova-coleta/dvwa-http.json
docker stop dvwa-etapa02-lab
~~~
