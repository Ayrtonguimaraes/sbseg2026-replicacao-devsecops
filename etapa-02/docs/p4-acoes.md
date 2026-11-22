# P4 orientada a ações, com contexto de execução: protocolo registrado antes

**Registrado em 22/11/2026, antes de calcular qualquer resultado desta versão.** Substitui a
"P4 com contexto de execução" de `p4-contexto.md` como proposta do grupo. Aquela versão fica
como registro da etapa anterior.

## 1. Por que mudar de novo

Uma revisão crítica da versão anterior, feita sobre os próprios dados do repositório, apontou:

1. **Nenhuma decisão de deploy muda.** P2, P3 e a P4 anterior bloqueiam os três alvos. A única
   diferença era uma contagem de unidades.
2. **A contagem era por pacote dpkg, não por vulnerabilidade.** Na DVWA, os "8 bloqueios evitados"
   correspondem a 1 CVE de 9, porque o mesmo CVE continua bloqueando por um pacote irmão
   carregado (`openssl`/`libssl1.1`, `libldap-common`/`libldap-2.4-2`). No TeaStore, as 96
   unidades correspondem a 6 CVEs de 15.
3. **O único acerto auditado é capturado por um limiar simples.** As duas fugas de sandbox do
   `vm2` têm nota 10,0, e a regra "P3 + indiretos ≥ 9" já as bloqueia.
4. **Dependia da matriz.** Só os achados "indiretos" eram filtrados, e quem é indireto vem da
   coincidência de CWE com a matriz de referência, que um pipeline real não tem.
5. **A métrica "bloqueios" é dominada por artefato de contagem.** 100 dos 139 bloqueios da P3 no
   TeaStore vêm de uma única regra do Semgrep (`detected-bcrypt-hash`), que dispara uma vez por
   linha do dump `setupData.sql`. Contar unidades não diz quanto trabalho o time tem.

**Transparência:** durante essa revisão foram vistas contagens exploratórias que antecipam parte
dos resultados (os números do item 2 e uma contagem grosseira de grupos por ferramenta e regra,
por exemplo 139 unidades → cerca de 39 grupos na P3 do TeaStore). A definição abaixo foi fixada
depois disso, e os critérios foram escritos para não depender desses números.

## 2. Pergunta prática

**"O que o time precisa fazer para liberar o deploy?"** A P4 responde com uma lista de **ações de
correção**, e não com uma contagem de achados, e usa o contexto de execução para tirar da lista,
com justificativa registrada, as vulnerabilidades de imagem que a implantação não executa.

## 3. Definição da P4

1. **Escopo sem matriz.** Todo registro do Trivy de imagem (Trivy Image no TeaStore e no Juice
   Shop, Trivy Container na DVWA) com nota ≥ 7, de qualquer classe (direta, indireta ou sem
   matriz). A classe direta/indireta deixa de ser usada para decidir.
2. **Filtro de execução, por vulnerabilidade.** Um registro (pacote, CVE) é **carregado** se o
   coletor observou o pacote em uso (S1, S2, S3, scripts de inicialização e, no Juice Shop, o fluxo
   autenticado S4, com as mesmas regras de `contexto_execucao.py`). Um CVE **bloqueia** se pelo
   menos um pacote afetado por ele, na mesma imagem, está carregado. Se nenhum está, o CVE sai do
   bloqueio com uma declaração OpenVEX `not_affected`, justificativa
   `vulnerable_code_not_in_execute_path`, e fica para reavaliação pelo Runtime Watch.
3. **Fim de suporte do SO não é filtrado.** O agregado de SO em fim de suporte (EOSL) continua
   bloqueando como na P3: é um fato do ciclo de vida da imagem, não uma vulnerabilidade de pacote.
4. **O resto é a P3\*.** Achados de aplicação (Semgrep, Trivy FS, Checkov, ZAP, teste de
   credenciais) seguem a regra da P3, e as confirmações do Deploy Gate executado somam como na P3\*.
5. **Unidade de decisão = ação de correção**, definida abaixo, e aplicada igualmente a **todas**
   as políticas comparadas.

## 4. Ações de correção (definição única para todas as políticas)

Uma ação é a mudança mínima que tira um conjunto de unidades bloqueadas do bloqueio:

| Origem | Chave da ação | Leitura |
|---|---|---|
| Registro de imagem (pacote de SO) | (imagem base, pacote fonte) | atualizar o pacote fonte para a maior versão corrigida entre os CVEs; "sem correção" se algum CVE não tiver |
| Registro de imagem (jar, npm, binário Go) | (ecossistema, pacote) | atualizar ou substituir a dependência |
| Agregado EOSL | (família e versão do SO) | migrar a imagem base |
| Agregado de pacotes com correção ou de demais CVEs | uma ação por registro membro com nota ≥ 7, pela regra acima | é o que zera o máximo do agregado |
| Semgrep | (regra, arquivo) | corrigir o padrão no arquivo |
| Trivy FS | (ecossistema, pacote) | atualizar a dependência |
| Demais (Checkov, ZAP, teste de credenciais, confirmação) | a própria unidade | uma correção |

"Imagem base" = família e versão do SO da imagem (Debian 10.10, Ubuntu 18.04, Debian 12.11,
Debian 9.5), porque as imagens do TeaStore compartilham a mesma base e uma correção na base vale
para todas. "Pacote fonte" = campo `Source` do banco do dpkg do contêiner (por exemplo `curl`,
`libcurl4` e `libcurl3-gnutls` saem do mesmo fonte `curl`); sem esse campo, o próprio pacote.

## 5. Políticas comparadas

| Política | Imagem | Demais |
|---|---|---|
| P2 | todos os registros e agregados ≥ 7 | todos ≥ 7 |
| P3 | sem indiretos | sem indiretos |
| P3\* | como P3 | P3 + confirmações |
| A2 | P3 + indiretos ≥ 9 | como P3 |
| **Escopo sem coletor (ablação)** | todos os registros ≥ 7, EOSL como agregado, sem filtro | como P3\* |
| **P4** | registros ≥ 7 carregados, EOSL como agregado | como P3\* |

A ablação é a P4 sem o coletor: mesmo escopo, mesma unidade de ação. A diferença entre as duas é
o efeito do coletor e nada mais. A diferença entre P3 em unidades e P3 em ações é o efeito da
mudança de unidade, e **não é atribuída à P4**.

## 6. Métricas (por alvo e política)

- **Ações para liberar o deploy** (total e por tipo: migrar SO, pacote de imagem, Semgrep, outros).
- **CVEs de imagem bloqueantes distintos** (fora o agregado EOSL).
- **CVEs justificados por VEX** (só P4).
- **Unidades bloqueadas** (métrica do artigo, para continuidade) e **cobertura da matriz**
  (contexto; a obtida por coincidência de CWE continua sendo coincidência).

## 7. Critérios registrados

- **S1 — o coletor é útil:** a P4 tira do bloqueio pelo menos 20% dos CVEs de imagem distintos
  com nota ≥ 7 da ablação em pelo menos 2 dos 3 alvos.
- **S2 — o coletor reduz trabalho:** a P4 exige menos ações de pacote de imagem que a ablação em
  pelo menos 2 dos 3 alvos. (Refinamento da proposta aprovada, que comparava com "P3 com ações":
  a P3 tem escopo diferente, então a comparação que isola o coletor é com a ablação. A comparação
  com P3 e A2 é reportada como descrição.)
- **S3 — sem perda:** a P4 cobre todos os casos da matriz que a P3\* cobre.
- **S4 — funciona num scanner real:** rodando o Trivy oficial com e sem o VEX gerado, numa imagem
  do TeaStore e na do Juice Shop, o conjunto suprimido é exatamente o conjunto de pares
  (pacote, CVE) declarados no VEX presentes no relatório, e nenhum outro. (O banco do Trivy de hoje
  difere do da coleta; por isso o critério compara com e sem VEX na mesma execução.)
- **S5 — falso negativo, verificação mecânica:** para cada pacote não carregado, checar (a) se
  algum executável dele aparece em Healthcheck, Entrypoint, Cmd, scripts de inicialização, cron da
  imagem ou sondas do manifesto de referência, e (b) se o nome de alguma biblioteca dele (soname)
  aparece como texto dentro de um binário ou biblioteca carregado, o que indicaria carregamento sob
  demanda (`dlopen`). Cada ocorrência é um falso negativo potencial, listado e examinado. O critério
  passa com zero falsos negativos confirmados. Esta checagem substitui o segundo avaliador, que o
  grupo não tem; o julgamento de aplicabilidade continua declarado como de avaliador único.

**Leitura se falhar.** Se S1 ou S2 falharem, o resultado é reportado como falha do coletor e a
redução de trabalho fica atribuída só à mudança de unidade. Se S3 falhar, os casos perdidos são
listados. Se S4 falhar, a P4 fica como simulação, não como integração.

## 8. Limites conhecidos antes

- Carregado não é explorável: o lado "carregado" continua com ruído (8 de 10 não aplicáveis na
  auditoria anterior). A P4 não resolve isso.
- A decisão de deploy deve continuar "bloqueado" nos três alvos (Semgrep, achados diretos de
  aplicação e SO em fim de suporte). O ganho que se procura é em trabalho para liberar e em quais
  itens o compõem, não na mudança do veredito.
- Agrupar por (regra, arquivo) pode juntar falhas distintas no mesmo arquivo: uma ação, não uma
  falha. A cobertura da matriz é reportada para mostrar que nenhum caso some.
- Trivy FS (dependências da aplicação no repositório) fica fora do filtro nesta versão.
- O coletor observa sem login na DVWA e no TeaStore (falso negativo possível em fluxos autenticados).

## Resultados

*Preenchido depois do cálculo. Fontes: `results/contexto_imagem.csv` (um registro do Trivy de
imagem por linha: 1.575 na DVWA, 3.858 no TeaStore, 448 no Juice Shop), `results/p4_acoes.csv`
(cada ação, por política), `results/p4_acoes_resumo.csv`, `results/p4_vex_trivy.csv`,
`results/p4_s5.csv`, observações brutas e VEX em `pilotos/contexto-acoes/`. Scripts:
`contexto_execucao.py --imagem`, `politica_acoes.py`, `trivy_vex.sh`, `validar_vex_trivy.py`,
`verificar_s5.py`. Testes: `tests/test_acoes.py`.*

**Reprodutibilidade da coleta.** A coleta foi feita três vezes seguidas, com os mesmos
contêineres. As 266 unidades indiretas da versão anterior (coletada em outra sessão, com
contêineres novos) têm a mesma classificação na coleta final, nas duas definições, e a P4 com a
definição registrada deu 74, 36 e 40 ações nas três coletas.

### Ações para liberar o deploy

| Política | DVWA | TeaStore | Juice Shop |
|---|---|---|---|
| P2 | 87 ações · 11/13 | 81 · 7/14 | 49 · 7/14 |
| P3 | 87 · 8/13 | 81 · 4/14 | 49 · 3/14 |
| P3\* | 89 · 10/13 | 82 · 5/14 | 50 · 4/14 |
| A2 (P3 + indiretos ≥ 9) | 87 · 8/13 | 81 · 6/14 | 49 · 4/14 |
| Escopo sem coletor (ablação) | 89 · 11/13 | 82 · 7/14 | 50 · 7/14 |
| P4 com a definição registrada | 74 · 11/13 | 36 · 7/14 | 40 · 7/14 |
| **P4** | **74 · 11/13** | **37 · 7/14** | **40 · 7/14** |
| *Unidades bloqueadas (artigo): P2 → P3* | *80 → 56* | *262 → 139* | *28 → 9* |

Composição das ações da P4: DVWA = 1 migração de SO, 39 pacotes de SO, 30 correções Semgrep e
4 outras; TeaStore = 2 migrações de SO (Debian 10 e Ubuntu 18.04), 20 pacotes de SO, 12
dependências Maven/Go, 2 correções Semgrep e 1 confirmação; Juice Shop = 1 pacote de SO, 31
dependências npm, 6 correções Semgrep e 2 outras.

### Achado 1 — medida em trabalho, a P3 do artigo não reduz nada

Em ações, **P2, P3 e A2 exigem exatamente o mesmo trabalho nos três alvos** (87, 81 e 49). A
redução de 30% a 68% que a P3 mostra em unidades vem da forma de contar. A P3 deixa de bloquear
as unidades indiretas, mas os mesmos CVEs continuam dentro do agregado de "pacotes com correção"
de cada imagem, que bloqueia pelo máximo. Para tirar o agregado do bloqueio, o time precisa
corrigir todos os seus membros com nota ≥ 7, inclusive os indiretos. Sobra só a diferença dos
indiretos sem correção, que no total é de 1 CVE (DVWA) e nenhuma ação. No TeaStore, 100 das 139
unidades da P3 viram **uma** ação (`detected-bcrypt-hash` em `setupData.sql`).

Esse achado vale para o modelo do próprio artigo e não depende da P4.

### Achado 2 — o coletor tira trabalho, com evidência

| | DVWA | TeaStore | Juice Shop |
|---|---|---|---|
| Ações totais: ablação → P4 | 89 → 74 (−17%) | 82 → 37 (**−55%**) | 50 → 40 (−20%) |
| Ações de pacote e dependência de imagem | 54 → 39 | 77 → 32 | 42 → 32 |
| CVEs de imagem distintos com nota ≥ 7 | 250 → 203 (−18,8%) | 287 → 155 (**−46,0%**) | 144 → 116 (−19,4%) |
| Pares (CVE, pacote) declarados no VEX | 78 | 371 | 46 |

**Comparada com as políticas do artigo**, a P4 pede menos trabalho e cobre mais casos da matriz
que a P3\* nos três alvos: 74 contra 89 ações e 11/13 contra 10/13 na DVWA; 37 contra 82 e 7/14
contra 5/14 no TeaStore; 40 contra 50 e 7/14 contra 4/14 no Juice Shop. A A2 também é dominada
nas duas medidas. *Ressalva que continua valendo:* a cobertura a mais vem dos indiretos e,
portanto, de coincidência de CWE. O que a P4 sustenta com evidência é a redução de trabalho, e
não a cobertura.

**Lista concreta, TeaStore.** Para liberar o deploy pela P4, o time precisa migrar as duas
imagens base fora de suporte, atualizar 12 dependências da aplicação (por exemplo
`jackson-databind`, `libthrift`, `amqp-client`, `tomcat-coyote`, `log4j`), atualizar 20 pacotes
fonte de SO que os serviços de fato carregam (`openssl`, `glibc`, `ncurses`, `zlib` e outros),
remover a chave privada versionada e o dump com hashes bcrypt, e corrigir o reset do banco sem
autenticação. Saem da lista, com declaração VEX, `curl`, `perl`, `gnupg`, `expat`, Heimdal e as
demais ferramentas que nenhum processo executa. **No Juice Shop**, as 43 ocorrências do `vm2`
viram uma ação só, "substituir o componente", porque o pacote não tem correção.

### Critérios registrados

| Critério | Resultado |
|---|---|
| S1: ≥ 20% dos CVEs de imagem distintos fora do bloqueio em ≥ 2 de 3 alvos | **Falha.** Só o TeaStore passa (46,0%); DVWA 18,8% e Juice Shop 19,4% ficam logo abaixo |
| S2: menos ações de pacote de imagem que a ablação em ≥ 2 de 3 alvos | **Passa** nos 3 (54 → 39, 77 → 32, 42 → 32) |
| S3: nenhum caso da P3\* perdido | **Passa** nos 3 |
| S4: o Trivy oficial suprime exatamente o que o VEX declara | **Passa.** Trivy 0.69.3 (imagem fixada por digest), com e sem VEX na mesma execução: TeaStore webui, 193 de 550 achados suprimidos, todos declarados; Juice Shop, 46 de 363; nenhum suprimido a mais ou a menos |
| S5: zero falsos negativos confirmados | **Falha** na definição registrada (detalhe abaixo); corrigido depois do registro |

**S5 — o falso negativo encontrado.** O contêiner de banco do TeaStore inicia pelo
`docker-entrypoint.sh` (`#!/bin/bash`), e o bash linka `libtinfo.so.5`. O bash roda na
inicialização e faz `exec` do `mysqld`, então o snapshot nunca o vê. A regra de inicialização
registrada só procurava executáveis de cada pacote citados nos scripts, e não as bibliotecas do
interpretador. Com isso, o VEX da definição registrada declarava como fora do caminho de execução
3 CVEs do ncurses (CVE-2021-39537, CVE-2022-29458, CVE-2023-29491; 15 pares com PURL). Nos
serviços Java, o mesmo acontece com `catalina.sh` e `libtinfo.so.6`, sem efeito na decisão porque
outro pacote do ncurses já estava carregado. **Correção pós-registro:** o interpretador dos
scripts de inicialização e as bibliotecas que ele carrega (`ldd` dentro do contêiner) contam como
carregados. O efeito na P4 é +1 ação no TeaStore (36 → 37). Os outros indícios
(`libidn2` citado pela glibc, `libsepol` pela libselinux, uma coincidência de nome com
`libgmp.so`) foram examinados e julgados improváveis ou não-indícios, com a justificativa em
`results/p4_s5.csv` (avaliador único). A checagem detecta o que foi desenhada para detectar, e foi
ela que achou o erro.

**Leitura dos critérios, como registrado.** O S1 falhou por pouco em dois alvos: na DVWA e no
Juice Shop, o coletor tira menos de um quinto dos CVEs. A redução de trabalho (S2) passa nos três
alvos, e só ela é atribuída ao coletor. A mudança de unidade é que explica a diferença entre
unidades e ações das políticas do artigo (Achado 1), e não entra na conta da P4.

### O que não muda

- **O veredito de deploy continua "bloqueado" nos três alvos**, em todas as políticas. A P4 muda o
  tamanho e a composição da lista de trabalho, não o veredito.
- Carregado não é explorável. O lado carregado continua com ruído: na auditoria anterior, 8 de 10
  pares carregados não eram aplicáveis.
- O coletor observa sem login na DVWA e no TeaStore, e o Trivy FS fica fora do filtro.

### Conclusão

A P4 desta versão responde **o que o time precisa fazer para liberar o deploy**, com uma lista de
ações que funciona num scanner real (VEX consumido pelo Trivy). Ela traz dois resultados
mensuráveis:

1. **A redução da P3 do artigo é um efeito da contagem.** Em trabalho, P2 e P3 são iguais nos três
   alvos.
2. **O coletor de contexto reduz o trabalho em 17% a 55%** em relação à mesma regra sem coletor,
   sem perder nenhum caso que a P3\* cobre, e a P4 fica com menos trabalho e mais cobertura que a
   P3\* nos três alvos.

O critério de magnitude por CVE (S1) falhou em dois alvos, e a verificação de falso negativo (S5)
achou um erro real, corrigido depois do registro e reportado com as duas definições.
