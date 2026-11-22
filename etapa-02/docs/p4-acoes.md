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

*Preenchido depois do cálculo.*
