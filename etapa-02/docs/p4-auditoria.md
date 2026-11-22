# Auditoria manual do coletor da P4: critérios registrados antes

**Registrado em 22/11/2026, antes de sortear e de olhar qualquer caso.** Complementa
`p4-contexto.md`. Pergunta: o coletor só separa os achados, ou separa **corretamente**?

## Unidade amostrada

Pares distintos (pacote, CVE) entre os achados indiretos com nota ≥ 7 (os que a P2 bloqueia e
a P3 não), por alvo. Pares, e não unidades, porque o TeaStore repete o mesmo par em várias
imagens.

## Sorteio (estratificado, semente fixa 20261123)

- **Estrato "não carregado" (10 pares):** DVWA 4, TeaStore 6. O Juice Shop não tem pares não
  carregados na classificação final.
- **Estrato "carregado" (10 pares):** DVWA 3, TeaStore 3, Juice Shop 4.
- Dentro de cada célula, sorteio aleatório simples sem reposição (`scripts/amostra_auditoria.py`).
  Se uma célula tiver menos pares que o pedido, entram todos.

## O que se verifica em cada caso

Fontes permitidas: a descrição do CVE no relatório do Trivy, o sistema de arquivos e a
configuração da imagem implantada, o código e os arquivos de configuração da aplicação na
versão analisada. Nenhum teste de exploração.

**Para um par "não carregado", a pergunta é: algo na implantação de referência executa ou
carrega esse pacote?**

- `confirmado_nao_usado`: nenhum processo, script de inicialização, configuração de serviço ou
  código da aplicação referencia os binários ou bibliotecas do pacote.
- `usado` (falso negativo do coletor): existe um caminho na implantação que executa ou carrega
  o pacote (por exemplo, um script chamado em algum fluxo, ou uma biblioteca carregada sob
  demanda).
- `indeterminado`: não foi possível decidir com as fontes permitidas.

**Para um par "carregado", a pergunta é: a condição descrita no CVE é plausível no uso que a
aplicação faz do pacote?**

- `aplicavel`: a aplicação usa a funcionalidade afetada (ou a descrição do CVE não restringe a
  funcionalidade além de carregar o componente).
- `nao_aplicavel`: o CVE exige uma funcionalidade, configuração ou entrada que a aplicação
  claramente não usa.
- `indeterminado`: não foi possível decidir com as fontes permitidas.

## Como o resultado será lido (definido antes)

- **Precisão do "não carregado"** = `confirmado_nao_usado` / (`confirmado_nao_usado` + `usado`).
  Se for menor que 80%, o filtro não é confiável para rebaixar achados, e a P4 deve tratar o
  "não carregado" apenas como prioridade menor, não como informativo.
- **Fração aplicável entre os "carregados"** = `aplicavel` / (`aplicavel` + `nao_aplicavel`).
  É descritiva: mostra quanto ruído ainda passa pelo filtro, já que carregado não é o mesmo
  que explorável.
- Indeterminados são reportados à parte e não entram nos denominadores.

## Limite declarado antes

A auditoria é feita por **um único avaliador** (o assistente de IA, com supervisão do grupo),
sem segundo avaliador independente. Os julgamentos ficam registrados caso a caso, com a
evidência usada, para que o grupo possa revisar ou contestar cada um.

## Resultados

*(preenchido em commit posterior)*
