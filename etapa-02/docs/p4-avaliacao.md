# Avaliação da P4 como melhoria: protocolo registrado antes da execução

**Registrado em 22/11/2026, antes de calcular qualquer política nova.** Este arquivo foi
commitado sem resultados. A seção "Resultados" é preenchida depois, em outro commit, para
que a diferença entre o que foi combinado e o que saiu fique visível no histórico do git.

## 1. A afirmação que queremos testar

A P3 do artigo trata todo achado indireto como informativo, e com isso perde casos de
cobertura que a P2 bloqueava. A P4 propõe um mecanismo diferente: **o achado indireto vira
uma obrigação de teste no Deploy**. O caso só bloqueia se um teste dirigido, sem payload de
ataque, confirmar a falha no ambiente.

Afirmação: *a P4 recupera parte da cobertura perdida pela P3 com um custo em bloqueios muito
menor que o da P2, e nenhuma alternativa simples, obtida só com ajustes de limiar, faz o
mesmo com menos bloqueios.*

## 2. Proposta e variantes

- **P4 (proposta) = P4-A.** P3 + um bloqueio no Deploy para cada caso da fila confirmado
  pelo teste dirigido.
- **P4-B e P4-B-alt deixam de ser variantes da proposta** e passam a ser **análise de
  sensibilidade**: mostram quanto o resultado mudaria se exigíssemos também nota CVSS ≥ 7,
  com vetores escolhidos pelo grupo. As colunas e os testes continuam no código.
  (Proposta do grupo; precisa ser ratificada.)

## 3. Políticas comparadas (lista fechada)

| Código | Política | Papel |
|---|---|---|
| P2 | Nota ≥ 7, todas as classes | Referência do artigo |
| P3 | Nota ≥ 7, só diretos e sem matriz | Referência do artigo |
| A1 | P3 com limiar 6 | Alternativa simples: P3 mais rígida |
| A2 | P3 + achados indiretos com nota ≥ 9 também bloqueiam | Alternativa simples: híbrida |
| A3 | P2 com limiar 8 | Alternativa simples: uniforme mais branda |
| A4 | P3 + bloqueia todas as unidades indiretas dos casos da fila, sem teste | Ablação: a P4 sem o passo de confirmação |
| P4 | P3 + 1 bloqueio por caso da fila confirmado (laudos reais) | Proposta |
| P4-teto | P3 + 1 bloqueio por caso da fila, todos confirmados | Limite superior, não é resultado |

Os três alvos: DVWA (13 casos), TeaStore 1.4.2 (14) e Juice Shop 19.0.0 (14), com as unidades
de `data/normalized/` e as filas de `results/p4_fila.csv` e `results/alvos_p4_fila.csv`.

## 4. Métricas (declaradas agora)

1. **Bloqueios**: unidades bloqueadas mais as decisões de Deploy da P4.
2. **Cobertura bruta**: casos da matriz com pelo menos um bloqueio, como no artigo.
3. **Cobertura sustentada**: casos com pelo menos um bloqueio vindo de uma unidade **direta
   para aquele caso**, ou de uma confirmação da P4. Um caso coberto só por achado indireto
   não conta.

   *Por que esta métrica existe:* o próprio artigo argumenta que o achado indireto tem
   outro escopo de impacto. E já sabemos, por leitura de código, que um bloqueio indireto
   pode cair num caso que nem existe na implantação: `ts-tls-trust-all` só roda com
   `USE_HTTPS=true`, ausente da implantação de referência.
4. **Recuperação** = (cobertura de X − cobertura da P3) / (cobertura da P2 − cobertura da P3).
5. **Custo** = (bloqueios de X − bloqueios da P3) / (bloqueios da P2 − bloqueios da P3).
6. **Testes exigidos** (só P4): tamanho da fila.

## 5. Regra de decisão (declarada agora)

- X **domina** Y num alvo se X tem bloqueios ≤ e cobertura ≥ que Y, com pelo menos uma
  desigualdade estrita. A dominância é avaliada separadamente para a cobertura bruta e para a
  sustentada.
- **A P4 se sustenta como melhoria** se, nos três alvos, nenhuma alternativa (A1 a A4) a
  domina em cobertura sustentada. O resultado em cobertura bruta é reportado por alvo, sem
  esconder os casos em que uma alternativa a domina.

**Previsão feita antes de calcular**, a partir de `results/alvos_politicas.csv` (a P1 do
TeaStore bloqueia 7 achados indiretos com nota ≥ 9, que cobrem `ts-output-encoding` e
`ts-tls-trust-all`): **é provável que A2 domine a P4 em cobertura bruta no TeaStore**. Se
isso acontecer, será reportado como resultado, não escondido.

## 6. Verificação do avaliador

O script novo (`scripts/comparar_politicas.py`) precisa reproduzir os números já publicados
antes de avaliar qualquer política nova: DVWA 5/80/56, TeaStore 32/262/139, Juice Shop
12/28/9 e as linhas de `results/alvos_limiares.csv`. Isso vira teste unitário.

## 7. Catálogo de testes benignos (automação da confirmação)

Um teste de catálogo é escolhido pelo CWE do caso e não envia payload de ataque. Cada
modelo tem critério de aprovação escrito antes e um **controle negativo**: o mesmo teste numa
rota protegida, que precisa reprovar.

| Modelo | CWEs | Critério de confirmação | Controle negativo |
|---|---|---|---|
| Acesso sem autenticação | 306, 284, 200 | Função sensível responde com o conteúdo esperado, sem redirecionar para login e sem 401/403 | Rota que exige sessão, que deve redirecionar ou negar |
| Função crítica sem autenticação | 306 | A ação executa (efeito observado no serviço), sem sessão | A mesma rota sem o parâmetro de confirmação, que não deve executar |
| CSRF | 352 | Ação com sessão, sem token, aceita com Referer de outra origem | Mesma ação sem sessão, que deve redirecionar para login |
| IDs de sessão previsíveis | 330 | 12 identificadores consecutivos com incremento constante | — (critério estatístico) |

Para a DVWA, `scripts/validar_dvwa_http.py` já é esse teste automatizado; o laudo existente
é reaproveitado.

**Ficam fora do catálogo, por decisão de protocolo:** XSS (exige enviar marcação ou script e
observar no navegador) e `js-rce-b2b` (o teste oficial tem efeito de negação de serviço).
Verificações de configuração estática (TLS, porta do banco) **não contam como confirmação**.

Funil reportado, em categorias exclusivas: na fila → com modelo dinâmico benigno → executável
na configuração local → confirmado.

**Limitação a declarar:** o modelo é escolhido pelo CWE, mas a rota testada vem da matriz de
referência, que um pipeline real não tem. Num pipeline, a rota viria do próprio achado
(o URL do alerta do ZAP ou o arquivo do Semgrep mapeado para a rota).

## Resultados

*Preenchido depois da execução (commits `0f47772` e `848ce2f`). Fontes:
`results/p4_comparacao.csv`, `results/p4_dominancia.csv` e `results/p4_funil.csv`.*

**Verificação do avaliador:** o script reproduziu DVWA 5/80/56, TeaStore 32/262/139,
Juice Shop 12/28/9 e todas as linhas de `alvos_limiares.csv` (teste
`tests/test_comparacao.py`).

### Tabela principal (bloqueios · cobertura bruta · cobertura sustentada)

| Política | DVWA (13) | TeaStore (14) | Juice Shop (14) |
|---|---|---|---|
| P2 | 80 · 11 · 8 | 262 · 7 · 4 | 28 · 7 · 3 |
| P3 | 56 · 8 · 8 | 139 · 4 · 4 | 9 · 3 · 3 |
| A1 · P3 limiar 6 | 56 · 8 · 8 | 140 · 4 · 4 | 9 · 3 · 3 |
| A2 · P3 + indiretos ≥ 9 | 58 · 8 · 8 | 146 · 6 · 4 | 19 · 4 · 3 |
| A3 · P2 limiar 8 | 12 · 4 · 2 | 82 · 5 · 2 | 18 · 5 · 1 |
| A4 · fila sem teste | 79 · 12 · 8 | 326 · 7 · 4 | 41 · 7 · 3 |
| **P4** | **58 · 10 · 10** | **140 · 5 · 5** | **10 · 4 · 4** |
| P4-teto | 60 · 12 · 12 | 142 · 7 · 7 | 13 · 7 · 7 |

### O que os números mostram

1. **A regra registrada se cumpre.** Em nenhum dos três alvos uma alternativa domina a P4 em
   cobertura sustentada. Pelo critério combinado antes, a P4 se sustenta como melhoria.
2. **A P2 não tem mais cobertura sustentada que a P3 em nenhum alvo.** Toda a cobertura que a
   P3 "perde" era sustentada só por achados indiretos. A P4 é a única política que aumenta a
   cobertura sustentada: +2 na DVWA, +1 no TeaStore e +1 no Juice Shop.
   *Ressalva:* em parte isso é por construção, porque a confirmação conta como evidência por
   definição. O teste justo é a A1 (achados diretos entre 6 e 7), e ela não acrescentou nenhum
   caso.
3. **O passo de confirmação é o que torna a P4 barata.** Bloquear os mesmos casos da fila sem
   testar (A4) custa +23, +187 e +32 bloqueios sobre a P3. A P4 custa +2, +1 e +1: de 91% a
   99% menos bloqueios extras.
4. **Recuperação frente à P2 (cobertura bruta):** a P4 recupera 67% da cobertura perdida na
   DVWA com 8% do custo em bloqueios da P2; 33% no TeaStore com 0,8%; 25% no Juice Shop com
   5%. No agregado: 4 dos 10 casos perdidos, com 4 dos 166 bloqueios extras da P2 (2,4%).
5. **Em cobertura bruta, a P4 não vence em todo lugar.** No TeaStore, a A3 (P2 com limiar 8)
   a domina: 82 bloqueios e 5/14, contra 140 e 5/14. A A3 chega lá trocando casos sustentados
   por indiretos: perde `ts-default-credentials` e `ts-private-key` e ganha casos cobertos só
   por achados indiretos (cobertura sustentada cai de 4 para 2). A A2 alcança 6/14 no TeaStore,
   mais que a P4, mas com 6 bloqueios a mais, então não a domina.
6. **A previsão registrada errou o mecanismo.** Previmos que a A2 dominaria a P4 em cobertura
   bruta no TeaStore; quem dominou foi a A3. A A2 ganha em cobertura, mas não em bloqueios.

### Funil da automação (catálogo benigno)

| Etapa | Casos | Detalhe |
|---|---:|---|
| Na fila da P4 | 11 | DVWA 4, TeaStore 3, Juice Shop 4 |
| Com modelo dinâmico benigno | 6 | CSRF, IDs previsíveis, redirecionamento, porta do banco, função crítica sem autenticação, acesso sem autenticação |
| Executável na configuração local | 5 | Exposed MySQL exige o manifesto Kubernetes dos autores |
| **Confirmados** | **4** | 1 inconclusivo (redirecionamento: rotas 404 na imagem) |

Os controles negativos reprovaram nos dois modelos executados agora (TeaStore: a mesma rota sem
confirmação não executa e `/profile` exige sessão; Juice Shop: `/api/Users` responde 401).
Ficaram fora: 3 XSS (manual, exige navegador), 1 RCE (efeito de DoS) e 1 caso só de
configuração (TLS). **Taxa de automação: 4 de 11 casos da fila (36%), ou 4 de 5 entre os que
têm modelo benigno executável (80%).**

### Desvios do protocolo

- A "recuperação" da métrica 4 ficou indefinida para a cobertura sustentada, porque a P2 e a
  P3 têm o mesmo valor nos três alvos (divisão por zero). No lugar, reporta-se o ganho absoluto
  (`ganho_sustentado`).
- No TeaStore, o laudo da P4 passou a apontar para a execução do catálogo
  (`pilotos/p4-catalogo/teastore.json`, com requisição bruta, log e controle negativo). A
  evidência anterior, do spider do ZAP, continua em `pilotos/p4-teastore/teastore-http.json`.

### Conclusão

A P4 é uma melhoria concreta no sentido registrado. É a única das políticas comparadas que
acrescenta cobertura sustentada por evidência, e custa entre 0,8% e 8% dos bloqueios extras
que a P2 exigiria. O limite também é concreto: hoje só 36% da fila é confirmável por testes
benignos automáticos, e os XSS dependem de uma etapa de DAST com navegador. A P4-B continua
no código como análise de sensibilidade: mostra que exigir CVSS ≥ 7 com vetores escolhidos à
mão muda qual caso é bloqueado.
