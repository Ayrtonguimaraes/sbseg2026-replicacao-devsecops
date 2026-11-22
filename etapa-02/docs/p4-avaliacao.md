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

*(preenchido em commit posterior)*
